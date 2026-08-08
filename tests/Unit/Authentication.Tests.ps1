#Requires -Version 7.4
#Requires -Modules Pester

<#
    Unit tests for src/Authentication, dot-sourced directly so private helpers are directly
    testable per engineering plan section 14 item 1. Covers PKCE generation, the loopback
    redirect listener (against real local HTTP requests), JWT client assertion construction and
    signing (against a real self-signed certificate, with real cryptographic signature
    verification), JWT claim decoding/validation, and the memory-only token cache. Network calls
    to the real Microsoft identity platform live separately in
    tests/Security/DelegatedAuthNetwork.Tests.ps1 (tagged 'Network').
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/NewCorrelationId.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/NewErrorRecord.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/Pkce.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/LoopbackListener.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/ClientAssertion.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/TokenValidation.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/TokenCache.ps1')

    function script:New-EntraPostureTestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=EntraPostureTestCert', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }

    function script:ConvertTo-EntraPostureTestBase64UrlJson {
        param([hashtable]$Claims)
        $json = $Claims | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        return [System.Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    function script:New-EntraPostureTestJwt {
        param([hashtable]$Claims, [string]$HeaderSegment = 'eyJhbGciOiJSUzI1NiJ9')
        $payloadSegment = ConvertTo-EntraPostureTestBase64UrlJson -Claims $Claims
        return "$HeaderSegment.$payloadSegment.fake-signature-not-verified"
    }
}

Describe 'New-EntraPosturePkceChallenge' {
    It 'generates a 43-character code_verifier and code_challenge using S256' {
        $pkce = New-EntraPosturePkceChallenge
        $pkce.CodeVerifier.Length | Should -Be 43
        $pkce.CodeChallenge.Length | Should -Be 43
        $pkce.ChallengeMethod | Should -Be 'S256'
    }

    It 'produces a code_challenge matching the SHA-256 hash of the code_verifier' {
        $pkce = New-EntraPosturePkceChallenge
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $expectedHash = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($pkce.CodeVerifier))
        } finally {
            $sha256.Dispose()
        }
        $expectedChallenge = [System.Convert]::ToBase64String($expectedHash).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $pkce.CodeChallenge | Should -Be $expectedChallenge
    }

    It 'generates a different verifier on each call' {
        (New-EntraPosturePkceChallenge).CodeVerifier | Should -Not -Be (New-EntraPosturePkceChallenge).CodeVerifier
    }
}

Describe 'New-EntraPostureOAuthState' {
    It 'generates a non-empty, URL-safe state value' {
        $state = New-EntraPostureOAuthState
        $state | Should -Not -BeNullOrEmpty
        $state | Should -Not -Match '[+/=]'
    }

    It 'generates a different value on each call' {
        (New-EntraPostureOAuthState) | Should -Not -Be (New-EntraPostureOAuthState)
    }
}

Describe 'Loopback redirect listener' {
    It 'starts on localhost and returns a matching RedirectUri' {
        # 'localhost', not the 127.0.0.1 literal -- see LoopbackListener.ps1's own comment: only
        # the literal 'localhost' hostname gets Microsoft's port-agnostic redirect URI matching,
        # which this listener's randomly-chosen per-run port depends on.
        $info = Start-EntraPostureLoopbackListener
        try {
            $info.RedirectUri | Should -Match '^http://localhost:\d+/$'
            $info.Listener.IsListening | Should -BeTrue
        } finally {
            Stop-EntraPostureLoopbackListener -Listener $info.Listener
        }
    }

    It 'returns the authorization code from a matching-state redirect' {
        $info = Start-EntraPostureLoopbackListener
        try {
            $state = New-EntraPostureOAuthState
            $job = Start-Job -ScriptBlock {
                param($Uri)
                Start-Sleep -Milliseconds 300
                try { Invoke-WebRequest -Uri $Uri -UseBasicParsing | Out-Null } catch { }
            } -ArgumentList "$($info.RedirectUri)?code=abc123&state=$state"

            $code = Receive-EntraPostureLoopbackRedirect -Listener $info.Listener -ExpectedState $state -TimeoutSeconds 10
            $code | Should -Be 'abc123'
            Wait-Job -Job $job -Timeout 5 | Out-Null
            Remove-Job -Job $job -Force
        } finally {
            Stop-EntraPostureLoopbackListener -Listener $info.Listener
        }
    }

    It 'throws on a state mismatch rather than returning the code' {
        $info = Start-EntraPostureLoopbackListener
        try {
            $job = Start-Job -ScriptBlock {
                param($Uri)
                Start-Sleep -Milliseconds 300
                try { Invoke-WebRequest -Uri $Uri -UseBasicParsing | Out-Null } catch { }
            } -ArgumentList "$($info.RedirectUri)?code=abc123&state=wrong-state"

            { Receive-EntraPostureLoopbackRedirect -Listener $info.Listener -ExpectedState 'expected-state' -TimeoutSeconds 10 } | Should -Throw '*state mismatch*'
            Wait-Job -Job $job -Timeout 5 | Out-Null
            Remove-Job -Job $job -Force
        } finally {
            Stop-EntraPostureLoopbackListener -Listener $info.Listener
        }
    }

    It 'throws with the OAuth error detail on an error redirect' {
        $info = Start-EntraPostureLoopbackListener
        try {
            $state = New-EntraPostureOAuthState
            $job = Start-Job -ScriptBlock {
                param($Uri)
                Start-Sleep -Milliseconds 300
                try { Invoke-WebRequest -Uri $Uri -UseBasicParsing | Out-Null } catch { }
            } -ArgumentList "$($info.RedirectUri)?error=access_denied&error_description=user+cancelled&state=$state"

            { Receive-EntraPostureLoopbackRedirect -Listener $info.Listener -ExpectedState $state -TimeoutSeconds 10 } | Should -Throw '*access_denied*'
            Wait-Job -Job $job -Timeout 5 | Out-Null
            Remove-Job -Job $job -Force
        } finally {
            Stop-EntraPostureLoopbackListener -Listener $info.Listener
        }
    }

    It 'times out when no redirect arrives' {
        $info = Start-EntraPostureLoopbackListener
        try {
            { Receive-EntraPostureLoopbackRedirect -Listener $info.Listener -ExpectedState 'x' -TimeoutSeconds 1 } | Should -Throw '*timed out*'
        } finally {
            Stop-EntraPostureLoopbackListener -Listener $info.Listener
        }
    }
}

Describe 'New-EntraPostureClientAssertion' {
    BeforeAll {
        $script:TestCert = New-EntraPostureTestCertificate
    }

    AfterAll {
        $script:TestCert.Dispose()
    }

    It 'produces a 3-segment compact JWT' {
        $jwt = New-EntraPostureClientAssertion -ClientId 'client-id' -TenantId 'tenant-id' -Certificate $script:TestCert -CloudEndpoint 'https://login.microsoftonline.com'
        @($jwt.Split('.')).Count | Should -Be 3
    }

    It 'sets aud to the token endpoint and iss/sub to the client ID' {
        $jwt = New-EntraPostureClientAssertion -ClientId 'my-client-id' -TenantId 'my-tenant-id' -Certificate $script:TestCert -CloudEndpoint 'https://login.microsoftonline.com'
        $claims = ConvertFrom-EntraPostureJwtClaim -Jwt $jwt
        $claims['aud'] | Should -Be 'https://login.microsoftonline.com/my-tenant-id/oauth2/v2.0/token'
        $claims['iss'] | Should -Be 'my-client-id'
        $claims['sub'] | Should -Be 'my-client-id'
        $claims['jti'] | Should -Not -BeNullOrEmpty
        (([long]$claims['exp']) - ([long]$claims['nbf'])) | Should -Be 120
    }

    It 'produces a signature that verifies against the certificate''s own public key' {
        $jwt = New-EntraPostureClientAssertion -ClientId 'client-id' -TenantId 'tenant-id' -Certificate $script:TestCert -CloudEndpoint 'https://login.microsoftonline.com'
        $segments = $jwt.Split('.')
        $signedData = [System.Text.Encoding]::ASCII.GetBytes("$($segments[0]).$($segments[1])")
        $normalized = $segments[2].Replace('-', '+').Replace('_', '/')
        switch ($normalized.Length % 4) { 2 { $normalized += '==' } 3 { $normalized += '=' } }
        $signatureBytes = [System.Convert]::FromBase64String($normalized)

        $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($script:TestCert)
        $isValid = $publicKey.VerifyData($signedData, $signatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $isValid | Should -BeTrue
    }

    It 'fails signature verification against a tampered payload' {
        $jwt = New-EntraPostureClientAssertion -ClientId 'client-id' -TenantId 'tenant-id' -Certificate $script:TestCert -CloudEndpoint 'https://login.microsoftonline.com'
        $segments = $jwt.Split('.')
        $tamperedPayload = $segments[1].Replace('e', 'f')
        $signedData = [System.Text.Encoding]::ASCII.GetBytes("$($segments[0]).$tamperedPayload")
        $normalized = $segments[2].Replace('-', '+').Replace('_', '/')
        switch ($normalized.Length % 4) { 2 { $normalized += '==' } 3 { $normalized += '=' } }
        $signatureBytes = [System.Convert]::FromBase64String($normalized)

        $publicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($script:TestCert)
        $isValid = $publicKey.VerifyData($signedData, $signatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $isValid | Should -BeFalse
    }

    It 'sets x5t to the certificate''s own SHA-1 thumbprint' {
        $jwt = New-EntraPostureClientAssertion -ClientId 'client-id' -TenantId 'tenant-id' -Certificate $script:TestCert -CloudEndpoint 'https://login.microsoftonline.com'
        $headerSegment = $jwt.Split('.')[0]
        $normalized = $headerSegment.Replace('-', '+').Replace('_', '/')
        switch ($normalized.Length % 4) { 2 { $normalized += '==' } 3 { $normalized += '=' } }
        $headerJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($normalized))
        $header = $headerJson | ConvertFrom-Json

        $expectedThumbprintBytes = $script:TestCert.GetCertHash()
        $expectedX5t = [System.Convert]::ToBase64String($expectedThumbprintBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $header.x5t | Should -Be $expectedX5t
    }

    It 'throws when the certificate has no private key' {
        $publicOnlyCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($script:TestCert.Export('Cert'))
        try {
            { New-EntraPostureClientAssertion -ClientId 'client-id' -TenantId 'tenant-id' -Certificate $publicOnlyCert -CloudEndpoint 'https://login.microsoftonline.com' } | Should -Throw
        } finally {
            $publicOnlyCert.Dispose()
        }
    }
}

Describe 'ConvertFrom-EntraPostureJwtClaim' {
    It 'decodes a well-formed JWT payload' {
        $jwt = New-EntraPostureTestJwt -Claims @{ aud = 'https://graph.microsoft.com'; sub = 'user1' }
        $claims = ConvertFrom-EntraPostureJwtClaim -Jwt $jwt
        $claims['aud'] | Should -Be 'https://graph.microsoft.com'
        $claims['sub'] | Should -Be 'user1'
    }

    It 'throws on input without 3 dot-separated segments' {
        { ConvertFrom-EntraPostureJwtClaim -Jwt 'not-a-jwt' } | Should -Throw '*3 dot-separated segments*'
    }
}

Describe 'Test-EntraPostureTokenClaim' {
    BeforeAll {
        $script:NowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $script:ValidClaims = @{
            aud = 'https://graph.microsoft.com'
            tid = 'tenant-1'
            iss = 'https://login.microsoftonline.com/tenant-1/v2.0'
            exp = $script:NowUnix + 3600
            nbf = $script:NowUnix - 60
            scp = 'User.Read Group.Read.All'
        }
    }

    It 'accepts a token satisfying every check' {
        $jwt = New-EntraPostureTestJwt -Claims $script:ValidClaims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeTrue
        $result.Errors.Count | Should -Be 0
    }

    It 'rejects an audience mismatch' {
        $jwt = New-EntraPostureTestJwt -Claims $script:ValidClaims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://management.azure.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'Audience mismatch'
    }

    It 'rejects a tenant mismatch' {
        $jwt = New-EntraPostureTestJwt -Claims $script:ValidClaims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-2'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'Tenant mismatch'
    }

    It 'rejects an issuer not rooted at the expected cloud/tenant' {
        $claims = $script:ValidClaims.Clone()
        $claims['iss'] = 'https://login.microsoftonline.com/other-tenant/v2.0'
        $jwt = New-EntraPostureTestJwt -Claims $claims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'Issuer'
    }

    It 'rejects an expired token' {
        $claims = $script:ValidClaims.Clone()
        $claims['exp'] = $script:NowUnix - 3600
        $jwt = New-EntraPostureTestJwt -Claims $claims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'expired'
    }

    It 'rejects a not-yet-valid token' {
        $claims = $script:ValidClaims.Clone()
        $claims['nbf'] = $script:NowUnix + 3600
        $jwt = New-EntraPostureTestJwt -Claims $claims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'not yet valid'
    }

    It 'rejects a token with neither scp nor roles' {
        $claims = $script:ValidClaims.Clone()
        $claims.Remove('scp')
        $jwt = New-EntraPostureTestJwt -Claims $claims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'neither delegated scopes'
    }

    It 'accepts a token carrying application roles instead of delegated scopes' {
        $claims = $script:ValidClaims.Clone()
        $claims.Remove('scp')
        $claims['roles'] = @('Directory.Read.All')
        $jwt = New-EntraPostureTestJwt -Claims $claims
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeTrue
    }

    It 'reports every failing check simultaneously, not just the first' {
        $jwt = New-EntraPostureTestJwt -Claims @{ aud = 'wrong'; tid = 'wrong'; iss = 'wrong'; exp = $script:NowUnix - 100 }
        $result = Test-EntraPostureTokenClaim -Jwt $jwt -ExpectedAudience 'https://graph.microsoft.com' -ExpectedTenantId 'tenant-1'
        $result.IsValid | Should -BeFalse
        $result.Errors.Count | Should -BeGreaterOrEqual 4
    }

    It 'reports IsValid false (not a thrown error) for a malformed token' {
        $result = Test-EntraPostureTokenClaim -Jwt 'not-a-jwt' -ExpectedAudience 'x' -ExpectedTenantId 'y'
        $result.IsValid | Should -BeFalse
    }
}

Describe 'Get-EntraPostureTokenGrantedPermission' {
    It 'extracts delegated scopes from the scp claim' {
        $jwt = New-EntraPostureTestJwt -Claims @{ scp = 'User.Read Group.Read.All' }
        $result = Get-EntraPostureTokenGrantedPermission -Jwt $jwt
        $result.GrantType | Should -Be 'Delegated'
        @($result.Permissions) | Should -Be @('User.Read', 'Group.Read.All')
    }

    It 'extracts application roles from the roles claim' {
        $jwt = New-EntraPostureTestJwt -Claims @{ roles = @('Directory.Read.All', 'Policy.Read.All') }
        $result = Get-EntraPostureTokenGrantedPermission -Jwt $jwt
        $result.GrantType | Should -Be 'Application'
        @($result.Permissions) | Should -Be @('Directory.Read.All', 'Policy.Read.All')
    }

    It 'returns GrantType None with an empty permission set when neither claim is present' {
        $jwt = New-EntraPostureTestJwt -Claims @{ aud = 'x' }
        $result = Get-EntraPostureTokenGrantedPermission -Jwt $jwt
        $result.GrantType | Should -Be 'None'
        @($result.Permissions).Count | Should -Be 0
    }
}

Describe 'Token cache' {
    It 'starts empty and returns null for an unknown key' {
        $cache = New-EntraPostureTokenCache
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -BeNullOrEmpty
    }

    It 'stores and retrieves a token by (audience, tenant)' {
        $cache = New-EntraPostureTokenCache
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' -AccessToken 'token-value' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -Be 'token-value'
    }

    It 'keeps tokens for different tenants/audiences independent' {
        $cache = New-EntraPostureTokenCache
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' -AccessToken 'graph-token' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://management.azure.com' -TenantId 't1' -AccessToken 'arm-token' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -Be 'graph-token'
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://management.azure.com' -TenantId 't1' | Should -Be 'arm-token'
    }

    It 'treats a token within the 60-second skew buffer of expiry as unusable' {
        $cache = New-EntraPostureTokenCache
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' -AccessToken 'about-to-expire' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddSeconds(30)
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -BeNullOrEmpty
    }

    It 'removes a single entry via Remove-EntraPostureCachedToken' {
        $cache = New-EntraPostureTokenCache
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' -AccessToken 'x' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Remove-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1'
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -BeNullOrEmpty
    }

    It 'removes every entry via Clear-EntraPostureTokenCache' {
        $cache = New-EntraPostureTokenCache
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' -AccessToken 'a' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Set-EntraPostureCachedToken -Cache $cache -Audience 'https://management.azure.com' -TenantId 't1' -AccessToken 'b' -ExpiresAtUtc (Get-Date).ToUniversalTime().AddHours(1)
        Clear-EntraPostureTokenCache -Cache $cache
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId 't1' | Should -BeNullOrEmpty
        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://management.azure.com' -TenantId 't1' | Should -BeNullOrEmpty
    }
}
