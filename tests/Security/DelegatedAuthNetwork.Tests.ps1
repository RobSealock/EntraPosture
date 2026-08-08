#Requires -Version 7.4
#Requires -Modules Pester

<#
    Tagged 'Network': these tests make real outbound HTTPS calls to Microsoft's production token
    endpoint (login.microsoftonline.com). They intentionally supply invalid credentials -- no
    real tenant, app registration, or user interaction is required or possible here -- and assert
    on the specific AADSTS error codes Microsoft's endpoint returns for a malformed/unregistered
    request. This is deliberate: it proves the full chain (client assertion construction ->
    signing -> token-endpoint POST -> error-body parsing -> safe-diagnostic-text gating) works
    against real infrastructure, not just a local mock. Exclude with
    `Invoke-Pester -Path ./tests -ExcludeTag Network` in an offline environment.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/NewCorrelationId.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/NewErrorRecord.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Logging/WriteLog.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/Pkce.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/LoopbackListener.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/ClientAssertion.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/TokenCache.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/DelegatedAuth.ps1')

    function script:New-EntraPostureTestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=EntraPostureTestCert', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }
}

Describe 'New-EntraPostureAuthorizeUrl' -Tag 'Network' {
    It 'never includes offline_access even when the caller-supplied scope omits it' {
        $pkce = New-EntraPosturePkceChallenge
        $state = New-EntraPostureOAuthState
        $url = New-EntraPostureAuthorizeUrl -ClientId 'client-1' -TenantId 'tenant-1' -RedirectUri 'http://127.0.0.1:12345/' `
            -Scope 'https://graph.microsoft.com/.default' -CodeChallenge $pkce.CodeChallenge -State $state
        $url | Should -Not -Match 'offline_access'
        $url | Should -Match '^https://login\.microsoftonline\.com/tenant-1/oauth2/v2\.0/authorize\?'
        $url | Should -Match 'code_challenge_method=S256'
    }
}

Describe 'Connect-EntraPostureCertificate against the real Microsoft token endpoint' -Tag 'Network' {
    BeforeAll {
        $script:TestCert = New-EntraPostureTestCertificate
    }

    AfterAll {
        $script:TestCert.Dispose()
    }

    It 'gets a real AADSTS error for an unregistered client, and never populates the cache on failure' {
        $cache = New-EntraPostureTokenCache
        $fakeTenantId = [guid]::NewGuid().ToString()
        $fakeClientId = [guid]::NewGuid().ToString()

        { Connect-EntraPostureCertificate -ClientId $fakeClientId -TenantId $fakeTenantId -Certificate $script:TestCert -TokenCache $cache } |
            Should -Throw '*AADSTS*'

        Get-EntraPostureCachedToken -Cache $cache -Audience 'https://graph.microsoft.com' -TenantId $fakeTenantId | Should -BeNullOrEmpty
    }

    It 'rejects a malformed tenant identifier with a specific AADSTS error rather than a generic transport error' {
        $cache = New-EntraPostureTokenCache
        # The exact code Microsoft returns depends on *why* the identifier is invalid (not a DNS
        # name/GUID at all vs. a well-formed but unregistered one) -- asserting on the family
        # (AADSTS900*, "tenant") rather than one hardcoded code, since that's the actual contract
        # this test is proving: a specific, parsed OAuth error reaches the caller, not a generic
        # "no response"/transport-level failure.
        { Connect-EntraPostureCertificate -ClientId ([guid]::NewGuid().ToString()) -TenantId 'not-a-valid-tenant-id' -Certificate $script:TestCert -TokenCache $cache } |
            Should -Throw '*AADSTS900*tenant identifier*'
    }
}
