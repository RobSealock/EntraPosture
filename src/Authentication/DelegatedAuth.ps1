#Requires -Version 7.4

function New-EntraPostureAuthorizeUrl {
    <#
        .SYNOPSIS
        Builds the Microsoft identity platform authorize URL for the delegated interactive
        authorization-code + PKCE flow.

        .PARAMETER ClientId
        .PARAMETER TenantId
        .PARAMETER RedirectUri
        .PARAMETER Scope
        Space-delimited scope string. 'offline_access' is deliberately never added here -- v1
        does not implement refresh-token/persistent-session handling (ADR-006 excludes
        persistent token caches), so requesting a refresh token would acquire a credential this
        tool has no supported way to use or protect.

        .PARAMETER CodeChallenge
        .PARAMETER State
        .PARAMETER CloudEndpoint
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure string construction (a URL) with no external side effect -- nothing to guard behind -WhatIf/-Confirm.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$RedirectUri,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter(Mandatory)]
        [string]$CodeChallenge,

        [Parameter(Mandatory)]
        [string]$State,

        [Parameter()]
        [string]$CloudEndpoint = 'https://login.microsoftonline.com'
    )

    $queryParams = [ordered]@{
        client_id             = $ClientId
        response_type         = 'code'
        redirect_uri          = $RedirectUri
        response_mode         = 'query'
        scope                 = $Scope
        state                 = $State
        code_challenge        = $CodeChallenge
        code_challenge_method = 'S256'
    }

    $queryString = ($queryParams.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$([Uri]::EscapeDataString($_.Value))"
    }) -join '&'

    return "$CloudEndpoint/$TenantId/oauth2/v2.0/authorize?$queryString"
}

function Invoke-EntraPostureTokenRequest {
    <#
        .SYNOPSIS
        POSTs a token request to the Microsoft identity platform token endpoint and returns a
        structured, sanitized result -- shared by both the delegated code-exchange step and the
        certificate client-credentials flow.

        .DESCRIPTION
        Every error path is sanitized through Test-EntraPostureSafeDiagnosticText before
        being included in a thrown message (defense in depth on top of the fact that this
        function never logs the request body, which is where a client_assertion/code/
        code_verifier would appear). Response body content is validated as JSON before any field
        is read.

        .PARAMETER TokenEndpoint
        .PARAMETER Body
        Hashtable of form-urlencoded body parameters. Never logged.

        .OUTPUTS
        Ordered dictionary: AccessToken, ExpiresAtUtc, TokenType.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$TokenEndpoint,

        [Parameter(Mandatory)]
        [hashtable]$Body
    )

    $formBody = ($Body.GetEnumerator() | ForEach-Object {
        "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString([string]$_.Value))"
    }) -join '&'

    $requestParams = @{
        Uri             = $TokenEndpoint
        Method          = 'POST'
        Body            = $formBody
        ContentType     = 'application/x-www-form-urlencoded'
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }

    try {
        $response = Invoke-RestMethod @requestParams
    } catch {
        $statusCode = $null
        $errorBody = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorBody = $_.ErrorDetails.Message
        }

        $parsedError = $null
        if ($errorBody) {
            try {
                $parsedError = ConvertFrom-EntraPostureJson -Json $errorBody
            } catch {
                # Non-JSON error body is a real, expected case (e.g. an HTML error page from an
                # intermediary proxy) -- fall through to the generic unparsed-body message below
                # rather than treating a parse failure here as itself an error.
                $parsedError = $null
            }
        }

        if ($parsedError -and $parsedError.Contains('error')) {
            $safeDetail = "$($parsedError['error']): $($parsedError['error_description'])" -replace '[\r\n]+', ' '
            # error_description from Microsoft can itself contain a correlation GUID and other
            # diagnostic text but never a token/secret (it describes *why* the request was
            # rejected, before any credential was issued) -- still routed through the same safe
            # -text gate as every other diagnostic message in this project, on principle.
            if (-not (Test-EntraPostureSafeDiagnosticText -Text $safeDetail)) {
                $safeDetail = "$($parsedError['error']) (description withheld: matched unsafe-content pattern)"
            }
            throw "Invoke-EntraPostureTokenRequest: token endpoint rejected the request (HTTP $statusCode): $safeDetail"
        }

        throw "Invoke-EntraPostureTokenRequest: token request failed (HTTP $statusCode) and the response body could not be parsed as a standard OAuth error."
    }

    if (-not $response.access_token) {
        throw 'Invoke-EntraPostureTokenRequest: token endpoint returned a 200 response with no access_token field.'
    }

    $expiresInSeconds = [int]$response.expires_in
    return [ordered]@{
        AccessToken  = $response.access_token
        ExpiresAtUtc = (Get-Date).ToUniversalTime().AddSeconds($expiresInSeconds)
        TokenType    = $response.token_type
    }
}

function Connect-EntraPostureDelegated {
    <#
        .SYNOPSIS
        Performs the delegated interactive authorization-code + PKCE flow via the system browser
        and a loopback redirect listener (RFC 8252).

        .DESCRIPTION
        Engineering plan section 7.1: delegated interactive authentication using a documented
        public-client flow. Opens the user's default system browser (never an embedded
        webview -- RFC 8252 explicitly discourages embedded webviews for native apps) to the
        Microsoft identity platform's own sign-in experience; this tool never sees the user's
        credentials at any point.

        .PARAMETER ClientId
        This tool's own app registration client ID -- never a Microsoft first-party client ID
        (see the Phase 1 finding on EntraFalcon's default 'BroCi' flow, which this project's
        architecture deliberately does not replicate). The organization deploying this tool
        must register their own public-client app registration and supply its ID here.

        .PARAMETER TenantId
        .PARAMETER Scope
        .PARAMETER TokenCache
        A handle from New-EntraPostureTokenCache. On success, the returned token is also
        stored in this cache under (Scope's resource audience, TenantId).

        .PARAMETER CloudEndpoint
        .PARAMETER TimeoutSeconds
        How long to wait for the user to complete sign-in in the browser. Default 300.

        .PARAMETER Browser
        Optional. Launches this specific browser instead of the OS default handler -- required
        (not optional) when -PrivateBrowsing is also supplied. See
        Start-EntraPostureAuthBrowser for the full rationale (isolating the sign-in from an
        existing browser-profile SSO session).

        .PARAMETER PrivateBrowsing
        Optional switch. Requires -Browser. Opens that browser's private/incognito window.

        .OUTPUTS
        Ordered dictionary: AccessToken, ExpiresAtUtc, TokenType.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$TokenCache,

        [Parameter()]
        [string]$CloudEndpoint = 'https://login.microsoftonline.com',

        [Parameter()]
        [int]$TimeoutSeconds = 300,

        [Parameter()]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [switch]$PrivateBrowsing
    )

    $pkce = New-EntraPosturePkceChallenge
    $state = New-EntraPostureOAuthState
    $listenerInfo = Start-EntraPostureLoopbackListener

    try {
        $authorizeUrl = New-EntraPostureAuthorizeUrl -ClientId $ClientId -TenantId $TenantId `
            -RedirectUri $listenerInfo.RedirectUri -Scope $Scope -CodeChallenge $pkce.CodeChallenge `
            -State $state -CloudEndpoint $CloudEndpoint

        Write-EntraPostureLog -Level Info -Stage Preflight -Message 'Opening system browser for sign-in. Complete authentication in the browser window.' | Out-Null
        Start-EntraPostureAuthBrowser -Url $authorizeUrl -Browser $Browser -PrivateBrowsing:$PrivateBrowsing

        $authorizationCode = Receive-EntraPostureLoopbackRedirect -Listener $listenerInfo.Listener -ExpectedState $state -TimeoutSeconds $TimeoutSeconds
    } finally {
        Stop-EntraPostureLoopbackListener -Listener $listenerInfo.Listener
    }

    $tokenEndpoint = "$CloudEndpoint/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $authorizationCode
        redirect_uri  = $listenerInfo.RedirectUri
        code_verifier = $pkce.CodeVerifier
        scope         = $Scope
    }

    $tokenResult = Invoke-EntraPostureTokenRequest -TokenEndpoint $tokenEndpoint -Body $tokenBody

    $resourceAudience = $Scope.Split(' ')[0] -replace '/\.default$', '' -replace '(https?://[^/]+).*', '$1'
    Set-EntraPostureCachedToken -Cache $TokenCache -Audience $resourceAudience -TenantId $TenantId -AccessToken $tokenResult.AccessToken -ExpiresAtUtc $tokenResult.ExpiresAtUtc

    return $tokenResult
}

function Connect-EntraPostureCertificate {
    <#
        .SYNOPSIS
        Performs the certificate app-only (client-credentials-with-certificate-assertion) flow.

        .DESCRIPTION
        Engineering plan section 7.1: certificate app-only authentication using a non-exported
        certificate private key. No client secret path exists anywhere in this function or
        callable from it (ADR-006 excludes client secrets from v1 entirely).

        .PARAMETER ClientId
        .PARAMETER TenantId
        .PARAMETER Certificate
        .PARAMETER Scope
        Defaults to the Graph default scope. Application permissions come entirely from what an
        admin consented to on the app registration -- this parameter does not request specific
        permissions, it names the resource (.default requests whatever was already consented).

        .PARAMETER TokenCache
        .PARAMETER CloudEndpoint

        .OUTPUTS
        Ordered dictionary: AccessToken, ExpiresAtUtc, TokenType.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [string]$Scope = 'https://graph.microsoft.com/.default',

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$TokenCache,

        [Parameter()]
        [string]$CloudEndpoint = 'https://login.microsoftonline.com'
    )

    $assertion = New-EntraPostureClientAssertion -ClientId $ClientId -TenantId $TenantId -Certificate $Certificate -CloudEndpoint $CloudEndpoint

    $tokenEndpoint = "$CloudEndpoint/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        client_id             = $ClientId
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
        scope                 = $Scope
    }

    $tokenResult = Invoke-EntraPostureTokenRequest -TokenEndpoint $tokenEndpoint -Body $tokenBody

    $resourceAudience = $Scope -replace '/\.default$', '' -replace '(https?://[^/]+).*', '$1'
    Set-EntraPostureCachedToken -Cache $TokenCache -Audience $resourceAudience -TenantId $TenantId -AccessToken $tokenResult.AccessToken -ExpiresAtUtc $tokenResult.ExpiresAtUtc

    return $tokenResult
}
