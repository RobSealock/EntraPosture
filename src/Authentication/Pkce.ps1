#Requires -Version 7.4

function ConvertTo-EntraPostureBase64Url {
    <#
        .SYNOPSIS
        Base64url-encodes a byte array (RFC 4648 section 5): standard Base64 with '+'/'/'
        replaced by '-'/'_' and '=' padding stripped.

        .DESCRIPTION
        Every OAuth/PKCE/JWT primitive in this module needs this exact encoding; centralized
        here so there is one implementation to get right rather than several ad hoc ones.

        .PARAMETER Bytes
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    return [System.Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-EntraPosturePkceChallenge {
    <#
        .SYNOPSIS
        Generates an RFC 7636 PKCE code_verifier and its S256 code_challenge for the delegated
        interactive authorization code flow.

        .DESCRIPTION
        Engineering plan section 7.1: "delegated interactive authentication using a documented
        public-client flow." PKCE is mandatory for a public client per RFC 8252 (OAuth 2.0 for
        Native Apps) -- without it, an authorization code intercepted in transit could be
        redeemed by an attacker with no further secret required. Always uses the S256 challenge
        method; plain-text PKCE is not offered as an option.

        code_verifier is 32 cryptographically random bytes, base64url-encoded -- this yields a
        43-character string, within RFC 7636's required 43-128 character range using only its
        unreserved-character alphabet, so no additional validation/truncation step is needed.

        .OUTPUTS
        Ordered dictionary: CodeVerifier (keep secret, memory-only, needed again at token
        exchange) and CodeChallenge (sent in the authorize request).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory cryptographic value generation -- no external side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    $verifierBytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($verifierBytes)
    } finally {
        $rng.Dispose()
    }
    $codeVerifier = ConvertTo-EntraPostureBase64Url -Bytes $verifierBytes

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $challengeBytes = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    } finally {
        $sha256.Dispose()
    }
    $codeChallenge = ConvertTo-EntraPostureBase64Url -Bytes $challengeBytes

    return [ordered]@{
        CodeVerifier  = $codeVerifier
        CodeChallenge = $codeChallenge
        ChallengeMethod = 'S256'
    }
}

function New-EntraPostureOAuthState {
    <#
        .SYNOPSIS
        Generates an opaque, high-entropy 'state' value for CSRF protection on the
        authorization-code redirect.

        .DESCRIPTION
        Verified against the value returned on the loopback redirect before an authorization
        code is ever trusted -- rejects a redirect that doesn't carry back the exact state this
        run generated, which is what makes the state parameter meaningful protection rather than
        a formality.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory cryptographic value generation -- no external side effect.')]
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $bytes = [byte[]]::new(24)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ConvertTo-EntraPostureBase64Url -Bytes $bytes
}
