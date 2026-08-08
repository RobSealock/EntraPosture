#Requires -Version 7.4

function ConvertFrom-EntraPostureJwtClaim {
    <#
        .SYNOPSIS
        Decodes a JWT's claims (payload segment) without verifying its signature.

        .DESCRIPTION
        Deliberately does not verify the token's cryptographic signature. That is a correct,
        bounded scope decision, not an oversight: this function only ever decodes tokens this
        tool acquired itself, directly from Microsoft's token endpoint, over a TLS connection it
        initiated -- the same trust model every native/public OAuth client uses (MSAL does not
        verify its own tokens' signatures either, for the same reason). Signature verification
        via the identity provider's published JWKS keys would only be required if this tool ever
        accepted a token *presented to it by a third party*, which it does not and architecturally
        cannot (ADR-023: read-only, no inbound service surface).

        .PARAMETER Jwt
        The JWT compact serialization string.

        .OUTPUTS
        Ordered dictionary of decoded claims.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$Jwt
    )

    $segments = $Jwt.Split('.')
    if ($segments.Count -ne 3) {
        throw "ConvertFrom-EntraPostureJwtClaim: input does not have the 3 dot-separated segments a JWT requires (found $($segments.Count))."
    }

    $payloadSegment = $segments[1]
    # Restore standard Base64 padding/alphabet from base64url before decoding.
    $normalized = $payloadSegment.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
        1 { throw "ConvertFrom-EntraPostureJwtClaim: JWT payload segment has an invalid length and cannot be valid base64url." }
    }

    try {
        $payloadBytes = [System.Convert]::FromBase64String($normalized)
    } catch {
        throw "ConvertFrom-EntraPostureJwtClaim: JWT payload segment is not valid base64url: $($_.Exception.Message)"
    }

    $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
    return (ConvertFrom-EntraPostureJson -Json $payloadJson)
}

function Test-EntraPostureTokenClaim {
    <#
        .SYNOPSIS
        Validates an access token's audience, tenant, issuer, cloud, and validity window before
        the token is trusted for any request.

        .DESCRIPTION
        Engineering plan section 7.1: "Token audience, tenant, issuer, expiry, scopes/roles, and
        cloud verified before use." This is that check. Every field is checked independently and
        every failure is reported (not just the first one found), since a caller deciding
        whether to proceed benefits from the complete picture -- a token that fails on both
        audience and tenant is a different, more concerning situation than one that just expired
        a few seconds early.

        .PARAMETER Jwt
        The access token to validate.

        .PARAMETER ExpectedAudience
        The exact resource audience this token must have been issued for (e.g.
        'https://graph.microsoft.com' or the resource's application ID URI/GUID -- Microsoft
        tokens vary in which form 'aud' takes depending on API and app manifest configuration,
        so the caller supplies the exact expected value rather than this function guessing).

        .PARAMETER ExpectedTenantId
        The tenant ID this run authenticated against.

        .PARAMETER ExpectedCloudEndpoint
        Base identity platform host the issuer must be rooted at. Defaults to Microsoft public
        cloud, matching ADR-032's v1 scope restriction.

        .PARAMETER ClockSkewToleranceSeconds
        Small allowance for clock drift between this machine and the token issuer when checking
        expiry/not-before. Default 60.

        .OUTPUTS
        Ordered dictionary: IsValid (bool) and Errors (string array, empty when IsValid).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$Jwt,

        [Parameter(Mandatory)]
        [string]$ExpectedAudience,

        [Parameter(Mandatory)]
        [string]$ExpectedTenantId,

        [Parameter()]
        [string]$ExpectedCloudEndpoint = 'https://login.microsoftonline.com',

        [Parameter()]
        [int]$ClockSkewToleranceSeconds = 60
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $claims = ConvertFrom-EntraPostureJwtClaim -Jwt $Jwt
    } catch {
        return [ordered]@{
            IsValid = $false
            Errors  = @("Token could not be decoded: $($_.Exception.Message)")
        }
    }

    if (-not $claims.Contains('aud') -or $claims['aud'] -ne $ExpectedAudience) {
        $errors.Add("Audience mismatch: expected '$ExpectedAudience', got '$($claims['aud'])'.")
    }

    $tenantClaim = if ($claims.Contains('tid')) { $claims['tid'] } else { $null }
    if ($tenantClaim -ne $ExpectedTenantId) {
        $errors.Add("Tenant mismatch: expected '$ExpectedTenantId', got '$tenantClaim'.")
    }

    $expectedIssuerPrefix = "$ExpectedCloudEndpoint/$ExpectedTenantId/"
    $issuerClaim = if ($claims.Contains('iss')) { [string]$claims['iss'] } else { '' }
    if (-not $issuerClaim.StartsWith($expectedIssuerPrefix, [StringComparison]::Ordinal)) {
        $errors.Add("Issuer '$issuerClaim' is not rooted at the expected cloud/tenant ('$expectedIssuerPrefix*').")
    }

    $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    if (-not $claims.Contains('exp')) {
        $errors.Add("Token has no 'exp' claim.")
    } elseif (([long]$claims['exp']) -lt ($nowUnix - $ClockSkewToleranceSeconds)) {
        $errors.Add("Token is expired (exp=$($claims['exp']), now=$nowUnix).")
    }

    if ($claims.Contains('nbf') -and (([long]$claims['nbf']) -gt ($nowUnix + $ClockSkewToleranceSeconds))) {
        $errors.Add("Token is not yet valid (nbf=$($claims['nbf']), now=$nowUnix).")
    }

    $hasDelegatedScopes = $claims.Contains('scp') -and -not [string]::IsNullOrWhiteSpace([string]$claims['scp'])
    $hasAppRoles = $claims.Contains('roles') -and @($claims['roles']).Count -gt 0
    if (-not $hasDelegatedScopes -and -not $hasAppRoles) {
        $errors.Add("Token carries neither delegated scopes ('scp') nor application roles ('roles') -- nothing was actually granted.")
    }

    return [ordered]@{
        IsValid = ($errors.Count -eq 0)
        Errors  = @($errors)
    }
}

function Get-EntraPostureTokenGrantedPermission {
    <#
        .SYNOPSIS
        Extracts the set of granted permissions from a token's 'scp' (delegated) or 'roles'
        (application) claim, whichever is present.

        .DESCRIPTION
        Feeds the coverage/preflight projection (section 7.2 item 2: "rights present in token
        claims") -- returns exactly what was granted, not what was requested, so a caller can
        compare the two and surface a gap rather than assuming they match.

        .PARAMETER Jwt

        .OUTPUTS
        Ordered dictionary: GrantType ('Delegated' or 'Application') and Permissions (string
        array).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$Jwt
    )

    $claims = ConvertFrom-EntraPostureJwtClaim -Jwt $Jwt

    if ($claims.Contains('scp') -and -not [string]::IsNullOrWhiteSpace([string]$claims['scp'])) {
        return [ordered]@{
            GrantType   = 'Delegated'
            Permissions = @(([string]$claims['scp']).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
        }
    }

    if ($claims.Contains('roles') -and @($claims['roles']).Count -gt 0) {
        return [ordered]@{
            GrantType   = 'Application'
            Permissions = @($claims['roles'])
        }
    }

    return [ordered]@{
        GrantType   = 'None'
        Permissions = @()
    }
}
