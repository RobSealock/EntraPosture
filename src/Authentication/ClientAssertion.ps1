#Requires -Version 7.4

function New-EntraPostureClientAssertion {
    <#
        .SYNOPSIS
        Builds and signs a JWT client assertion for the OAuth2 client-credentials-with-
        certificate flow (RFC 7523), for certificate app-only authentication.

        .DESCRIPTION
        Hand-rolled JWT construction and RS256 signing using only the base class library
        (System.Text.Json + System.Security.Cryptography) -- deliberately not a dependency on
        System.IdentityModel.Tokens.Jwt or any other JWT package, consistent with ADR-007's
        no-SDK-dependency rationale applied at the same scope to a JWT library as it already
        applies to the Microsoft.Graph PowerShell SDK: a small, self-owned, auditable
        implementation of a well-defined compact serialization format is easier to pin and
        review than tracking an external package's own version churn.

        Claims match Microsoft's documented certificate-credential assertion shape: 'aud' is the
        token endpoint itself (not the resource being accessed), 'iss'/'sub' are both the
        client (application) ID, 'jti' is a fresh GUID per assertion (replay protection), and
        the validity window defaults to 2 minutes -- comfortably inside Microsoft's documented
        maximum assertion lifetime, and short because a fresh assertion is cheap to mint per
        token request; there is no reason to make a client assertion long-lived.

        .PARAMETER ClientId
        The application (client) ID of this tool's own app registration -- not a Microsoft
        first-party client ID (see ADR-006/ADR-007 and the Phase 1 finding on EntraFalcon's
        'BroCi' flow reusing a Microsoft first-party client, which this project's architecture
        explicitly does not do).

        .PARAMETER TenantId
        Tenant ID or verified domain the token endpoint audience targets.

        .PARAMETER Certificate
        X509Certificate2 with an available, non-exported-by-this-call private key (engineering
        plan section 7.1: "certificate app-only authentication using a non-exported Windows
        certificate private key").

        .PARAMETER CloudEndpoint
        Base identity platform host. Defaults to Microsoft public cloud
        (login.microsoftonline.com) -- ADR-032 restricts v1 to public cloud only; this parameter
        exists so the endpoint is centrally configurable rather than hardcoded inline, ready for
        sovereign-cloud support to be added later without touching this function's logic.

        .OUTPUTS
        The signed JWT compact serialization string (header.payload.signature).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory JWT construction and signing -- no external side effect.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [string]$CloudEndpoint = 'https://login.microsoftonline.com',

        [Parameter()]
        [int]$ValiditySeconds = 120
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "New-EntraPostureClientAssertion: certificate '$($Certificate.Thumbprint)' has no available private key."
    }

    $tokenEndpoint = "$CloudEndpoint/$TenantId/oauth2/v2.0/token"

    $thumbprintBytes = $Certificate.GetCertHash([System.Security.Cryptography.HashAlgorithmName]::SHA1)
    $x5t = ConvertTo-EntraPostureBase64Url -Bytes $thumbprintBytes

    $header = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = $x5t
    }

    $now = [DateTimeOffset]::UtcNow
    $nowUnix = $now.ToUnixTimeSeconds()
    $expUnix = $now.AddSeconds($ValiditySeconds).ToUnixTimeSeconds()

    $payload = [ordered]@{
        aud = $tokenEndpoint
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $nowUnix
        iat = $nowUnix
        exp = $expUnix
    }

    # JWT claim ordering is not semantically significant, but this project's own canonical
    # serializer requires [ordered] dictionaries and rejects PSCustomObject/plain hashtable --
    # reusing it here keeps exactly one JSON-construction discipline everywhere in the codebase,
    # including for JWT segments.
    $headerJson = ConvertTo-EntraPostureCanonicalJson -InputObject $header
    $payloadJson = ConvertTo-EntraPostureCanonicalJson -InputObject $payload

    $headerSegment = ConvertTo-EntraPostureBase64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($headerJson))
    $payloadSegment = ConvertTo-EntraPostureBase64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($payloadJson))

    $signingInput = "$headerSegment.$payloadSegment"
    $signingInputBytes = [System.Text.Encoding]::ASCII.GetBytes($signingInput)

    # X509Certificate2.GetRSAPrivateKey() is a C# extension method
    # (RSACertificateExtensions), not an instance method -- confirmed empirically that
    # PowerShell's dot-notation member resolution does not reach it directly ("does not
    # contain a method named 'GetRSAPrivateKey'"), same class of gotcha as OrderedDictionary's
    # .Clone() found in Phase 3. Called as an explicit static extension-method invocation instead.
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) {
        throw "New-EntraPostureClientAssertion: certificate '$($Certificate.Thumbprint)' does not have an RSA private key (only RSA certificates are supported)."
    }

    $signatureBytes = $rsa.SignData($signingInputBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureSegment = ConvertTo-EntraPostureBase64Url -Bytes $signatureBytes

    return "$signingInput.$signatureSegment"
}
