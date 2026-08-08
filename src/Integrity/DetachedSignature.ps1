#Requires -Version 7.4

function New-EntraPostureDetachedSignature {
    <#
        .SYNOPSIS
        Produces a detached PKCS#7/CMS signature over a byte array using a user-selected
        certificate.

        .DESCRIPTION
        Engineering plan section 8.4: "Optional detached signing uses a user-selected Windows
        certificate." This uses System.Security.Cryptography.Pkcs.SignedCms rather than the
        Set-AuthenticodeSignature cmdlet: Set-AuthenticodeSignature embeds a signature inside a
        single script/executable file, which is the wrong shape for signing a bundle's
        integrity record as a separate artifact, and it is also a Windows-only cmdlet (not
        present on this development platform at all -- confirmed empirically, not assumed).
        SignedCms is a cross-platform managed-crypto primitive that produces a real, separate
        .p7s-shaped detached signature and works identically on the Windows hosts this tool
        targets (ADR-005) and on non-Windows development/test environments alike.

        .PARAMETER Content
        The exact bytes to sign -- for this project, always the canonical JSON bytes of the
        {files, aggregateHash, recordCount} attestation payload
        (Get-EntraPostureIntegrityAttestationPayload), deliberately excluding
        signatureStatus/signature themselves to avoid signing a payload that describes its own
        not-yet-computed signature.

        .PARAMETER Certificate
        An X509Certificate2 with an available private key.

        .OUTPUTS
        The encoded detached CMS signature bytes (the content of integrity.p7s).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure in-memory cryptographic computation with no external side effect (returns bytes for the caller to write); the New- verb reflects what the value represents, not a state change to guard with -WhatIf/-Confirm.')]
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Content,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "New-EntraPostureDetachedSignature: certificate '$($Certificate.Thumbprint)' has no available private key."
    }

    $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($Content)
    $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true) # detached = true
    $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($Certificate)
    $signedCms.ComputeSignature($signer)

    return $signedCms.Encode()
}

function Test-EntraPostureDetachedSignature {
    <#
        .SYNOPSIS
        Verifies a detached PKCS#7/CMS signature against the exact bytes it claims to cover.

        .DESCRIPTION
        Checks only cryptographic signature validity (that the signature was produced by the
        private key matching the embedded certificate, over exactly this content) -- it
        deliberately does not require the signing certificate to chain to a trusted root.
        Whether a given organization's signing certificate should be trusted is a PKI/deployment
        policy decision outside this function's scope; conflating "signature is
        cryptographically valid" with "certificate chains to a root this machine trusts" would
        make bundles signed with a legitimate internal-CA certificate unverifiable on a machine
        that simply hasn't been given that CA's root, which is a deployment problem, not a
        tampering signal. Bundle status determination (Signed/InvalidSignature/HashMismatch) is
        the caller's job (Test-EntraPostureBundleIntegrity), built on top of this primitive.

        .PARAMETER Content
        The exact bytes the signature is expected to cover.

        .PARAMETER SignatureBytes
        The encoded detached CMS signature (integrity.p7s contents).

        .OUTPUTS
        $true if the signature is cryptographically valid for the given content, $false
        otherwise (never throws on an invalid/tampered signature -- an invalid signature is an
        expected, representable outcome).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [byte[]]$Content,

        [Parameter(Mandatory)]
        [byte[]]$SignatureBytes
    )

    $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($Content)
    $signedCms = [System.Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)

    try {
        $signedCms.Decode($SignatureBytes)
        $signedCms.CheckSignature($true) # $true = verify signature only, do not require a trusted chain
        return $true
    } catch {
        return $false
    }
}
