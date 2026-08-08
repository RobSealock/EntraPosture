#Requires -Version 7.4

function Test-EntraPostureBundle {
    <#
        .SYNOPSIS
        Verifies a snapshot or assessment bundle's schema, file hashes, and optional detached
        signature.

        .DESCRIPTION
        Bundle-verification command (engineering plan section 6.2/8.4). Reports one of Signed,
        Unsigned, InvalidSignature, HashMismatch, or NotSealed; never partially trusts a bundle
        that fails verification. -BundleKind selects which manifest-schema discipline applies:
        a snapshot's manifest.json is schema-validated against snapshot-manifest.schema.json
        (Test-EntraPostureBundleIntegrity); an assessment's manifest.json has no schema yet
        (Test-EntraPostureAssessmentBundleIntegrity skips that specific check -- see that
        function's own DESCRIPTION for why).

        .PARAMETER BundlePath
        .PARAMETER BundleKind
        .OUTPUTS
        Ordered dictionary: IsTrusted, Status, Details.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BundlePath,

        [Parameter()]
        [ValidateSet('Snapshot', 'Assessment')]
        [string]$BundleKind = 'Snapshot'
    )

    if ($BundleKind -eq 'Snapshot') {
        return Test-EntraPostureBundleIntegrity -BundlePath $BundlePath
    }

    return Test-EntraPostureAssessmentBundleIntegrity -BundlePath $BundlePath
}
