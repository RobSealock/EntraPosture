#Requires -Version 7.4

function New-EntraPostureSnapshot {
    <#
        .SYNOPSIS
        Collects tenant evidence and seals it into an immutable snapshot bundle.

        .DESCRIPTION
        Collect-and-seal-only command (engineering plan section 6.2). Authenticates (delegated
        interactive or certificate app-only, per -AuthMode), then runs the fixed collection
        pipeline (ADR-027: preflight -> collect to staging -> validate -> seal) via
        Invoke-EntraPostureCollectAndSeal. Produces the run-root/staging-<id>/ bundle
        described in engineering plan section 8.1, sealed as 'Sealed' or 'Partial' (ADR-015)
        depending on whether every collector's evidence was actually Collected.

        Azure RBAC collection is skipped entirely (not attempted, not silently pretended
        complete) when -ArmScope is omitted -- a real, deliberately-exercised partial-evidence
        path, not a placeholder.

        .PARAMETER TenantId
        .PARAMETER ClientId
        This tool's own app registration client ID (never a Microsoft first-party client ID --
        see Connect-EntraPostureDelegated's own docs for why).

        .PARAMETER AuthMode
        .PARAMETER Certificate
        Required when -AuthMode is 'Certificate'.

        .PARAMETER Browser
        .PARAMETER PrivateBrowsing
        Optional, only meaningful when -AuthMode is 'Delegated'. See
        Connect-EntraPostureDelegated's parameters of the same names.

        .PARAMETER RunRoot
        Parent directory for the staging bundle.

        .PARAMETER ArmScope
        Optional ARM scope (e.g. '/subscriptions/{id}') for Azure RBAC collection. Azure RBAC
        collection is skipped entirely when omitted.

        .PARAMETER SigningCertificate
        Optional detached-signing certificate for the sealed bundle.

        .PARAMETER AccessTokenOverride
        Test-only: ordered dictionary { Graph = <token>; Arm = <token or $null> }. Bypasses real
        authentication entirely. Production callers must never pass this -- it exists solely so
        the collection pipeline can be tested without live Entra credentials, matching every
        other -Override-suffixed test-only parameter in this project.

        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER GraphRequestHostOverride
        .PARAMETER ArmRequestHostOverride
        Test-only, forwarded to Invoke-EntraPostureCollectAndSeal.

        .OUTPUTS
        Ordered dictionary: SnapshotPath, Manifest, Coverage.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Real side effects here are authentication and network collection, not a locally guardable/reversible write -- the actual staging-directory creation one layer down (New-EntraPostureStagingDirectory) already implements real SupportsShouldProcess. -WhatIf semantics do not meaningfully apply to "would this have made a live Graph/ARM request" the way they do to a single local file write.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [ValidateSet('Delegated', 'Certificate')]
        [string]$AuthMode,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [switch]$PrivateBrowsing,

        [Parameter(Mandatory)]
        [string]$RunRoot,

        [Parameter()]
        [string]$ArmScope,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$AccessTokenOverride,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$GraphRequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [string]$ArmRequestHostOverride = 'management.azure.com'
    )

    if (-not $AccessTokenOverride -and $AuthMode -eq 'Certificate' -and -not $Certificate) {
        throw 'New-EntraPostureSnapshot: -Certificate is required when -AuthMode is Certificate (unless -AccessTokenOverride bypasses authentication entirely).'
    }

    if ($AccessTokenOverride) {
        $graphToken = $AccessTokenOverride.Graph
        $armToken = $AccessTokenOverride.Arm
    } else {
        $tokenCache = New-EntraPostureTokenCache
        $graphScope = 'https://graph.microsoft.com/.default'
        if ($AuthMode -eq 'Delegated') {
            $graphResult = Connect-EntraPostureDelegated -ClientId $ClientId -TenantId $TenantId -Scope $graphScope -TokenCache $tokenCache -Browser $Browser -PrivateBrowsing:$PrivateBrowsing
        } else {
            $graphResult = Connect-EntraPostureCertificate -ClientId $ClientId -TenantId $TenantId -Certificate $Certificate -Scope $graphScope -TokenCache $tokenCache
        }
        $graphToken = $graphResult.AccessToken

        $armToken = $null
        if ($ArmScope) {
            $armScope = 'https://management.azure.com/.default'
            if ($AuthMode -eq 'Delegated') {
                $armResult = Connect-EntraPostureDelegated -ClientId $ClientId -TenantId $TenantId -Scope $armScope -TokenCache $tokenCache -Browser $Browser -PrivateBrowsing:$PrivateBrowsing
            } else {
                $armResult = Connect-EntraPostureCertificate -ClientId $ClientId -TenantId $TenantId -Certificate $Certificate -Scope $armScope -TokenCache $tokenCache
            }
            $armToken = $armResult.AccessToken
        }
    }

    $graphGranted = (Get-EntraPostureTokenGrantedPermission -Jwt $graphToken).Permissions
    # @() around the whole if/else -- the taken branch's value (a .Permissions array, which can
    # legitimately have exactly 0 or 1 elements) is still subject to if/else-as-expression
    # collapse regardless of it coming from a property access rather than a bare variable.
    $armGranted = @(if ($armToken) { (Get-EntraPostureTokenGrantedPermission -Jwt $armToken).Permissions } else { @() })

    $snapshotId = New-EntraPostureCorrelationId
    $resolvedAuthMode = if ($AuthMode -eq 'Delegated') { 'DelegatedInteractive' } else { 'CertificateAppOnly' }

    $collectParams = @{
        RunRoot                 = $RunRoot
        SnapshotId              = $snapshotId
        TenantScope             = $TenantId
        AuthMode                = $resolvedAuthMode
        GraphAccessToken        = $graphToken
        GraphGrantedPermissions = $graphGranted
        GraphRequestHostOverride = $GraphRequestHostOverride
        ArmRequestHostOverride   = $ArmRequestHostOverride
        SchemeOverride           = $SchemeOverride
    }
    if ($AllowlistOverride) { $collectParams['AllowlistOverride'] = $AllowlistOverride }
    if ($armToken) {
        $collectParams['ArmAccessToken'] = $armToken
        $collectParams['ArmGrantedPermissions'] = $armGranted
        $collectParams['ArmScope'] = $ArmScope
    }
    if ($SigningCertificate) { $collectParams['SigningCertificate'] = $SigningCertificate }

    return Invoke-EntraPostureCollectAndSeal @collectParams
}
