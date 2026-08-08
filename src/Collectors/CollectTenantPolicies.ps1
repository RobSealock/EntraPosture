#Requires -Version 7.4

function Get-EntraPostureTenantPolicyCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureTenantPolicyCollector's permission/coverage requirements.

        .DESCRIPTION
        Policy.Read.All, confirmed for both authorizationPolicy and adminConsentRequestPolicy
        during XTA/AC control design (00-permission-report-matrix.md). Feeds AC-001 and AC-002
        (Phase 7), and USR-001/GRP-001 (VNext build order item 2, both reading sibling fields on
        the same AuthorizationPolicy entity) -- AffectedControlIds is load-bearing, not
        descriptive: Invoke-EntraPostureSnapshotEvaluation (src/Orchestration/
        EvaluateSnapshot.ps1) uses it to decide whether a control's required evidence was
        actually collected, so every control reading this collector's evidence must be listed
        here or it's wrongly marked NotEvaluated regardless of real coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'TenantPolicies' `
        -RequiredPermissions @('Policy.Read.All') `
        -EndpointsUsed @('/v1.0/policies/authorizationPolicy', '/v1.0/policies/adminConsentRequestPolicy') `
        -AffectedControlIds @('AC-001', 'AC-002', 'USR-001', 'GRP-001', 'COL-002', 'COL-001', 'PAS-005', 'USR-002', 'USR-003', 'USR-004', 'GRP-004') `
        -AffectedReportSections @('Consent and Authorization')
}

function Invoke-EntraPostureTenantPolicyCollector {
    <#
        .SYNOPSIS
        Collects the tenant's authorization policy and admin-consent-request policy, normalized
        to canonical Entity records. Read-only: two allowlisted Graph GET calls against
        singleton resources.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AuthorizationPolicy[1], AdminConsentRequestPolicy[1]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'graph.microsoft.com'
    )

    $collectorVersion = (Get-EntraPostureToolVersionInfo).ToolVersion
    $collectedAt = (Get-Date).ToUniversalTime().ToString('o')

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $entities = [System.Collections.Generic.List[object]]::new()

    $authPath = '/v1.0/policies/authorizationPolicy'
    $rawAuthPolicies = Send-EntraPostureRequest @sendParams -Path $authPath -Method GET
    foreach ($rawAuthPolicy in $rawAuthPolicies) {
        $entities.Add((ConvertTo-EntraPostureAuthorizationPolicyEntity -RawPolicy $rawAuthPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $authPath -CollectedAt $collectedAt))
    }

    $consentPath = '/v1.0/policies/adminConsentRequestPolicy'
    $rawConsentPolicies = Send-EntraPostureRequest @sendParams -Path $consentPath -Method GET
    foreach ($rawConsentPolicy in $rawConsentPolicies) {
        $entities.Add((ConvertTo-EntraPostureAdminConsentRequestPolicyEntity -RawPolicy $rawConsentPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $consentPath -CollectedAt $collectedAt))
    }

    return [ordered]@{
        Entities = @($entities.ToArray())
    }
}
