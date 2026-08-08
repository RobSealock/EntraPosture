#Requires -Version 7.4

function Get-EntraPostureAuthenticationStrengthPolicyCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAuthenticationStrengthPolicyCollector's permission/
        coverage requirements.

        .DESCRIPTION
        Policy.Read.AuthenticationMethod, confirmed directly against Microsoft Graph's "List
        authenticationStrengthPolicies" documentation (least-privileged delegated/application
        permission for GET /policies/authenticationStrengthPolicies, re-fetched 2026-08-07) --
        deliberately NOT Policy.Read.All (a "higher privileged" alternative the same permissions
        table lists, but this project always requests the least-privileged scope a real endpoint
        documents, per its own no-write/minimum-necessary posture). This is a genuinely new
        permission this project didn't already hold, unlike NamedLocations (build order item 4),
        which reused an already-granted scope -- see 00-open-questions.md's item-5 entry.

        Fed no control directly through Phase 8 (feeding only
        Resolve-EntraPostureAuthenticationStrengthRequirement, VNext build order item 5, a
        resolution helper) until v.next build order item 12: CA-002 is the first control to
        actually depend on this evidence, via that same resolution helper, to recognize a
        satisfying authenticationStrengthId as MFA-equivalent coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AuthenticationStrengthPolicies' `
        -RequiredPermissions @('Policy.Read.AuthenticationMethod') `
        -EndpointsUsed @('/v1.0/policies/authenticationStrengthPolicies') `
        -AffectedControlIds @('CA-002') `
        -AffectedReportSections @('Conditional Access')
}

function Invoke-EntraPostureAuthenticationStrengthPolicyCollector {
    <#
        .SYNOPSIS
        Collects every authentication strength policy (built-in and custom), normalized to
        canonical Entity records. Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AuthenticationStrengthPolicy[]).
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

    $path = '/v1.0/policies/authenticationStrengthPolicies'
    $rawPolicies = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawPolicy in $rawPolicies) {
        ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity -RawPolicy $rawPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
