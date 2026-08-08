#Requires -Version 7.4

function Get-EntraPostureGroupSettingsCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureGroupSettingsCollector's permission/coverage requirements.

        .DESCRIPTION
        GroupSettings.Read.All is Microsoft's documented least-privileged permission for both
        delegated and application access to GET /v1.0/groupSettings (confirmed directly against
        the live "List settings" Graph reference page, re-fetched 2026-08-08) -- a distinct
        permission from every other permission this project already requests, not a reuse of
        Group.Read.All/Directory.Read.All. New collector, VNext build order item 2's new-evidence
        phase (batch 6/7, 2026-08-08): the first control needing this evidence is COL-003.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'GroupSettings' `
        -RequiredPermissions @('GroupSettings.Read.All') `
        -EndpointsUsed @('/v1.0/groupSettings') `
        -AffectedControlIds @('COL-003') `
        -AffectedReportSections @('External Collaboration')
}

function Invoke-EntraPostureGroupSettingsCollector {
    <#
        .SYNOPSIS
        Collects tenant-wide group settings objects (e.g. the customized "Group.Unified"
        template, if the tenant has ever changed it away from its documented defaults),
        normalized to canonical Entity records. Read-only: one allowlisted Graph GET call
        against a small, typically single-digit-count collection (not paginated N+1 -- this is
        not a per-group endpoint, it is the tenant-wide singleton collection).

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (GroupSetting[], commonly zero or one element -- zero if the
        tenant has never customized Group.Unified, per this collector's own normalizer
        DESCRIPTION).
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

    $path = '/v1.0/groupSettings'
    $rawGroupSettings = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawGroupSetting in $rawGroupSettings) {
        ConvertTo-EntraPostureGroupSettingEntity -RawGroupSetting $rawGroupSetting -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
