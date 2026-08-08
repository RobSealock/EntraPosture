#Requires -Version 7.4

function Get-EntraPosturePimEligibilityCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPosturePimEligibilityCollector's permission/coverage
        requirements.

        .DESCRIPTION
        RoleManagement.Read.Directory (same permission as Phase 5's DirectoryRoleAssignments
        collector -- PIM eligibility and active-assignment data share this one permission per
        Microsoft's documentation). Feeds 'PIM-002' (Phase 7) alongside DirectoryRoleAssignments.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'PimEligibility' `
        -RequiredPermissions @('RoleManagement.Read.Directory') `
        -EndpointsUsed @('/v1.0/roleManagement/directory/roleEligibilityScheduleInstances') `
        -AffectedControlIds @('PIM-002', 'PIM-001') `
        -AffectedReportSections @('Privileged Roles')
}

function Invoke-EntraPosturePimEligibilityCollector {
    <#
        .SYNOPSIS
        Collects PIM role-eligibility schedule instances for Entra directory roles, normalized
        to canonical Relationship records. Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Relationships (PimEligible[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

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

    $path = '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'
    $rawInstances = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $relationships = foreach ($rawInstance in $rawInstances) {
        ConvertTo-EntraPosturePimEligibilityRelationship -RawInstance $rawInstance `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}
