#Requires -Version 7.4

function Get-EntraPostureUserRegistrationDetailsCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureUserRegistrationDetailsCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AuditLog.Read.All -- confirmed live 2026-08-08 against the "List userRegistrationDetails"
        Graph reference page, the same permission this project's UserSignInActivity collector
        already requests for USR-005. Also requires the tenant to be licensed for Entra ID P1 or
        P2 (see NormalizeUserRegistrationDetails.ps1's own DESCRIPTION) -- a real API-level
        dependency this collector does not attempt to detect itself; an unlicensed tenant simply
        fails the call, surfacing as NotEvaluated via the orchestration layer's own
        partial-evidence handling. New collector, VNext build order item 2's 109-row backlog
        completion pass (batch 12, 2026-08-08) -- the first control built from the "ranked by
        value" continuation past that backlog's own original close-out.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'UserRegistrationDetails' `
        -RequiredPermissions @('AuditLog.Read.All') `
        -EndpointsUsed @('/v1.0/reports/authenticationMethods/userRegistrationDetails') `
        -AffectedControlIds @('USR-012', 'USR-010', 'USR-011') `
        -AffectedReportSections @('Identity')
}

function Invoke-EntraPostureUserRegistrationDetailsCollector {
    <#
        .SYNOPSIS
        Collects every user's authentication-method registration state, normalized to canonical
        UserRegistrationDetails Entity records. Read-only: one allowlisted, paginated Graph GET
        call -- a single bulk report, not a per-user N+1 fetch (see the normalizer's own
        DESCRIPTION for why this shape was deliberately chosen over the naive per-user
        /authentication/methods approach).

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (UserRegistrationDetails[]).
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

    $path = '/v1.0/reports/authenticationMethods/userRegistrationDetails'
    $rawDetails = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawDetail in $rawDetails) {
        ConvertTo-EntraPostureUserRegistrationDetailsEntity -RawUserRegistrationDetail $rawDetail -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
