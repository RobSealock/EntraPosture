#Requires -Version 7.4

function New-EntraPostureCollectorRequirement {
    <#
        .SYNOPSIS
        Declares one collector's permission and coverage requirements -- the input to
        Test-EntraPosturePreflight.

        .DESCRIPTION
        Engineering plan section 7.2: "Each collector declares: required Graph delegated
        scopes, required Graph application roles... endpoints and methods used, controls and
        report sections dependent on its evidence." This function builds one such declaration.
        No collector exists yet (Phase 6) -- this is the declared-requirement contract Phase 6
        collectors will each populate one of, matching the "define contracts before building
        evaluators/collectors against unstable shapes" ordering already used throughout this
        project (review plan WS5).

        .PARAMETER CollectorName
        .PARAMETER RequiredPermissions
        The minimum Graph/Azure permission scope(s) this collector needs, exactly as confirmed
        against Microsoft documentation (00-permission-report-matrix.md is the source of truth
        for which scope each evidence domain actually requires).

        .PARAMETER EndpointsUsed
        Array of allowlist PathTemplate strings (Get-EntraPostureEndpointAllowlist) this
        collector calls -- every value here must resolve to a real allowlist entry (checked by
        Test-EntraPosturePreflight, not by this constructor, since the allowlist may not be
        loaded at declaration-authoring time).

        .PARAMETER AffectedControlIds
        .PARAMETER AffectedReportSections
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory data construction -- no external side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string[]]$RequiredPermissions,

        [Parameter(Mandatory)]
        [string[]]$EndpointsUsed,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$AffectedControlIds,

        [Parameter(Mandatory)]
        [string[]]$AffectedReportSections
    )

    return [ordered]@{
        CollectorName          = $CollectorName
        RequiredPermissions    = $RequiredPermissions
        EndpointsUsed          = $EndpointsUsed
        AffectedControlIds     = $AffectedControlIds
        AffectedReportSections = $AffectedReportSections
    }
}
