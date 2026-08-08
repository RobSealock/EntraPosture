#Requires -Version 7.4

function Test-EntraPostureConditionalAccessAdminCoverageControl {
    <#
        .SYNOPSIS
        CA-001's evaluator: runs 16 fixed representative sign-in scenarios (4 platforms x 4
        client app types) for the Global Administrator role through Phase 8's CA simulation
        engine and checks each for MFA/block coverage.

        .DESCRIPTION
        Deliberately a fixed, always-fully-reported grid, not a sampled subset -- the engineering
        plan's "controls combinatorial explosion... never hide sampling" requirement is satisfied
        by keeping the grid small and constant (16 scenarios) rather than by sampling a larger
        space down. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per CA-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        16 elements when the Global Administrator role exists in evidence, 1 (NotApplicable)
        otherwise.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $gaRole = $roles | Where-Object { $_.displayName -eq 'Global Administrator' } | Select-Object -First 1

    if (-not $gaRole) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'CA-001-NO-GA-ROLE-ACTIVATED'
                Rationale          = 'No Global Administrator DirectoryRole entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'

    # Fixed, always-fully-evaluated 4x4 grid -- see this function's own DESCRIPTION for why this
    # is a constant representative set rather than a sampled subset of a larger combinatorial
    # space.
    $platforms = @('windows', 'iOS', 'android', 'macOS')
    $clientAppTypes = @('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')

    $evidenceRef = @([ordered]@{ entityId = $gaRole.entityId; entityType = 'DirectoryRole' })
    foreach ($policy in $policies) {
        $evidenceRef += [ordered]@{ entityId = $policy.entityId; entityType = 'ConditionalAccessPolicy' }
    }

    $evaluationResults = @(foreach ($platform in $platforms) {
        foreach ($clientAppType in $clientAppTypes) {
            $scenario = New-EntraPostureConditionalAccessScenario -UserId 'synthetic-ga-holder' `
                -UserRoleIds @($gaRole.entityId) -ApplicationId 'All' -ClientAppType $clientAppType -Platform $platform

            $simulationResult = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario $scenario

            $isCovered = ($simulationResult.Result -eq 'Blocked') `
                -or (@($simulationResult.RequiredControlGroups | Where-Object { $_.Controls -contains 'mfa' })).Count -gt 0

            $scope = "$platform::$clientAppType"

            if ($isCovered) {
                [ordered]@{
                    Scope              = $scope
                    Status             = 'Pass'
                    ReasonCode         = 'CA-001-SCENARIO-COVERED'
                    Rationale          = "A Global Administrator signing in from platform '$platform' via client app type '$clientAppType' is blocked or required to complete MFA by at least one applicable enabled policy."
                    EvidenceReferences = $evidenceRef
                }
            } else {
                [ordered]@{
                    Scope              = $scope
                    Status             = 'Fail'
                    ReasonCode         = 'CA-001-UNCOVERED-SCENARIO'
                    Rationale          = "A Global Administrator signing in from platform '$platform' via client app type '$clientAppType' is not blocked and not required to complete MFA by any applicable enabled policy."
                    EvidenceReferences = $evidenceRef
                }
            }
        }
    })

    return ,@($evaluationResults)
}
