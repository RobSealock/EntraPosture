#Requires -Version 7.4

function Test-EntraPostureTierZeroActivationDurationControl {
    <#
        .SYNOPSIS
        PIM-003's evaluator: checks each curated Tier-0 role's PIM activation maximumDuration
        against a 4-hour threshold.

        .DESCRIPTION
        Temporal, same curated Tier-0 role set as PIM-002
        (EvaluateStandingTierZeroAssignment.ps1). Never produces NotEvaluated or Error status --
        assigned by the orchestration layer, per PIM-003.psd1's expectedResultSemantics.

        ISO 8601 duration parsing uses .NET's System.Xml.XmlConvert.ToTimeSpan -- confirmed
        directly to correctly parse every duration shape Microsoft's PIM activation-duration
        slider can actually produce (PT1H through PT24H).

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')
    $threshold = [TimeSpan]::FromHours(4)

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoles = @($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    if (@($tierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIM-003-NO-TIER-ZERO-ROLES-ACTIVATED'
                Rationale          = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policyAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'RoleManagementPolicyAssignment'

    $evaluationResults = @(foreach ($role in $tierZeroRoles) {
        $assignment = $policyAssignments | Where-Object { $_.properties.roleDefinitionId -eq $role.entityId } | Select-Object -First 1
        if (-not $assignment) { continue }

        $rawDuration = [string]$assignment.properties.maximumDuration
        if ([string]::IsNullOrWhiteSpace($rawDuration)) { continue }

        $duration = $null
        try {
            $duration = [System.Xml.XmlConvert]::ToTimeSpan($rawDuration)
        } catch {
            continue
        }

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if ($duration -gt $threshold) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-003-DURATION-EXCEEDS-THRESHOLD'
                Rationale          = "Tier-0 role '$($role.displayName)' allows activation for $($duration.TotalHours) hour(s), exceeding the 4-hour threshold."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-003-DURATION-WITHIN-THRESHOLD'
                Rationale          = "Tier-0 role '$($role.displayName)' allows activation for $($duration.TotalHours) hour(s), within the 4-hour threshold."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
