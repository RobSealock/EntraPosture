#Requires -Version 7.4

function Test-EntraPosturePublicM365GroupsControl {
    <#
        .SYNOPSIS
        GRP-003's evaluator: for each Group entity, checks whether it is a statically-membered,
        publicly-visible Microsoft 365 group.

        .DESCRIPTION
        Fail when groupTypes contains 'Unified' (a Microsoft 365 / "unified" group, confirmed
        directly against the live "List groups" Graph reference page's own worked example,
        re-fetched 2026-08-08) AND visibility equals 'Public' AND the group is NOT dynamically
        membered (groupTypes does not contain 'DynamicMembership') -- dynamic public groups are
        excluded from this specific finding because their membership is admin-curated via a rule
        rather than open self-join, a materially different risk shape independently re-derived
        from EntraFalcon's own equivalent check, not ported. Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per GRP-003.psd1's
        expectedResultSemantics.

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

    $groups = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Group'

    if (@($groups).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'GRP-003-NO-GROUPS'
                Rationale = 'No Group entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($group in $groups) {
        $groupTypes = @($group.properties.groupTypes)
        $isM365Group = $groupTypes -contains 'Unified'
        $isDynamic = $groupTypes -contains 'DynamicMembership'
        $isPublic = [string]$group.properties.visibility -eq 'Public'
        $evidenceRef = @([ordered]@{ entityId = $group.entityId; entityType = 'Group' })

        if ($isM365Group -and $isPublic -and -not $isDynamic) {
            [ordered]@{
                Scope = $group.entityId; Status = 'Fail'; ReasonCode = 'GRP-003-PUBLIC-M365-GROUP'
                Rationale = "Microsoft 365 group '$($group.displayName)' is publicly visible with static membership."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $group.entityId; Status = 'Pass'; ReasonCode = 'GRP-003-NOT-PUBLIC-M365-GROUP'
                Rationale = "Group '$($group.displayName)' is not a publicly visible, statically-membered Microsoft 365 group."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
