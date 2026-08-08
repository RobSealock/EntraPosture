#Requires -Version 7.4

function Test-EntraPosturePimEntraRoleAdoptionControl {
    <#
        .SYNOPSIS
        PIM-001's evaluator: checks whether Privileged Identity Management (PIM) is actively used
        for Entra ID role assignments at all.

        .DESCRIPTION
        A single tenant-scoped result: Fail if zero PimEligible relationships exist anywhere in
        the evidence set (no Entra ID role has ever been configured with an eligible, PIM-managed
        assignment), Pass if at least one does. Deliberately does not replicate EntraFalcon's own
        additional PIM-licensing pre-check (this project has no reliable way to detect Entra ID
        P2 licensing status independent of the API call itself already succeeding or failing,
        the same reasoning USR-005's own signInActivity licensing dependency already established
        for a different feature) -- if PIM licensing were actually missing, the underlying
        PimEligibility collector call itself would fail, surfacing as PIM-001-EVIDENCE-NOT-
        COLLECTED via the orchestration layer's own partial-evidence handling, not a value this
        evaluator needs to detect itself. Never produces NotEvaluated or Error status -- assigned
        by the orchestration layer, per PIM-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Always exactly one element (tenant-scoped).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $eligibleAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimEligible'

    $results = @(if (@($eligibleAssignments).Count -eq 0) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'PIM-001-NOT-ADOPTED'
            Rationale = 'No PIM-eligible Entra ID role assignment exists -- Privileged Identity Management is not actively used for Entra ID roles.'
            EvidenceReferences = @()
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PIM-001-ADOPTED'
            Rationale = "Privileged Identity Management is in use for Entra ID roles ($(@($eligibleAssignments).Count) eligible assignment(s) found)."
            EvidenceReferences = @()
        }
    })

    return ,@($results)
}
