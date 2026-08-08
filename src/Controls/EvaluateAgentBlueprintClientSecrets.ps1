#Requires -Version 7.4

function Test-EntraPostureAgentBlueprintClientSecretControl {
    <#
        .SYNOPSIS
        AGT-001's evaluator: checks each AgentIdentityBlueprint for the presence of any
        password credential (client secret).

        .DESCRIPTION
        Fixed-state, single-field check -- direct field check per 15-feature-parity-matrix.md
        section 11's own design note, the same class of check GRP-005-adjacent credential-
        presence controls elsewhere in this registry already use. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per AGT-001.psd1's
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

    $blueprints = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentityBlueprint'

    if (@($blueprints).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-001-NO-BLUEPRINTS'
                Rationale          = 'No AgentIdentityBlueprint entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($blueprint in $blueprints) {
        $hasSecret = [int]$blueprint.properties.passwordCredentialCount -gt 0
        $evidenceRef = @([ordered]@{ entityId = $blueprint.entityId; entityType = 'AgentIdentityBlueprint' })

        if ($hasSecret) {
            [ordered]@{
                Scope              = $blueprint.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-001-HAS-PASSWORD-CREDENTIAL'
                Rationale          = "Agent identity blueprint '$($blueprint.displayName)' has at least one password credential (client secret) configured."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $blueprint.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-001-NO-PASSWORD-CREDENTIAL'
                Rationale          = "Agent identity blueprint '$($blueprint.displayName)' has no password credential configured."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
