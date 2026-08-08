#Requires -Version 7.4

function Test-EntraPostureForeignAgentIdentityAzureRoleControl {
    <#
        .SYNOPSIS
        AGT-005's evaluator: checks each foreign AgentIdentity for any AzureRoleAssignment.

        .DESCRIPTION
        Same correlation pattern as AGT-004's evaluator, against AzureRoleAssignment.properties.
        principalId instead of a DirectoryRoleAssignment relationship -- AzureRoleAssignment is
        collected as an Entity, not a Relationship, in this project's model (see
        NormalizeAzureRoleAssignment.ps1), so this control filters the full AzureRoleAssignment
        entity set by principalId directly rather than using Get-EntraPostureRelationship, the
        same access pattern EvaluateAccessPackageExpirationEnforcement.ps1/
        EvaluateAccessPackagePrivilegedPolicyVetting.ps1 already use for the same entity type.
        No Tier-0 curation here (unlike AGT-004's DirectoryRoleAssignment correlation) -- any
        Azure role assignment held by a foreign agent identity is in scope, matching AGT-005's
        own design note ("holding any Azure role"). An AgentIdentity whose foreign-ness is
        unresolvable is excluded from this control's population entirely, the same reasoning
        AGT-004's evaluator documents. Never produces NotEvaluated or Error status -- assigned by
        the orchestration layer, per AGT-005.psd1's expectedResultSemantics.

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

    $azureRoleAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AzureRoleAssignment'

    $agentIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentity'
    $foreignMap = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $EvidenceProvider
    $foreignIdentities = @($agentIdentities | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $true })

    if (@($foreignIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-005-NO-FOREIGN-AGENT-IDENTITIES'
                Rationale          = 'No AgentIdentity entity was confirmed foreign in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $foreignIdentities) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $identity.entityId })

        $evidenceRef = @([ordered]@{ entityId = $identity.entityId; entityType = 'AgentIdentity' })
        foreach ($assignment in $matchingAssignments) {
            $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' }
        }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-005-FOREIGN-AZURE-ROLE'
                Rationale          = "Foreign agent identity '$($identity.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-005-NO-AZURE-ROLE'
                Rationale          = "Foreign agent identity '$($identity.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
