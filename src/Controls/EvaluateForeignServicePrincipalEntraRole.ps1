#Requires -Version 7.4

function Test-EntraPostureForeignServicePrincipalEntraRoleControl {
    <#
        .SYNOPSIS
        ENT-006's evaluator: checks each foreign ServicePrincipal entity (appOwnerOrganizationId
        differs from this tenant) for an Active DirectoryRoleAssignment to a curated Tier-0
        role.

        .DESCRIPTION
        Unlike the AGT-* agent-identity family (which needs a two-hop join through a blueprint
        principal to reach appOwnerOrganizationId), an ordinary ServicePrincipal entity carries
        this field directly on itself (see ConvertTo-EntraPostureServicePrincipalEntity's own
        DESCRIPTION) -- a single-hop foreign check, no shared helper needed. TenantScope is read
        directly from the first available ServicePrincipal entity's own tenantScope field, the
        same "derive from already-collected evidence, evaluators are invoked with only
        -EvidenceProvider" reasoning Get-EntraPostureAgentIdentityForeignMap's own DESCRIPTION
        documents at length. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per ENT-006.psd1's expectedResultSemantics.

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

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoleIds = @(@($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName }) | ForEach-Object { $_.entityId })

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'
    $tenantScope = if (@($servicePrincipals).Count -gt 0) { $servicePrincipals[0].tenantScope } else { $null }
    $foreignPrincipals = @($servicePrincipals | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -and
        [string]$_.properties.appOwnerOrganizationId -ne $tenantScope
    })

    if (@($foreignPrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-006-NO-FOREIGN-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was confirmed foreign in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $foreignPrincipals) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $principal.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })
        foreach ($assignment in $activeAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' } }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-006-FOREIGN-TIER-ZERO-ROLE'
                Rationale = "Foreign service principal '$($principal.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-006-NO-TIER-ZERO-ROLE'
                Rationale = "Foreign service principal '$($principal.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
