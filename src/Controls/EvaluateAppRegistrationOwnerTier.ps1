#Requires -Version 7.4

function Test-EntraPostureAppRegistrationOwnerTierControl {
    <#
        .SYNOPSIS
        APP-003's evaluator: for each Application, checks whether every owner holds a curated
        Tier-0 Entra ID role.

        .DESCRIPTION
        Same evaluator shape as ENT-003 (Test-EntraPostureEnterpriseAppOwnerTierControl) and
        AGT-017 (Test-EntraPostureAgentBlueprintOwnerTierControl) before it, applied to the
        Application entity type instead of ServicePrincipal/AgentIdentityBlueprint -- an app
        registration able to be modified by an owner (adding credentials, changing API
        permissions, altering the sign-in audience) should itself be owned only by
        already-privileged, accountable principals. Correlates OwnerOf (owner -> application,
        collected by CollectApplications.ps1's owners N+1 fetch, APP-003's own reason for that
        fetch existing) against DirectoryRoleAssignment by principal ID. Evaluated once per
        collected Application entity. Never produces NotEvaluated or Error status -- assigned by
        the orchestration layer, per APP-003.psd1's expectedResultSemantics.

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

    $applications = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Application'

    if (@($applications).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'APP-003-NO-APPLICATIONS'
                Rationale          = 'No Application entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($application in $applications) {
        $owners = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'OwnerOf' -TargetEntityId $application.entityId

        if (@($owners).Count -eq 0) {
            [ordered]@{
                Scope              = $application.entityId
                Status             = 'NotApplicable'
                ReasonCode         = 'APP-003-NO-OWNERS'
                Rationale          = "Application '$($application.displayName)' has no collected owner."
                EvidenceReferences = @([ordered]@{ entityId = $application.entityId; entityType = 'Application' })
            }
            continue
        }

        $nonTierZeroOwnerIds = [System.Collections.Generic.List[string]]::new()
        foreach ($owner in $owners) {
            $ownerActiveTierZeroAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $owner.sourceEntityId
            $ownerActiveTierZeroAssignments = @($ownerActiveTierZeroAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })
            if (@($ownerActiveTierZeroAssignments).Count -eq 0) {
                $nonTierZeroOwnerIds.Add($owner.sourceEntityId)
            }
        }

        $evidenceRef = @([ordered]@{ entityId = $application.entityId; entityType = 'Application' })
        foreach ($ownerId in $nonTierZeroOwnerIds) {
            $evidenceRef += [ordered]@{ entityId = $ownerId; entityType = 'Unknown' }
        }

        if ($nonTierZeroOwnerIds.Count -gt 0) {
            [ordered]@{
                Scope              = $application.entityId
                Status             = 'Fail'
                ReasonCode         = 'APP-003-NON-TIER-ZERO-OWNER'
                Rationale          = "Application '$($application.displayName)' has at least one owner ($($nonTierZeroOwnerIds.Count) of $(@($owners).Count)) with no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $application.entityId
                Status             = 'Pass'
                ReasonCode         = 'APP-003-TIER-ZERO-OWNER-ONLY'
                Rationale          = "Application '$($application.displayName)' has every owner holding an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
