#Requires -Version 7.4

function Test-EntraPostureForeignServicePrincipalOwnedObjectsControl {
    <#
        .SYNOPSIS
        ENT-008's evaluator: checks each foreign ServicePrincipal entity (appOwnerOrganizationId
        differs from this tenant) for ownership of any object in this tenant.

        .DESCRIPTION
        Same single-hop foreign-derivation pattern as ENT-006/007/011/012's evaluators (an
        ordinary ServicePrincipal entity carries appOwnerOrganizationId directly on itself, no
        two-hop blueprint-principal join needed). Consolidates the matrix's EF-EAP-008
        ("Ownership over app registrations"), EF-EAP-009 ("Ownership of other service
        principals"), and EF-EAP-011 ("App owns app registration") signals into one finding, per
        15-feature-parity-matrix.md section 3.3's own canonical registry -- deliberately not
        split by owned-object type, the same "one canonical ID, not fragmented" pattern GRP-005
        already established. Correlates OwnerOf (foreign service principal -> owned object,
        collected by CollectServicePrincipals.ps1's ownedObjects N+1 fetch, scoped to foreign
        principals only since that fetch is the only reason this control exists) by source
        entity ID -- no entity-type filtering on the owned object, an owned Application and an
        owned ServicePrincipal are both a Fail. Never produces NotEvaluated or Error status --
        assigned by the orchestration layer, per ENT-008.psd1's expectedResultSemantics.

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

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'
    $tenantScope = if (@($servicePrincipals).Count -gt 0) { $servicePrincipals[0].tenantScope } else { $null }
    $foreignPrincipals = @($servicePrincipals | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -and
        [string]$_.properties.appOwnerOrganizationId -ne $tenantScope
    })

    if (@($foreignPrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-008-NO-FOREIGN-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was confirmed foreign in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $foreignPrincipals) {
        $ownedObjects = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'OwnerOf' -SourceEntityId $principal.entityId

        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })
        foreach ($owned in $ownedObjects) { $evidenceRef += [ordered]@{ entityId = $owned.targetEntityId; entityType = 'Unknown' } }

        if (@($ownedObjects).Count -gt 0) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-008-FOREIGN-OWNS-OBJECT'
                Rationale = "Foreign service principal '$($principal.displayName)' owns $(@($ownedObjects).Count) object(s) in this tenant."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-008-FOREIGN-OWNS-NOTHING'
                Rationale = "Foreign service principal '$($principal.displayName)' owns no object in this tenant."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
