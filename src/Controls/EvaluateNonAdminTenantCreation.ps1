#Requires -Version 7.4

function Test-EntraPostureNonAdminTenantCreationControl {
    <#
        .SYNOPSIS
        USR-002's evaluator: checks the tenant's AuthorizationPolicy.defaultUserRolePermissions.
        allowedToCreateTenants setting.

        .DESCRIPTION
        Fail when non-admin users are allowed to create new Entra ID tenants -- confirmed
        directly against the live defaultUserRolePermissions Graph reference page (re-fetched
        2026-08-08): "Indicates whether the default user role can create tenants." Same
        single-entity-scoped shape as COL-001/002/PAS-005. Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per USR-002.psd1's
        expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AuthorizationPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-002-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })
        if ($policy.properties.allowedToCreateTenants -eq $true) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'USR-002-NON-ADMIN-TENANT-CREATION-ALLOWED'
                Rationale = 'Non-admin users are allowed to create new Entra ID tenants.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'USR-002-NON-ADMIN-TENANT-CREATION-RESTRICTED'
                Rationale = 'Non-admin users are not allowed to create new Entra ID tenants.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
