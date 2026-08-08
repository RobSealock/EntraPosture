#Requires -Version 7.4

function Get-EntraPostureExtensiveApiPrivilegeControlResult {
    <#
        .SYNOPSIS
        Shared evaluator logic behind every "Extensive API Privileges" finding (ENT-004/005/009/
        010, AGT-002/003/006/007, MAI-001) -- one general service-principal-permission-risk check
        reused across every population, not nine independently-written copies.

        .DESCRIPTION
        Resolves the architecture fork 15-feature-parity-matrix.md section 11 left open (whether
        "extensive API privilege" belongs to agent identities specifically or is a general
        service-principal-permission-risk control agent identities are simply the first consumer
        of): resolved 2026-08-08, by explicit project owner decision, as the general form -- this
        function is the single evaluator every one of the nine controls above thinly wraps,
        differing only in which population and permission type they supply.

        Checks whether each candidate entity (a ServicePrincipal, ManagedIdentity, or
        AgentIdentity) holds at least one Microsoft-Graph-scoped application or delegated
        permission from this project's own curated "Dangerous" tier (ApiPermissionRiskList.ps1),
        correlating against the ServicePrincipalApiPermissions entity collected for the same
        underlying object (entityId is a 1:1 correlation key across ServicePrincipal/
        ManagedIdentity/AgentIdentity and ServicePrincipalApiPermissions, since agent identities
        and managed identities are both service principals under the hood -- see
        NormalizeAgentIdentity.ps1 and NormalizeServicePrincipal.ps1's own DESCRIPTIONs).

        Population construction per -PopulationEntityType/-ForeignFilter:
        - ServicePrincipal, Foreign/Internal: the same single-hop appOwnerOrganizationId check
          ENT-006/007/011/012's evaluators already established (a ServicePrincipal entity, unlike
          AgentIdentity, carries this field directly on itself).
        - ManagedIdentity, All: every collected ManagedIdentity, no foreign/internal split --
          matching MAI-002/003's own established precedent that a managed identity has no
          meaningful "foreign" concept (it's an Azure-resource-backed identity, inherently
          tenant-local).
        - AgentIdentity, Foreign/Internal: Get-EntraPostureAgentIdentityForeignMap (the two-hop
          blueprint-principal join every other AGT-* foreign/internal evaluator already reuses).
          An AgentIdentity whose foreign-ness is unresolvable ($null from that map) is excluded
          from both the Foreign and Internal populations -- the same "never silently promote an
          unresolvable case to a definite answer" rule that map's own DESCRIPTION establishes.

        A candidate with no correlated ServicePrincipalApiPermissions record at all (e.g. it holds
        zero Graph-resource permission grants of either type) is treated as holding none --
        Pass, not excluded from the population.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        each wrapping control's own expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .PARAMETER PermissionType
        'Application' or 'Delegated' -- which half of ServicePrincipalApiPermissions and which
        curated dangerous-permission set to check against.

        .PARAMETER PopulationEntityType
        'ServicePrincipal', 'ManagedIdentity', or 'AgentIdentity'.

        .PARAMETER ForeignFilter
        'Foreign', 'Internal', or 'All'.

        .PARAMETER ControlId
        The wrapping control's own ID (e.g. 'ENT-004'), used as the prefix for every reason code
        this function returns -- each wrapping control's own .psd1 registers the exact resulting
        codes (<ControlId>-EXTENSIVE-PRIVILEGE, <ControlId>-NO-EXTENSIVE-PRIVILEGE,
        <ControlId>-NO-CANDIDATES).

        .PARAMETER PopulationLabel
        Free-text phrase describing the population, used only in Rationale strings (e.g. "foreign
        enterprise application").

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider,

        [Parameter(Mandatory)]
        [ValidateSet('Application', 'Delegated')]
        [string]$PermissionType,

        [Parameter(Mandatory)]
        [ValidateSet('ServicePrincipal', 'ManagedIdentity', 'AgentIdentity')]
        [string]$PopulationEntityType,

        [Parameter(Mandatory)]
        [ValidateSet('Foreign', 'Internal', 'All')]
        [string]$ForeignFilter,

        [Parameter(Mandatory)]
        [string]$ControlId,

        [Parameter(Mandatory)]
        [string]$PopulationLabel
    )

    $dangerousSet = if ($PermissionType -eq 'Application') {
        @(Get-EntraPostureDangerousApplicationPermissionId)
    } else {
        @(Get-EntraPostureDangerousDelegatedPermissionName)
    }

    $candidates = @(
        if ($PopulationEntityType -eq 'ManagedIdentity') {
            $managedIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ManagedIdentity'
            $managedIdentities
        } elseif ($PopulationEntityType -eq 'ServicePrincipal') {
            $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'
            $tenantScope = if (@($servicePrincipals).Count -gt 0) { $servicePrincipals[0].tenantScope } else { $null }
            $servicePrincipals | Where-Object {
                $isForeign = -not [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -and [string]$_.properties.appOwnerOrganizationId -ne $tenantScope
                if ($ForeignFilter -eq 'Foreign') { $isForeign } elseif ($ForeignFilter -eq 'Internal') { -not $isForeign } else { $true }
            }
        } else {
            $agentIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentity'
            $foreignMap = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $EvidenceProvider
            $agentIdentities | Where-Object {
                $isForeign = $foreignMap[$_.entityId]
                if ($null -eq $isForeign) { return $false }
                if ($ForeignFilter -eq 'Foreign') { $isForeign } elseif ($ForeignFilter -eq 'Internal') { -not $isForeign } else { $true }
            }
        }
    )

    if (@($candidates).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = "$ControlId-NO-CANDIDATES"
                Rationale = "No $PopulationLabel entity was present in the evidence set."
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $apiPermissionsByEntityId = @{}
    $apiPermissionsEntities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipalApiPermissions'
    foreach ($record in $apiPermissionsEntities) {
        $apiPermissionsByEntityId[$record.entityId] = $record
    }

    $evaluationResults = @(foreach ($candidate in $candidates) {
        $apiPermissions = $apiPermissionsByEntityId[$candidate.entityId]
        $grantedSet = @(if ($apiPermissions) {
            if ($PermissionType -eq 'Application') { $apiPermissions.properties.applicationPermissionAppRoleIds } else { $apiPermissions.properties.delegatedPermissionScopes }
        } else { @() })
        $matched = @($grantedSet | Where-Object { $dangerousSet -contains $_ })

        $evidenceRef = @([ordered]@{ entityId = $candidate.entityId; entityType = $PopulationEntityType })
        if ($apiPermissions) { $evidenceRef += [ordered]@{ entityId = $apiPermissions.entityId; entityType = 'ServicePrincipalApiPermissions' } }

        if (@($matched).Count -gt 0) {
            [ordered]@{
                Scope = $candidate.entityId; Status = 'Fail'; ReasonCode = "$ControlId-EXTENSIVE-PRIVILEGE"
                Rationale = "$($PopulationLabel.Substring(0,1).ToUpperInvariant())$($PopulationLabel.Substring(1)) '$($candidate.displayName)' holds $(@($matched).Count) $PermissionType permission(s) from this project's curated dangerous-permission list."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $candidate.entityId; Status = 'Pass'; ReasonCode = "$ControlId-NO-EXTENSIVE-PRIVILEGE"
                Rationale = "$($PopulationLabel.Substring(0,1).ToUpperInvariant())$($PopulationLabel.Substring(1)) '$($candidate.displayName)' holds no $PermissionType permission from this project's curated dangerous-permission list."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
