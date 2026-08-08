#Requires -Version 7.4

function ConvertTo-EntraPostureRoleAssignmentScopeRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph unifiedRoleAssignment record
        (GET /v1.0/roleManagement/directory/roleAssignments) into a canonical Relationship
        record, classifying its directoryScopeId into this project's own 'directory'/
        'administrativeUnit'/'resource' scope buckets.

        .DESCRIPTION
        A distinct relationshipType and evidence file from the existing 'DirectoryRoleAssignment'
        (sourced from GET /directoryRoles/{id}/members, always tenant-wide, per that normalizer's
        own hardcoded 'directory' scope) -- CAP-011's own reason for existing: that endpoint
        structurally cannot return administrative-unit-scoped role assignments at all, confirmed
        live 2026-08-08 against the "List unifiedRoleAssignments" Graph reference page's own
        example response, which shows `directoryScopeId` alongside `resourceScope` on every
        record. `directoryScopeId` is `"/"` for a tenant-wide assignment; an administrative-unit-
        scoped assignment's `directoryScopeId` takes the form `/administrativeUnits/{id}`
        (confirmed against Microsoft's own `unifiedRoleAssignment` resource page and the
        Conditional Access "Directory roles" condition's own documented warning: "Conditional
        Access policies don't support users assigned a directory role scoped to an administrative
        unit or directory roles scoped directly to an object, like through custom roles" --
        `concept-conditional-access-users-groups.md`, re-fetched 2026-08-08). Any other prefix
        (e.g. a specific object ID, via a custom role) is classified 'resource' -- CAP-011 doesn't
        currently act on that bucket (Conditional Access role targeting only supports built-in
        roles at all, so a custom-role scenario is out of scope for that control), but this
        normalizer still classifies it accurately rather than folding it into 'administrativeUnit'
        by default.

        .PARAMETER RawRoleAssignment
        One element of the Graph response's 'value' array.

        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawRoleAssignment,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    foreach ($requiredField in @('id', 'principalId', 'roleDefinitionId')) {
        if (-not $RawRoleAssignment.Contains($requiredField) -or [string]::IsNullOrWhiteSpace([string]$RawRoleAssignment[$requiredField])) {
            throw "ConvertTo-EntraPostureRoleAssignmentScopeRelationship: raw unifiedRoleAssignment record has no $requiredField."
        }
    }

    $principalId = [string]$RawRoleAssignment['principalId']
    $roleDefinitionId = [string]$RawRoleAssignment['roleDefinitionId']
    $directoryScopeId = if ($RawRoleAssignment.Contains('directoryScopeId')) { [string]$RawRoleAssignment['directoryScopeId'] } else { '/' }

    $scope = if ($directoryScopeId -eq '/') {
        'directory'
    } elseif ($directoryScopeId.StartsWith('/administrativeUnits/', [System.StringComparison]::OrdinalIgnoreCase)) {
        'administrativeUnit'
    } else {
        'resource'
    }

    return [ordered]@{
        relationshipId   = "$principalId::$roleDefinitionId::RoleAssignmentScope::$([string]$RawRoleAssignment['id'])"
        sourceEntityId   = $principalId
        targetEntityId   = $roleDefinitionId
        relationshipType = 'RoleAssignmentScope'
        assignmentState  = 'Active'
        scope            = $scope
        provenance       = [ordered]@{
            collectorVersion = $CollectorVersion
            sourceEndpoint   = $SourceEndpoint
            collectedAt      = $CollectedAt
        }
        validity         = [ordered]@{
            startDateTime = $null
            endDateTime   = $null
            isTransitive  = $false
        }
    }
}
