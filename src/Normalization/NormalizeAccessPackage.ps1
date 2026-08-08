#Requires -Version 7.4

function ConvertTo-EntraPostureAccessPackageEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph accessPackage object -- fetched per-package with
        `$expand=resourceRoleScopes($expand=role,scope)` (GET .../accessPackages/{id}) -- into a
        canonical Entity record.

        .DESCRIPTION
        v.next build order item 11 (EM-001/EM-002), admitted into v1 scope by the deviation
        record in 00-open-questions.md item 28. Field allowlist per 15-feature-parity-matrix.md
        section 8: id, displayName, description, isHidden, plus a resourceRoles array derived
        from resourceRoleScopes -- confirmed live against Microsoft's own
        accessPackageResourceRoleScope resource page (role.originSystem/originId identify the
        underlying resource; for a Microsoft Entra group, originSystem is 'AadGroup' and
        originId is the group's own object ID, confirmed against the accessPackageResource
        resource page's own documented example values, not assumed). Only roleDisplayName/
        originSystem/originId/scopeDisplayName are kept -- the resourceRoleScopes/role/scope
        wrapper IDs themselves are internal entitlement-management bookkeeping this project's
        controls never need to reference.

        .PARAMETER RawPackage
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawPackage,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawPackage.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawPackage['id'])) {
        throw 'ConvertTo-EntraPostureAccessPackageEntity: raw access package record has no id.'
    }

    $rawResourceRoleScopes = @(if ($RawPackage.Contains('resourceRoleScopes')) { $RawPackage['resourceRoleScopes'] } else { @() })

    $resourceRoles = @(foreach ($rawScope in $rawResourceRoleScopes) {
        $role = if ($rawScope.Contains('role')) { $rawScope['role'] } else { $null }
        $scope = if ($rawScope.Contains('scope')) { $rawScope['scope'] } else { $null }
        [ordered]@{
            roleDisplayName  = if ($role -and $role.Contains('displayName')) { $role['displayName'] } else { $null }
            originSystem     = if ($role -and $role.Contains('originSystem')) { $role['originSystem'] } else { $null }
            originId         = if ($role -and $role.Contains('originId')) { $role['originId'] } else { $null }
            scopeDisplayName = if ($scope -and $scope.Contains('displayName')) { $scope['displayName'] } else { $null }
        }
    })

    return [ordered]@{
        entityId         = [string]$RawPackage['id']
        entityType       = 'AccessPackage'
        tenantScope      = $TenantScope
        displayName      = if ($RawPackage.Contains('displayName')) { $RawPackage['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            description   = if ($RawPackage.Contains('description')) { $RawPackage['description'] } else { $null }
            isHidden      = if ($RawPackage.Contains('isHidden')) { [bool]$RawPackage['isHidden'] } else { $null }
            resourceRoles = $resourceRoles
        }
        redacted         = $false
    }
}
