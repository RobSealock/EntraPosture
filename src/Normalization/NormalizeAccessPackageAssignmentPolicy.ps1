#Requires -Version 7.4

function ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph accessPackageAssignmentPolicy object -- fetched per-package via
        `$expand=assignmentPolicies` alongside resourceRoleScopes -- into a canonical Entity
        record.

        .DESCRIPTION
        v.next build order item 11 (EM-001/EM-002). Field allowlist confirmed live against
        Microsoft's own accessPackageAssignmentPolicy and accessPackageAssignmentApprovalSettings
        resource pages: allowedTargetScope (pass-through enum string), isAutoAssignment (this
        project's own name for "automaticRequestSettings is present" -- Microsoft's own resource
        page states plainly "This property is only present for an auto assignment policy; if
        absent, this is a request-based policy"), isApprovalRequiredForAdd (the exact field name
        Microsoft uses -- NOT a generic "isApprovalRequired", confirmed directly against the
        approval-settings resource page rather than assumed from the matrix's own looser
        paraphrase), and the three expiration fields (type/endDateTime/duration) from
        expirationPattern. isApprovalRequiredForAdd is left explicitly null (not assumed true or
        false) when requestApprovalSettings itself is absent -- which Microsoft's own auto-
        assignment-policy documentation implies is the normal case for an auto-assignment policy,
        since the whole approval concept doesn't apply there.

        .PARAMETER RawPolicy
        .PARAMETER AccessPackageId
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
        [System.Collections.Specialized.OrderedDictionary]$RawPolicy,

        [Parameter(Mandatory)]
        [string]$AccessPackageId,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawPolicy.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawPolicy['id'])) {
        throw 'ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity: raw access package assignment policy record has no id.'
    }

    $approvalSettings = if ($RawPolicy.Contains('requestApprovalSettings')) { $RawPolicy['requestApprovalSettings'] } else { $null }
    $expiration = if ($RawPolicy.Contains('expiration')) { $RawPolicy['expiration'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawPolicy['id']
        entityType       = 'AccessPackageAssignmentPolicy'
        tenantScope      = $TenantScope
        displayName      = if ($RawPolicy.Contains('displayName')) { $RawPolicy['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            accessPackageId          = $AccessPackageId
            allowedTargetScope       = if ($RawPolicy.Contains('allowedTargetScope')) { $RawPolicy['allowedTargetScope'] } else { $null }
            isAutoAssignment         = $RawPolicy.Contains('automaticRequestSettings')
            isApprovalRequiredForAdd = if ($approvalSettings -and $approvalSettings.Contains('isApprovalRequiredForAdd')) { [bool]$approvalSettings['isApprovalRequiredForAdd'] } else { $null }
            expirationType           = if ($expiration -and $expiration.Contains('type')) { $expiration['type'] } else { $null }
            expirationEndDateTime    = if ($expiration -and $expiration.Contains('endDateTime')) { $expiration['endDateTime'] } else { $null }
            expirationDuration       = if ($expiration -and $expiration.Contains('duration')) { $expiration['duration'] } else { $null }
        }
        redacted         = $false
    }
}
