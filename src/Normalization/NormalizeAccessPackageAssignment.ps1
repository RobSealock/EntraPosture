#Requires -Version 7.4

function ConvertTo-EntraPostureAccessPackageAssignmentEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph accessPackageAssignment object (tenant-wide GET
        /identityGovernance/entitlementManagement/assignments?$expand=accessPackage) into a
        canonical Entity record, for EM-002's assignment-lapse check.

        .DESCRIPTION
        v.next build order item 11 (EM-002). Redaction by construction, same discipline as
        AR-002/NormalizeAccessReviewInstance.ps1: the matrix's own EM-002 design states "store
        the assignment ID and computed overdue duration, not the assigned principal's full
        profile" -- this project reads that conservatively as "no principal-identifying field at
        all," so the raw response's `target` (the accessPackageSubject) is never requested by
        the collector's own $expand and is not present in this allowlist even if it were.

        Field allowlist confirmed live against Microsoft's own accessPackageAssignment resource
        page: state (the authoritative enum -- `delivering`, `partiallyDelivered`, `delivered`,
        `expired`, `deliveryFailed` -- confirmed directly, not assumed; `expired` is a real,
        distinct, listable state, which is what makes EM-002's lapse check possible without this
        project having to independently recompute "is this now past its expiration" the way
        AR-002's overdue check does), status (free-text lifecycle detail, e.g.
        'NearExpiry1DayNotificationTriggered'), expiredDateTime, and accessPackageId (read from
        the $expand=accessPackage navigation property, since accessPackageAssignment's own body
        has no direct accessPackageId scalar field).

        .PARAMETER RawAssignment
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
        [System.Collections.Specialized.OrderedDictionary]$RawAssignment,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAssignment.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAssignment['id'])) {
        throw 'ConvertTo-EntraPostureAccessPackageAssignmentEntity: raw access package assignment record has no id.'
    }

    $accessPackage = if ($RawAssignment.Contains('accessPackage')) { $RawAssignment['accessPackage'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawAssignment['id']
        entityType       = 'AccessPackageAssignment'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            accessPackageId = if ($accessPackage -and $accessPackage.Contains('id')) { $accessPackage['id'] } else { $null }
            state           = if ($RawAssignment.Contains('state')) { $RawAssignment['state'] } else { $null }
            status          = if ($RawAssignment.Contains('status')) { $RawAssignment['status'] } else { $null }
            expiredDateTime = if ($RawAssignment.Contains('expiredDateTime')) { $RawAssignment['expiredDateTime'] } else { $null }
        }
        redacted         = $false
    }
}
