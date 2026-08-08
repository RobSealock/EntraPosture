#Requires -Version 7.4

function ConvertTo-EntraPostureCrossTenantAccessPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes the raw Graph default crossTenantAccessPolicy object
        (GET /v1.0/policies/crossTenantAccessPolicy) into a canonical Entity record.

        .DESCRIPTION
        This is a Graph singleton resource (one default policy per tenant, no 'value' array
        wrapper) -- the collector calling this passes the single response object directly, not
        an array element. Field allowlist per section 8.4: id and inboundTrust.{isMfaAccepted,
        isCompliantDeviceAccepted, isHybridAzureADJoinedDeviceAccepted} only -- the much larger
        b2bCollaborationInbound/Outbound and b2bDirectConnectInbound/Outbound objects are out of
        scope for this phase's single predicate control, which only reads inboundTrust.

        .PARAMETER RawPolicy
        The raw response object (not wrapped in a 'value' array).

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
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    # Graph's default policy resource is a tenant-wide singleton; its 'id' is documented as the
    # literal string 'default'. Falling back to that literal (rather than throwing) when 'id' is
    # absent is deliberate here -- unlike a collection endpoint's array elements, there is only
    # ever one of these per tenant, so a missing 'id' field is Graph shape drift, not a signal
    # this specific record is unidentifiable.
    $entityId = if ($RawPolicy.Contains('id') -and -not [string]::IsNullOrWhiteSpace([string]$RawPolicy['id'])) {
        [string]$RawPolicy['id']
    } else {
        'default'
    }

    $inboundTrust = if ($RawPolicy.Contains('inboundTrust')) { $RawPolicy['inboundTrust'] } else { $null }

    return [ordered]@{
        entityId         = $entityId
        entityType       = 'CrossTenantAccessPolicy'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            inboundTrustIsMfaAccepted                   = if ($inboundTrust -and $inboundTrust.Contains('isMfaAccepted')) { $inboundTrust['isMfaAccepted'] } else { $null }
            inboundTrustIsCompliantDeviceAccepted        = if ($inboundTrust -and $inboundTrust.Contains('isCompliantDeviceAccepted')) { $inboundTrust['isCompliantDeviceAccepted'] } else { $null }
            inboundTrustIsHybridAzureADJoinedDeviceAccepted = if ($inboundTrust -and $inboundTrust.Contains('isHybridAzureADJoinedDeviceAccepted')) { $inboundTrust['isHybridAzureADJoinedDeviceAccepted'] } else { $null }
        }
        redacted         = $false
    }
}
