#Requires -Version 7.4

function ConvertTo-EntraPostureCrossTenantAccessPolicyPartnerEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph crossTenantAccessPolicyConfigurationPartner object
        (GET /v1.0/policies/crossTenantAccessPolicy/partners) into a canonical Entity record.

        .DESCRIPTION
        entityId is the partner's own tenantId (Graph does not return a separate 'id' field for
        partner-override entries -- tenantId is this resource's natural, stable key). Field
        allowlist mirrors ConvertTo-EntraPostureCrossTenantAccessPolicyEntity's inboundTrust
        fields exactly, plus isServiceProvider -- this project's future XTA-002 control
        ("Partner-Specific Cross-Tenant Overrides More Permissive Than the Default",
        15-feature-parity-matrix.md section 6) needs to compare a partner override's trust
        settings against the tenant default those same field names represent.

        .PARAMETER RawPartner
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
        [System.Collections.Specialized.OrderedDictionary]$RawPartner,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawPartner.Contains('tenantId') -or [string]::IsNullOrWhiteSpace([string]$RawPartner['tenantId'])) {
        throw 'ConvertTo-EntraPostureCrossTenantAccessPolicyPartnerEntity: raw partner record has no tenantId.'
    }

    $inboundTrust = if ($RawPartner.Contains('inboundTrust')) { $RawPartner['inboundTrust'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawPartner['tenantId']
        entityType       = 'CrossTenantAccessPolicyPartner'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            isServiceProvider                                = if ($RawPartner.Contains('isServiceProvider')) { $RawPartner['isServiceProvider'] } else { $null }
            inboundTrustIsMfaAccepted                        = if ($inboundTrust -and $inboundTrust.Contains('isMfaAccepted')) { $inboundTrust['isMfaAccepted'] } else { $null }
            inboundTrustIsCompliantDeviceAccepted            = if ($inboundTrust -and $inboundTrust.Contains('isCompliantDeviceAccepted')) { $inboundTrust['isCompliantDeviceAccepted'] } else { $null }
            inboundTrustIsHybridAzureADJoinedDeviceAccepted  = if ($inboundTrust -and $inboundTrust.Contains('isHybridAzureADJoinedDeviceAccepted')) { $inboundTrust['isHybridAzureADJoinedDeviceAccepted'] } else { $null }
        }
        redacted         = $false
    }
}
