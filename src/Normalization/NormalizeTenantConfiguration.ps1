#Requires -Version 7.4

function ConvertTo-EntraPostureOrganizationEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph organization object (GET /v1.0/organization, a single-element
        'value' array despite being effectively a tenant singleton) into a canonical Entity
        record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, createdDateTime -- general
        tenant-configuration baseline fields per 00-permission-report-matrix.md's
        "Tenant/organization configuration" row, deliberately not the larger set of billing/
        licensing/branding fields this project has no security-evaluation need for.

        .PARAMETER RawOrganization
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
        [System.Collections.Specialized.OrderedDictionary]$RawOrganization,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawOrganization.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawOrganization['id'])) {
        throw 'ConvertTo-EntraPostureOrganizationEntity: raw organization record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawOrganization['id']
        entityType       = 'Organization'
        tenantScope      = $TenantScope
        displayName      = if ($RawOrganization.Contains('displayName')) { $RawOrganization['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            createdDateTime = if ($RawOrganization.Contains('createdDateTime')) { $RawOrganization['createdDateTime'] } else { $null }
        }
        redacted         = $false
    }
}

function ConvertTo-EntraPostureSecurityDefaultsPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes the raw Graph identitySecurityDefaultsEnforcementPolicy singleton
        (GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy) into a canonical Entity
        record.

        .DESCRIPTION
        Field allowlist: id, isEnabled. Directly closes the "Security Defaults status
        (MS-ENTRA-001 gap)" item named in 00-permission-report-matrix.md's tenant-configuration
        row -- this is the one field (isEnabled) a future MS-ENTRA-001 control would read.

        .PARAMETER RawPolicy
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

    $entityId = if ($RawPolicy.Contains('id') -and -not [string]::IsNullOrWhiteSpace([string]$RawPolicy['id'])) { [string]$RawPolicy['id'] } else { 'default' }

    return [ordered]@{
        entityId         = $entityId
        entityType       = 'SecurityDefaultsPolicy'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            isEnabled = if ($RawPolicy.Contains('isEnabled')) { $RawPolicy['isEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
