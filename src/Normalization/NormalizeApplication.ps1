#Requires -Version 7.4

function ConvertTo-EntraPostureApplicationEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph application object (GET /v1.0/applications) into a canonical
        Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, appId, displayName, signInAudience,
        createdDateTime. signInAudience is load-bearing for multi-tenant/personal-account
        exposure findings (a v.next candidate, not evaluated in v1, but worth collecting now
        per this phase's own "schema-first collectors for the accepted v1 domains" instruction
        -- Applications is itself a section 4.1 v1-included domain regardless of which specific
        controls read it yet).

        .PARAMETER RawApplication
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
        [System.Collections.Specialized.OrderedDictionary]$RawApplication,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawApplication.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawApplication['id'])) {
        throw 'ConvertTo-EntraPostureApplicationEntity: raw application record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawApplication['id']
        entityType       = 'Application'
        tenantScope      = $TenantScope
        displayName      = if ($RawApplication.Contains('displayName')) { $RawApplication['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            appId            = if ($RawApplication.Contains('appId')) { $RawApplication['appId'] } else { $null }
            signInAudience   = if ($RawApplication.Contains('signInAudience')) { $RawApplication['signInAudience'] } else { $null }
            createdDateTime  = if ($RawApplication.Contains('createdDateTime')) { $RawApplication['createdDateTime'] } else { $null }
        }
        redacted         = $false
    }
}
