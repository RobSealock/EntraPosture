#Requires -Version 7.4

function ConvertTo-EntraPostureKnownAbusedAppEntity {
    <#
        .SYNOPSIS
        Normalizes one parsed rogueapps.toml app record (from
        ConvertFrom-EntraPostureRogueAppsToml) into a canonical Entity record.

        .DESCRIPTION
        Source, not tenant, evidence -- entityId is the app's own appId (a stable GUID in the
        vendored dataset), not anything collected from the tenant. permissions/contributors/
        mitreTTP are intentionally dropped here: nothing downstream (ENT-013's own evaluator)
        reads them, and this project's own field-allowlist discipline (keep only what a
        control actually consumes) applies to reference data exactly as it does to tenant
        evidence. description/tags/references/dateAdded are kept because ENT-013's own finding
        rationale quotes them directly.

        .PARAMETER App
        One element of ConvertFrom-EntraPostureRogueAppsToml's own output array.

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        The local file path this record was read from (not a URL -- this is local-file evidence,
        not a Graph/ARM collection).

        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$App,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if ([string]::IsNullOrWhiteSpace([string]$App['appId'])) {
        throw 'ConvertTo-EntraPostureKnownAbusedAppEntity: app record has no appId.'
    }

    return [ordered]@{
        entityId         = [string]$App['appId']
        entityType       = 'KnownAbusedApp'
        tenantScope      = $TenantScope
        displayName      = $App['appDisplayName']
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            appOwnerOrganizationId = $App['appOwnerOrganizationId']
            appPublisherName       = $App['appPublisherName']
            appPublisherId         = $App['appPublisherId']
            description            = $App['description']
            tags                   = @($App['tags'])
            references             = @($App['references'])
            dateAdded              = $App['dateAdded']
        }
        redacted         = $false
    }
}

function ConvertTo-EntraPostureKnownAbusedAppListMetadataEntity {
    <#
        .SYNOPSIS
        Builds the single KnownAbusedAppListMetadata entity carrying provenance for whichever
        local file was actually read -- the file path plus whatever the refresh sidecar recorded
        (commit date, fetched date), so ENT-013's own findings can quote "as of" freshness
        information directly instead of a bare Fail with no context.

        .PARAMETER FilePath
        The resolved local path that was actually read.

        .PARAMETER CommitDateUtc
        .PARAMETER FetchedAtUtc
        From the sidecar `*.meta.json` if one exists next to FilePath; $null if it doesn't
        (a hand-placed file via -Path with no sidecar is valid -- "unknown freshness" is a real,
        expected state, not an error).

        .PARAMETER AppCount
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json. entityId is always 'default' -- exactly
        one of these per snapshot, mirroring AuthorizationPolicy/TenantConfiguration's own
        singleton-entity convention.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [AllowNull()]
        [string]$CommitDateUtc,

        [Parameter()]
        [AllowNull()]
        [string]$FetchedAtUtc,

        [Parameter(Mandatory)]
        [int]$AppCount,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    return [ordered]@{
        entityId         = 'default'
        entityType       = 'KnownAbusedAppListMetadata'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            filePath      = $FilePath
            commitDateUtc = $CommitDateUtc
            fetchedAtUtc  = $FetchedAtUtc
            appCount      = $AppCount
        }
        redacted         = $false
    }
}
