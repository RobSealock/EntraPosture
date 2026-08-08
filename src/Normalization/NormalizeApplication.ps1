#Requires -Version 7.4

function ConvertTo-EntraPostureApplicationEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph application object (GET /v1.0/applications) into a canonical
        Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, appId, displayName, signInAudience,
        createdDateTime, passwordCredentialCount. signInAudience is load-bearing for
        multi-tenant/personal-account exposure findings (a v.next candidate, not evaluated in
        v1, but worth collecting now per this phase's own "schema-first collectors for the
        accepted v1 domains" instruction -- Applications is itself a section 4.1 v1-included
        domain regardless of which specific controls read it yet).

        passwordCredentialCount (added 2026-08-08, VNext build order item 2 batch 3, APP-001):
        the raw passwordCredentials array (present by default on this same
        GET /v1.0/applications response this collector already makes -- confirmed by its
        presence on the agentIdentityBlueprint-list example response, the same underlying
        /applications resource family) is aggregated to a bare count at normalization time and
        never persisted, the same aggregate-not-raw redaction-by-construction choice
        ConvertTo-EntraPostureAgentIdentityBlueprintEntity already made for the identical field.

        appInstancePropertyLockEnabled (added 2026-08-08, VNext build order item 2 batch 5,
        APP-002): the servicePrincipalLockConfiguration sub-object's own isEnabled field --
        confirmed present on the same default GET /v1.0/applications response, no additional
        $select needed (the live application Graph reference page, re-fetched 2026-08-08, shows
        it in the standard JSON representation with no "not returned by default" caveat). Only
        the boolean is extracted, not the sub-object's other lock-granularity fields
        (allProperties/credentialsWithUsageSign/etc.), since APP-002's own check is simply
        whether the lock is enabled at all.

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
            passwordCredentialCount = @(if ($RawApplication.Contains('passwordCredentials')) { $RawApplication['passwordCredentials'] } else { @() }).Count
            appInstancePropertyLockEnabled = if ($RawApplication.Contains('servicePrincipalLockConfiguration') -and $RawApplication['servicePrincipalLockConfiguration'] -and $RawApplication['servicePrincipalLockConfiguration'].Contains('isEnabled')) { $RawApplication['servicePrincipalLockConfiguration']['isEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
