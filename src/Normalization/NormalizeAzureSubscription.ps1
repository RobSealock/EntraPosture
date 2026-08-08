#Requires -Version 7.4

function ConvertTo-EntraPostureAzureSubscriptionEntity {
    <#
        .SYNOPSIS
        Normalizes one raw ARM subscription object (GET /subscriptions) into a canonical Entity
        record.

        .DESCRIPTION
        Field allowlist per section 8.4: subscriptionId, displayName, state, tenantId. This is
        the "subscription discovery" half of Phase 6's "management-group/subscription discovery
        and inherited Azure RBAC correlation" -- entityId is the subscription's own ARM scope
        path ('/subscriptions/{id}'), not just the bare GUID, so it can be used directly as a
        -Scope argument to the role-assignment/role-definition collectors without
        reconstruction.

        .PARAMETER RawSubscription
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
        [System.Collections.Specialized.OrderedDictionary]$RawSubscription,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawSubscription.Contains('subscriptionId') -or [string]::IsNullOrWhiteSpace([string]$RawSubscription['subscriptionId'])) {
        throw 'ConvertTo-EntraPostureAzureSubscriptionEntity: raw subscription record has no subscriptionId.'
    }
    $subscriptionId = [string]$RawSubscription['subscriptionId']

    return [ordered]@{
        entityId         = "/subscriptions/$subscriptionId"
        entityType       = 'AzureSubscription'
        tenantScope      = $TenantScope
        displayName      = if ($RawSubscription.Contains('displayName')) { $RawSubscription['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            subscriptionId = $subscriptionId
            state          = if ($RawSubscription.Contains('state')) { $RawSubscription['state'] } else { $null }
            tenantId       = if ($RawSubscription.Contains('tenantId')) { $RawSubscription['tenantId'] } else { $null }
        }
        redacted         = $false
    }
}
