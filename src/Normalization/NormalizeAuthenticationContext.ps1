#Requires -Version 7.4

function ConvertTo-EntraPostureAuthenticationContextEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph authenticationContextClassReference object
        (GET /v1.0/identity/conditionalAccess/authenticationContextClassReferences) into a
        canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id (the 'c1'-'c99' class reference value itself),
        displayName, description, isAvailable. Feeds the future AUTHCTX-001/AUTHCTX-002
        controls (15-feature-parity-matrix.md section 10) -- specifically AUTHCTX-001's need to
        know which authentication contexts exist at all (to cross-reference against which ones
        are actually assigned anywhere and which ones a Conditional Access policy references).

        .PARAMETER RawContext
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
        [System.Collections.Specialized.OrderedDictionary]$RawContext,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawContext.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawContext['id'])) {
        throw 'ConvertTo-EntraPostureAuthenticationContextEntity: raw authentication context record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawContext['id']
        entityType       = 'AuthenticationContextClassReference'
        tenantScope      = $TenantScope
        displayName      = if ($RawContext.Contains('displayName')) { $RawContext['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            description = if ($RawContext.Contains('description')) { $RawContext['description'] } else { $null }
            isAvailable = if ($RawContext.Contains('isAvailable')) { $RawContext['isAvailable'] } else { $null }
        }
        redacted         = $false
    }
}
