#Requires -Version 7.4

function ConvertTo-EntraPostureAccessReviewDefinitionEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph accessReviewScheduleDefinition object
        (GET /v1.0/identityGovernance/accessReviews/definitions) into a canonical Entity
        record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, descriptionForAdmins, status, the
        scope sub-object's query field (which names what the review actually covers, e.g. a
        role-assignments or group-membership resource path), and (VNext build order item 9,
        AR-002) the settings sub-object's autoApplyDecisionsEnabled field -- the fields AR-001
        ("No Recurring Access Review Covers Privileged Roles, Guests, Groups, or Application
        Access") and AR-002 ("Existing Access Reviews Are Stale, Incomplete, or Have Unapplied
        Decisions", 15-feature-parity-matrix.md section 7) need. Reviewer identities and
        individual decisions are deliberately not collected here -- see
        NormalizeAccessReviewInstance.ps1 for the separate, redaction-aware instance/decisions
        drill-down AR-002 actually reads.

        .PARAMETER RawDefinition
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
        [System.Collections.Specialized.OrderedDictionary]$RawDefinition,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawDefinition.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawDefinition['id'])) {
        throw 'ConvertTo-EntraPostureAccessReviewDefinitionEntity: raw access review definition record has no id.'
    }

    $scope = if ($RawDefinition.Contains('scope')) { $RawDefinition['scope'] } else { $null }
    $settings = if ($RawDefinition.Contains('settings')) { $RawDefinition['settings'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawDefinition['id']
        entityType       = 'AccessReviewDefinition'
        tenantScope      = $TenantScope
        displayName      = if ($RawDefinition.Contains('displayName')) { $RawDefinition['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            descriptionForAdmins    = if ($RawDefinition.Contains('descriptionForAdmins')) { $RawDefinition['descriptionForAdmins'] } else { $null }
            status                  = if ($RawDefinition.Contains('status')) { $RawDefinition['status'] } else { $null }
            scopeQuery              = if ($scope -and $scope.Contains('query')) { $scope['query'] } else { $null }
            # Explicit $null (not assumed-false) when settings itself wasn't returned -- this is
            # evidence of what the API actually reported, not this project's own guess at
            # Microsoft's documented platform default (see AR-002.psd1's provenance notes).
            autoApplyDecisionsEnabled = if ($settings -and $settings.Contains('autoApplyDecisionsEnabled')) { [bool]$settings['autoApplyDecisionsEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
