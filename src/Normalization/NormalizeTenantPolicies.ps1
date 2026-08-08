#Requires -Version 7.4

function ConvertTo-EntraPostureAuthorizationPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes the raw Graph authorizationPolicy singleton (GET /v1.0/policies/
        authorizationPolicy) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, allowInvitesFrom, and the
        defaultUserRolePermissions sub-object's allowedToCreateApps/
        allowedToCreateSecurityGroups/allowedToReadOtherUsers/permissionGrantPoliciesAssigned --
        the fields this project's future AC-001 control ("Default User Consent Policy More
        Permissive Than Microsoft's Recommended State", 15-feature-parity-matrix.md section 9)
        is expected to need. Exact field-name confirmation against a live tenant response is
        still pending (00-open-questions.md's Phase 6 section) -- these are the well-documented
        Microsoft Graph field names, not independently re-verified this pass.

        .PARAMETER RawPolicy
        The raw response object (singleton, no 'value' array wrapper).

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
    $defaultUserRolePermissions = if ($RawPolicy.Contains('defaultUserRolePermissions')) { $RawPolicy['defaultUserRolePermissions'] } else { $null }

    return [ordered]@{
        entityId         = $entityId
        entityType       = 'AuthorizationPolicy'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            allowInvitesFrom                     = if ($RawPolicy.Contains('allowInvitesFrom')) { $RawPolicy['allowInvitesFrom'] } else { $null }
            allowedToCreateApps                  = if ($defaultUserRolePermissions -and $defaultUserRolePermissions.Contains('allowedToCreateApps')) { $defaultUserRolePermissions['allowedToCreateApps'] } else { $null }
            allowedToCreateSecurityGroups         = if ($defaultUserRolePermissions -and $defaultUserRolePermissions.Contains('allowedToCreateSecurityGroups')) { $defaultUserRolePermissions['allowedToCreateSecurityGroups'] } else { $null }
            allowedToReadOtherUsers              = if ($defaultUserRolePermissions -and $defaultUserRolePermissions.Contains('allowedToReadOtherUsers')) { $defaultUserRolePermissions['allowedToReadOtherUsers'] } else { $null }
            permissionGrantPoliciesAssigned      = @(if ($defaultUserRolePermissions -and $defaultUserRolePermissions.Contains('permissionGrantPoliciesAssigned')) { $defaultUserRolePermissions['permissionGrantPoliciesAssigned'] } else { @() })
        }
        redacted         = $false
    }
}

function ConvertTo-EntraPostureAdminConsentRequestPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes the raw Graph adminConsentRequestPolicy singleton (GET /v1.0/policies/
        adminConsentRequestPolicy) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, isEnabled, notifyReviewers, remindersEnabled,
        requestDurationInDays, and the count (not the reviewer identities themselves --
        avoiding persisting a list of specific admin identities here) of configured reviewers.
        Feeds the future AC-002 control ("Admin Consent Workflow Not Enabled or Has No
        Functioning Reviewers", 15-feature-parity-matrix.md section 9).

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
    $reviewerCount = if ($RawPolicy.Contains('reviewers')) { @($RawPolicy['reviewers']).Count } else { 0 }

    return [ordered]@{
        entityId         = $entityId
        entityType       = 'AdminConsentRequestPolicy'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            isEnabled              = if ($RawPolicy.Contains('isEnabled')) { $RawPolicy['isEnabled'] } else { $null }
            notifyReviewers        = if ($RawPolicy.Contains('notifyReviewers')) { $RawPolicy['notifyReviewers'] } else { $null }
            remindersEnabled       = if ($RawPolicy.Contains('remindersEnabled')) { $RawPolicy['remindersEnabled'] } else { $null }
            requestDurationInDays  = if ($RawPolicy.Contains('requestDurationInDays')) { $RawPolicy['requestDurationInDays'] } else { $null }
            reviewerCount          = $reviewerCount
        }
        redacted         = $false
    }
}
