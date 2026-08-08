#Requires -Version 7.4

function Get-EntraPostureRoleManagementPolicyRuleForTarget {
    <#
        .SYNOPSIS
        Filters a unifiedRoleManagementPolicy rules array down to the ones matching a specific
        target.caller/target.level combination.

        .DESCRIPTION
        Top-level, not nested inside ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity
        -- Build-Module.ps1's export/duplicate-name AST scan searches nested scopes too, so a
        helper function defined inside another function's body gets swept into that validation
        regardless of which src/ subdirectory it lives in (a confirmed, enforced project rule, not
        specific to src/Public/).

        .PARAMETER Rules
        .PARAMETER Caller
        .PARAMETER Level

        .OUTPUTS
        Array of ordered dictionaries (raw rule objects), possibly empty.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rules,

        [Parameter(Mandatory)]
        [string]$Caller,

        [Parameter(Mandatory)]
        [string]$Level
    )

    return ,@($Rules | Where-Object {
        $target = if ($_.Contains('target')) { $_['target'] } else { $null }
        $target -and $target.Contains('caller') -and $target.Contains('level') -and $target['caller'] -eq $Caller -and $target['level'] -eq $Level
    })
}

function ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph unifiedRoleManagementPolicyAssignment object
        (GET /v1.0/policies/roleManagementPolicyAssignments, $expand=policy($expand=rules)) into
        a canonical Entity record.

        .DESCRIPTION
        Field shape confirmed directly against Microsoft Graph's unifiedRoleManagementPolicy/
        PolicyAssignment/PolicyRule resource documentation (re-fetched 2026-08-07).
        roleDefinitionId is the role's stable roleTemplateId (e.g. Global Administrator is always
        62e90394-69f5-4237-9190-012177145e10, confirmed directly in Microsoft's own example
        response) -- the same value space as DirectoryRole.entityId and
        PimEligible/DirectoryRoleAssignment relationships' own targetEntityId, so correlating this
        evidence against those needs no adapter.

        A policy's rules array carries multiple rules of the same type at different
        target.caller/target.level combinations. Build order item 8 (PIM-003 through PIM-009)
        confirmed directly against Microsoft's own PIM role-settings documentation
        (learn.microsoft.com/entra/id-governance/privileged-identity-management/
        pim-how-to-change-default-settings, re-fetched 2026-08-07) that caller=EndUser/
        level=Assignment is NOT the only target that matters: "Allow permanent active assignment" /
        "Expire active assignment after", "Require multifactor authentication on active
        assignment", and "Require justification on active assignment" are documented as
        settings for when an ADMIN creates a direct/permanent active assignment -- a materially
        different event from a user self-activating an eligible assignment, and (confirmed by
        inspecting a real policy's rules array) a SEPARATE rule instance at caller=Admin/
        level=Assignment, not the same rule the EndUser/Assignment fields below already capture.
        Getting this distinction right mattered directly: PIM-005/006/007 would have silently read
        the wrong setting entirely if this hadn't been checked against Microsoft's docs before
        writing the normalizer, since both target combinations produce rules of the identical
        @odata.type. Admin/Eligibility-level rules (how an admin configures who is eligible at
        all, not activation/assignment behavior) remain uncaptured -- no known project need.

        Field allowlist per section 8.4:
        - EndUser/Assignment (the user's own self-activation event):
          unifiedRoleManagementPolicyEnablementRule.enabledRules (e.g. "MultiFactorAuthentication",
          "Justification"); unifiedRoleManagementPolicyExpirationRule.isExpirationRequired/
          maximumDuration (ISO 8601 duration, Microsoft's admin UI calls this "Activation maximum
          duration"); unifiedRoleManagementPolicyApprovalRule.setting.isApprovalRequired;
          unifiedRoleManagementPolicyAuthenticationContextRule.isEnabled/claimValue.
        - Admin/Assignment (an admin creating a direct/permanent active assignment):
          unifiedRoleManagementPolicyEnablementRule.enabledRules (adminAssignmentEnabledRules);
          unifiedRoleManagementPolicyExpirationRule.isExpirationRequired/maximumDuration
          (adminAssignmentIsExpirationRequired/adminAssignmentMaximumDuration).
        - EndUser/Assignment NotificationRules (PIM-008's own need only): aggregated to a single
          activationNotificationEnabled boolean (true if any of the three recipientType variants --
          Admin, Requestor, Approver -- at this exact target has isDefaultRecipientsEnabled=true or
          a non-empty notificationRecipients list) rather than exposing the raw per-recipient-type
          rules, since no control needs anything more granular than "is notification for this event
          silenced entirely." Admin/Eligibility-caller notification rules are out of scope -- this
          project's controls only ever reason about the self-activation event, matching every other
          field captured here.

        claimValue correlation caveat (AUTHCTX-001's own citation notes this precisely, not
        assumed silently): Microsoft's own unifiedRoleManagementPolicyAuthenticationContextRule
        documentation describes claimValue only as "the value of the authentication context
        claim" -- it does not explicitly state claimValue equals a authenticationContextClassReference's
        own id (e.g. 'c1'). This project treats them as equal (the only interpretation consistent
        with how Conditional Access authentication context assignment actually works end to end),
        but grades this correlation as an inference, not a directly-quoted fact -- reflected in
        AUTHCTX-001's own baselineDependency citationStrength.

        .PARAMETER RawAssignment
        One element of the Graph response's 'value' array (with policy/rules already expanded).

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
        [System.Collections.Specialized.OrderedDictionary]$RawAssignment,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAssignment.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAssignment['id'])) {
        throw 'ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity: raw roleManagementPolicyAssignment record has no id.'
    }
    if (-not $RawAssignment.Contains('roleDefinitionId') -or [string]::IsNullOrWhiteSpace([string]$RawAssignment['roleDefinitionId'])) {
        throw 'ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity: raw roleManagementPolicyAssignment record has no roleDefinitionId -- refusing to normalize with no correlatable role.'
    }

    $policy = if ($RawAssignment.Contains('policy')) { $RawAssignment['policy'] } else { $null }
    $rules = @(if ($policy -and $policy.Contains('rules')) { $policy['rules'] } else { @() })

    $enduserAssignmentRules = Get-EntraPostureRoleManagementPolicyRuleForTarget -Rules $rules -Caller 'EndUser' -Level 'Assignment'
    $adminAssignmentRules = Get-EntraPostureRoleManagementPolicyRuleForTarget -Rules $rules -Caller 'Admin' -Level 'Assignment'

    $enablementRule = $enduserAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule' } | Select-Object -First 1
    $expirationRule = $enduserAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule' } | Select-Object -First 1
    $approvalRule = $enduserAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule' } | Select-Object -First 1
    $authContextRule = $enduserAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule' } | Select-Object -First 1
    $notificationRules = @($enduserAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule' })

    $adminEnablementRule = $adminAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule' } | Select-Object -First 1
    $adminExpirationRule = $adminAssignmentRules | Where-Object { $_.Contains('@odata.type') -and $_['@odata.type'] -eq '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule' } | Select-Object -First 1

    $approvalSetting = if ($approvalRule -and $approvalRule.Contains('setting')) { $approvalRule['setting'] } else { $null }

    $anyActivationNotificationEnabled = [bool](@($notificationRules | Where-Object {
        $defaultEnabled = $_.Contains('isDefaultRecipientsEnabled') -and [bool]$_['isDefaultRecipientsEnabled']
        $hasExplicitRecipients = $_.Contains('notificationRecipients') -and @($_['notificationRecipients']).Count -gt 0
        $defaultEnabled -or $hasExplicitRecipients
    })).Count -gt 0

    return [ordered]@{
        entityId         = [string]$RawAssignment['id']
        entityType       = 'RoleManagementPolicyAssignment'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            roleDefinitionId                    = [string]$RawAssignment['roleDefinitionId']
            enabledRules                        = @(if ($enablementRule -and $enablementRule.Contains('enabledRules')) { $enablementRule['enabledRules'] } else { @() })
            isExpirationRequired                = if ($expirationRule -and $expirationRule.Contains('isExpirationRequired')) { [bool]$expirationRule['isExpirationRequired'] } else { $null }
            maximumDuration                     = if ($expirationRule -and $expirationRule.Contains('maximumDuration')) { $expirationRule['maximumDuration'] } else { $null }
            approvalRequired                    = if ($approvalSetting -and $approvalSetting.Contains('isApprovalRequired')) { [bool]$approvalSetting['isApprovalRequired'] } else { $null }
            authenticationContextEnabled        = if ($authContextRule -and $authContextRule.Contains('isEnabled')) { [bool]$authContextRule['isEnabled'] } else { $false }
            authenticationContextClaimValue     = if ($authContextRule -and $authContextRule.Contains('claimValue')) { $authContextRule['claimValue'] } else { $null }
            activationNotificationEnabled       = $anyActivationNotificationEnabled
            adminAssignmentEnabledRules         = @(if ($adminEnablementRule -and $adminEnablementRule.Contains('enabledRules')) { $adminEnablementRule['enabledRules'] } else { @() })
            adminAssignmentIsExpirationRequired = if ($adminExpirationRule -and $adminExpirationRule.Contains('isExpirationRequired')) { [bool]$adminExpirationRule['isExpirationRequired'] } else { $null }
            adminAssignmentMaximumDuration      = if ($adminExpirationRule -and $adminExpirationRule.Contains('maximumDuration')) { $adminExpirationRule['maximumDuration'] } else { $null }
        }
        redacted         = $false
    }
}
