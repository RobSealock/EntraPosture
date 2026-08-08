#Requires -Version 7.4

function Test-EntraPostureDangerousDynamicGroupRuleControl {
    <#
        .SYNOPSIS
        GRP-004's evaluator: for each dynamically-membered Group entity, checks whether its
        membershipRule references a user attribute a member could edit about themselves to
        manipulate their own dynamic-group membership.

        .DESCRIPTION
        Two tiers of curated attribute, independently re-derived from EntraFalcon's own publicly
        visible check_Tenant.psm1 (github.com/CompassSecurity/EntraFalcon), then confirmed each
        attribute is genuinely self-editable via Microsoft's own "Update user" documentation
        before inclusion:
        - Always risky: user.preferredLanguage, user.mobilePhone, user.businessPhones -- every
          user can edit these about their own account via Microsoft Graph or the My Profile
          portal regardless of any tenant setting.
        - Invite-dependent: user.userPrincipalName, user.mail -- only a meaningful risk when
          guest invitations are actually possible (AuthorizationPolicy.allowInvitesFrom != 'none',
          the same field COL-002's evaluator already reads), since these two become
          attacker-influenceable specifically through the guest-invitation flow itself, not
          through an existing member's own self-service profile edit.

        A membership rule referencing any of the applicable attributes for the current tenant
        configuration is Fail -- a user (or, for the invite-dependent pair, an inviter) could set
        that attribute to a value matching the rule and be added to the group, regardless of
        whether the rule's author intended that. Population: every Group entity with groupTypes
        containing 'DynamicMembership' and a non-empty membershipRule. Never produces
        NotEvaluated or Error status -- assigned by the orchestration layer, per GRP-004.psd1's
        expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $groups = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Group'
    $dynamicGroups = @($groups | Where-Object {
        @($_.properties.groupTypes) -contains 'DynamicMembership' -and -not [string]::IsNullOrWhiteSpace([string]$_.properties.membershipRule)
    })

    if (@($dynamicGroups).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'GRP-004-NO-DYNAMIC-GROUPS'
                Rationale = 'No dynamically-membered Group entity with a membership rule was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'
    $allowInvitesFrom = if (@($policies).Count -gt 0) { [string]$policies[0].properties.allowInvitesFrom } else { $null }
    $guestInvitesPossible = -not [string]::IsNullOrWhiteSpace($allowInvitesFrom) -and $allowInvitesFrom.Trim().ToLowerInvariant() -ne 'none'

    $alwaysRiskyAttributes = @('user.preferredLanguage', 'user.mobilePhone', 'user.businessPhones')
    $inviteDependentAttributes = @('user.userPrincipalName', 'user.mail')

    $evaluationResults = @(foreach ($group in $dynamicGroups) {
        $ruleText = [string]$group.properties.membershipRule
        $matchedAttributes = [System.Collections.Generic.List[string]]::new()

        foreach ($attribute in $alwaysRiskyAttributes) {
            if ($ruleText -match "(?i)\b$([regex]::Escape($attribute))\b") { $matchedAttributes.Add($attribute) }
        }
        if ($guestInvitesPossible) {
            foreach ($attribute in $inviteDependentAttributes) {
                if ($ruleText -match "(?i)\b$([regex]::Escape($attribute))\b") { $matchedAttributes.Add($attribute) }
            }
        }

        $evidenceRef = @([ordered]@{ entityId = $group.entityId; entityType = 'Group' })

        if ($matchedAttributes.Count -gt 0) {
            [ordered]@{
                Scope = $group.entityId; Status = 'Fail'; ReasonCode = 'GRP-004-DANGEROUS-MEMBERSHIP-RULE'
                Rationale = "Dynamic group '$($group.displayName)''s membership rule references self-editable attribute(s): $($matchedAttributes -join ', ')."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $group.entityId; Status = 'Pass'; ReasonCode = 'GRP-004-SAFE-MEMBERSHIP-RULE'
                Rationale = "Dynamic group '$($group.displayName)''s membership rule references no known self-editable attribute."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
