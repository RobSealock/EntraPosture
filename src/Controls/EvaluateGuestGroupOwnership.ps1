#Requires -Version 7.4

function Test-EntraPostureGuestGroupOwnershipControl {
    <#
        .SYNOPSIS
        COL-003's evaluator: checks the tenant's Group.Unified group settings for
        AllowGuestsToBeGroupOwner.

        .DESCRIPTION
        A single tenant-scoped result, same shape as COL-001/002 -- but unlike those two (which
        read a singleton AuthorizationPolicy entity guaranteed to exist), a groupSetting object
        for the "Group.Unified" template only exists in evidence if the tenant has ever
        explicitly customized it away from Microsoft's own documented template default. Per the
        live "List settings" Graph reference page (re-fetched 2026-08-08), "by default, all
        groups inherit the preset defaults" -- and AllowGuestsToBeGroupOwner's own documented
        default is false. So: no Group.Unified groupSetting entity at all is treated as Pass
        (the tenant is running the default, not a missing-evidence case -- the collector call
        itself succeeded and returned zero rows, which is what "never customized" looks like on
        the wire), not folded into a generic "no evidence" NotApplicable the way COL-001/002's
        NO-POLICY-FOUND branches are (those exist only for the pathological case of the
        AuthorizationPolicy singleton itself being absent, which does not happen in practice).
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        COL-003.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Always exactly one element (tenant-scoped).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $groupSettings = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'GroupSetting'
    $unifiedSetting = @($groupSettings | Where-Object { $_.displayName -eq 'Group.Unified' }) | Select-Object -First 1

    $results = @(if (-not $unifiedSetting) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'COL-003-DEFAULT-GUESTS-NOT-ALLOWED'
            Rationale = 'No Group.Unified group settings object exists for this tenant -- Microsoft''s own documented template default for AllowGuestsToBeGroupOwner is false, so guests cannot be group owners.'
            EvidenceReferences = @()
        }
    } elseif ($unifiedSetting.properties.allowGuestsToBeGroupOwner -eq $true) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'COL-003-GUESTS-ALLOWED-GROUP-OWNER'
            Rationale = 'The tenant''s Group.Unified settings explicitly set AllowGuestsToBeGroupOwner to true -- guest users can be assigned as Microsoft 365 group owners.'
            EvidenceReferences = @([ordered]@{ entityId = $unifiedSetting.entityId; entityType = 'GroupSetting' })
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'COL-003-GUESTS-NOT-ALLOWED-GROUP-OWNER'
            Rationale = 'The tenant''s Group.Unified settings do not allow guest users to be assigned as Microsoft 365 group owners.'
            EvidenceReferences = @([ordered]@{ entityId = $unifiedSetting.entityId; entityType = 'GroupSetting' })
        }
    })

    return ,@($results)
}
