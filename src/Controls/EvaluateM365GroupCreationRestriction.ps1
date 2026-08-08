#Requires -Version 7.4

function Test-EntraPostureM365GroupCreationRestrictionControl {
    <#
        .SYNOPSIS
        GRP-002's evaluator: checks the tenant's Group.Unified group settings for
        EnableGroupCreation.

        .DESCRIPTION
        Fail when EnableGroupCreation is true (or no customized Group.Unified settings object
        exists at all -- its own documented default is true, confirmed live 2026-08-08 against a
        worked example of this exact groupSettingTemplate) -- the opposite absence-handling
        direction from COL-003's own AllowGuestsToBeGroupOwner check (whose documented default is
        false): each finding built against GroupSetting evidence applies its own field's actual
        documented default, not a single project-wide assumption. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per GRP-002.psd1's
        expectedResultSemantics.

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

    $results = @(if (-not $unifiedSetting -or $null -eq $unifiedSetting.properties.enableGroupCreation -or $unifiedSetting.properties.enableGroupCreation -eq $true) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'GRP-002-GROUP-CREATION-UNRESTRICTED'
            Rationale = 'Microsoft 365 group creation is not restricted (or no customized Group.Unified settings object exists, and Microsoft''s own documented default for EnableGroupCreation is true).'
            EvidenceReferences = if ($unifiedSetting) { @([ordered]@{ entityId = $unifiedSetting.entityId; entityType = 'GroupSetting' }) } else { @() }
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'GRP-002-GROUP-CREATION-RESTRICTED'
            Rationale = 'Microsoft 365 group creation is restricted for default users (EnableGroupCreation is false).'
            EvidenceReferences = @([ordered]@{ entityId = $unifiedSetting.entityId; entityType = 'GroupSetting' })
        }
    })

    return ,@($results)
}
