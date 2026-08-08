#Requires -Version 7.4

function Get-EntraPostureAgentIdentityForeignMap {
    <#
        .SYNOPSIS
        Resolves every collected AgentIdentity entity to whether it is "foreign" -- shared
        correlation logic behind AGT-004/005/008/009 (VNext build order item 13), extracted into
        its own standalone top-level function rather than duplicated four times, the same
        "avoid duplicating relational correlation logic across evaluators" discipline
        Find-EntraPostureRelatedResultTransition already established for drift detection (build
        order item 10).

        .DESCRIPTION
        An AgentIdentity's own record carries no appOwnerOrganizationId directly -- reaching it
        requires joining AgentIdentity.properties.agentIdentityBlueprintId (documented as "the
        appId of the agent identity blueprint," not either object's own id -- see
        ConvertTo-EntraPostureAgentIdentityEntity's own DESCRIPTION for the citation) against
        AgentIdentityBlueprintPrincipal.properties.appId, then reading that matched principal's
        own appOwnerOrganizationId. "Foreign" means that appOwnerOrganizationId is present and
        differs from -TenantScope; a blueprint principal with no appOwnerOrganizationId at all
        (an internally-authored blueprint that was never itself an external multi-tenant app) is
        internal, not unresolvable.

        An AgentIdentity whose agentIdentityBlueprintId cannot be matched to any collected
        AgentIdentityBlueprintPrincipal (e.g. that collector's evidence wasn't collected, or the
        blueprint principal was deleted after the agent identity was created) is mapped to $null,
        not $false -- callers must treat $null as "cannot determine foreign-ness," never as
        "confirmed internal," so a coverage gap in one evidence domain can never silently produce
        a false-negative Pass in a control reading this map.

        Every evaluator function in this project is invoked with only -EvidenceProvider (see
        Invoke-EntraPostureSnapshotEvaluation's own `& $control.evaluatorFunctionName
        -EvidenceProvider $evidenceProvider` call site) -- there is no separate -TenantScope
        input available to an evaluator, so this function derives the tenant's own scope
        directly from already-collected evidence instead of taking it as a parameter: every
        entity in this project's canonical model carries its own tenantScope field
        (entity.schema.json's own required field), so the first available
        AgentIdentityBlueprintPrincipal or AgentIdentity record's tenantScope is exactly the same
        value orchestration would have passed explicitly, with no new input plumbing needed.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Ordered dictionary: AgentIdentity.entityId -> [bool]$IsForeign, or $null if
        unresolvable.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $agentIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentity'
    $blueprintPrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentityBlueprintPrincipal'

    $tenantScope = if (@($blueprintPrincipals).Count -gt 0) {
        $blueprintPrincipals[0].tenantScope
    } elseif (@($agentIdentities).Count -gt 0) {
        $agentIdentities[0].tenantScope
    } else {
        $null
    }

    $blueprintPrincipalByAppId = [ordered]@{}
    foreach ($principal in $blueprintPrincipals) {
        $appId = [string]$principal.properties.appId
        if (-not [string]::IsNullOrWhiteSpace($appId) -and -not $blueprintPrincipalByAppId.Contains($appId)) {
            $blueprintPrincipalByAppId[$appId] = $principal
        }
    }

    $result = [ordered]@{}
    foreach ($identity in $agentIdentities) {
        $blueprintAppId = [string]$identity.properties.agentIdentityBlueprintId
        if ([string]::IsNullOrWhiteSpace($blueprintAppId) -or -not $blueprintPrincipalByAppId.Contains($blueprintAppId)) {
            $result[$identity.entityId] = $null
            continue
        }
        $ownerOrgId = [string]$blueprintPrincipalByAppId[$blueprintAppId].properties.appOwnerOrganizationId
        $result[$identity.entityId] = (-not [string]::IsNullOrWhiteSpace($ownerOrgId)) -and ($ownerOrgId -ne $TenantScope)
    }

    return $result
}

function Get-EntraPostureAgentUserForeignMap {
    <#
        .SYNOPSIS
        Resolves every collected AgentUser entity to whether its parent AgentIdentity is
        "foreign" -- shared correlation logic behind AGT-011/012/013/014/016 (VNext build order
        item 13).

        .DESCRIPTION
        A single hop beyond Get-EntraPostureAgentIdentityForeignMap: AgentUser.properties.
        identityParentId "references the object ID of the associated agent identity" (direct
        quote, agentUser resource page, re-fetched 2026-08-07) -- a plain entityId match against
        AgentIdentity.entityId, then this function reuses the identity-level foreign map above
        for that parent. An AgentUser whose identityParentId doesn't match any collected
        AgentIdentity, or whose parent identity's own foreign-ness is itself unresolvable, maps
        to $null -- the same "never silently promote an unresolvable case to a definite answer"
        rule the identity-level map applies.

        .PARAMETER EvidenceProvider

        .OUTPUTS
        Ordered dictionary: AgentUser.entityId -> [bool]$IsForeign, or $null if unresolvable.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $agentUsers = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentUser'
    $identityForeignMap = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $EvidenceProvider

    $result = [ordered]@{}
    foreach ($agentUser in $agentUsers) {
        $parentId = [string]$agentUser.properties.identityParentId
        if ([string]::IsNullOrWhiteSpace($parentId) -or -not $identityForeignMap.Contains($parentId)) {
            $result[$agentUser.entityId] = $null
            continue
        }
        $result[$agentUser.entityId] = $identityForeignMap[$parentId]
    }

    return $result
}
