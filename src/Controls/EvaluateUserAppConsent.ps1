#Requires -Version 7.4

function Test-EntraPostureUserAppConsentControl {
    <#
        .SYNOPSIS
        USR-004's evaluator: checks the tenant's AuthorizationPolicy.defaultUserRolePermissions.
        permissionGrantPoliciesAssigned setting for the deprecated, most-permissive built-in
        consent policy.

        .DESCRIPTION
        Confirmed directly (web search corroborating Microsoft's own "Manage app consent
        policies" guidance, re-fetched 2026-08-08): the built-in policy ID
        `managePermissionGrantsForSelf.microsoft-user-default-legacy` is the deprecated "allow
        user consent for all apps" policy Microsoft is actively phasing out in favor of
        `microsoft-user-default-recommended` (verified publishers + low-risk permissions only)
        and `microsoft-user-default-low` (all low-risk permissions). Per the
        defaultUserRolePermissions reference page's own words, "an empty list indicates user
        consent to apps is disabled" -- the most restrictive state, Pass.

        Deliberately simpler than EntraFalcon's own USR-004 check, which additionally
        cross-references a live delegated-permission-classification API against this project's
        curated dangerous-permission list to further sub-classify the `-low` policy's own
        specific low-risk permissions -- that extra classification data isn't collected by this
        project and was judged unnecessary complexity for what this control is fundamentally
        checking: whether the tenant is still on the deprecated unrestricted-consent policy.
        Any policy ID other than the three well-known built-in ones (a custom app consent policy)
        is treated conservatively as Fail -- this project has no way to verify a custom policy's
        own permission scope is safe. Never produces NotEvaluated or Error status -- assigned by
        the orchestration layer, per USR-004.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AuthorizationPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $safeBuiltInPolicyIds = @(
        'managePermissionGrantsForSelf.microsoft-user-default-recommended'
        'managePermissionGrantsForSelf.microsoft-user-default-low'
    )
    $legacyPolicyId = 'managePermissionGrantsForSelf.microsoft-user-default-legacy'

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-004-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $assignedPolicyIds = @($policy.properties.permissionGrantPoliciesAssigned | ForEach-Object { [string]$_ })
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if (@($assignedPolicyIds).Count -eq 0) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'USR-004-CONSENT-DISABLED'
                Rationale = 'User consent to apps is disabled entirely (permissionGrantPoliciesAssigned is empty).'
                EvidenceReferences = $evidenceRef
            }
        } elseif ($assignedPolicyIds -contains $legacyPolicyId) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'USR-004-LEGACY-CONSENT-POLICY'
                Rationale = 'Users may consent to apps under the deprecated, unrestricted "microsoft-user-default-legacy" built-in policy.'
                EvidenceReferences = $evidenceRef
            }
        } elseif (@($assignedPolicyIds | Where-Object { $safeBuiltInPolicyIds -notcontains $_ }).Count -eq 0) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'USR-004-RESTRICTED-CONSENT-POLICY'
                Rationale = 'Users may consent to apps only under Microsoft''s own restrictive built-in policy (verified-publisher/low-risk permissions).'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'USR-004-CUSTOM-CONSENT-POLICY'
                Rationale = 'Users may consent to apps under at least one custom app consent policy this project cannot independently verify the scope of.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
