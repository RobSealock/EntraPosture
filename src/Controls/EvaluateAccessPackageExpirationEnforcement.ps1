#Requires -Version 7.4

function Test-EntraPostureAccessPackageExpirationEnforcementControl {
    <#
        .SYNOPSIS
        EM-002's evaluator: for every access package EM-001 would establish as privileged, checks
        each attached policy's expiration setting and each of that package's assignments for a
        past-expiration state.

        .DESCRIPTION
        Relational, and (for the assignment half) reuses Microsoft's own platform-computed state
        rather than reimplementing a wall-clock comparison the way AR-002's overdue check has to.
        Confirmed directly against the accessPackageAssignment resource page: `state` is `expired`
        as a real, distinct, listable value (not just an absence of a still-active record) --
        this is stronger evidence than the matrix anticipated at design time (its own test-fixture
        note flagged needing "to confirm whether it's actually reachable, or whether Microsoft's
        platform prevents it from ever occurring"). Whether a `state: expired` record still
        represents currently-live access, or is a historical record of access already
        deprovisioned, is not itself confirmed by Microsoft's documentation -- flagged here
        exactly as the matrix's own open question asked, not resolved by assumption. This
        control's premise (an `expired`-state record is worth surfacing either way, since it's at
        minimum evidence of the deprovisioning path having been exercised) is this project's own
        judgment call, not a Microsoft directive -- graded `Inference` in this control's
        baselineDependency, same tier as AR-001's own "zero reviews by default" claim.

        Applicability reuses EM-001's exact privileged-package correlation (duplicated locally,
        not cross-called -- the same self-contained-evaluator convention AUTHCTX-002/AR-002
        already established).

        Redaction: assignment results reference only the assignment's own entityId, never a
        principal -- the collector/normalizer already never captured one (see
        NormalizeAccessPackageAssignment.ps1's own DESCRIPTION), so there is nothing here to
        redact after the fact.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        EM-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per policy attached to a privileged package, plus one element per stale
        assignment under a privileged package, or a single tenant-scoped NotApplicable element if
        no package is privileged.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $packages = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessPackage'
    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessPackageAssignmentPolicy'
    $groups = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Group'
    $azureRoleAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AzureRoleAssignment'
    $assignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessPackageAssignment'

    $roleAssignableGroupIds = @($groups | Where-Object { [bool]$_.properties.isAssignableToRole } | ForEach-Object { $_.entityId })
    $azureRoleBearingGroupIds = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalType -eq 'Group' } | ForEach-Object { [string]$_.properties.principalId })
    $privilegedGroupIds = @($roleAssignableGroupIds + $azureRoleBearingGroupIds | Select-Object -Unique)

    $privilegedPackageIds = @($packages | Where-Object {
        $privilegedRoles = @($_.properties.resourceRoles | Where-Object {
            [string]$_.originSystem -eq 'AadGroup' -and $privilegedGroupIds -contains [string]$_.originId
        })
        @($privilegedRoles).Count -gt 0
    } | ForEach-Object { $_.entityId })

    $policyResults = @(foreach ($policy in ($policies | Where-Object { $privilegedPackageIds -contains [string]$_.properties.accessPackageId })) {
        $evidenceRef = @([ordered]@{ entityId = $policy.properties.accessPackageId; entityType = 'AccessPackage' }; [ordered]@{ entityId = $policy.entityId; entityType = 'AccessPackageAssignmentPolicy' })
        if ([string]$policy.properties.expirationType -eq 'noExpiration') {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'EM002-POLICY-NO-EXPIRATION'
                Rationale          = "Assignment policy '$($policy.displayName)' on a privileged-resource access package has expiration.type set to 'noExpiration'."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'EM002-EXPIRATION-ENFORCED'
                Rationale          = "Assignment policy '$($policy.displayName)' on a privileged-resource access package has a bounded expiration configured."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    $assignmentResults = @(foreach ($assignment in ($assignments | Where-Object { $privilegedPackageIds -contains [string]$_.properties.accessPackageId })) {
        if ([string]$assignment.properties.state -ne 'expired') { continue }
        [ordered]@{
            Scope              = $assignment.entityId
            Status             = 'Fail'
            ReasonCode         = 'EM002-ASSIGNMENT-PAST-EXPIRATION'
            Rationale          = "Access package assignment '$($assignment.entityId)' on a privileged-resource access package is in state 'expired' (expiredDateTime: $($assignment.properties.expiredDateTime))."
            EvidenceReferences = @(
                [ordered]@{ entityId = $assignment.properties.accessPackageId; entityType = 'AccessPackage' }
                [ordered]@{ entityId = $assignment.entityId; entityType = 'AccessPackageAssignment' }
            )
        }
    })

    $evaluationResults = @($policyResults + $assignmentResults)

    if (@($evaluationResults).Count -eq 0) {
        # Covers both "no package is privileged at all" and "at least one package is privileged,
        # but it has zero attached policies and zero stale assignments to report" -- this project's
        # standing convention is that an evaluator never returns zero results (see AR-002/EM-001's
        # own tenant-scoped NotApplicable fallback for the same reason).
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'EM002-NO-APPLICABLE-POLICIES'
                Rationale          = 'No access package''s resource roles resolve to a role-assignable or Azure-role-bearing group, or no privileged-resource package has any attached policy or stale assignment to evaluate.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    return ,@($evaluationResults)
}
