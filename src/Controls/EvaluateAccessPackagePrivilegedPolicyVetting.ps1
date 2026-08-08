#Requires -Version 7.4

function Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl {
    <#
        .SYNOPSIS
        EM-001's evaluator: for each access package with at least one privileged resource role,
        checks whether every attached assignment policy either requires approval or is narrowly
        scoped to specific pre-identified principals.

        .DESCRIPTION
        Relational. "Privileged resource role" reuses this project's existing evidence rather
        than re-deriving a second definition of "privileged" -- the matrix's own recommended
        resolution to its open question on this point (15-feature-parity-matrix.md section 8,
        "Open questions... not resolved here"). A resource role is privileged when its
        originSystem is 'AadGroup' (confirmed against Microsoft's accessPackageResource resource
        page as a real, documented originSystem value) and the underlying group is either
        role-assignable (Group.properties.isAssignableToRole, the same field GRP-005 already
        reads) or is itself the principal of a collected AzureRoleAssignment
        (principalType 'Group') -- both are the exact two privileged-group paths the matrix's own
        citations name Microsoft as documenting entitlement management can grant. Application-role
        (AadApplication-origin) privilege classification is a deliberate, documented boundary,
        not implemented here -- the matrix's own open question on this point is left genuinely
        open, not silently narrowed without saying so.

        License-gate NotApplicable handling (EM001-LICENSE-INSUFFICIENT in the matrix's design)
        is not implemented, for the same reason AR-001/AR-002 don't implement it: license state
        is not currently collected evidence anywhere in this project. Not declared as a reason
        code here, matching AR-001.psd1's own precedent of omitting reason codes for boundaries
        it doesn't implement rather than declaring a code the evaluator can never actually emit.

        This project resolves an internal inconsistency in the matrix's own EM-001 design:
        "Applicability" describes a per-package NotApplicable (EM001-NO-PRIVILEGED-RESOURCES) for
        every non-privileged package, while "Expected result semantics" says "one result per
        access package with at least one privileged resource role" (implying non-privileged
        packages produce no result at all). Since most packages in most tenants have no
        privileged resource role (the matrix's own words), producing a NotApplicable result per
        non-privileged package would be noise at real-tenant scale. Resolved the same way AR-002
        resolves an analogous "most things don't apply" case: a single tenant-scoped
        NotApplicable when NO package anywhere has a privileged resource role, and silent
        exclusion (no result) for an individual non-privileged package when at least one other
        package does qualify.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        EM-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per privileged access package, or a single tenant-scoped NotApplicable
        element if none are privileged.
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

    $roleAssignableGroupIds = @($groups | Where-Object { [bool]$_.properties.isAssignableToRole } | ForEach-Object { $_.entityId })
    $azureRoleBearingGroupIds = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalType -eq 'Group' } | ForEach-Object { [string]$_.properties.principalId })
    $privilegedGroupIds = @($roleAssignableGroupIds + $azureRoleBearingGroupIds | Select-Object -Unique)

    $broadScopes = @('allDirectoryUsers', 'allMemberUsers', 'allExternalUsers', 'allConfiguredConnectedOrganizationUsers')

    $privilegedPackages = @(foreach ($package in $packages) {
        $privilegedRoles = @($package.properties.resourceRoles | Where-Object {
            [string]$_.originSystem -eq 'AadGroup' -and $privilegedGroupIds -contains [string]$_.originId
        })
        if (@($privilegedRoles).Count -eq 0) { continue }
        [ordered]@{ Package = $package; PrivilegedRoles = $privilegedRoles }
    })

    if (@($privilegedPackages).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'EM001-NO-PRIVILEGED-RESOURCES'
                Rationale          = 'No access package''s resource roles resolve to a role-assignable or Azure-role-bearing group.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($entry in $privilegedPackages) {
        $package = $entry.Package
        $packagePolicies = @($policies | Where-Object { [string]$_.properties.accessPackageId -eq $package.entityId })

        $evidenceRef = @([ordered]@{ entityId = $package.entityId; entityType = 'AccessPackage' })

        $autoAssignmentPolicy = $packagePolicies | Where-Object { [bool]$_.properties.isAutoAssignment } | Select-Object -First 1
        $broadNoApprovalPolicy = $packagePolicies | Where-Object {
            -not [bool]$_.properties.isAutoAssignment -and
            $_.properties.isApprovalRequiredForAdd -eq $false -and
            $broadScopes -contains [string]$_.properties.allowedTargetScope
        } | Select-Object -First 1

        if ($autoAssignmentPolicy) {
            [ordered]@{
                Scope              = $package.entityId
                Status             = 'Fail'
                ReasonCode         = 'EM001-AUTO-ASSIGNMENT-NO-APPROVAL'
                Rationale          = "Access package '$($package.displayName)' has a privileged resource role and at least one auto-assignment policy ('$($autoAssignmentPolicy.displayName)'), which has no approval step at all."
                EvidenceReferences = @($evidenceRef + [ordered]@{ entityId = $autoAssignmentPolicy.entityId; entityType = 'AccessPackageAssignmentPolicy' })
            }
        } elseif ($broadNoApprovalPolicy) {
            [ordered]@{
                Scope              = $package.entityId
                Status             = 'Fail'
                ReasonCode         = 'EM001-BROAD-SCOPE-NO-APPROVAL'
                Rationale          = "Access package '$($package.displayName)' has a privileged resource role and at least one request-based policy ('$($broadNoApprovalPolicy.displayName)') with approval not required and a broad target scope ('$($broadNoApprovalPolicy.properties.allowedTargetScope)')."
                EvidenceReferences = @($evidenceRef + [ordered]@{ entityId = $broadNoApprovalPolicy.entityId; entityType = 'AccessPackageAssignmentPolicy' })
            }
        } else {
            [ordered]@{
                Scope              = $package.entityId
                Status             = 'Pass'
                ReasonCode         = 'EM001-ADEQUATELY-VETTED'
                Rationale          = "Access package '$($package.displayName)' has a privileged resource role, but every attached policy either requires approval or is narrowly scoped."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
