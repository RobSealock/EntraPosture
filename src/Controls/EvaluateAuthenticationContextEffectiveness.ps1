#Requires -Version 7.4

function Test-EntraPostureAuthenticationContextEffectivenessControl {
    <#
        .SYNOPSIS
        AUTHCTX-002's evaluator: for each (context, role) pairing AUTHCTX-001 would pass for,
        checks whether at least one referencing Conditional Access policy is actually enabled and
        covers the role's full eligible/active assignee population.

        .DESCRIPTION
        Relational, and the deepest correlation in this project's registry: authentication
        contexts, role management policy assignments, Conditional Access policies, and two
        relationship types (PimEligible, DirectoryRoleAssignment) for the role's actual
        assignees, plus a third (TransitiveMemberOf) to resolve group-based policy exclusions.
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AUTHCTX-002.psd1's expectedResultSemantics.

        Exclusion-scope coverage checks conditions.users.excludeUsers (direct) and
        conditions.users.excludeGroups (direct, or via the assignee's own TransitiveMemberOf
        relationships) -- conditions.users.excludeRoles is a deliberate, documented v1 boundary,
        not implemented here (see AUTHCTX-002.psd1's own provenance notes for why).

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per applicable (context, role) pairing, or a single NotApplicable element if
        none are applicable.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $contexts = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthenticationContextClassReference'
    $publishedContexts = @($contexts | Where-Object { [bool]$_.properties.isAvailable })

    $policyAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'RoleManagementPolicyAssignment'
    $authContextAssignments = @($policyAssignments | Where-Object {
        [bool]$_.properties.authenticationContextEnabled -and -not [string]::IsNullOrEmpty([string]$_.properties.authenticationContextClaimValue)
    })

    $caPolicies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'

    # (context, role) pairings where a published, PIM-configured context also has at least one
    # referencing policy (any state) -- exactly the set AUTHCTX-001 would Pass for.
    $pairings = @(foreach ($assignment in $authContextAssignments) {
        $claimValue = [string]$assignment.properties.authenticationContextClaimValue
        $context = $publishedContexts | Where-Object { $_.entityId -eq $claimValue } | Select-Object -First 1
        if (-not $context) { continue }

        $referencingPolicies = @($caPolicies | Where-Object {
            @($_.properties.conditions.applications.includeAuthenticationContextClassReferences) -contains $context.entityId
        })
        if (@($referencingPolicies).Count -eq 0) { continue }

        [ordered]@{
            Context             = $context
            Assignment          = $assignment
            ReferencingPolicies = $referencingPolicies
        }
    })

    if (@($pairings).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AUTHCTX-002-NO-APPLICABLE-PAIRINGS'
                Rationale          = 'No (context, role) pairing exists where a published, PIM-configured authentication context has at least one referencing Conditional Access policy.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($pairing in $pairings) {
        $roleDefinitionId = [string]$pairing.Assignment.properties.roleDefinitionId

        # The role's actual population: eligible (PimEligible, Eligible or PendingActivation) and
        # active (DirectoryRoleAssignment, Active) assignees, deduplicated by principal ID.
        $eligibleAssignees = @(Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimEligible' -TargetEntityId $roleDefinitionId |
            Where-Object { $_.assignmentState -in @('Eligible', 'PendingActivation') })
        $activeAssignees = @(Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $roleDefinitionId |
            Where-Object { $_.assignmentState -eq 'Active' })
        $assigneeIds = @(@($eligibleAssignees | ForEach-Object { $_.sourceEntityId }) + @($activeAssignees | ForEach-Object { $_.sourceEntityId }) | Select-Object -Unique)

        $enabledEffectivePolicy = $null
        $enabledButExcludingPolicies = [System.Collections.Generic.List[object]]::new()
        $excludedAssigneeIds = [System.Collections.Generic.List[string]]::new()
        $anyEnabled = $false
        $anyReportOnly = $false

        foreach ($policy in $pairing.ReferencingPolicies) {
            $state = $policy.properties.state
            if ($state -ne 'enabled') {
                if ($state -eq 'enabledForReportingButNotEnforced') { $anyReportOnly = $true }
                continue
            }
            $anyEnabled = $true

            $excludeUsers = @($policy.properties.conditions.users.excludeUsers)
            $excludeGroups = @($policy.properties.conditions.users.excludeGroups)

            $thisPolicyExcluded = @(foreach ($assigneeId in $assigneeIds) {
                $directUserMatch = $excludeUsers -contains $assigneeId
                $directGroupMatch = $excludeGroups -contains $assigneeId
                $transitiveGroupMatch = $false
                if (-not $directGroupMatch -and @($excludeGroups).Count -gt 0) {
                    $assigneeGroups = @(Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'TransitiveMemberOf' -SourceEntityId $assigneeId)
                    $transitiveGroupMatch = @($assigneeGroups | Where-Object { $excludeGroups -contains $_.targetEntityId }).Count -gt 0
                }
                if ($directUserMatch -or $directGroupMatch -or $transitiveGroupMatch) { $assigneeId }
            })

            if (@($thisPolicyExcluded).Count -eq 0) {
                $enabledEffectivePolicy = $policy
            } else {
                $enabledButExcludingPolicies.Add($policy)
                foreach ($id in $thisPolicyExcluded) { $excludedAssigneeIds.Add($id) }
            }
        }

        $evidenceRef = @(
            [ordered]@{ entityId = $pairing.Context.entityId; entityType = 'AuthenticationContextClassReference' }
            [ordered]@{ entityId = $pairing.Assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )
        foreach ($policy in $pairing.ReferencingPolicies) {
            $evidenceRef += [ordered]@{ entityId = $policy.entityId; entityType = 'ConditionalAccessPolicy' }
        }

        if ($enabledEffectivePolicy) {
            [ordered]@{
                Scope              = "$($pairing.Context.entityId)::$roleDefinitionId"
                Status             = 'Pass'
                ReasonCode         = 'AUTHCTX-002-EFFECTIVE'
                Rationale          = "At least one policy referencing authentication context '$($pairing.Context.displayName)' for this role is enabled and covers the full eligible/active assignee population ($($assigneeIds.Count) principal(s))."
                EvidenceReferences = $evidenceRef
            }
        } elseif ($anyEnabled) {
            # At least one referencing policy is enabled but excludes an assignee -- the most
            # specific, most actionable failure state, so it takes priority over
            # POLICY-DISABLED/POLICY-REPORT-ONLY even if other referencing policies also happen to
            # be disabled or report-only (see AUTHCTX-002-ASSIGNEE-EXCLUDED's own psd1 description).
            $excludedRef = @(foreach ($id in ($excludedAssigneeIds | Select-Object -Unique)) { [ordered]@{ entityId = $id; entityType = 'Unknown' } })
            [ordered]@{
                Scope              = "$($pairing.Context.entityId)::$roleDefinitionId"
                Status             = 'Fail'
                ReasonCode         = 'AUTHCTX-002-ASSIGNEE-EXCLUDED'
                Rationale          = "Every enabled policy referencing authentication context '$($pairing.Context.displayName)' for this role excludes at least one of the role's $($assigneeIds.Count) actual eligible/active assignee(s) -- no fallback protection applies to an excluded assignee."
                EvidenceReferences = @($evidenceRef + $excludedRef)
            }
        } elseif ($anyReportOnly) {
            [ordered]@{
                Scope              = "$($pairing.Context.entityId)::$roleDefinitionId"
                Status             = 'Fail'
                ReasonCode         = 'AUTHCTX-002-POLICY-REPORT-ONLY'
                Rationale          = "No policy referencing authentication context '$($pairing.Context.displayName)' for this role is enabled -- at least one is report-only, which Microsoft documents as not triggering the PIM authentication-context fallback."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = "$($pairing.Context.entityId)::$roleDefinitionId"
                Status             = 'Fail'
                ReasonCode         = 'AUTHCTX-002-POLICY-DISABLED'
                Rationale          = "Every policy referencing authentication context '$($pairing.Context.displayName)' for this role is disabled."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
