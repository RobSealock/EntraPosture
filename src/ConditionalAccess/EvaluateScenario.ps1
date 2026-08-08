#Requires -Version 7.4

function Invoke-EntraPostureConditionalAccessScenario {
    <#
        .SYNOPSIS
        Evaluates a synthetic sign-in scenario against every collected Conditional Access policy,
        per 16-ca-evaluation-semantics.md -- this project's deterministic local "What If"
        equivalent.

        .DESCRIPTION
        Implements the cited combination model directly: disabled policies never match (§5);
        report-only policies are matched and reported but never contribute to the enforced result
        (§5); any applicable enabled policy requiring the 'block' control makes the overall result
        Blocked immediately (§3), before any grant-control combination is computed; every other
        applicable enabled policy's own grant-control requirement (already resolved per its own
        AND/OR operator, §2) becomes one entry in RequiredControlGroups -- the cross-policy
        combination is always AND (§1), deliberately represented as a list of groups rather than a
        single flattened control list, since flattening an OR-operator policy's control set into
        the same list as an AND-operator policy's would silently misrepresent "any one of these"
        as "all of these."

        Never calls a live endpoint (ADR-019: evaluators never call live APIs) -- this is the
        offline simulation half of Phase 8; live comparison against Microsoft's real What-If API
        is a separate, explicit function (Invoke-EntraPostureWhatIfComparison).

        Dispatches to one of two per-dimension match functions based on the scenario's own
        ScenarioKind field (VNext build order item 3): Test-EntraPostureConditionalAccessPolicyMatch
        for a 'User' scenario (from New-EntraPostureConditionalAccessScenario), or
        Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch for a 'WorkloadIdentity'
        scenario (from New-EntraPostureConditionalAccessWorkloadIdentityScenario) -- everything
        below this dispatch (block precedence, report-only exclusion, RequiredControlGroups) is
        already scenario-kind-agnostic and unchanged for both.

        .PARAMETER Policies
        Array of ConditionalAccessPolicy entities.

        .PARAMETER Scenario
        A scenario from New-EntraPostureConditionalAccessScenario or
        New-EntraPostureConditionalAccessWorkloadIdentityScenario.

        .OUTPUTS
        Ordered dictionary: Result ('Blocked'/'NotBlocked'), ApplicablePolicies (array, each
        entry: PolicyId, DisplayName, State, IsReportOnly, Operator, BuiltInControls,
        AuthenticationStrengthId, TermsOfUse), NotApplicablePolicies (array, each entry:
        PolicyId, DisplayName, ExcludedByDimension, Reason -- the explanation trace WS4 task 7
        calls for), RequiredControlGroups (array, each entry: PolicyId, Operator, Controls --
        omits report-only and block policies, since those don't contribute an enforced grant-
        control requirement).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Policies,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Scenario
    )

    $applicable = [System.Collections.Generic.List[object]]::new()
    $notApplicable = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $Policies) {
        $state = $policy.properties.state

        if ($state -eq 'disabled') {
            $notApplicable.Add([ordered]@{
                PolicyId            = $policy.entityId
                DisplayName         = $policy.displayName
                ExcludedByDimension = 'state'
                Reason              = "Policy state is 'disabled' -- not evaluated at all (16-ca-evaluation-semantics.md §5)."
            })
            continue
        }

        $matchResult = if ($Scenario.ScenarioKind -eq 'WorkloadIdentity') {
            Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario $Scenario
        } else {
            Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $Scenario
        }

        if (-not $matchResult.Applies) {
            $notApplicable.Add([ordered]@{
                PolicyId            = $policy.entityId
                DisplayName         = $policy.displayName
                ExcludedByDimension = $matchResult.ExcludedByDimension
                Reason              = $matchResult.Reason
            })
            continue
        }

        $applicable.Add([ordered]@{
            PolicyId                = $policy.entityId
            DisplayName             = $policy.displayName
            State                   = $state
            IsReportOnly            = ($state -eq 'enabledForReportingButNotEnforced')
            Operator                = $policy.properties.grantControls.operator
            BuiltInControls         = @($policy.properties.grantControls.builtInControls)
            AuthenticationStrengthId = $policy.properties.grantControls.authenticationStrengthId
            TermsOfUse              = @($policy.properties.grantControls.termsOfUse)
        })
    }

    # @() around the whole Where-Object pipeline -- see this project's established rationale
    # (e.g. EvaluateStandingTierZeroAssignment.ps1) for why a filtered result that may legitimately
    # collapse to 0 or 1 elements needs the outer wrap.
    $enforcingApplicable = @($applicable | Where-Object { -not $_.IsReportOnly })

    $isBlocked = @($enforcingApplicable | Where-Object { $_.BuiltInControls -contains 'block' }).Count -gt 0

    $requiredControlGroups = @(if ($isBlocked) {
        @()
    } else {
        @(foreach ($entry in $enforcingApplicable) {
            if (@($entry.BuiltInControls).Count -gt 0 -or @($entry.TermsOfUse).Count -gt 0 -or $entry.AuthenticationStrengthId) {
                [ordered]@{
                    PolicyId = $entry.PolicyId
                    Operator = $entry.Operator
                    Controls = @($entry.BuiltInControls)
                    AuthenticationStrengthId = $entry.AuthenticationStrengthId
                    TermsOfUse = @($entry.TermsOfUse)
                }
            }
        })
    })

    return [ordered]@{
        Result                 = if ($isBlocked) { 'Blocked' } else { 'NotBlocked' }
        ApplicablePolicies      = @($applicable.ToArray())
        NotApplicablePolicies   = @($notApplicable.ToArray())
        RequiredControlGroups  = $requiredControlGroups
    }
}
