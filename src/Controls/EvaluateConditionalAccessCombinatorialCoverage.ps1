#Requires -Version 7.4

function Test-EntraPostureConditionalAccessCombinatorialCoverageControl {
    <#
        .SYNOPSIS
        CA-002's evaluator: runs the full policy-induced combinatorial scenario set (VNext build
        order item 12) for every curated Tier-0 role through the Phase 8 CA simulation engine and
        checks each for a "strong control" (block, MFA, or an authentication-strength requirement
        that itself satisfies MFA).

        .DESCRIPTION
        Generalizes CA-001's fixed 16-scenario (4 platform x 4 client app type, Global
        Administrator only) grid two ways: (1) the scenario set is generated deterministically
        from this tenant's own collected policies (Get-EntraPostureConditionalAccessCombinatorialScenario)
        rather than a hardcoded constant grid, covering platform, clientAppType, location-trust,
        signInRiskLevel, and userRiskLevel; (2) every curated Tier-0 role is checked, not only
        Global Administrator. "Strong control" is also a strictly more complete definition than
        CA-001's own (which checks only a literal 'mfa' builtInControls entry): a scenario also
        counts as covered when a matched policy's grantControls.authenticationStrengthId resolves
        (via Resolve-EntraPostureAuthenticationStrengthRequirement, VNext build order item 5)
        to an authentication strength whose own requirementsSatisfied is 'mfa' -- CA-001 itself is
        not retroactively changed to use this fuller definition; that is a separate, out-of-scope
        observation for this item, not fixed here.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        CA-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per (role, generated scenario) pair, or a single tenant-scoped NotApplicable
        element if no curated Tier-0 role exists in evidence.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')
    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoles = @($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    if (@($tierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'CA-002-NO-TIER-ZERO-ROLE-ACTIVATED'
                Rationale          = 'No curated Tier-0 DirectoryRole entity (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator) was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $authStrengthPolicies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthenticationStrengthPolicy'

    $cases = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies $policies -RoleEntities $tierZeroRoles

    $evidenceRef = [System.Collections.Generic.List[object]]::new()
    foreach ($role in $tierZeroRoles) { $evidenceRef.Add([ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }) }
    foreach ($policy in $policies) { $evidenceRef.Add([ordered]@{ entityId = $policy.entityId; entityType = 'ConditionalAccessPolicy' }) }
    $evidenceRefArray = @($evidenceRef.ToArray())

    $evaluationResults = @(foreach ($case in $cases) {
        $role = $case.RoleEntity
        $scenario = $case.Scenario
        $simulationResult = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario $scenario

        $mfaControlGroup = $simulationResult.RequiredControlGroups | Where-Object {
            ($_.Controls -contains 'mfa') -or
            ($_.AuthenticationStrengthId -and (Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies $authStrengthPolicies -AuthenticationStrengthId $_.AuthenticationStrengthId).RequirementsSatisfied -eq 'mfa')
        } | Select-Object -First 1

        $isCovered = ($simulationResult.Result -eq 'Blocked') -or ($null -ne $mfaControlGroup)

        $scope = "$($role.entityId)::$($scenario.Platform)::$($scenario.ClientAppType)::$(if ($scenario.IsTrustedLocation) { 'trusted' } else { 'untrusted' })::$($scenario.SignInRiskLevel)::$($scenario.UserRiskLevel)"

        if ($isCovered) {
            [ordered]@{
                Scope              = $scope
                Status             = 'Pass'
                ReasonCode         = 'CA-002-SCENARIO-COVERED'
                Rationale          = "A $($role.displayName) signing in under this scenario (platform '$($scenario.Platform)', client app type '$($scenario.ClientAppType)', $(if ($scenario.IsTrustedLocation) { 'trusted' } else { 'untrusted' }) location, sign-in risk '$($scenario.SignInRiskLevel)', user risk '$($scenario.UserRiskLevel)') is blocked or required to complete MFA (directly or via a satisfying authentication strength) by at least one applicable enabled policy."
                EvidenceReferences = $evidenceRefArray
            }
        } else {
            [ordered]@{
                Scope              = $scope
                Status             = 'Fail'
                ReasonCode         = 'CA-002-UNCOVERED-SCENARIO'
                Rationale          = "A $($role.displayName) signing in under this scenario (platform '$($scenario.Platform)', client app type '$($scenario.ClientAppType)', $(if ($scenario.IsTrustedLocation) { 'trusted' } else { 'untrusted' }) location, sign-in risk '$($scenario.SignInRiskLevel)', user risk '$($scenario.UserRiskLevel)') is not blocked and not required to complete MFA by any applicable enabled policy."
                EvidenceReferences = $evidenceRefArray
            }
        }
    })

    return ,@($evaluationResults)
}
