#Requires -Version 7.4

function Resolve-EntraPostureAuthenticationStrengthRequirement {
    <#
        .SYNOPSIS
        Resolves a Conditional Access policy's opaque grantControls.authenticationStrengthId
        (as returned in Invoke-EntraPostureConditionalAccessScenario's RequiredControlGroups)
        into its actual allowed authentication method combinations, using collected
        AuthenticationStrengthPolicy evidence (VNext build order item 5, the authenticationStrength
        half of the item -- see docs/VNext.md for why device-filter rule-language evaluation was
        split out as its own larger, separately-scoped item).

        .DESCRIPTION
        A resolution helper the caller invokes after Invoke-EntraPostureConditionalAccessScenario
        returns, same composable pattern as Resolve-EntraPostureNamedLocationId (build order
        item 4) -- not woven into the evaluation function itself, so EvaluateScenario.ps1 keeps
        depending only on ConditionalAccessPolicy evidence and doesn't need
        AuthenticationStrengthPolicy evidence to run at all (a scenario can still be evaluated
        correctly with authenticationStrengthId left unresolved -- RequiredControlGroups.
        AuthenticationStrengthId is exactly what it always was, this function just adds a second,
        optional lens on top of it).

        A $null or empty -AuthenticationStrengthId (the common case: most policies use
        builtInControls, not a custom authentication strength) resolves to Resolved=$false with
        empty results, not an error -- this is the expected, majority-case input, not a defensive
        edge case.

        .PARAMETER AuthenticationStrengthPolicies
        AuthenticationStrengthPolicy entities (from
        ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity). Empty is valid.

        .PARAMETER AuthenticationStrengthId
        A RequiredControlGroups entry's own AuthenticationStrengthId field. $null/empty is valid
        and resolves to Resolved=$false.

        .OUTPUTS
        Ordered dictionary: Resolved (bool -- $false if the ID was empty or matched no collected
        policy), AllowedCombinations (string[], each entry an authenticationMethodModes value or
        comma-joined combination, verbatim from Graph -- not further parsed), RequirementsSatisfied
        ('mfa'/'none'/$null -- whether satisfying this authentication strength grants an MFA claim,
        directly from Microsoft's own field, not inferred), PolicyType ('builtIn'/'custom'/$null).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$AuthenticationStrengthPolicies,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AuthenticationStrengthId
    )

    $unresolved = [ordered]@{
        Resolved               = $false
        AllowedCombinations    = @()
        RequirementsSatisfied  = $null
        PolicyType             = $null
    }

    if ([string]::IsNullOrEmpty($AuthenticationStrengthId)) {
        return $unresolved
    }

    $matchingPolicies = @($AuthenticationStrengthPolicies | Where-Object { $_.entityId -eq $AuthenticationStrengthId })
    if (@($matchingPolicies).Count -eq 0) {
        return $unresolved
    }

    $policy = $matchingPolicies[0]
    return [ordered]@{
        Resolved               = $true
        AllowedCombinations    = @($policy.properties.allowedCombinations)
        RequirementsSatisfied  = $policy.properties.requirementsSatisfied
        PolicyType             = $policy.properties.policyType
    }
}
