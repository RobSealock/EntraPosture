#Requires -Version 7.4

function Test-EntraPostureConditionalAccessPolicyMatch {
    <#
        .SYNOPSIS
        Determines whether one normalized Conditional Access policy entity applies to a synthetic
        sign-in scenario, per 16-ca-evaluation-semantics.md.

        .DESCRIPTION
        Matches users (§4's exclude-wins rule, extended by direct analogy to every dimension
        below per that section's own documented caveat), applications, platforms, locations,
        clientAppTypes, sign-in/user risk levels (§7: absent/empty condition array =
        risk-independent, not risk-excluding), and (VNext build order item 5) the device filter
        (conditions.devices.deviceFilterMode/deviceFilterRule), via
        Test-EntraPostureDeviceFilterCondition. Workload identity conditions, insider risk,
        and granular guest sub-typing are still explicitly not matched -- see
        16-ca-evaluation-semantics.md §8 for the full boundary list and rationale; a policy using
        ONLY those unmatched dimensions to target users (e.g. includeUserActions with no
        includeApplications) will not match any scenario in v1, which is a real, documented gap,
        not a silent wrong answer.

        Never throws for a well-formed policy/scenario -- an unmatched dimension is treated as
        "this policy does not apply," with the specific reason recorded, never as an error.

        .PARAMETER Policy
        A ConditionalAccessPolicy entity (from ConvertTo-EntraPostureConditionalAccessPolicyEntity).

        .PARAMETER Scenario
        A scenario from New-EntraPostureConditionalAccessScenario.

        .OUTPUTS
        Ordered dictionary: Applies (bool), ExcludedByDimension (string or $null -- which
        dimension's exclude list matched, when Applies is $false specifically because of an
        exclusion rather than a missing inclusion), Reason (human-readable explanation, for the
        simulation engine's explanation trace).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Policy,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Scenario
    )

    $conditions = $Policy.properties.conditions

    # -- Users dimension (§4: exclude always wins) --
    $users = $conditions.users
    $userIncluded = ($users.includeUsers -contains 'All') `
        -or ($users.includeUsers -contains $Scenario.UserId) `
        -or (@($users.includeGroups | Where-Object { $Scenario.UserGroupIds -contains $_ })).Count -gt 0 `
        -or (@($users.includeRoles | Where-Object { $Scenario.UserRoleIds -contains $_ })).Count -gt 0 `
        -or ($Scenario.IsGuest -and (@($users.includeGuestOrExternalUserTypes).Count -gt 0 -or $users.includeUsers -contains 'GuestsOrExternalUsers'))
    $userExcluded = ($users.excludeUsers -contains $Scenario.UserId) `
        -or (@($users.excludeGroups | Where-Object { $Scenario.UserGroupIds -contains $_ })).Count -gt 0 `
        -or (@($users.excludeRoles | Where-Object { $Scenario.UserRoleIds -contains $_ })).Count -gt 0 `
        -or ($Scenario.IsGuest -and @($users.excludeGuestOrExternalUserTypes).Count -gt 0)

    if ($userExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'users'; Reason = "Scenario user/group/role is in the policy's exclude list." }
    }
    if (-not $userIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = 'Scenario user is not in the policy''s include scope (users/groups/roles/guests).' }
    }

    # -- Applications dimension (only includeApplications/excludeApplications matched in v1 --
    # includeUserActions/includeAuthenticationContextClassReferences-only policies never match,
    # see this function's own DESCRIPTION) --
    $applications = $conditions.applications
    $appIncluded = ($applications.includeApplications -contains 'All') -or ($applications.includeApplications -contains $Scenario.ApplicationId)
    $appExcluded = ($applications.excludeApplications -contains $Scenario.ApplicationId) -or ($applications.excludeApplications -contains 'All')

    if ($appExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'applications'; Reason = "Scenario application is in the policy's exclude list." }
    }
    if (-not $appIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = 'Scenario application is not in the policy''s include scope (or the policy targets only user actions/authentication contexts, not matched in v1).' }
    }

    # -- clientAppTypes (no exclude concept in Graph's model; empty/absent = matches all) --
    $clientAppTypesConfigured = @($conditions.clientAppTypes).Count -gt 0
    $clientAppTypeMatches = (-not $clientAppTypesConfigured) -or ($conditions.clientAppTypes -contains 'all') -or ($conditions.clientAppTypes -contains $Scenario.ClientAppType)
    if (-not $clientAppTypeMatches) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario client app type '$($Scenario.ClientAppType)' does not match the policy's configured client app types." }
    }

    # -- Platforms (exclude wins; empty/absent include = not restricted by platform) --
    $platforms = $conditions.platforms
    $platformsConfigured = @($platforms.includePlatforms).Count -gt 0
    $platformIncluded = (-not $platformsConfigured) -or ($platforms.includePlatforms -contains 'all') -or ($platforms.includePlatforms -contains $Scenario.Platform)
    $platformExcluded = $platforms.excludePlatforms -contains $Scenario.Platform
    if ($platformExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'platforms'; Reason = "Scenario platform '$($Scenario.Platform)' is in the policy's exclude list." }
    }
    if (-not $platformIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario platform '$($Scenario.Platform)' does not match the policy's configured platforms." }
    }

    # -- Locations (exclude wins; empty/absent include = not restricted by location. VNext build
    # order item 4: LocationId is an array -- a real IP can fall inside more than one overlapping
    # named location at once, see New-EntraPostureConditionalAccessScenario's own -LocationId
    # documentation -- and 'AllTrusted' is resolved against the scenario's real IsTrustedLocation
    # flag (from Resolve-EntraPostureNamedLocationId's IsTrustedMatch), not matched literally.) --
    $locations = $conditions.locations
    $scenarioLocationIds = @($Scenario.LocationId)
    $locationsConfigured = @($locations.includeLocations).Count -gt 0
    $locationIncluded = (-not $locationsConfigured) `
        -or ($locations.includeLocations -contains 'All') `
        -or (($locations.includeLocations -contains 'AllTrusted') -and $Scenario.IsTrustedLocation) `
        -or (@($locations.includeLocations | Where-Object { $scenarioLocationIds -contains $_ })).Count -gt 0
    $locationExcluded = ($locations.excludeLocations -contains 'All') `
        -or (($locations.excludeLocations -contains 'AllTrusted') -and $Scenario.IsTrustedLocation) `
        -or (@($locations.excludeLocations | Where-Object { $scenarioLocationIds -contains $_ })).Count -gt 0
    if ($locationExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'locations'; Reason = "Scenario location(s) '$($scenarioLocationIds -join ', ')' (trusted=$($Scenario.IsTrustedLocation)) match the policy's exclude list." }
    }
    if (-not $locationIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario location(s) '$($scenarioLocationIds -join ', ')' (trusted=$($Scenario.IsTrustedLocation)) do not match the policy's configured locations." }
    }

    # -- Risk levels (§7: empty/absent = risk-independent, this project's own documented decision,
    # not a quoted Microsoft default -- see 16-ca-evaluation-semantics.md §7) --
    $signInRiskConfigured = @($conditions.signInRiskLevels).Count -gt 0
    $signInRiskMatches = (-not $signInRiskConfigured) -or ($conditions.signInRiskLevels -contains $Scenario.SignInRiskLevel)
    if (-not $signInRiskMatches) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario sign-in risk level '$($Scenario.SignInRiskLevel)' does not match the policy's configured sign-in risk levels." }
    }

    $userRiskConfigured = @($conditions.userRiskLevels).Count -gt 0
    $userRiskMatches = (-not $userRiskConfigured) -or ($conditions.userRiskLevels -contains $Scenario.UserRiskLevel)
    if (-not $userRiskMatches) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario user risk level '$($Scenario.UserRiskLevel)' does not match the policy's configured user risk levels." }
    }

    # -- Device filter (VNext build order item 5, device-filter rule-language evaluation) --
    # Absent mode/rule = not restricted by device filter, same "absent condition doesn't narrow
    # the match" posture as every other dimension above. A device-filter evaluation exception
    # (e.g. an operator this project's v1 grammar doesn't accept -- see
    # EvaluateDeviceFilterCondition.ps1's own DESCRIPTION for exactly which) is caught, not
    # propagated -- this function's own top-level DESCRIPTION promises it never throws for a
    # well-formed policy/scenario; an unsupported device-filter feature is treated the same way
    # this project already treats includeUserActions-only policies (a documented v1 boundary,
    # "no match," not a crash), with the real exception message preserved in Reason for the
    # explanation trace rather than silently discarded.
    $deviceFilterMode = $conditions.devices.deviceFilterMode
    $deviceFilterRule = $conditions.devices.deviceFilterRule
    if (-not [string]::IsNullOrWhiteSpace([string]$deviceFilterMode) -and -not [string]::IsNullOrWhiteSpace([string]$deviceFilterRule)) {
        try {
            $deviceFilterSatisfied = Test-EntraPostureDeviceFilterCondition -Mode $deviceFilterMode -Rule $deviceFilterRule `
                -IsDeviceRegistered $Scenario.IsDeviceRegistered -IsIntuneManaged $Scenario.IsIntuneManaged `
                -IsCompliantDevice $Scenario.IsCompliantDevice -IsHybridJoined $Scenario.IsHybridJoined `
                -DeviceAttributes $Scenario.DeviceAttributes
        } catch {
            return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Device filter rule could not be evaluated (unsupported v1 device-filter feature): $($_.Exception.Message)" }
        }
        if (-not $deviceFilterSatisfied) {
            return [ordered]@{ Applies = $false; ExcludedByDimension = 'devices'; Reason = "Scenario device does not satisfy the policy's device filter (mode '$deviceFilterMode')." }
        }
    }

    return [ordered]@{ Applies = $true; ExcludedByDimension = $null; Reason = 'Every matched condition dimension is satisfied.' }
}

function Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch {
    <#
        .SYNOPSIS
        Determines whether one normalized Conditional Access policy entity applies to a synthetic
        workload-identity (service principal) sign-in scenario, per 16-ca-evaluation-semantics.md
        section 8's workload-identity subsection.

        .DESCRIPTION
        A deliberately separate, narrower sibling to Test-EntraPostureConditionalAccessPolicyMatch
        -- see New-EntraPostureConditionalAccessWorkloadIdentityScenario's own DESCRIPTION for
        why workload-identity policies have a materially different, narrower condition surface
        (only clientApplications targeting, locations, and service principal risk) rather than
        threading a scenario-kind branch through every dimension of the user-scenario match
        function above.

        Targeting is opt-in, not defaulted: unlike risk-level conditions (empty/absent = matches
        regardless of risk, per section 7's documented judgment call, extended here to
        servicePrincipalRiskLevels by direct analogy), an empty/absent
        clientApplications.includeServicePrincipals means this policy targets no service principal
        at all -- the same "no default match" posture the user-scenario function already takes for
        conditions.users.includeUsers (a policy with no configured user/group/role include never
        matches, it isn't treated as unrestricted).

        'ServicePrincipalsInMyTenant' is Microsoft's own documented sentinel (the workload-identity
        Learn page's own sample JSON) for "every service principal registered in this tenant" --
        matched literally here, the same way the user-scenario function matches 'All' literally
        rather than resolving it against a real population.

        .PARAMETER Policy
        A ConditionalAccessPolicy entity (from ConvertTo-EntraPostureConditionalAccessPolicyEntity).

        .PARAMETER Scenario
        A scenario from New-EntraPostureConditionalAccessWorkloadIdentityScenario.

        .OUTPUTS
        Ordered dictionary: Applies (bool), ExcludedByDimension (string or $null), Reason (human-
        readable explanation) -- same shape as the user-scenario match function.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Policy,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Scenario
    )

    $conditions = $Policy.properties.conditions

    # -- Client applications (service principals) dimension: exclude wins; opt-in targeting only,
    # no "empty include = matches everyone" default (see this function's own DESCRIPTION) --
    $clientApps = $conditions.clientApplications
    $spIncluded = ($clientApps.includeServicePrincipals -contains $Scenario.ServicePrincipalId) `
        -or ($clientApps.includeServicePrincipals -contains 'ServicePrincipalsInMyTenant')
    $spExcluded = $clientApps.excludeServicePrincipals -contains $Scenario.ServicePrincipalId

    if ($spExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'clientApplications'; Reason = "Scenario service principal is in the policy's exclude list." }
    }
    if (-not $spIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = 'Scenario service principal is not in the policy''s include scope, or this policy does not target workload identities at all.' }
    }

    # -- Locations (same exclude-wins / array-of-ID / resolved-'AllTrusted' semantics as the
    # user-scenario function's locations dimension -- see that function's own comment) --
    $locations = $conditions.locations
    $scenarioLocationIds = @($Scenario.LocationId)
    $locationsConfigured = @($locations.includeLocations).Count -gt 0
    $locationIncluded = (-not $locationsConfigured) `
        -or ($locations.includeLocations -contains 'All') `
        -or (($locations.includeLocations -contains 'AllTrusted') -and $Scenario.IsTrustedLocation) `
        -or (@($locations.includeLocations | Where-Object { $scenarioLocationIds -contains $_ })).Count -gt 0
    $locationExcluded = ($locations.excludeLocations -contains 'All') `
        -or (($locations.excludeLocations -contains 'AllTrusted') -and $Scenario.IsTrustedLocation) `
        -or (@($locations.excludeLocations | Where-Object { $scenarioLocationIds -contains $_ })).Count -gt 0
    if ($locationExcluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = 'locations'; Reason = "Scenario location(s) '$($scenarioLocationIds -join ', ')' (trusted=$($Scenario.IsTrustedLocation)) match the policy's exclude list." }
    }
    if (-not $locationIncluded) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario location(s) '$($scenarioLocationIds -join ', ')' (trusted=$($Scenario.IsTrustedLocation)) do not match the policy's configured locations." }
    }

    # -- Service principal risk (empty/absent = risk-independent, by direct analogy to section 7's
    # signInRiskLevels/userRiskLevels judgment call -- see this function's own DESCRIPTION) --
    $spRiskConfigured = @($conditions.servicePrincipalRiskLevels).Count -gt 0
    $spRiskMatches = (-not $spRiskConfigured) -or ($conditions.servicePrincipalRiskLevels -contains $Scenario.ServicePrincipalRiskLevel)
    if (-not $spRiskMatches) {
        return [ordered]@{ Applies = $false; ExcludedByDimension = $null; Reason = "Scenario service principal risk level '$($Scenario.ServicePrincipalRiskLevel)' does not match the policy's configured service principal risk levels." }
    }

    return [ordered]@{ Applies = $true; ExcludedByDimension = $null; Reason = 'Every matched condition dimension is satisfied.' }
}
