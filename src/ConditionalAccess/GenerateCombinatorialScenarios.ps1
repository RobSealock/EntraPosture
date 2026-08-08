#Requires -Version 7.4

function Get-EntraPostureConditionalAccessCombinatorialScenario {
    <#
        .SYNOPSIS
        Deterministically generates CA-002's combinatorial sign-in scenario set -- one scenario
        per (curated Tier-0 role) x (policy-induced distinguishing value per dimension)
        combination, across platform, clientAppType, location-trust, signInRiskLevel, and
        userRiskLevel.

        .DESCRIPTION
        v.next build order item 12. Policy-induced equivalence partitioning, not brute-force
        enumeration or per-real-object sampling. caOptics' and CA Insight's own README-level
        algorithm descriptions were reviewed (design/approach only, per docs/VNext.md's
        review-not-reuse policy -- neither project's source was read) before designing this
        independently. CA Insight's own description of a "representation-based strategy" that
        avoids per-combination brute force over its full theoretical ~250-million-combination
        space is the specific idea this function generalizes: for each dimension, only the VALUES
        A COLLECTED POLICY ACTUALLY DISTINGUISHES BY need their own scenario -- two platforms
        neither policy ever names behave identically under every policy's condition matching, so
        they don't need separate scenarios. This bounds the combination space by this tenant's own
        policy complexity (a handful of distinguishing values per dimension in any real tenant),
        not by tenant size or Entra's full theoretical value space -- polynomial in policy count,
        not exponential in principal/object count.

        Per dimension, the distinguishing value set is every value referenced in any collected
        policy's own condition (platforms.includePlatforms/excludePlatforms, clientAppTypes,
        signInRiskLevels, userRiskLevels respectively), plus one baseline "not specifically named
        by any policy" sentinel value ('all' for platform/clientAppType, 'none' for both risk
        levels) -- the sentinel is what catches, e.g., every policy excluding iOS/Android while no
        policy names a brand-new platform value, exactly the class of gap caOptics/CA Insight both
        describe as their point. Location is a fixed two-value set (untrusted:
        LocationId 'All'/IsTrustedLocation $false; trusted: LocationId
        'AllTrusted'/IsTrustedLocation $true), deliberately not derived from real NamedLocation
        IDs -- real-object location expansion is a separately-scopable amount of work this item
        does not attempt. Any raw policy-condition value outside the scenario constructor's own
        documented ValidateSet (Microsoft's real platform/clientAppType/risk enums, established
        during Phase 8) is skipped, not force-fit -- a documented boundary rather than a
        constructor exception.

        The "role" dimension reuses this project's existing curated Tier-0 set (Global
        Administrator, Privileged Role Administrator, Privileged Authentication Administrator --
        the same three PIM-002 established and every PIM-00x/AUTHCTX control since has reused)
        rather than a full per-principal equivalence-class derivation across every real user/group
        in the tenant -- a deliberate, documented scope boundary matching established precedent.
        Application is not combinatorially expanded either -- every scenario uses the fixed 'All'
        representative application, the same choice CA-001 already makes.

        Throws if the computed scenario count would exceed -MaxScenarios, rather than silently
        truncating -- the engineering plan's explicit "never hide sampling" requirement (section
        9.4) applies here exactly as it does to CA-001's own fixed grid.

        .PARAMETER Policies
        Array of ConditionalAccessPolicy entities.

        .PARAMETER RoleEntities
        Array of DirectoryRole entities for the curated Tier-0 roles actually present in evidence
        -- the caller resolves which of the three curated roles exist before calling this
        function, matching every other PIM-family control's own pattern.

        .PARAMETER MaxScenarios
        Safety bound (default 5000) -- throws rather than truncating if exceeded.

        .OUTPUTS
        Array of ordered dictionaries: RoleEntity, Scenario (from
        New-EntraPostureConditionalAccessScenario).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Policies,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$RoleEntities,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxScenarios = 5000
    )

    $validPlatforms = @('android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'all', 'unknownFutureValue')
    $validClientAppTypes = @('all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')
    $validRiskLevels = @('none', 'low', 'medium', 'high')

    $platformValues = [System.Collections.Generic.List[string]]::new()
    $platformValues.Add('all')
    $clientAppTypeValues = [System.Collections.Generic.List[string]]::new()
    $clientAppTypeValues.Add('all')
    $signInRiskValues = [System.Collections.Generic.List[string]]::new()
    $signInRiskValues.Add('none')
    $userRiskValues = [System.Collections.Generic.List[string]]::new()
    $userRiskValues.Add('none')

    foreach ($policy in $Policies) {
        $conditions = $policy.properties.conditions
        foreach ($v in @($conditions.platforms.includePlatforms) + @($conditions.platforms.excludePlatforms)) {
            $sv = [string]$v
            if ($validPlatforms -contains $sv -and $platformValues -notcontains $sv) { $platformValues.Add($sv) }
        }
        foreach ($v in @($conditions.clientAppTypes)) {
            $sv = [string]$v
            if ($validClientAppTypes -contains $sv -and $clientAppTypeValues -notcontains $sv) { $clientAppTypeValues.Add($sv) }
        }
        foreach ($v in @($conditions.signInRiskLevels)) {
            $sv = [string]$v
            if ($validRiskLevels -contains $sv -and $signInRiskValues -notcontains $sv) { $signInRiskValues.Add($sv) }
        }
        foreach ($v in @($conditions.userRiskLevels)) {
            $sv = [string]$v
            if ($validRiskLevels -contains $sv -and $userRiskValues -notcontains $sv) { $userRiskValues.Add($sv) }
        }
    }

    $locationDimension = @(
        [ordered]@{ LocationId = @('All'); IsTrustedLocation = $false }
        [ordered]@{ LocationId = @('AllTrusted'); IsTrustedLocation = $true }
    )

    $totalCount = @($RoleEntities).Count * $platformValues.Count * $clientAppTypeValues.Count * $locationDimension.Count * $signInRiskValues.Count * $userRiskValues.Count
    if ($totalCount -gt $MaxScenarios) {
        throw "Get-EntraPostureConditionalAccessCombinatorialScenario: computed scenario count ($totalCount) exceeds -MaxScenarios ($MaxScenarios). This is a real, honestly-reported bound, not a silent truncation (engineering plan section 9.4, 'never hide sampling')."
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($roleEntity in $RoleEntities) {
        foreach ($platform in $platformValues) {
            foreach ($clientAppType in $clientAppTypeValues) {
                foreach ($location in $locationDimension) {
                    foreach ($signInRisk in $signInRiskValues) {
                        foreach ($userRisk in $userRiskValues) {
                            $scenario = New-EntraPostureConditionalAccessScenario -UserId "synthetic-$($roleEntity.entityId)" `
                                -UserRoleIds @($roleEntity.entityId) -ApplicationId 'All' -Platform $platform -ClientAppType $clientAppType `
                                -LocationId $location.LocationId -IsTrustedLocation $location.IsTrustedLocation `
                                -SignInRiskLevel $signInRisk -UserRiskLevel $userRisk
                            $results.Add([ordered]@{ RoleEntity = $roleEntity; Scenario = $scenario })
                        }
                    }
                }
            }
        }
    }

    return ,@($results.ToArray())
}
