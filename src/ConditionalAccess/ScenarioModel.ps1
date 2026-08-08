#Requires -Version 7.4

function New-EntraPostureConditionalAccessScenario {
    <#
        .SYNOPSIS
        Builds a synthetic sign-in scenario -- the simulation engine's input contract, mirroring
        (a bounded subset of) Microsoft Graph's own What-If evaluate request shape
        (signInIdentity/signInContext/signInConditions) so the same scenario can drive both the
        offline simulation engine and, unchanged, a real live What-If comparison call.

        .DESCRIPTION
        Field scope matches exactly what 16-ca-evaluation-semantics.md documents the v1
        simulation engine as matching (§8 lists what is deliberately not modeled). Locations are
        supplied as location ID(s) -- literally, or the special 'All'/'AllTrusted' values a
        policy's own includeLocations/excludeLocations can contain -- not a raw IP/country
        directly; resolving a raw IP/country into the matching named-location ID(s) is
        Resolve-EntraPostureNamedLocationId's job (VNext build order item 4), called by the
        scenario's caller before this function, not by this function itself. Guests/external
        users are collapsed to a single IsGuest signal rather than Microsoft's six documented
        sub-categories, per the same documented boundary.

        .PARAMETER UserId
        .PARAMETER UserGroupIds
        Every group the user is a (transitive) member of -- the caller resolves transitivity
        (e.g. from TransitiveMemberOf evidence) before building the scenario; this function does
        no group-membership resolution itself.

        .PARAMETER UserRoleIds
        Directory role template IDs the user actively holds.

        .PARAMETER IsGuest
        .PARAMETER ApplicationId
        .PARAMETER ClientAppType
        .PARAMETER Platform

        .PARAMETER LocationId
        One or more location IDs the sign-in matches -- an array, not a single ID, because a real
        IP address can fall inside more than one overlapping ipNamedLocation range at once (VNext
        build order item 4); a policy matches if ANY of these IDs appears in its own
        includeLocations/excludeLocations. Still accepts a single bare string for a literal
        location ID or 'All' (PowerShell coerces it into a one-element array), so every caller
        from before this parameter became an array is unaffected.

        .PARAMETER IsTrustedLocation
        Whether the resolved location(s) include at least one marked isTrusted=true in
        NamedLocation evidence (from Resolve-EntraPostureNamedLocationId's IsTrustedMatch) --
        lets the match function resolve a policy's literal 'AllTrusted' sentinel against the
        scenario's real trust status instead of requiring the caller to already know to pass the
        literal string 'AllTrusted' as a location ID.

        .PARAMETER SignInRiskLevel
        .PARAMETER UserRiskLevel
        .PARAMETER IsCompliantDevice
        .PARAMETER IsHybridJoined

        .PARAMETER IsDeviceRegistered
        Whether the synthetic device is registered with Microsoft Entra ID at all -- VNext build
        order item 5 (device-filter rule-language evaluation). Governs
        Test-EntraPostureDeviceFilterCondition's own nullability model: an unregistered
        device's properties are all treated as null (see that function's own DESCRIPTION for the
        citation trail). Defaults to $false, the same "assume nothing about a synthetic
        principal beyond what's explicitly supplied" posture every other boolean here already
        takes.

        .PARAMETER IsIntuneManaged
        Whether the synthetic device is managed by Microsoft Intune -- one of the three signals
        (alongside IsCompliantDevice/IsHybridJoined) that gates whether extensionAttribute1-15
        are available to a device-filter rule at all, per Microsoft's own documented warning.

        .PARAMETER DeviceAttributes
        Ordered dictionary of the synthetic device's own property values (property name without
        the 'device.' prefix -> value; string for scalar properties, string[] for
        physicalIds/systemLabels) -- only consulted for a property Test-
        EntraPostureDeviceFilterCondition's own nullability model resolves as "available" for
        this scenario. Defaults to an empty ordered dictionary (every property unset).

        .OUTPUTS
        Ordered dictionary: the scenario contract every matching/evaluation function in this
        module consumes.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory record construction, no external side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter()]
        [string[]]$UserGroupIds = @(),

        [Parameter()]
        [string[]]$UserRoleIds = @(),

        [Parameter()]
        [bool]$IsGuest = $false,

        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter()]
        [ValidateSet('all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')]
        [string]$ClientAppType = 'browser',

        [Parameter()]
        [ValidateSet('android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'all', 'unknownFutureValue')]
        [string]$Platform = 'all',

        [Parameter()]
        [string[]]$LocationId = @('All'),

        [Parameter()]
        [bool]$IsTrustedLocation = $false,

        [Parameter()]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$SignInRiskLevel = 'none',

        [Parameter()]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$UserRiskLevel = 'none',

        [Parameter()]
        [bool]$IsCompliantDevice = $false,

        [Parameter()]
        [bool]$IsHybridJoined = $false,

        [Parameter()]
        [bool]$IsDeviceRegistered = $false,

        [Parameter()]
        [bool]$IsIntuneManaged = $false,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$DeviceAttributes = [ordered]@{}
    )

    return [ordered]@{
        ScenarioKind       = 'User'
        UserId             = $UserId
        UserGroupIds       = @($UserGroupIds)
        UserRoleIds        = @($UserRoleIds)
        IsGuest            = $IsGuest
        ApplicationId      = $ApplicationId
        ClientAppType      = $ClientAppType
        Platform           = $Platform
        LocationId         = @($LocationId)
        IsTrustedLocation  = $IsTrustedLocation
        SignInRiskLevel    = $SignInRiskLevel
        UserRiskLevel      = $UserRiskLevel
        IsCompliantDevice  = $IsCompliantDevice
        IsHybridJoined     = $IsHybridJoined
        IsDeviceRegistered = $IsDeviceRegistered
        IsIntuneManaged    = $IsIntuneManaged
        DeviceAttributes   = $DeviceAttributes
    }
}

function New-EntraPostureConditionalAccessWorkloadIdentityScenario {
    <#
        .SYNOPSIS
        Builds a synthetic service-principal (workload identity) sign-in scenario -- the
        simulation engine's second input contract, alongside the user sign-in scenario above
        (VNext build order item 3: "evidence is already captured; this is simulation-engine logic
        only").

        .DESCRIPTION
        Deliberately a separate, narrower function rather than adding parameters to
        New-EntraPostureConditionalAccessScenario: per Microsoft's own workload-identity
        Conditional Access documentation (learn.microsoft.com/entra/identity/conditional-access/
        workload-identity, re-fetched 2026-08-07), a policy authored to target workload identities
        is a distinct assignment mode ("Users or workload identities" -> "Workload identities" in
        the admin center) with a materially narrower condition surface than user sign-in policies:
        only client-application (service principal) targeting, resource scope (always 'All' --
        "the policy applies only when a service principal requests a token", no per-resource
        scoping in this Microsoft feature today), locations, and service principal risk are
        supported conditions. Platform, client app type, device compliance/hybrid-join, and
        user/sign-in risk are user/device signals that don't exist for a non-interactive service
        principal token request -- not modeled here because Microsoft's own policy authoring
        surface doesn't expose them for this scenario kind, not because of a v1 boundary.
        Similarly, "Block access" is documented as the only available grant control for this
        policy type in the admin center; this project's engine still aggregates whatever
        builtInControls a matched policy actually declares (no special-casing), since a real
        tenant's policy is the source of truth, not this scenario constructor.

        .PARAMETER ServicePrincipalId
        The target service principal's Object ID (not the app registration's Object ID -- see the
        Microsoft Learn page's own "Finding the objectID" section, which calls this distinction
        out explicitly as a common mistake).

        .PARAMETER LocationId
        Same array-of-ID / 'All'/'AllTrusted' semantics as the user scenario's LocationId -- see
        that parameter's own documentation (VNext build order item 4).

        .PARAMETER IsTrustedLocation
        Same semantics as the user scenario's IsTrustedLocation -- see that parameter's own
        documentation.

        .PARAMETER ServicePrincipalRiskLevel
        Requires Entra ID Workload Identities Premium in the real tenant being modeled; this
        project's evaluator does not verify licensing, matching the same posture already taken for
        signInRiskLevels/userRiskLevels (16-ca-evaluation-semantics.md section 9's named-in/out
        decision).

        .OUTPUTS
        Ordered dictionary: the scenario contract Invoke-EntraPostureConditionalAccessScenario
        dispatches on ScenarioKind to route to the matching workload-identity match function.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory record construction, no external side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId,

        [Parameter()]
        [string[]]$LocationId = @('All'),

        [Parameter()]
        [bool]$IsTrustedLocation = $false,

        [Parameter()]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$ServicePrincipalRiskLevel = 'none'
    )

    return [ordered]@{
        ScenarioKind              = 'WorkloadIdentity'
        ServicePrincipalId        = $ServicePrincipalId
        LocationId                = @($LocationId)
        IsTrustedLocation         = $IsTrustedLocation
        ServicePrincipalRiskLevel = $ServicePrincipalRiskLevel
    }
}
