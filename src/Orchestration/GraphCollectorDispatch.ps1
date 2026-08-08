#Requires -Version 7.4

function Invoke-EntraPostureGraphCollectorDispatch {
    <#
        .SYNOPSIS
        Invokes exactly one named Graph collector by CollectorName, returning $null for an
        unrecognized name. Extracted from Invoke-EntraPostureCollectAndSeal's own dispatch
        switch (VNext build order item 6, "bounded collection concurrency") specifically so it can
        be the -CommandName target of Invoke-EntraPostureBoundedParallel -- a bounded runspace
        pool invokes a named, already-loaded function per unit of work, not an inline switch
        statement, so this dispatch logic needed to exist as its own standalone function either
        way.

        .DESCRIPTION
        Every branch is a straight pass-through to that collector's own Invoke-* function -- this
        function adds no logic of its own beyond the name-to-function mapping and the shared
        -AllowlistOverride/-SchemeOverride passthrough every collector accepts identically. Side-
        effect-free with respect to anything outside its own parameters and return value (a
        requirement Invoke-EntraPostureBoundedParallel's own DESCRIPTION states explicitly for
        any -CommandName target), so it's safe to invoke concurrently, once per collector, across
        a bounded pool.

        .PARAMETER CollectorName
        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Whatever the matched collector's own Invoke-* function returns (an ordered dictionary with
        an Entities key, and a Relationships key for relationship-producing collectors), or $null
        for an unrecognized CollectorName.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$CollectorName,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$RequestHostOverride,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https'
    )

    $sendCommonParams = @{}
    if ($AllowlistOverride) { $sendCommonParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendCommonParams['SchemeOverride'] = $SchemeOverride }

    $result = switch ($CollectorName) {
        'DirectoryRoleAssignments' {
            Invoke-EntraPostureDirectoryRoleCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'ConditionalAccessPolicies' {
            Invoke-EntraPostureConditionalAccessPolicyCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'CrossTenantAccessPolicy' {
            Invoke-EntraPostureCrossTenantAccessPolicyCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'Users' {
            Invoke-EntraPostureUserCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'Groups' {
            Invoke-EntraPostureGroupCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'Applications' {
            Invoke-EntraPostureApplicationCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'ServicePrincipals' {
            Invoke-EntraPostureServicePrincipalCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AdministrativeUnits' {
            Invoke-EntraPostureAdministrativeUnitCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'PimEligibility' {
            Invoke-EntraPosturePimEligibilityCollector -AccessToken $AccessToken -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'CrossTenantAccessPolicyPartners' {
            Invoke-EntraPostureCrossTenantAccessPolicyPartnerCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'TenantPolicies' {
            Invoke-EntraPostureTenantPolicyCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AccessReviewDefinitions' {
            Invoke-EntraPostureAccessReviewDefinitionCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AuthenticationContexts' {
            Invoke-EntraPostureAuthenticationContextCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'TenantConfiguration' {
            Invoke-EntraPostureTenantConfigurationCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'NamedLocations' {
            Invoke-EntraPostureNamedLocationCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AuthenticationStrengthPolicies' {
            Invoke-EntraPostureAuthenticationStrengthPolicyCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'RoleManagementPolicyAssignments' {
            Invoke-EntraPostureRoleManagementPolicyAssignmentCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AccessPackages' {
            Invoke-EntraPostureAccessPackageCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AgentIdentityBlueprints' {
            Invoke-EntraPostureAgentIdentityBlueprintCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AgentIdentityBlueprintPrincipals' {
            Invoke-EntraPostureAgentIdentityBlueprintPrincipalCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AgentIdentities' {
            Invoke-EntraPostureAgentIdentityCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'AgentUsers' {
            Invoke-EntraPostureAgentUserCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'PimForGroups' {
            Invoke-EntraPosturePimForGroupsCollector -AccessToken $AccessToken -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        'GroupSettings' {
            Invoke-EntraPostureGroupSettingsCollector -AccessToken $AccessToken -TenantScope $TenantScope -RequestHostOverride $RequestHostOverride @sendCommonParams
        }
        default { $null }
    }
    return $result
}
