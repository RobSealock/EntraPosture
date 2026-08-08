#Requires -Version 7.4

function Get-EntraPostureEndpointAllowlist {
    <#
        .SYNOPSIS
        Returns the versioned registry of every host/path-template/API-version/method
        combination this tool is permitted to call.

        .DESCRIPTION
        Engineering plan section 7.3: "The transport layer maintains versioned allowlists for
        host, path template, API version, and method. GET is not globally permitted; it must
        target a declared endpoint. POST is denied unless the endpoint is explicitly classified
        as a read-only query/evaluation operation." This is that registry -- a static array
        literal (not a runtime-loaded data file) so it participates in the same
        no-dynamic-loading discipline (ADR-004) as every other part of this module, and so a
        change to it is a visible code diff, not a config-file edit that could bypass review.

        This is a Phase 4 *initial* allowlist covering the evidence domains already established
        through Phase 0-3 (00-permission-report-matrix.md, the designed controls in
        15-feature-parity-matrix.md sections 6-10), not a claim of completeness -- Phase 6's
        collector-breadth work will add entries here as each collector is actually built, and
        the same "unexpected/undeclared" failure discipline used for build-time source files
        applies here at request time (Test-EntraPostureEndpointAllowed denies anything not
        listed, it does not warn-and-allow).

        PathTemplate uses '{name}' segments to match a single non-slash path component (e.g.
        '/v1.0/groups/{groupId}' matches '/v1.0/groups/abc-123' but not
        '/v1.0/groups/abc-123/owners' -- that longer path needs its own explicit entry).

        .OUTPUTS
        Array of ordered dictionaries: Host, PathTemplate, ApiStability ('Stable'/'Preview'),
        Method, ReadOnlyClassification (only meaningful for POST; null for GET), Description.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param ()

    return @(
        # --- Microsoft Graph v1.0: Entra identity/directory objects ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/users';                          ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List users' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/users/{userId}';                 ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get a user' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/users/{userId}/memberOf';        ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a user''s group/role memberships' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/groups';                         ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List groups' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/groups/{groupId}';               ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get a group' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/groups/{groupId}/transitiveMembers'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a group''s transitive members (Phase 1 finding: paginate this one, EntraFalcon/CAV precedent both use it)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/groups/{groupId}/owners';        ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a group''s owners' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/applications';                   ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List app registrations' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/applications/{appId}';           ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get an app registration' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals';               ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List service principals (enterprise apps, managed identities)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/{spId}';       ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get a service principal' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/{spId}/appRoleAssignedTo'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List app role assignments for a service principal' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/{spId}/owners';  ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a service principal''s owners (ENT-003)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/{spId}/ownedObjects'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List objects owned by a service principal (ENT-008, foreign service principals only)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/directoryRoles';                 ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List active directory roles' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/directoryRoles/{roleId}/members'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a directory role''s active members' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/directory/administrativeUnits';  ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List administrative units' }

        # --- Microsoft Graph v1.0: Conditional Access and related policies ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identity/conditionalAccess/policies'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List Conditional Access policies' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identity/conditionalAccess/authenticationContextClassReferences'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List authentication context class references (AUTHCTX-001/002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identity/conditionalAccess/namedLocations'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List named locations (VNext build order item 4 -- CA simulation location resolution)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/authenticationStrengthPolicies'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List authentication strength policies (VNext build order item 5 -- CA simulation authenticationStrength resolution)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/roleManagementPolicyAssignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List directory role PIM activation-policy assignments (VNext build order item 7 -- AUTHCTX-001/002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/crossTenantAccessPolicy'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get the default cross-tenant access policy (XTA-001)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/crossTenantAccessPolicy/partners'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List cross-tenant access partner overrides (XTA-002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/authorizationPolicy';   ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get the authorization/consent policy (AC-001)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/adminConsentRequestPolicy'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get the admin consent workflow policy (AC-002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List access review definitions (AR-001/002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List a definition''s review instances (VNext build order item 9 -- AR-002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances/{instanceId}/decisions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List an instance''s decisions, aggregated to counts only at normalization time -- never persisted raw (VNext build order item 9 -- AR-002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List access packages (VNext build order item 11 -- EM-001/002, admitted per 00-open-questions.md item 28)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages/{accessPackageId}'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get one access package with resourceRoleScopes/assignmentPolicies expanded (VNext build order item 11 -- EM-001/002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/assignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List access package assignments tenant-wide, target never expanded -- redaction by omission (VNext build order item 11 -- EM-002)' }

        # --- Microsoft Graph v1.0: tenant/organization configuration (Phase 6) ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/organization';               ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get tenant/organization basic configuration' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get Security Defaults enforcement status (MS-ENTRA-001 gap)' }

        # --- Microsoft Graph v1.0: PIM ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List eligible Entra role assignments (PIM)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List active Entra role assignments (PIM)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/beta/roleManagement/directory/roleDefinitions'; ApiStability = 'Preview'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'Get Entra role definitions with settings (Phase 1 finding: EntraFalcon check_PIM.psm1 confirmed uses -BetaAPI here -- requires an explicit approved-deviation record per ADR-020 before Phase 6 collectors may rely on it, not carried over as already-approved)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List PIM-for-Groups eligibility schedule instances, filtered by groupId (VNext build order item 13 -- PIMG-001/002)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List PIM-for-Groups active assignment schedule instances, filtered by groupId (VNext build order item 13 -- PIMG-001/002)' }

        # --- Microsoft Graph v1.0: Agent identities (VNext build order item 13) ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/applications/microsoft.graph.agentIdentityBlueprint'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List agent identity blueprints (AGT-001/017)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/applications/{applicationId}/owners'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List an application''s (including an agent identity blueprint''s) owners (AGT-017)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List agent identity blueprint principals, carries appOwnerOrganizationId for foreign-agent derivation' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/servicePrincipals/microsoft.graph.agentIdentity'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List agent identities (AGT-004/005/008/009)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/users/microsoft.graph.agentUser'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List agent users (AGT-011/012/015)' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/users/{userId}/ownedObjects'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List an agent user''s owned directory objects, filtered to groups at normalization time (AGT-015; delegated-only, no application-permission path per Microsoft''s own reference page)' }

        # --- Microsoft Graph v1.0: read-only evaluation operations (POST, explicitly classified) ---
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/identity/conditionalAccess/evaluate'; ApiStability = 'Stable'; Method = 'POST'; ReadOnlyClassification = 'WhatIfEvaluation'; Description = 'Conditional Access What If evaluation (section 9.4) -- least-privileged permission documented as Policy.Read.ConditionalAccess' }
        [ordered]@{ Host = 'graph.microsoft.com'; PathTemplate = '/v1.0/$batch';                          ApiStability = 'Stable'; Method = 'POST'; ReadOnlyClassification = 'GraphBatch'; Description = 'Graph batching -- every sub-request inside the batch must itself independently satisfy this same allowlist (enforced by the transport layer, not by this registry entry alone)' }

        # --- Azure Resource Manager: RBAC and subscription discovery ---
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/subscriptions';                      ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List accessible Azure subscriptions' }
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/providers/Microsoft.Management/managementGroups'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List accessible management groups' }
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/{scope}/providers/Microsoft.Authorization/roleAssignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List Azure RBAC role assignments at a scope' }
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/{scope}/providers/Microsoft.Authorization/roleDefinitions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List Azure RBAC role definitions at a scope' }
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/{scope}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'List active Azure PIM role assignments at a scope (Phase 1 finding: EntraFalcon collects this but never scores it -- MS-AZURE-003 gap)' }
        [ordered]@{ Host = 'management.azure.com'; PathTemplate = '/providers/Microsoft.ResourceGraph/resources'; ApiStability = 'Stable'; Method = 'POST'; ReadOnlyClassification = 'AzureResourceGraphQuery'; Description = 'Azure Resource Graph query -- read-only KQL query execution, never a write operation' }
    )
}

function ConvertTo-EntraPosturePathTemplateRegex {
    <#
        .SYNOPSIS
        Converts a '{param}'-style path template into an anchored regex.

        .DESCRIPTION
        Every placeholder except the literal name '{scope}' matches exactly one non-slash path
        segment (Graph's object-ID placeholders, e.g. '{groupId}', are always a single GUID
        segment). '{scope}' is a deliberate special case for Azure Resource Manager paths, where
        a "scope" is itself a genuinely variable-depth resource path (e.g.
        '/subscriptions/{id}', '/subscriptions/{id}/resourceGroups/{rg}', or a management-group
        path) -- confirmed as a real distinction, not an edge case, when a single-segment
        matcher was tested against a real ARM-shaped path and failed. '{scope}' therefore
        matches one or more characters including slashes.

        .PARAMETER PathTemplate
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$PathTemplate
    )

    $escaped = [regex]::Escape($PathTemplate)
    # [regex]::Escape only escapes the OPENING brace ('{' -> '\{'); the closing '}' is left
    # unescaped (confirmed empirically: [regex]::Escape('/x/{id}') -> '/x/\{id}', not
    # '/x/\{id\}') -- .NET's escaper treats a bare '}' as never needing escaping on its own,
    # since it only has special meaning as the close of a '{n,m}' quantifier. The replacements
    # below match that asymmetry exactly rather than assuming both braces are escaped.
    $pattern = $escaped -replace '\\\{scope\}', '.+'
    $pattern = $pattern -replace '\\\{[^}]+\}', '[^/]+'
    return "^$pattern`$"
}

function Test-EntraPostureEndpointAllowed {
    <#
        .SYNOPSIS
        Checks a request (host, path, method) against the endpoint allowlist and returns
        whether it is permitted, plus which registry entry matched -- the concrete mechanism
        behind "every request is traceable to an allowlist entry" (Phase 4 exit criterion).

        .DESCRIPTION
        GET is denied by default unless a matching entry exists (never globally permitted, per
        section 7.3). POST is denied unless a matching entry exists AND that entry carries a
        non-null ReadOnlyClassification -- an entry that is present but only for GET does not
        implicitly authorize POST to the same path.

        .PARAMETER Host
        .PARAMETER Path
        .PARAMETER Method
        .PARAMETER ApiStability
        Caller-supplied classification of the actual endpoint version being called (Stable for
        /v1.0/, Preview for /beta/, etc.) -- checked against the matched entry's own declared
        ApiStability so a Stable-only registry entry cannot be silently satisfied by calling the
        beta version of the same logical endpoint.

        .PARAMETER Allowlist
        Overrides the real registry. Production code must never pass this -- it exists solely so
        tests can exercise Send-EntraPostureRequest's pagination/retry/loop-detection
        mechanics against a local mock listener (which cannot be added to the real,
        production-only allowlist) without weakening the default, always-real-allowlist code
        path that every actual collector uses.

        .OUTPUTS
        Ordered dictionary: IsAllowed (bool), MatchedEntry (the allowlist entry, or $null),
        Reason (string, populated when IsAllowed is $false).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$RequestHost,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateSet('Stable', 'Preview')]
        [string]$ApiStability,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$Allowlist
    )

    if (-not $Allowlist) {
        $Allowlist = Get-EntraPostureEndpointAllowlist
    }

    foreach ($entry in $allowlist) {
        if ($entry.Host -ne $RequestHost) { continue }
        if ($entry.Method -ne $Method) { continue }
        if ($entry.ApiStability -ne $ApiStability) { continue }

        $pattern = ConvertTo-EntraPosturePathTemplateRegex -PathTemplate $entry.PathTemplate
        if ($Path -notmatch $pattern) { continue }

        if ($Method -eq 'POST' -and [string]::IsNullOrWhiteSpace($entry.ReadOnlyClassification)) {
            return [ordered]@{
                IsAllowed    = $false
                MatchedEntry = $null
                Reason       = "POST to '$Path' matched a registry entry with no ReadOnlyClassification -- POST requires an explicit read-only classification (section 7.3), not just a matching path."
            }
        }

        return [ordered]@{
            IsAllowed    = $true
            MatchedEntry = $entry
            Reason       = $null
        }
    }

    return [ordered]@{
        IsAllowed    = $false
        MatchedEntry = $null
        Reason       = "No allowlist entry matches Host='$RequestHost' Method='$Method' ApiStability='$ApiStability' Path='$Path'."
    }
}
