#Requires -Version 7.4

function Get-EntraPostureAllCollectorRequirement {
    <#
        .SYNOPSIS
        Static, hardcoded list of every declared collector requirement (Phase 5's four plus
        Phase 6's fourteen). Not dynamically discovered -- ADR-004's no-runtime-discovery
        discipline applies here exactly as it does to the build manifest's SourceFiles list.

        .OUTPUTS
        Array of ordered dictionaries from New-EntraPostureCollectorRequirement.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param ()

    $requirements = @(
        Get-EntraPostureDirectoryRoleCollectorRequirement
        Get-EntraPostureAzureRoleAssignmentCollectorRequirement
        Get-EntraPostureConditionalAccessPolicyCollectorRequirement
        Get-EntraPostureCrossTenantAccessPolicyCollectorRequirement
        Get-EntraPostureUserCollectorRequirement
        Get-EntraPostureGroupCollectorRequirement
        Get-EntraPostureApplicationCollectorRequirement
        Get-EntraPostureServicePrincipalCollectorRequirement
        Get-EntraPostureAdministrativeUnitCollectorRequirement
        Get-EntraPosturePimEligibilityCollectorRequirement
        Get-EntraPostureCrossTenantAccessPolicyPartnerCollectorRequirement
        Get-EntraPostureTenantPolicyCollectorRequirement
        Get-EntraPostureAccessReviewDefinitionCollectorRequirement
        Get-EntraPostureAuthenticationContextCollectorRequirement
        Get-EntraPostureTenantConfigurationCollectorRequirement
        Get-EntraPostureNamedLocationCollectorRequirement
        Get-EntraPostureAuthenticationStrengthPolicyCollectorRequirement
        Get-EntraPostureRoleManagementPolicyAssignmentCollectorRequirement
        Get-EntraPostureAzureSubscriptionCollectorRequirement
        Get-EntraPostureAzureManagementGroupCollectorRequirement
        Get-EntraPostureAzureRoleDefinitionCollectorRequirement
        Get-EntraPostureAccessPackageCollectorRequirement
        Get-EntraPostureAgentIdentityBlueprintCollectorRequirement
        Get-EntraPostureAgentIdentityBlueprintPrincipalCollectorRequirement
        Get-EntraPostureAgentIdentityCollectorRequirement
        Get-EntraPostureAgentUserCollectorRequirement
        Get-EntraPosturePimForGroupsCollectorRequirement
        Get-EntraPostureGroupSettingsCollectorRequirement
        Get-EntraPostureUserSignInActivityCollectorRequirement
        Get-EntraPostureServicePrincipalApiPermissionsCollectorRequirement
        Get-EntraPostureUserRegistrationDetailsCollectorRequirement
        Get-EntraPostureRoleAssignmentScopeCollectorRequirement
    )
    return ,@($requirements)
}

function Invoke-EntraPostureCollectAndSeal {
    <#
        .SYNOPSIS
        The fixed collection pipeline (ADR-027): preflight -> collect to staging -> validate ->
        seal. Runs every declared collector, tolerating per-collector failure so one domain's
        unavailability never aborts the whole run (partial evidence, ADR-015).

        .DESCRIPTION
        Graph and Azure ARM collectors are preflighted separately (Test-EntraPosturePreflight
        takes one granted-permission set; this run has two, one per token audience) and their
        coverage.collectors arrays are merged afterward -- Phase 4's preflight function itself
        is unchanged, this split is an orchestration-layer decision.

        Azure RBAC scope handling (Phase 6): when an ARM token is supplied, subscription and
        management-group *discovery* always runs first (if permitted); role-assignment and
        role-definition collection then runs once per discovered scope, unioned with an
        explicitly-supplied -ArmScope if one was also given (useful for targeting a scope
        discovery cannot see, or for tests that skip mocking discovery entirely). A multi-scope
        collector's coverage is marked verified as soon as at least one scope succeeds --
        partial per-scope failure is logged into the partial reason narrative, not treated as a
        reason to call the whole domain undelivered.

        A collector is only actually invoked if its declared required permissions are present
        in the relevant token's granted set; if invoked, a thrown exception is caught and
        logged rather than propagated, and that collector's coverage stays whatever
        Test-EntraPosturePreflight already computed from permissions alone (accessVerified
        remains false, evidenceStatus 'Unavailable') -- a real API failure despite adequate
        permissions is not silently promoted to 'Collected'. The snapshot is sealed as 'Partial'
        (ADR-015) whenever any collector's final evidenceStatus is not 'Collected'.

        .PARAMETER RunRoot
        .PARAMETER SnapshotId
        .PARAMETER TenantScope
        .PARAMETER AuthMode
        .PARAMETER GraphAccessToken
        .PARAMETER GraphGrantedPermissions
        From Get-EntraPostureTokenGrantedPermission's .Permissions field for the Graph token.

        .PARAMETER ArmAccessToken
        Optional -- if omitted, every Azure RBAC collector (including subscription/
        management-group discovery) is never attempted and their coverage is computed from an
        empty granted-permission set (Denied), a real, deliberately-exercised partial-evidence
        path, not a test-only shortcut.

        .PARAMETER ArmGrantedPermissions
        .PARAMETER ArmScope
        Optional explicit ARM scope, unioned with whatever subscription/management-group
        discovery finds. Not required even when -ArmAccessToken is supplied -- discovery alone
        can supply every scope.

        .PARAMETER SigningCertificate
        Optional detached-signing certificate, passed through to Protect-EntraPostureSnapshot.

        .PARAMETER GraphCollectorConcurrency
        Maximum concurrent Graph collectors (engineering plan section 12: "bounded collection
        concurrency, default four"), passed to Invoke-EntraPostureBoundedParallel. ARM
        role-assignment/role-definition collection (already inherently sequential, one call per
        discovered scope, see this function's own Azure RBAC scope-handling paragraph above) is
        unaffected by this parameter -- only the independent Graph collectors run concurrently.

        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER GraphRequestHostOverride
        .PARAMETER ArmRequestHostOverride
        Test-only, passed through to every collector. Production orchestration callers must
        never pass any of these -- see Send-EntraPostureRequest's own parameter docs for why
        they exist.

        .PARAMETER KnownAbusedAppListPath
        Optional local file path to a vendored rogueapps.toml-shaped file (ENT-013's own
        reference data -- see Update-EntraPostureKnownAbusedAppList). This function itself
        applies NO default resolution -- $null/omitted here means "nothing to check," not "look
        in the usual place"; only New-EntraPostureSnapshot resolves a caller-omitted value via
        Get-EntraPostureKnownAbusedAppListPath before calling down to this function, so a direct
        caller of this lower-level function (every test in this project included) gets
        deterministic, no-network, no-file-I/O-for-this-domain behavior unless it explicitly
        opts in. When the effective path (given or previously resolved) doesn't point at an
        existing, parseable file, this domain contributes NOTHING to coverage.collectors at
        all -- not even 'Unavailable' -- specifically so an assessment run that never configured
        this entirely optional domain is never marked Partial because of it (ADR-015's partial-
        evidence handling exists for real permission/API gaps in evidence a user is expected to
        have configured; "never opted into an optional reference dataset" is not that). A file
        that DOES exist but fails to parse is different -- that's a real, actionable problem
        (evidenceStatus 'Malformed'), and does contribute to Partial like any other collection
        failure. ENT-013 itself is gated on CollectServicePrincipals.ps1's own AffectedControlIds
        alone (not this domain's) specifically so it's never NotEvaluated just because this
        optional domain was never configured -- see ENT-013.psd1's own applicability field and
        EvaluateKnownAbusedApp.ps1's own DESCRIPTION for the full reasoning. A 'Malformed'
        coverage record here DOES also name ENT-013 in its own affectedControlIds, so a
        configured-but-broken list still correctly drives ENT-013 to NotEvaluated too.

        .OUTPUTS
        Ordered dictionary: SnapshotPath (sealed bundle root), Manifest, Coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$RunRoot,

        [Parameter(Mandatory)]
        [string]$SnapshotId,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [ValidateSet('DelegatedInteractive', 'CertificateAppOnly')]
        [string]$AuthMode,

        [Parameter(Mandatory)]
        [string]$GraphAccessToken,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$GraphGrantedPermissions,

        [Parameter()]
        [string]$ArmAccessToken,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$ArmGrantedPermissions = @(),

        [Parameter()]
        [string]$ArmScope,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$GraphCollectorConcurrency = 4,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$GraphRequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [string]$ArmRequestHostOverride = 'management.azure.com',

        [Parameter()]
        [AllowNull()]
        [string]$KnownAbusedAppListPath
    )

    $collectionStartUtc = (Get-Date).ToUniversalTime().ToString('o')

    $allRequirements = Get-EntraPostureAllCollectorRequirement
    $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
    $graphRequirements = @($allRequirements | Where-Object { $_.CollectorName -notin $armCollectorNames })
    $armRequirements = @($allRequirements | Where-Object { $_.CollectorName -in $armCollectorNames })

    $verificationResults = @{}
    $entities = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()
    $collectionErrors = [System.Collections.Generic.List[string]]::new()

    $graphPreflight = Test-EntraPosturePreflight -CollectorRequirements $graphRequirements -GrantedPermissions $GraphGrantedPermissions

    $sendCommonParams = @{}
    if ($AllowlistOverride) { $sendCommonParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendCommonParams['SchemeOverride'] = $SchemeOverride }

    # Bounded collection concurrency (engineering plan section 12, "default four", VNext build
    # order item 6): every collectable Graph collector's parameter set is built up front, then
    # Invoke-EntraPostureBoundedParallel runs them concurrently (throttled to
    # $GraphCollectorConcurrency) and returns results back in this same, original order --
    # merging into $entities/$relationships/$collectionErrors/$verificationResults below is a
    # single-threaded, sequential loop over that ordered result array, so it needs no thread-safe
    # collections and produces byte-identical output regardless of which collector's HTTP call
    # actually finished first (section 12's own "deterministic... independently of collection
    # concurrency" requirement).
    $collectableGraphCollectors = @($graphPreflight.collectors | Where-Object { $_.evidenceStatus -in @('Unavailable', 'Collected') })
    $graphParameterSets = @(foreach ($collector in $collectableGraphCollectors) {
        $parameterSet = @{
            CollectorName       = $collector.collectorName
            AccessToken         = $GraphAccessToken
            TenantScope         = $TenantScope
            RequestHostOverride = $GraphRequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $graphDispatchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureGraphCollectorDispatch' `
        -ParameterSets $graphParameterSets -ThrottleLimit $GraphCollectorConcurrency

    for ($i = 0; $i -lt $collectableGraphCollectors.Count; $i++) {
        $collectorName = $collectableGraphCollectors[$i].collectorName
        $dispatchResult = $graphDispatchResults[$i]

        if (-not $dispatchResult.Success) {
            $collectionErrors.Add("Collector '$collectorName' failed: $($dispatchResult.ErrorMessage)")
            continue
        }

        $result = $dispatchResult.Result
        if ($null -ne $result) {
            foreach ($e in @($result.Entities)) { $entities.Add($e) }
            if ($result.Contains('Relationships')) {
                foreach ($r in @($result.Relationships)) { $relationships.Add($r) }
            }
            $verificationResults[$collectorName] = $true
        }
    }

    if ($ArmAccessToken) {
        $armPreflight = Test-EntraPosturePreflight -CollectorRequirements $armRequirements -GrantedPermissions $ArmGrantedPermissions
    } else {
        $armPreflight = Test-EntraPosturePreflight -CollectorRequirements $armRequirements -GrantedPermissions @()
    }

    if ($ArmAccessToken) {
        $collectableArmNames = @($armPreflight.collectors | Where-Object { $_.evidenceStatus -in @('Unavailable', 'Collected') } | ForEach-Object { $_.collectorName })

        $discoveredScopes = [System.Collections.Generic.List[string]]::new()

        if ('AzureSubscriptions' -in $collectableArmNames) {
            try {
                $result = Invoke-EntraPostureAzureSubscriptionCollector -AccessToken $ArmAccessToken -TenantScope $TenantScope -RequestHostOverride $ArmRequestHostOverride @sendCommonParams
                foreach ($e in @($result.Entities)) { $entities.Add($e); $discoveredScopes.Add($e.entityId) }
                $verificationResults['AzureSubscriptions'] = $true
            } catch {
                $collectionErrors.Add("Collector 'AzureSubscriptions' failed: $($_.Exception.Message)")
            }
        }

        if ('AzureManagementGroups' -in $collectableArmNames) {
            try {
                $result = Invoke-EntraPostureAzureManagementGroupCollector -AccessToken $ArmAccessToken -TenantScope $TenantScope -RequestHostOverride $ArmRequestHostOverride @sendCommonParams
                foreach ($e in @($result.Entities)) { $entities.Add($e); $discoveredScopes.Add($e.entityId) }
                $verificationResults['AzureManagementGroups'] = $true
            } catch {
                $collectionErrors.Add("Collector 'AzureManagementGroups' failed: $($_.Exception.Message)")
            }
        }

        if ($ArmScope -and $ArmScope -notin $discoveredScopes) {
            $discoveredScopes.Add($ArmScope)
        }
        $scopesToQuery = @($discoveredScopes | Select-Object -Unique)

        if ('AzureRoleAssignments' -in $collectableArmNames) {
            $anySucceeded = $false
            # ARM's List role assignments API (called without '$filter=atScope()', see
            # NormalizeAzureRoleAssignment.ps1) returns every assignment that applies AT the
            # queried scope, including ones actually defined at an ancestor scope and inherited
            # down. $scopesToQuery is deduplicated by exact scope-string match only (a
            # subscription's scope string is never equal to an ancestor management group's), so a
            # subscription discovered both directly and as a descendant of a discovered
            # management group still gets queried at both -- and the management-group-defined
            # assignment comes back twice: once as a direct record from the management-group
            # query, once as an inherited copy from the subscription query. The assignment's own
            # entityId (its ARM resource ID) reflects where it's actually defined, so it's
            # identical both times -- deduplicating on entityId here collapses those copies
            # without needing to know the actual management-group/subscription hierarchy (which
            # this project doesn't collect). Prefer the direct occurrence over an inherited one so
            # inheritedAtQueriedScope on the kept record is accurate; break remaining ties by the
            # ordinal-smallest queriedScope so the result doesn't depend on scope-enumeration order.
            $roleAssignmentsByEntityId = [ordered]@{}
            foreach ($scope in $scopesToQuery) {
                try {
                    $result = Invoke-EntraPostureAzureRoleAssignmentCollector -AccessToken $ArmAccessToken -Scope $scope -TenantScope $TenantScope -RequestHostOverride $ArmRequestHostOverride @sendCommonParams
                    foreach ($e in @($result.Entities)) {
                        if (-not $roleAssignmentsByEntityId.Contains($e.entityId)) {
                            $roleAssignmentsByEntityId[$e.entityId] = $e
                            continue
                        }
                        $existing = $roleAssignmentsByEntityId[$e.entityId]
                        $existingIsDirect = -not [bool]$existing.properties.inheritedAtQueriedScope
                        $candidateIsDirect = -not [bool]$e.properties.inheritedAtQueriedScope
                        $preferCandidate = if ($candidateIsDirect -and -not $existingIsDirect) {
                            $true
                        } elseif ($candidateIsDirect -eq $existingIsDirect) {
                            [string]::Compare([string]$e.properties.queriedScope, [string]$existing.properties.queriedScope, [StringComparison]::Ordinal) -lt 0
                        } else {
                            $false
                        }
                        if ($preferCandidate) { $roleAssignmentsByEntityId[$e.entityId] = $e }
                    }
                    $anySucceeded = $true
                } catch {
                    $collectionErrors.Add("Collector 'AzureRoleAssignments' failed at scope '$scope': $($_.Exception.Message)")
                }
            }
            foreach ($e in $roleAssignmentsByEntityId.Values) { $entities.Add($e) }
            if ($anySucceeded) { $verificationResults['AzureRoleAssignments'] = $true }
        }

        if ('AzureRoleDefinitions' -in $collectableArmNames) {
            $anySucceeded = $false
            foreach ($scope in $scopesToQuery) {
                try {
                    $result = Invoke-EntraPostureAzureRoleDefinitionCollector -AccessToken $ArmAccessToken -Scope $scope -TenantScope $TenantScope -RequestHostOverride $ArmRequestHostOverride @sendCommonParams
                    foreach ($e in @($result.Entities)) { $entities.Add($e) }
                    $anySucceeded = $true
                } catch {
                    $collectionErrors.Add("Collector 'AzureRoleDefinitions' failed at scope '$scope': $($_.Exception.Message)")
                }
            }
            if ($anySucceeded) { $verificationResults['AzureRoleDefinitions'] = $true }
        }
    }

    # Known-abused-app list (ENT-013's own reference data, VNext §46): a local file read, not a
    # Graph/ARM call -- deliberately NOT run through Test-EntraPosturePreflight/
    # GraphCollectorDispatch.ps1 (both assume a token-authenticated network call; there's no
    # permission concept here at all). Emits AT MOST one coverage record, and only when there's
    # something real to report -- see this function's own .PARAMETER KnownAbusedAppListPath for
    # why "no file present" contributes nothing to coverage.collectors (never 'Unavailable')
    # while "file present but unparseable" does (a real, actionable 'Malformed').
    $knownAbusedAppCoverage = $null
    if (-not [string]::IsNullOrWhiteSpace($KnownAbusedAppListPath) -and (Test-Path -LiteralPath $KnownAbusedAppListPath -PathType Leaf)) {
        $collectedAtLocal = (Get-Date).ToUniversalTime().ToString('o')
        $collectorVersionLocal = (Get-EntraPostureToolVersionInfo).ToolVersion
        try {
            $rawToml = Get-Content -LiteralPath $KnownAbusedAppListPath -Raw
            $parsedApps = ConvertFrom-EntraPostureRogueAppsToml -RawToml $rawToml

            $metaPath = [System.IO.Path]::ChangeExtension($KnownAbusedAppListPath, '.meta.json')
            $commitDateUtc = $null
            $fetchedAtUtc = $null
            if (Test-Path -LiteralPath $metaPath -PathType Leaf) {
                try {
                    $sidecarMeta = ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $metaPath -Raw)
                    $commitDateUtc = $sidecarMeta.commitDateUtc
                    $fetchedAtUtc = $sidecarMeta.fetchedAtUtc
                } catch {
                    Write-Warning "Invoke-EntraPostureCollectAndSeal: sidecar '$metaPath' could not be read as JSON ($($_.Exception.Message)) -- freshness metadata will be unknown in ENT-013's own findings."
                }
            }

            foreach ($app in $parsedApps) {
                $entities.Add((ConvertTo-EntraPostureKnownAbusedAppEntity -App $app -TenantScope $TenantScope -CollectorVersion $collectorVersionLocal -SourceEndpoint $KnownAbusedAppListPath -CollectedAt $collectedAtLocal))
            }
            $entities.Add((ConvertTo-EntraPostureKnownAbusedAppListMetadataEntity -FilePath $KnownAbusedAppListPath -CommitDateUtc $commitDateUtc -FetchedAtUtc $fetchedAtUtc -AppCount $parsedApps.Count -TenantScope $TenantScope -CollectorVersion $collectorVersionLocal -SourceEndpoint $KnownAbusedAppListPath -CollectedAt $collectedAtLocal))

            $knownAbusedAppCoverage = [ordered]@{
                collectorName          = 'KnownAbusedAppList'
                accessRequested        = @()
                rightsPresentInToken   = @()
                rightsExpected         = @()
                accessVerified         = $true
                evidenceStatus         = 'Collected'
                affectedControlIds     = @('ENT-013')
                affectedReportSections = @('Applications')
            }
        } catch {
            Write-Warning "Invoke-EntraPostureCollectAndSeal: '$KnownAbusedAppListPath' exists but could not be parsed as a rogueapps.toml-shaped file ($($_.Exception.Message)) -- ENT-013 will be NotEvaluated for this snapshot."
            $collectionErrors.Add("Collector 'KnownAbusedAppList' failed: $($_.Exception.Message)")
            $knownAbusedAppCoverage = [ordered]@{
                collectorName          = 'KnownAbusedAppList'
                accessRequested        = @()
                rightsPresentInToken   = @()
                rightsExpected         = @()
                accessVerified         = $false
                evidenceStatus         = 'Malformed'
                affectedControlIds     = @('ENT-013')
                affectedReportSections = @('Applications')
            }
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($KnownAbusedAppListPath)) {
        Write-Warning "Invoke-EntraPostureCollectAndSeal: '$KnownAbusedAppListPath' does not exist -- ENT-013 will be NotEvaluated for this snapshot (not counted as Partial; this is an optional reference-data domain, not a required evidence gap)."
    }

    # Recompute both preflight passes now that EndpointVerificationResults reflects what
    # actually happened, not just what looked possible from token claims alone.
    $graphCoverage = Test-EntraPosturePreflight -CollectorRequirements $graphRequirements -GrantedPermissions $GraphGrantedPermissions -EndpointVerificationResults $verificationResults
    # @() around the whole if/else, not just the else branch's own @() -- assigning an if/else
    # expression whose taken branch emits zero objects collapses to $null, not an empty array
    # (the same class of bug documented at length in src/Snapshots/SealSnapshot.ps1 for the
    # one-element case; this is the zero-element manifestation of the identical mechanism).
    $armGrantedForCoverage = @(if ($ArmAccessToken) { $ArmGrantedPermissions } else { @() })
    $armCoverage = Test-EntraPosturePreflight -CollectorRequirements $armRequirements -GrantedPermissions $armGrantedForCoverage -EndpointVerificationResults $verificationResults

    $knownAbusedAppCoverageArray = @(if ($knownAbusedAppCoverage) { $knownAbusedAppCoverage })
    $mergedCoverage = [ordered]@{
        collectors = @(@($graphCoverage.collectors) + @($armCoverage.collectors) + $knownAbusedAppCoverageArray)
    }

    $isPartial = @($mergedCoverage.collectors | Where-Object { $_.evidenceStatus -ne 'Collected' }).Count -gt 0
    $partialReason = $null
    if ($isPartial) {
        $incompleteNames = @($mergedCoverage.collectors | Where-Object { $_.evidenceStatus -ne 'Collected' } | ForEach-Object { "$($_.collectorName) ($($_.evidenceStatus))" })
        $partialReason = "Incomplete evidence: $($incompleteNames -join '; ')" + $(if ($collectionErrors.Count -gt 0) { "; collection errors: $($collectionErrors -join '; ')" } else { '' })
    }

    $collectionEndUtc = (Get-Date).ToUniversalTime().ToString('o')

    $stagingPath = New-EntraPostureStagingDirectory -RunRoot $RunRoot -SnapshotId $SnapshotId

    $evidenceSchemaMap = @{}
    $registry = Get-EntraPostureEvidenceFileRegistry
    foreach ($registryEntry in $registry) {
        # @() around the whole if/else, not just each branch's own inner @() -- an inner @()
        # does not survive the outer if/else-as-expression assignment boundary when the taken
        # branch yields 0 or 1 elements (see src/Snapshots/SealSnapshot.ps1's original writeup
        # of this bug class). Without this outer wrap, $recordsForType.Count below could
        # silently evaluate against a collapsed scalar's key count or a $null, not the real
        # record count.
        $recordsForType = @(if ($registryEntry.RecordKind -eq 'Entity') {
            @($entities | Where-Object { $_.entityType -eq $registryEntry.TypeName })
        } else {
            @($relationships | Where-Object { $_.relationshipType -eq $registryEntry.TypeName })
        })

        if ($recordsForType.Count -eq 0) { continue }

        $fullPath = Join-Path $stagingPath $registryEntry.RelativePath
        $lines = @(foreach ($record in $recordsForType) { ConvertTo-EntraPostureCanonicalJson -InputObject $record })
        [System.IO.File]::WriteAllText($fullPath, (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
        $evidenceSchemaMap[$registryEntry.RelativePath] = $registryEntry.ContractName
    }

    $versionInfo = Get-EntraPostureToolVersionInfo
    $manifestMetadata = [ordered]@{
        toolVersion            = $versionInfo.ToolVersion
        schemaVersion          = $versionInfo.SchemaVersion
        controlRegistryVersion = $versionInfo.ControlRegistryVersion
        powerShellVersion      = $PSVersionTable.PSVersion.ToString()
        tenantScope            = $TenantScope
        cloud                  = 'Public'
        authMode               = $AuthMode
        collectionStartUtc     = $collectionStartUtc
        collectionEndUtc       = $collectionEndUtc
    }

    $sealParams = @{
        StagingPath       = $stagingPath
        EvidenceSchemaMap = $evidenceSchemaMap
        ManifestMetadata  = $manifestMetadata
        SnapshotId        = $SnapshotId
        IsPartial         = $isPartial
        Coverage          = $mergedCoverage
    }
    if ($isPartial) { $sealParams['PartialReason'] = $partialReason }
    if ($SigningCertificate) { $sealParams['SigningCertificate'] = $SigningCertificate }

    $manifest = Protect-EntraPostureSnapshot @sealParams

    return [ordered]@{
        SnapshotPath = $stagingPath
        Manifest     = $manifest
        Coverage     = $mergedCoverage
    }
}
