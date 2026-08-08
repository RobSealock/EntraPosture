#Requires -Version 7.4
#Requires -Modules Pester

<#
    Engineering plan section 14, gate 7: "Permission degradation: Global Reader and deliberately
    constrained identities; required rights and absent report sections must be unambiguous."
    Also Phase 6's own exit criterion: "requested/discovered/accessed/inaccessible Azure and
    Entra scope is explicit and reproducible."

    Two scenarios against a real local mock server: a realistic Global Reader-shaped token
    (confirmed by 00-permission-report-matrix.md to be insufficient for role-assignment-scoped
    Access Reviews specifically -- a real, documented v1 coverage gap, not a hypothetical one),
    and a zero-permission token (every collector denied). Both assert the coverage projection
    names the exact missing permission/collector/report-section rather than a vague "some
    evidence missing" -- "missing evidence never becomes a clean result" (section 7.2).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/ExitCode.ps1', 'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1',
        'src/Common/CanonicalJson.ps1', 'src/Common/ToolVersionInfo.ps1',
        'src/Logging/WriteLog.ps1',
        'src/Validation/StrictJson.ps1', 'src/Validation/TestSchema.ps1',
        'src/Integrity/FileHash.ps1', 'src/Integrity/AggregateHash.ps1', 'src/Integrity/DetachedSignature.ps1',
        'src/Snapshots/NewStagingDirectory.ps1', 'src/Snapshots/SealSnapshot.ps1', 'src/Integrity/TestBundleIntegrity.ps1',
        'src/Authentication/Pkce.ps1', 'src/Authentication/ClientAssertion.ps1', 'src/Authentication/TokenValidation.ps1',
        'src/Authentication/TokenCache.ps1', 'src/Authentication/LoopbackListener.ps1', 'src/Authentication/DelegatedAuth.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/Preflight/CollectorRequirement.ps1', 'src/Preflight/CoveragePreflight.ps1',
        'src/Normalization/NormalizeDirectoryRole.ps1', 'src/Normalization/NormalizeDirectoryRoleAssignment.ps1',
        'src/Normalization/NormalizeAzureRoleAssignment.ps1', 'src/Normalization/NormalizeConditionalAccessPolicy.ps1',
        'src/Normalization/NormalizeCrossTenantAccessPolicy.ps1',
        'src/Normalization/NormalizeUser.ps1', 'src/Normalization/NormalizeGroup.ps1',
        'src/Normalization/NormalizeApplication.ps1', 'src/Normalization/NormalizeServicePrincipal.ps1',
        'src/Normalization/NormalizeAdministrativeUnit.ps1', 'src/Normalization/NormalizePimEligibility.ps1',
        'src/Normalization/NormalizeCrossTenantAccessPolicyPartner.ps1', 'src/Normalization/NormalizeTenantPolicies.ps1',
        'src/Normalization/NormalizeAccessReviewDefinition.ps1', 'src/Normalization/NormalizeAccessReviewInstance.ps1',
        'src/Normalization/NormalizeAuthenticationContext.ps1',
        'src/Normalization/NormalizeTenantConfiguration.ps1', 'src/Normalization/NormalizeAzureSubscription.ps1',
        'src/Normalization/NormalizeAzureManagementGroup.ps1', 'src/Normalization/NormalizeAzureRoleDefinition.ps1',
        'src/Normalization/NormalizeNamedLocation.ps1', 'src/Normalization/NormalizeAuthenticationStrengthPolicy.ps1',
        'src/Normalization/NormalizeRoleManagementPolicyAssignment.ps1',
        'src/Normalization/NormalizeAccessPackage.ps1', 'src/Normalization/NormalizeAccessPackageAssignmentPolicy.ps1',
        'src/Normalization/NormalizeAccessPackageAssignment.ps1',
        'src/Collectors/CollectDirectoryRoles.ps1', 'src/Collectors/CollectAzureRoleAssignments.ps1',
        'src/Collectors/CollectConditionalAccessPolicies.ps1', 'src/Collectors/CollectCrossTenantAccessPolicy.ps1',
        'src/Collectors/CollectUsers.ps1', 'src/Collectors/CollectGroups.ps1',
        'src/Collectors/CollectApplications.ps1', 'src/Collectors/CollectServicePrincipals.ps1',
        'src/Collectors/CollectAdministrativeUnits.ps1', 'src/Collectors/CollectPimEligibility.ps1',
        'src/Collectors/CollectCrossTenantAccessPolicyPartners.ps1', 'src/Collectors/CollectTenantPolicies.ps1',
        'src/Collectors/CollectAccessReviewDefinitions.ps1', 'src/Collectors/CollectAuthenticationContexts.ps1',
        'src/Collectors/CollectTenantConfiguration.ps1', 'src/Collectors/CollectAzureSubscriptions.ps1',
        'src/Collectors/CollectAzureManagementGroups.ps1', 'src/Collectors/CollectAzureRoleDefinitions.ps1',
        'src/Collectors/CollectNamedLocations.ps1', 'src/Collectors/CollectAuthenticationStrengthPolicies.ps1',
        'src/Collectors/CollectRoleManagementPolicyAssignments.ps1', 'src/Collectors/CollectAccessPackages.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/ControlRegistry.ps1', 'src/Controls/EvaluateCrossTenantInboundTrust.ps1',
        'src/Controls/EvaluatePrivilegedRoleAssignment.ps1', 'src/Controls/DeviationApplication.ps1',
        'src/Reporting/BuildAssessmentDocument.ps1', 'src/Reporting/RedactionApplication.ps1',
        'src/Reporting/RenderHtmlReport.ps1', 'src/Reporting/RenderCsvReport.ps1', 'src/Reporting/RenderConsoleReport.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1', 'src/Orchestration/GraphCollectorDispatch.ps1',
        'src/Orchestration/CollectAndSeal.ps1', 'src/Orchestration/EvaluateSnapshot.ps1',
        'src/Orchestration/EvaluationPipeline.ps1', 'src/Orchestration/ReportPipeline.ps1',
        'src/Orchestration/DetermineExitCode.ps1',
        'src/Public/New-EntraPostureSnapshot.ps1', 'src/Public/Test-EntraPostureAccess.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestAccessToken {
        param([string[]]$Roles)
        $header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"alg":"none"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $payloadObj = @{ aud = 'test'; roles = $Roles }
        $payloadJson = $payloadObj | ConvertTo-Json -Compress
        $payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return "$header.$payload.sig"
    }

    # Global Reader's actual documented coverage per 00-permission-report-matrix.md: every
    # domain this project collects EXCEPT role-assignment-scoped Access Reviews, which the
    # matrix confirms requires Security Reader / Identity Governance Administrator / Privileged
    # Role Administrator / Security Administrator instead, and (VNext build order item 5, added
    # 2026-08-07) authentication strength policies: Microsoft's own "List
    # authenticationStrengthPolicies" permissions table names exactly three supported built-in
    # roles for delegated access -- Conditional Access Administrator, Security Administrator,
    # Security Reader -- and Global Reader is not among them, the same "app permission alone
    # isn't enough, a specific Entra role is also required" pattern as the Access Reviews gap.
    # Two deliberate gaps now, not one. RoleManagementPolicy.Read.Directory (VNext build order item
    # 7, added 2026-08-07) is NOT a third gap -- Microsoft's "List roleManagementPolicyAssignments"
    # permissions table explicitly confirms Global Reader as a supported built-in role for read
    # access, unlike the two gaps above -- so it's included below, not omitted.
    function script:Get-GlobalReaderShapedPermissions {
        return @(
            'RoleManagement.Read.Directory', 'Policy.Read.All', 'User.Read.All', 'Group.Read.All',
            'GroupMember.Read.All', 'Application.Read.All', 'AdministrativeUnit.Read.All',
            'AuthenticationContext.Read.All', 'Organization.Read.All', 'RoleManagementPolicy.Read.Directory',
            'EntitlementManagement.Read.All'
            # AccessReview.Read.All and Policy.Read.AuthenticationMethod deliberately omitted.
        )
    }

    $script:MockServerScript = {
        param($Listener, $ResponseMap)
        while ($Listener.IsListening) {
            try { $context = $Listener.GetContext() } catch { break }
            $path = $context.Request.Url.AbsolutePath
            $body = if ($ResponseMap.ContainsKey($path)) { $ResponseMap[$path] } else { $context.Response.StatusCode = 404; '{"error":"not found: ' + $path + '"}' }
            $context.Response.ContentType = 'application/json'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$body)
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.OutputStream.Close()
        }
    }

    function script:Start-DegradationMockServer {
        param([hashtable]$ResponseMap)
        $port = Get-EntraPostureAvailableLoopbackPort
        $prefix = "http://127.0.0.1:$port/"
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($prefix)
        $listener.Start()
        $syncMap = [System.Collections.Hashtable]::Synchronized($ResponseMap)
        $ps = [powershell]::Create()
        $ps.AddScript($script:MockServerScript).AddArgument($listener).AddArgument($syncMap) | Out-Null
        $asyncResult = $ps.BeginInvoke()
        return [ordered]@{ Listener = $listener; PowerShell = $ps; AsyncResult = $asyncResult; HostHeader = "127.0.0.1:$port" }
    }

    function script:Stop-DegradationMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-DegradationAllowlist {
        param([string]$HostHeader)
        $paths = @(
            '/v1.0/directoryRoles', '/v1.0/directoryRoles/{roleId}/members', '/v1.0/identity/conditionalAccess/policies',
            '/v1.0/policies/crossTenantAccessPolicy', '/v1.0/users', '/v1.0/groups', '/v1.0/groups/{groupId}/transitiveMembers',
            '/v1.0/applications', '/v1.0/servicePrincipals', '/v1.0/directory/administrativeUnits',
            '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances', '/v1.0/policies/crossTenantAccessPolicy/partners',
            '/v1.0/policies/authorizationPolicy', '/v1.0/policies/adminConsentRequestPolicy',
            '/v1.0/identityGovernance/accessReviews/definitions', '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances',
            '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances/{instanceId}/decisions',
            '/v1.0/identity/conditionalAccess/authenticationContextClassReferences',
            '/v1.0/organization', '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy',
            '/v1.0/identity/conditionalAccess/namedLocations', '/v1.0/policies/roleManagementPolicyAssignments',
            '/v1.0/identityGovernance/entitlementManagement/accessPackages',
            '/v1.0/identityGovernance/entitlementManagement/accessPackages/{accessPackageId}',
            '/v1.0/identityGovernance/entitlementManagement/assignments'
        )
        return @($paths | ForEach-Object {
            [ordered]@{ Host = $HostHeader; PathTemplate = $_; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        })
    }

    function script:Get-DegradationResponseMap {
        return @{
            '/v1.0/directoryRoles' = '{"value":[]}'
            '/v1.0/identity/conditionalAccess/policies' = '{"value":[]}'
            '/v1.0/policies/crossTenantAccessPolicy' = '{"id":"default","inboundTrust":{"isMfaAccepted":false,"isCompliantDeviceAccepted":false,"isHybridAzureADJoinedDeviceAccepted":false}}'
            '/v1.0/users' = '{"value":[]}'
            '/v1.0/groups' = '{"value":[]}'
            '/v1.0/applications' = '{"value":[]}'
            '/v1.0/servicePrincipals' = '{"value":[]}'
            '/v1.0/directory/administrativeUnits' = '{"value":[]}'
            '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances' = '{"value":[]}'
            '/v1.0/policies/crossTenantAccessPolicy/partners' = '{"value":[]}'
            '/v1.0/policies/authorizationPolicy' = '{"id":"default"}'
            '/v1.0/policies/adminConsentRequestPolicy' = '{"isEnabled":true}'
            '/v1.0/identityGovernance/accessReviews/definitions' = '{"value":[]}'
            '/v1.0/identity/conditionalAccess/authenticationContextClassReferences' = '{"value":[]}'
            '/v1.0/organization' = '{"value":[{"id":"org1"}]}'
            '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' = '{"isEnabled":false}'
            '/v1.0/identity/conditionalAccess/namedLocations' = '{"value":[]}'
            '/v1.0/policies/roleManagementPolicyAssignments' = '{"value":[]}'
            '/v1.0/identityGovernance/entitlementManagement/accessPackages' = '{"value":[]}'
            '/v1.0/identityGovernance/entitlementManagement/assignments' = '{"value":[]}'
        }
    }
}

Describe 'Global Reader-shaped identity: the two documented coverage gaps are explicit, not silent' {
    It 'marks AccessReviewDefinitions and AuthenticationStrengthPolicies Denied while every other Graph collector is Collected' {
        $server = Start-DegradationMockServer -ResponseMap (Get-DegradationResponseMap)
        try {
            $allowlist = Get-DegradationAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-GlobalReaderShapedPermissions)

            $result = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot ([System.IO.Path]::GetTempPath()) `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            try {
                $accessReviewCollector = $result.Coverage.collectors | Where-Object { $_.collectorName -eq 'AccessReviewDefinitions' }
                $accessReviewCollector.evidenceStatus | Should -Be 'Denied'
                @($accessReviewCollector.rightsExpected) | Should -Contain 'AccessReview.Read.All'
                @($accessReviewCollector.rightsPresentInToken) | Should -Not -Contain 'AccessReview.Read.All'
                @($accessReviewCollector.affectedReportSections) | Should -Contain 'Access Reviews'

                $authStrengthCollector = $result.Coverage.collectors | Where-Object { $_.collectorName -eq 'AuthenticationStrengthPolicies' }
                $authStrengthCollector.evidenceStatus | Should -Be 'Denied'
                @($authStrengthCollector.rightsExpected) | Should -Contain 'Policy.Read.AuthenticationMethod'
                @($authStrengthCollector.rightsPresentInToken) | Should -Not -Contain 'Policy.Read.AuthenticationMethod'

                $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
                $deniedByDesign = @('AccessReviewDefinitions', 'AuthenticationStrengthPolicies')
                $otherGraphCollectors = $result.Coverage.collectors | Where-Object { $_.collectorName -notin ($deniedByDesign + $armCollectorNames) }
                $notCollected = @($otherGraphCollectors | Where-Object { $_.evidenceStatus -ne 'Collected' })
                $notCollected.Count | Should -Be 0 -Because "every other Graph collector should have everything it needs under a Global Reader-shaped token; unexpected gaps: $(($notCollected | ForEach-Object { $_.collectorName }) -join ', ')"
            } finally {
                Remove-Item -LiteralPath $result.SnapshotPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } finally {
            Stop-DegradationMockServer -Server $server
        }
    }

    It 'preflight (Test-EntraPostureAccess) reports the same two gaps without collecting anything' {
        $graphToken = New-TestAccessToken -Roles (Get-GlobalReaderShapedPermissions)
        $coverage = Test-EntraPostureAccess -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -AccessTokenOverride $graphToken

        $accessReviewCollector = $coverage.collectors | Where-Object { $_.collectorName -eq 'AccessReviewDefinitions' }
        $accessReviewCollector.evidenceStatus | Should -Be 'Denied'
        $accessReviewCollector.accessVerified | Should -BeFalse -Because 'Test-EntraPostureAccess never calls a collector endpoint'

        $authStrengthCollector = $coverage.collectors | Where-Object { $_.collectorName -eq 'AuthenticationStrengthPolicies' }
        $authStrengthCollector.evidenceStatus | Should -Be 'Denied'
        $authStrengthCollector.accessVerified | Should -BeFalse -Because 'Test-EntraPostureAccess never calls a collector endpoint'
    }
}

Describe 'Zero-permission identity: every collector denied, unambiguously' {
    It 'every collector shows Denied with its required permission and affected report section named' {
        $graphToken = New-TestAccessToken -Roles @()
        $coverage = Test-EntraPostureAccess -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -AccessTokenOverride $graphToken

        $graphCollectorNames = @(
            'DirectoryRoleAssignments', 'ConditionalAccessPolicies', 'CrossTenantAccessPolicy', 'Users', 'Groups',
            'Applications', 'ServicePrincipals', 'AdministrativeUnits', 'PimEligibility',
            'CrossTenantAccessPolicyPartners', 'TenantPolicies', 'AccessReviewDefinitions',
            'AuthenticationContexts', 'TenantConfiguration', 'NamedLocations', 'AuthenticationStrengthPolicies',
            'RoleManagementPolicyAssignments', 'AccessPackages'
        )
        $graphCollectors = @($coverage.collectors | Where-Object { $_.collectorName -in $graphCollectorNames })
        $graphCollectors.Count | Should -Be $graphCollectorNames.Count

        foreach ($collector in $graphCollectors) {
            $collector.evidenceStatus | Should -Be 'Denied' -Because "collector '$($collector.collectorName)' should be Denied with zero granted permissions"
            @($collector.rightsPresentInToken).Count | Should -Be 0
            @($collector.rightsExpected).Count | Should -BeGreaterThan 0
            @($collector.affectedReportSections).Count | Should -BeGreaterThan 0
        }
    }
}
