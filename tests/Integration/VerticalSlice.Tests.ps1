#Requires -Version 7.4
#Requires -Modules Pester

<#
    End-to-end tests for Phase 5's minimal vertical slice (engineering plan section 16, Phase 5
    exit criterion: "the fixed pipeline works live and offline without evaluator network
    access"). Two paths:
      - "Live" (this file's Describe 'Collect and seal'): a real local HttpListener mock server
        stands in for both Graph and Azure ARM, exercised through the real transport client and
        New-EntraPostureSnapshot -- not a mocked function, a real HTTP round trip.
      - "Offline" (Describe 'Evaluate and report'): the mock server is stopped before
        evaluation/report ever runs, proving those stages have no network dependency at all.
    Also exercises partial evidence, NotEvaluated, deviations, redaction, integrity, and exit
    codes end to end, per the exit criterion's explicit list.
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
        'src/Normalization/NormalizeOwnerOf.ps1', 'src/Normalization/NormalizeAgentIdentityBlueprint.ps1',
        'src/Normalization/NormalizeAgentIdentityBlueprintPrincipal.ps1', 'src/Normalization/NormalizeAgentIdentity.ps1',
        'src/Normalization/NormalizeAgentUser.ps1', 'src/Normalization/NormalizePimForGroups.ps1',
        'src/Normalization/NormalizeGroupSettings.ps1', 'src/Normalization/NormalizeUserSignInActivity.ps1',
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
        'src/Collectors/CollectAgentIdentityBlueprints.ps1', 'src/Collectors/CollectAgentIdentityBlueprintPrincipals.ps1',
        'src/Collectors/CollectAgentIdentities.ps1', 'src/Collectors/CollectAgentUsers.ps1',
        'src/Collectors/CollectPimForGroups.ps1', 'src/Collectors/CollectGroupSettings.ps1',
        'src/Collectors/CollectUserSignInActivity.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/ControlRegistry.ps1', 'src/Controls/EvaluateCrossTenantInboundTrust.ps1',
        'src/Controls/EvaluatePrivilegedRoleAssignment.ps1', 'src/Controls/DeviationApplication.ps1',
        # NOT a fix for VNext.md build order item 2's own documented dot-source gap ("silently
        # [Error]s on most controls") -- that gap is pre-existing, harmless to this Describe's own
        # exit-code assertions specifically (Get-EntraPostureRunExitCode never counts Error status
        # at all, only Fail/NotEvaluated), and out of scope here. Only CAP-*'s own evaluator files
        # are added below, the minimum needed so CAP-*'s coverage (now wired via
        # CollectConditionalAccessPolicies.ps1's AffectedControlIds) evaluates instead of Erroring
        # -- deliberately not touching the wider gap in the same pass.
        'src/Controls/AgentIdentityForeignDerivation.ps1', 'src/Controls/EvaluateAgentBlueprintClientSecrets.ps1',
        'src/Controls/EvaluateForeignAgentIdentityEntraRole.ps1', 'src/Controls/EvaluateForeignAgentIdentityAzureRole.ps1',
        'src/Controls/EvaluateInternalAgentIdentityEntraRole.ps1', 'src/Controls/EvaluateInternalAgentIdentityAzureRole.ps1',
        'src/Controls/EvaluateForeignAgentUserEntraRole.ps1', 'src/Controls/EvaluateForeignAgentUserAzureRole.ps1',
        'src/Controls/EvaluateAgentUserCapGroupOwnership.ps1', 'src/Controls/EvaluateAgentBlueprintOwnerTier.ps1',
        'src/Controls/EvaluatePimForGroupsStandingMembership.ps1', 'src/Controls/EvaluatePimForGroupsPermanentAssignment.ps1',
        'src/Controls/EvaluateDeviceCodeFlowRestriction.ps1', 'src/Controls/EvaluateSecurityInfoRegistrationRestriction.ps1',
        'src/Controls/EvaluateLegacyAuthenticationBlock.ps1', 'src/Controls/EvaluateDeviceRegistrationMfa.ps1',
        'src/Controls/EvaluatePhishingResistantMfaEnforcement.ps1', 'src/Controls/EvaluateCombinedRiskPolicy.ps1',
        'src/Controls/EvaluateSignInRiskManagement.ps1', 'src/Controls/EvaluateUserRiskManagement.ps1',
        'src/Controls/EvaluateBroadMfaEnforcement.ps1', 'src/Controls/EvaluateTierZeroRoleCaCoverage.ps1',
        'src/Controls/EvaluateGuestInviteRestriction.ps1',
        'src/Reporting/BuildAssessmentDocument.ps1', 'src/Reporting/RedactionApplication.ps1',
        'src/ConditionalAccess/ScenarioModel.ps1', 'src/ConditionalAccess/GenerateCombinatorialScenarios.ps1',
        'src/Reporting/RenderHtmlReport.ps1', 'src/Reporting/RenderCsvReport.ps1', 'src/Reporting/RenderConsoleReport.ps1', 'src/Reporting/CompareAssessment.ps1',
        'src/Reporting/CompareConditionalAccessDrift.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1', 'src/Orchestration/GraphCollectorDispatch.ps1',
        'src/Orchestration/CollectAndSeal.ps1', 'src/Orchestration/EvaluateSnapshot.ps1',
        'src/Orchestration/EvaluationPipeline.ps1', 'src/Orchestration/ReportPipeline.ps1',
        'src/Orchestration/DetermineExitCode.ps1',
        'src/Public/New-EntraPostureSnapshot.ps1', 'src/Public/Invoke-EntraPostureEvaluation.ps1',
        'src/Public/New-EntraPostureReport.ps1', 'src/Public/Test-EntraPostureAccess.ps1',
        'src/Public/Test-EntraPostureBundle.ps1', 'src/Public/Get-EntraPostureControl.ps1',
        'src/Public/Invoke-EntraPosture.ps1', 'src/Public/Compare-EntraPosture.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-VerticalSliceTestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=VerticalSliceTestCert', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }

    # A JWT-*shaped* string is enough for Get-EntraPostureTokenGrantedPermission/
    # ConvertFrom-EntraPostureJwtClaim -- signature is never checked (see
    # TokenValidation.ps1's own DESCRIPTION for why this project's trust model doesn't need to).
    function script:New-TestAccessToken {
        param([string[]]$Roles)
        $header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"alg":"none"}')).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $payloadObj = @{ aud = 'test'; roles = $Roles }
        $payloadJson = $payloadObj | ConvertTo-Json -Compress
        $payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return "$header.$payload.sig"
    }

    $script:MockServerScript = {
        param($Listener, $ResponseMap)
        while ($Listener.IsListening) {
            try { $context = $Listener.GetContext() } catch { break }
            $path = $context.Request.Url.AbsolutePath
            $body = $null
            $status = 200
            if ($ResponseMap.ContainsKey($path)) {
                $body = $ResponseMap[$path]
            } else {
                $status = 404
                $body = '{"error":"not found: ' + $path + '"}'
            }
            $context.Response.StatusCode = $status
            $context.Response.ContentType = 'application/json'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$body)
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.OutputStream.Close()
        }
    }

    function script:Start-VerticalSliceMockServer {
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

        return [ordered]@{ Listener = $listener; PowerShell = $ps; AsyncResult = $asyncResult; Port = $port; HostHeader = "127.0.0.1:$port" }
    }

    function script:Stop-VerticalSliceMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-VerticalSliceAllowlist {
        param([string]$HostHeader)
        return @(
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/directoryRoles';                          ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/directoryRoles/{roleId}/members';         ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identity/conditionalAccess/policies';     ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/crossTenantAccessPolicy';        ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/{scope}/providers/Microsoft.Authorization/roleAssignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/users';                                   ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/groups';                                  ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/groups/{groupId}/transitiveMembers';      ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/applications';                            ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/servicePrincipals';                       ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/directory/administrativeUnits';           ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/roleManagement/directory/roleEligibilityScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/crossTenantAccessPolicy/partners'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/authorizationPolicy';            ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/adminConsentRequestPolicy';      ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances/{instanceId}/decisions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identity/conditionalAccess/authenticationContextClassReferences'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identity/conditionalAccess/namedLocations'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/authenticationStrengthPolicies'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/roleManagementPolicyAssignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/organization';                            ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/subscriptions';                                ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/providers/Microsoft.Management/managementGroups'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/{scope}/providers/Microsoft.Authorization/roleDefinitions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages/{accessPackageId}'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/assignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/applications/microsoft.graph.agentIdentityBlueprint'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/applications/{applicationId}/owners'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/servicePrincipals/microsoft.graph.agentIdentity'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/users/microsoft.graph.agentUser'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/users/{userId}/ownedObjects'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/groupSettings'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        )
    }

    $script:GaRoleId = '62e90394-69f5-4237-9190-012177145e10'

    # Every Graph permission across all fourteen Phase 5/6 Graph collectors, and every ARM
    # permission across all four ARM collectors -- used by test scenarios whose intent is "every
    # collector succeeds," so they don't have to be updated by hand each time a new collector's
    # own permission requirement is added.
    function script:Get-VerticalSliceFullGraphPermissions {
        return @(
            'RoleManagement.Read.Directory', 'Policy.Read.All', 'User.Read.All', 'Group.Read.All',
            'GroupMember.Read.All', 'Application.Read.All', 'AdministrativeUnit.Read.All',
            'AccessReview.Read.All', 'AuthenticationContext.Read.All', 'Organization.Read.All',
            'Policy.Read.AuthenticationMethod', 'RoleManagementPolicy.Read.Directory', 'EntitlementManagement.Read.All',
            'AgentIdentityBlueprint.Read.All', 'AgentIdentityBlueprintPrincipal.Read.All', 'AgentIdentity.Read.All',
            'User.ReadBasic.All', 'Directory.Read.All',
            'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup',
            'GroupSettings.Read.All', 'AuditLog.Read.All'
        )
    }

    function script:Get-VerticalSliceFullArmPermissions {
        return @(
            'Microsoft.Authorization/roleAssignments/read', 'Microsoft.Resources/subscriptions/read',
            'Microsoft.Management/managementGroups/read', 'Microsoft.Authorization/roleDefinitions/read'
        )
    }

    function script:Get-VerticalSliceResponseMap {
        param([int]$GlobalAdminCount = 3, [bool]$MfaWithoutDeviceTrust = $false)

        $membersJson = ($null)
        $memberObjs = for ($i = 1; $i -le $GlobalAdminCount; $i++) {
            "{`"@odata.type`":`"#microsoft.graph.user`",`"id`":`"user-$i`",`"displayName`":`"User $i`"}"
        }
        $membersJson = '{"value":[' + ($memberObjs -join ',') + ']}'

        $mfaAccepted = if ($MfaWithoutDeviceTrust) { 'true' } else { 'true' }
        $compliantAccepted = if ($MfaWithoutDeviceTrust) { 'false' } else { 'true' }

        # Phase 6 breadth collectors are given valid-but-empty ('{"value":[]}') responses here --
        # their field-mapping/normalization correctness is already covered by dedicated
        # per-collector smoke tests; this suite's job is proving orchestration wiring
        # (permission-gating, coverage, evidence-file writing, evaluation, reporting), not
        # re-proving every collector's own data handling a second time. An empty list is still a
        # real, valid 'Collected' outcome, not a stand-in for failure.
        return @{
            '/v1.0/directoryRoles' = "{`"value`":[{`"id`":`"inst-ga`",`"displayName`":`"Global Administrator`",`"description`":`"desc`",`"roleTemplateId`":`"$script:GaRoleId`"}]}"
            '/v1.0/directoryRoles/inst-ga/members' = $membersJson
            # A single generic "Require MFA" policy through 2026-08-07; extended 2026-08-08 (VNext
            # build order item 2's CAP-* slice) with enough real policy shapes that this "clean,
            # well-configured tenant" fixture actually satisfies every registered Conditional
            # Access control, not just the pre-existing ones -- exit-code "success" scenarios
            # depend on this being genuinely clean, not narrowly clean for the controls that
            # existed when the fixture was first written.
            '/v1.0/identity/conditionalAccess/policies' = "{`"value`":[
                {`"id`":`"ca1`",`"displayName`":`"Require MFA for all users`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"users`":{`"includeUsers`":[`"All`"]}},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"mfa`"]}},
                {`"id`":`"ca-devicecode`",`"displayName`":`"Block device code flow`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"authenticationFlows`":{`"transferMethods`":`"deviceCodeFlow`"}},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"block`"]}},
                {`"id`":`"ca-secinfo`",`"displayName`":`"Govern security info registration`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"applications`":{`"includeUserActions`":[`"urn:user:registersecurityinfo`"]}},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"mfa`"]}},
                {`"id`":`"ca-legacy`",`"displayName`":`"Block legacy authentication`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"clientAppTypes`":[`"exchangeActiveSync`",`"other`"]},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"block`"]}},
                {`"id`":`"ca-devicereg`",`"displayName`":`"Require MFA for device registration`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"applications`":{`"includeUserActions`":[`"urn:user:registerdevice`"]}},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"mfa`"]}},
                {`"id`":`"ca-phishres`",`"displayName`":`"Require phishing-resistant MFA`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{},`"grantControls`":{`"operator`":`"OR`",`"authenticationStrength`":{`"id`":`"strength-phishres`"}}},
                {`"id`":`"ca-risk`",`"displayName`":`"Require MFA for sign-in and user risk`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"signInRiskLevels`":[`"high`"],`"userRiskLevels`":[`"high`"]},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"mfa`"]}},
                {`"id`":`"ca-tierzero`",`"displayName`":`"Require MFA for Tier-0 roles`",`"state`":`"enabled`",`"createdDateTime`":`"2026-01-01T00:00:00Z`",`"modifiedDateTime`":`"2026-01-02T00:00:00Z`",
                 `"conditions`":{`"users`":{`"includeRoles`":[`"$script:GaRoleId`"]}},`"grantControls`":{`"operator`":`"OR`",`"builtInControls`":[`"mfa`"]}}
            ]}"
            '/v1.0/policies/crossTenantAccessPolicy' = "{`"id`":`"default`",`"inboundTrust`":{`"isMfaAccepted`":$mfaAccepted,`"isCompliantDeviceAccepted`":$compliantAccepted,`"isHybridAzureADJoinedDeviceAccepted`":false}}"
            '/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments' = '{"value":[{"id":"/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/abc","name":"abc","properties":{"roleDefinitionId":"rd1","principalId":"p1","principalType":"User","scope":"/subscriptions/sub-1","createdOn":"2026-01-01T00:00:00Z"}}]}'
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
            '/v1.0/identity/conditionalAccess/namedLocations' = '{"value":[]}'
            '/v1.0/policies/authenticationStrengthPolicies' = '{"value":[{"id":"strength-phishres","displayName":"Phishing-resistant MFA","policyType":"builtIn","requirementsSatisfied":"mfa","allowedCombinations":["windowsHelloForBusiness","fido2","x509CertificateMultiFactor"]}]}'
            '/v1.0/policies/roleManagementPolicyAssignments' = '{"value":[]}'
            '/v1.0/organization' = '{"value":[{"id":"org1","displayName":"Contoso","createdDateTime":"2020-01-01T00:00:00Z"}]}'
            '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' = '{"isEnabled":false}'
            '/subscriptions' = '{"value":[]}'
            '/providers/Microsoft.Management/managementGroups' = '{"value":[]}'
            '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions' = '{"value":[]}'
            '/v1.0/identityGovernance/entitlementManagement/accessPackages' = '{"value":[]}'
            '/v1.0/identityGovernance/entitlementManagement/assignments' = '{"value":[]}'
            '/v1.0/applications/microsoft.graph.agentIdentityBlueprint' = '{"value":[]}'
            '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' = '{"value":[]}'
            '/v1.0/servicePrincipals/microsoft.graph.agentIdentity' = '{"value":[]}'
            '/v1.0/users/microsoft.graph.agentUser' = '{"value":[]}'
            '/v1.0/groupSettings' = '{"value":[]}'
        }
    }
}

Describe 'Collect and seal (live path against a real local mock server)' {
    BeforeEach {
        $script:RunRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vslice-run-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:RunRoot -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:RunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'produces a fully Sealed (non-Partial) snapshot when every collector succeeds' {
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)
            $armToken = New-TestAccessToken -Roles (Get-VerticalSliceFullArmPermissions)

            $result = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot $script:RunRoot -ArmScope '/subscriptions/sub-1' `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.Manifest.status | Should -Be 'Sealed'
            @($result.Coverage.collectors | Where-Object { $_.evidenceStatus -ne 'Collected' }).Count | Should -Be 0

            $trust = Test-EntraPostureBundle -BundlePath $result.SnapshotPath -BundleKind Snapshot
            $trust.IsTrusted | Should -BeTrue
            $trust.Status | Should -Be 'Unsigned'

            $roleLines = @(Get-Content -LiteralPath (Join-Path $result.SnapshotPath 'evidence/entra-roles.jsonl'))
            $roleLines.Count | Should -Be 1
            $assignmentLines = @(Get-Content -LiteralPath (Join-Path $result.SnapshotPath 'evidence/entra-role-assignments.jsonl'))
            $assignmentLines.Count | Should -Be 3

            $script:SealedSnapshotPath = $result.SnapshotPath
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It 'deduplicates an Azure role assignment inherited into a subscription from a management group discovered at the same time (VNext build-order item 1)' {
        # Regression test for docs/VNext.md's "Azure RBAC scope-discovery dedup" item: sub-1 is
        # discovered both directly (AzureSubscriptions) and as a descendant of mg-root
        # (AzureManagementGroups); ARM's real List role assignments behavior means the single
        # assignment actually defined at mg-root comes back from *both* scope queries -- as a
        # direct record when querying mg-root, as an inherited copy when querying sub-1. Both mock
        # responses below return the identical entityId/defined-scope, exactly reproducing that.
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $responseMap['/subscriptions'] = '{"value":[{"subscriptionId":"sub-1","displayName":"Sub One","state":"Enabled","tenantId":"tenant-1"}]}'
        $responseMap['/providers/Microsoft.Management/managementGroups'] = '{"value":[{"name":"mg-root","properties":{"displayName":"Root MG","tenantId":"tenant-1"}}]}'
        $assignmentDefinedAtMg = '{"value":[{"id":"/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleAssignments/abc","name":"abc","properties":{"roleDefinitionId":"rd1","principalId":"p1","principalType":"User","scope":"/providers/Microsoft.Management/managementGroups/mg-root","createdOn":"2026-01-01T00:00:00Z"}}]}'
        $responseMap['/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments'] = $assignmentDefinedAtMg
        $responseMap['/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleAssignments'] = $assignmentDefinedAtMg
        $responseMap['/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleDefinitions'] = '{"value":[]}'

        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)
            $armToken = New-TestAccessToken -Roles (Get-VerticalSliceFullArmPermissions)

            $result = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot $script:RunRoot `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.Manifest.status | Should -Be 'Sealed'

            $assignmentLines = @(Get-Content -LiteralPath (Join-Path $result.SnapshotPath 'evidence/azure-role-assignments.jsonl'))
            $assignmentLines.Count | Should -Be 1

            $kept = $assignmentLines[0] | ConvertFrom-Json
            $kept.entityId | Should -Be '/providers/Microsoft.Management/managementGroups/mg-root/providers/Microsoft.Authorization/roleAssignments/abc'
            $kept.properties.queriedScope | Should -Be '/providers/Microsoft.Management/managementGroups/mg-root'
            $kept.properties.inheritedAtQueriedScope | Should -BeFalse
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It 'produces a Partial snapshot with correct partialReason when the ARM token is withheld (real partial-evidence path)' {
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)

            $result = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot $script:RunRoot `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.Manifest.status | Should -Be 'Partial'
            $result.Manifest.partialReason | Should -Match 'AzureRoleAssignments'

            $azureCollector = $result.Coverage.collectors | Where-Object { $_.collectorName -eq 'AzureRoleAssignments' }
            $azureCollector.evidenceStatus | Should -Be 'Denied'

            $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
            $graphCollectors = $result.Coverage.collectors | Where-Object { $_.collectorName -notin $armCollectorNames }
            @($graphCollectors | Where-Object { $_.evidenceStatus -ne 'Collected' }).Count | Should -Be 0
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It 'never sends a request the token lacks permission for -- Denied Graph collectors are skipped entirely' {
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            # Only Policy.Read.All granted -- RoleManagement.Read.Directory (needed for the
            # DirectoryRoleAssignments collector) is deliberately absent.
            $graphToken = New-TestAccessToken -Roles @('Policy.Read.All')

            $result = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot $script:RunRoot `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.Manifest.status | Should -Be 'Partial'
            $roleCollector = $result.Coverage.collectors | Where-Object { $_.collectorName -eq 'DirectoryRoleAssignments' }
            $roleCollector.evidenceStatus | Should -Be 'Denied'
            (Test-Path -LiteralPath (Join-Path $result.SnapshotPath 'evidence/entra-roles.jsonl')) | Should -BeFalse
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }
}

Describe 'Evaluate and report (offline path -- mock server stopped before this Describe runs)' {
    BeforeAll {
        $script:OfflineRunRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vslice-offline-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:OfflineRunRoot -Force | Out-Null

        # Build one real sealed snapshot up front (server torn down immediately after), then every
        # test in this Describe operates purely offline against files already on disk.
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 1
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
        $graphToken = New-TestAccessToken -Roles @('RoleManagement.Read.Directory', 'Policy.Read.All')
        try {
            $script:SnapshotResult = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                -RunRoot $script:OfflineRunRoot `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    AfterAll {
        Remove-Item -LiteralPath $script:OfflineRunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'evaluates PRIV-001 as Fail (too few Global Admins) entirely offline -- no listener running' {
        $evalResult = Invoke-EntraPostureEvaluation -SnapshotPath $script:SnapshotResult.SnapshotPath -RunRoot $script:OfflineRunRoot
        $privResult = $evalResult.Results | Where-Object { $_.controlId -eq 'PRIV-001' }
        $privResult.status | Should -Be 'Fail'
        $privResult.reasonCode | Should -Be 'PRIV-001-TOO-FEW-GLOBAL-ADMINS'

        $script:EvalResult = $evalResult
    }

    It 'evaluates XTA-001 as Pass (device trust present in the fixture)' {
        $xtaResult = $script:EvalResult.Results | Where-Object { $_.controlId -eq 'XTA-001' }
        $xtaResult.status | Should -Be 'Pass'
    }

    It 'marks AzureRoleAssignments-dependent evaluation as NotEvaluated when ARM was never collected' {
        # No control in this Phase 5 registry actually depends on AzureRoleAssignments evidence,
        # so this asserts the coverage-side fact directly instead: the collector's evidenceStatus
        # is Denied (ARM was never attempted), proving NotEvaluated-driving coverage state is
        # correctly recorded even though no control happens to consume it yet.
        $armCollector = $script:SnapshotResult.Coverage.collectors | Where-Object { $_.collectorName -eq 'AzureRoleAssignments' }
        $armCollector.evidenceStatus | Should -Be 'Denied'
    }

    It 'seals the assessment bundle with valid integrity, verifiable via Test-EntraPostureBundle' {
        $trust = Test-EntraPostureBundle -BundlePath $script:EvalResult.AssessmentPath -BundleKind Assessment
        $trust.IsTrusted | Should -BeTrue
        $trust.Status | Should -Be 'Unsigned'
    }

    It 'detects tampering in an assessment bundle after sealing (integrity)' {
        $tamperedResultsPath = Join-Path $script:EvalResult.AssessmentPath 'results.jsonl'
        $original = Get-Content -LiteralPath $tamperedResultsPath -Raw
        try {
            Set-Content -LiteralPath $tamperedResultsPath -Value ($original -replace 'Fail', 'Pass') -NoNewline
            $trust = Test-EntraPostureBundle -BundlePath $script:EvalResult.AssessmentPath -BundleKind Assessment
            $trust.IsTrusted | Should -BeFalse
            $trust.Status | Should -Be 'HashMismatch'
        } finally {
            Set-Content -LiteralPath $tamperedResultsPath -Value $original -NoNewline
        }
    }

    It 'applies an approved deviation: status stays Fail, but a deviation ID is attached' {
        $deviation = [ordered]@{
            deviationId = 'DEV-1'; controlId = 'PRIV-001'; objectScope = $script:GaRoleId
            approver = 'mgr'; justification = 'temporary, approved'; owner = 'sec-team'
            startDate = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-dd')
            expiryDate = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-dd')
            compensatingControl = $null; evidence = @()
        }
        $deviationsPath = Join-Path $script:OfflineRunRoot 'deviations.jsonl'
        Set-Content -LiteralPath $deviationsPath -Value (ConvertTo-EntraPostureCanonicalJson -InputObject $deviation) -NoNewline

        $evalWithDeviation = Invoke-EntraPostureEvaluation -SnapshotPath $script:SnapshotResult.SnapshotPath -RunRoot $script:OfflineRunRoot -DeviationsPath $deviationsPath
        $privResult = $evalWithDeviation.Results | Where-Object { $_.controlId -eq 'PRIV-001' }
        $privResult.status | Should -Be 'Fail'
        $privResult.deviation | Should -Be 'DEV-1'

        $script:DeviatedAssessmentPath = $evalWithDeviation.AssessmentPath
    }

    It 'renders "Fail -- Approved Deviation" in the HTML report for the deviated result' {
        $reportResult = New-EntraPostureReport -AssessmentPath $script:DeviatedAssessmentPath -SnapshotPath $script:SnapshotResult.SnapshotPath
        $html = Get-Content -LiteralPath $reportResult.HtmlReportPath -Raw
        $html | Should -Match 'Fail -- Approved Deviation'
    }

    It 'redaction mode Identifiers pseudonymizes scope/entityId in the rendered assessment.json' {
        $reportResult = New-EntraPostureReport -AssessmentPath $script:EvalResult.AssessmentPath -SnapshotPath $script:SnapshotResult.SnapshotPath -RedactionMode Identifiers
        $assessmentJson = Get-Content -LiteralPath $reportResult.AssessmentJsonPath -Raw
        $assessmentJson | Should -Not -Match ([regex]::Escape($script:GaRoleId))
        $assessmentJson | Should -Match 'DirectoryRole-1'
    }

    It 'redaction mode None keeps real identifiers in the rendered assessment.json' {
        $reportResult = New-EntraPostureReport -AssessmentPath $script:EvalResult.AssessmentPath -SnapshotPath $script:SnapshotResult.SnapshotPath -RedactionMode None
        $assessmentJson = Get-Content -LiteralPath $reportResult.AssessmentJsonPath -Raw
        $assessmentJson | Should -Match ([regex]::Escape($script:GaRoleId))
    }

    It 'CSV findings export exists and is well-formed' {
        $reportResult = New-EntraPostureReport -AssessmentPath $script:EvalResult.AssessmentPath -SnapshotPath $script:SnapshotResult.SnapshotPath
        $csv = Get-Content -LiteralPath $reportResult.CsvReportPath -Raw
        $csv | Should -Match 'controlId,scope,status'
        $csv | Should -Match 'PRIV-001'
    }
}

Describe 'Compare-EntraPosture (Phase 9): end-to-end bundle-loading and trust-verification wiring' {
    <#
        The pure classification logic (Compare-EntraPostureAssessmentDocument) is unit-tested
        directly in tests/Unit/CompareAssessment.Tests.ps1 with fixture documents -- this Describe
        covers the other half: Compare-EntraPosture (the Public command) actually loading and
        trust-verifying two REAL sealed assessment bundles, the same "thin wrapper, tested through
        the full pipeline" split every other Public command gets in this file.

        Deliberately self-contained -- builds both the "old" and "new" fixtures in its own
        BeforeAll rather than reusing the sibling "Evaluate and report" Describe's
        $script:EvalResult/$script:SnapshotResult. Confirmed directly that reusing them doesn't
        work: that Describe's own AfterAll deletes its temp run-root as soon as its own It blocks
        finish, which happens before this later Describe's Its run at all -- Pester runs each
        Describe's AfterAll immediately after that Describe's own body, not deferred to the end
        of the file, so the borrowed AssessmentPath no longer exists by the time this Describe
        would have used it.
    #>
    BeforeAll {
        $script:CompareRunRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vslice-compare-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:CompareRunRoot -Force | Out-Null

        function script:New-CompareFixture {
            param([int]$GlobalAdminCount)
            $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount $GlobalAdminCount
            $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles @('RoleManagement.Read.Directory', 'Policy.Read.All')
            try {
                $snapshotResult = New-EntraPostureSnapshot -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate `
                    -RunRoot $script:CompareRunRoot `
                    -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                    -AllowlistOverride $allowlist -SchemeOverride 'http' `
                    -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader
            } finally {
                Stop-VerticalSliceMockServer -Server $server
            }
            $evalResult = Invoke-EntraPostureEvaluation -SnapshotPath $snapshotResult.SnapshotPath -RunRoot $script:CompareRunRoot
            return [ordered]@{ Snapshot = $snapshotResult; Eval = $evalResult }
        }

        # "Old" (GlobalAdminCount 1, PRIV-001 Fail) and "new" (GlobalAdminCount 2, PRIV-001 Pass)
        # -- a real Fail-to-Pass transition to compare, not a synthetic one.
        $script:OldFixture = New-CompareFixture -GlobalAdminCount 1
        $script:NewFixture = New-CompareFixture -GlobalAdminCount 2
    }

    AfterAll {
        Remove-Item -LiteralPath $script:CompareRunRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'the fixtures really do evaluate PRIV-001 as Fail/Pass respectively (sanity check on the fixtures, not the comparison)' {
        ($script:OldFixture.Eval.Results | Where-Object { $_.controlId -eq 'PRIV-001' }).status | Should -Be 'Fail'
        ($script:NewFixture.Eval.Results | Where-Object { $_.controlId -eq 'PRIV-001' }).status | Should -Be 'Pass'
    }

    It 'reports the real PRIV-001 Fail-to-Pass transition when comparing two real sealed bundles' {
        $comparison = Compare-EntraPosture -OldAssessmentPath $script:OldFixture.Eval.AssessmentPath -NewAssessmentPath $script:NewFixture.Eval.AssessmentPath
        $privTransition = $comparison.ResultTransitions | Where-Object { $_.ControlId -eq 'PRIV-001' }
        $privTransition | Should -Not -BeNullOrEmpty
        $privTransition.OldStatus | Should -Be 'Fail'
        $privTransition.NewStatus | Should -Be 'Pass'
    }

    It 'skips the cross-tenant check (TenantCheckPerformed=false) when no snapshot paths are supplied' {
        $comparison = Compare-EntraPosture -OldAssessmentPath $script:OldFixture.Eval.AssessmentPath -NewAssessmentPath $script:NewFixture.Eval.AssessmentPath
        $comparison.TenantCheckPerformed | Should -BeFalse
    }

    It 'performs and passes the cross-tenant check for two same-tenant snapshots when both snapshot paths are supplied' {
        $comparison = Compare-EntraPosture -OldAssessmentPath $script:OldFixture.Eval.AssessmentPath -NewAssessmentPath $script:NewFixture.Eval.AssessmentPath `
            -OldSnapshotPath $script:OldFixture.Snapshot.SnapshotPath -NewSnapshotPath $script:NewFixture.Snapshot.SnapshotPath
        $comparison.TenantCheckPerformed | Should -BeTrue
    }

    It 'refuses to compare a tampered bundle -- integrity check runs before any comparison logic' {
        $tamperedPath = Join-Path ([System.IO.Path]::GetTempPath()) "vslice-compare-tampered-$([guid]::NewGuid())"
        Copy-Item -LiteralPath $script:OldFixture.Eval.AssessmentPath -Destination $tamperedPath -Recurse
        try {
            $resultsPath = Join-Path $tamperedPath 'results.jsonl'
            Set-Content -LiteralPath $resultsPath -Value ((Get-Content -LiteralPath $resultsPath -Raw) -replace 'Fail', 'Pass') -NoNewline
            { Compare-EntraPosture -OldAssessmentPath $tamperedPath -NewAssessmentPath $script:NewFixture.Eval.AssessmentPath } |
                Should -Throw '*not trusted*'
        } finally {
            Remove-Item -LiteralPath $tamperedPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Exit codes (engineering plan section 11 priority table, exercised through the full pipeline)' {
    BeforeEach {
        $script:ExitCodeRunRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vslice-exitcode-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:ExitCodeRunRoot -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:ExitCodeRunRoot -Recurse -Force -ErrorAction SilentlyContinue
        $global:LASTEXITCODE = $null
    }

    It 'returns exit code 2 (unapproved failure) for a tenant with too few Global Admins' {
        # Supplies a full ARM token too (AzureRoleAssignments has zero AffectedControlIds today,
        # but ADR-015's "any collector gap marks the snapshot Partial" is deliberately
        # conservative and correctly dominates the exit code regardless -- omitting the ARM
        # token here would make every snapshot structurally Partial and always return exit code
        # 3, masking the specific unapproved-Fail behavior this test exists to isolate).
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 1
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)
            $armToken = New-TestAccessToken -Roles (Get-VerticalSliceFullArmPermissions)

            $result = Invoke-EntraPosture -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -RunRoot $script:ExitCodeRunRoot `
                -ArmScope '/subscriptions/sub-1' -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.ExitCode | Should -Be 2
            $global:LASTEXITCODE | Should -Be 2
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It 'returns exit code 0 (success) for a tenant with 2-4 Global Admins and safe cross-tenant trust' {
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)
            $armToken = New-TestAccessToken -Roles (Get-VerticalSliceFullArmPermissions)

            $result = Invoke-EntraPosture -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -RunRoot $script:ExitCodeRunRoot `
                -ArmScope '/subscriptions/sub-1' -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.ExitCode | Should -Be 0
            $global:LASTEXITCODE | Should -Be 0
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It 'returns exit code 3 (partial assessment) when a required permission is missing, even if the controls that did run would have passed' {
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 3
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            # Policy.Read.All withheld -- XTA-001's evidence domain becomes Denied, so its
            # result is NotEvaluated even though PRIV-001 (which only needs
            # RoleManagement.Read.Directory) would independently Pass.
            $graphToken = New-TestAccessToken -Roles @('RoleManagement.Read.Directory')

            $result = Invoke-EntraPosture -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -RunRoot $script:ExitCodeRunRoot `
                -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $null }) `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader

            $result.ExitCode | Should -Be 3
            $global:LASTEXITCODE | Should -Be 3
            $xtaResult = $result.Results | Where-Object { $_.controlId -eq 'XTA-001' }
            $xtaResult.status | Should -Be 'NotEvaluated'
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }

    It '-Strict returns exit code 2 even for an approved-deviation Fail that returns 0 without -Strict' {
        # Documents the -Strict contract directly (section 11: "-Strict makes all technical
        # failures return code 2") using a deviated Fail, to make the distinction from the
        # non-Strict "approved fail is not code 2" behavior explicit and adjacent in the suite.
        $responseMap = Get-VerticalSliceResponseMap -GlobalAdminCount 1
        $server = Start-VerticalSliceMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-VerticalSliceAllowlist -HostHeader $server.HostHeader
            $graphToken = New-TestAccessToken -Roles (Get-VerticalSliceFullGraphPermissions)
            $armToken = New-TestAccessToken -Roles (Get-VerticalSliceFullArmPermissions)

            $deviation = [ordered]@{
                deviationId = 'DEV-STRICT'; controlId = 'PRIV-001'; objectScope = $script:GaRoleId
                approver = 'mgr'; justification = 'temporary, approved'; owner = 'sec-team'
                startDate = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-dd')
                expiryDate = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-dd')
                compensatingControl = $null; evidence = @()
            }
            $deviationsPath = Join-Path $script:ExitCodeRunRoot 'deviations.jsonl'
            Set-Content -LiteralPath $deviationsPath -Value (ConvertTo-EntraPostureCanonicalJson -InputObject $deviation) -NoNewline

            $nonStrictResult = Invoke-EntraPosture -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -RunRoot $script:ExitCodeRunRoot `
                -ArmScope '/subscriptions/sub-1' -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) -DeviationsPath $deviationsPath `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader
            $nonStrictResult.ExitCode | Should -Be 0

            $strictResult = Invoke-EntraPosture -TenantId 'tenant-1' -ClientId 'client-1' -AuthMode Certificate -RunRoot $script:ExitCodeRunRoot `
                -ArmScope '/subscriptions/sub-1' -AccessTokenOverride ([ordered]@{ Graph = $graphToken; Arm = $armToken }) -DeviationsPath $deviationsPath -Strict `
                -AllowlistOverride $allowlist -SchemeOverride 'http' `
                -GraphRequestHostOverride $server.HostHeader -ArmRequestHostOverride $server.HostHeader
            $strictResult.ExitCode | Should -Be 2
        } finally {
            Stop-VerticalSliceMockServer -Server $server
        }
    }
}
