@{
    <#
        Explicit build declaration (engineering plan section 6.1): "The build manifest specifies
        an explicit source order and fails on unexpected source files, duplicate function names,
        unapproved exports, schema drift, or non-deterministic output. Runtime discovery is not
        used."

        SourceFiles is authoritative and ordered: Build-Module.ps1 loads exactly these files, in
        exactly this order, and fails the build if:
          - a file under src/ exists but is not listed here (unexpected source file)
          - a file listed here does not exist under src/ (missing source file)
          - two files define a function with the same name (duplicate function name)
          - a function outside src/Public/ ends up exported (unapproved export)

        Add new files here explicitly as each phase introduces them. Do not switch this to a
        wildcard/Get-ChildItem scan -- that is exactly the "runtime discovery" ADR-004 forbids,
        moved one layer down into the build script instead of the runtime module.
    #>

    ModuleMetadata = @{
        Name              = 'EntraPosture'
        Guid              = 'b3f2c9a1-6d4e-4f1a-9c3b-8e2d7a5f10c4'
        Description        = 'Native, read-only Entra ID and Azure access assessment tool (working name, not a product commitment -- see engineering plan section "Working module name").'
        Author            = 'Internal'
        CompanyName       = 'Internal'
        PowerShellVersion = '7.4'
        ModuleVersion     = '0.1.0'
    }

    # Loaded in this exact order. Common must precede everything; Logging is deliberately
    # ordered right after Common (moved up from its original post-Snapshots position during
    # Phase 4, since Authentication/DelegatedAuth.ps1 also needs Write-EntraPostureLog --
    # Logging is a foundational cross-cutting concern, not something specific to the
    # snapshot-sealing pipeline it originally shipped next to).
    #
    # Phase 3: CanonicalJson/StrictJson/TestSchema/FileHash/AggregateHash/DetachedSignature have
    # no intra-project dependencies and are ordered before SealSnapshot.ps1, which calls all of
    # them; TestBundleIntegrity.ps1 additionally calls SealSnapshot.ps1's
    # Get-EntraPostureBundleFileInventory/Get-EntraPostureIntegrityAttestationPayload and
    # so is ordered after it.
    #
    # Phase 4: within Authentication/, Pkce.ps1 (defines ConvertTo-EntraPostureBase64Url) must
    # precede ClientAssertion.ps1 (uses it); DelegatedAuth.ps1 uses Pkce, LoopbackListener,
    # ClientAssertion, and TokenCache functions and so is ordered last in that folder. Transport/
    # EndpointAllowlist.ps1 precedes SendRequest.ps1 (uses Test-EntraPostureEndpointAllowed).
    # Preflight/ has no dependency on Authentication/Transport and could sit anywhere after
    # Common, but is grouped at the end for readability (it is conceptually the "last mile"
    # before Public/ command implementations consume all of the above).
    #
    # Phase 5: Common/ToolVersionInfo.ps1 has no dependencies, ordered with the rest of Common.
    # Normalization/ has no intra-project dependencies beyond Common and is ordered before
    # Collectors/ (which calls the normalizers) and before Evidence/ (whose registry references
    # the same entity/relationship type names, though not the normalizer functions directly).
    # Collectors/ additionally depends on Transport/SendRequest.ps1 and Preflight/
    # CollectorRequirement.ps1 (each collector declares one), so the whole Preflight/ block was
    # moved earlier, ahead of Normalization/Collectors, instead of staying at the end.
    # Evidence/EvidenceFileRegistry.ps1 precedes EvidenceProvider.ps1 (uses the registry).
    SourceFiles = @(
        'src/Common/ExitCode.ps1'
        'src/Common/NewCorrelationId.ps1'
        'src/Common/NewErrorRecord.ps1'
        'src/Common/AssertNotImplemented.ps1'
        'src/Common/CanonicalJson.ps1'
        'src/Common/ToolVersionInfo.ps1'
        'src/Logging/WriteLog.ps1'
        'src/Validation/StrictJson.ps1'
        'src/Validation/TestSchema.ps1'
        'src/Integrity/FileHash.ps1'
        'src/Integrity/AggregateHash.ps1'
        'src/Integrity/DetachedSignature.ps1'
        'src/Snapshots/NewStagingDirectory.ps1'
        'src/Snapshots/SealSnapshot.ps1'
        'src/Integrity/TestBundleIntegrity.ps1'
        'src/Authentication/Pkce.ps1'
        'src/Authentication/ClientAssertion.ps1'
        'src/Authentication/TokenValidation.ps1'
        'src/Authentication/TokenCache.ps1'
        'src/Authentication/LoopbackListener.ps1'
        'src/Authentication/BrowserLaunch.ps1'
        'src/Authentication/DelegatedAuth.ps1'
        'src/Transport/EndpointAllowlist.ps1'
        'src/Transport/SendRequest.ps1'
        'src/Preflight/CollectorRequirement.ps1'
        'src/Preflight/CoveragePreflight.ps1'
        'src/Normalization/NormalizeDirectoryRole.ps1'
        'src/Normalization/NormalizeDirectoryRoleAssignment.ps1'
        'src/Normalization/NormalizeAzureRoleAssignment.ps1'
        'src/Normalization/NormalizeConditionalAccessPolicy.ps1'
        'src/Normalization/NormalizeCrossTenantAccessPolicy.ps1'
        'src/Normalization/NormalizeUser.ps1'
        'src/Normalization/NormalizeGroup.ps1'
        'src/Normalization/NormalizeApplication.ps1'
        'src/Normalization/NormalizeServicePrincipal.ps1'
        'src/Normalization/NormalizeAdministrativeUnit.ps1'
        'src/Normalization/NormalizePimEligibility.ps1'
        'src/Normalization/NormalizeCrossTenantAccessPolicyPartner.ps1'
        'src/Normalization/NormalizeTenantPolicies.ps1'
        'src/Normalization/NormalizeAccessReviewDefinition.ps1'
        'src/Normalization/NormalizeAccessReviewInstance.ps1'
        'src/Normalization/NormalizeAccessPackage.ps1'
        'src/Normalization/NormalizeAccessPackageAssignmentPolicy.ps1'
        'src/Normalization/NormalizeAccessPackageAssignment.ps1'
        'src/Normalization/NormalizeAuthenticationContext.ps1'
        'src/Normalization/NormalizeTenantConfiguration.ps1'
        'src/Normalization/NormalizeAzureSubscription.ps1'
        'src/Normalization/NormalizeAzureManagementGroup.ps1'
        'src/Normalization/NormalizeAzureRoleDefinition.ps1'
        'src/Normalization/NormalizeNamedLocation.ps1'
        'src/Normalization/NormalizeAuthenticationStrengthPolicy.ps1'
        'src/Normalization/NormalizeRoleManagementPolicyAssignment.ps1'
        'src/Normalization/NormalizeOwnerOf.ps1'
        'src/Normalization/NormalizeAgentIdentityBlueprint.ps1'
        'src/Normalization/NormalizeAgentIdentityBlueprintPrincipal.ps1'
        'src/Normalization/NormalizeAgentIdentity.ps1'
        'src/Normalization/NormalizeAgentUser.ps1'
        'src/Normalization/NormalizePimForGroups.ps1'
        'src/Collectors/CollectDirectoryRoles.ps1'
        'src/Collectors/CollectAzureRoleAssignments.ps1'
        'src/Collectors/CollectConditionalAccessPolicies.ps1'
        'src/Collectors/CollectCrossTenantAccessPolicy.ps1'
        'src/Collectors/CollectUsers.ps1'
        'src/Collectors/CollectGroups.ps1'
        'src/Collectors/CollectApplications.ps1'
        'src/Collectors/CollectServicePrincipals.ps1'
        'src/Collectors/CollectAdministrativeUnits.ps1'
        'src/Collectors/CollectPimEligibility.ps1'
        'src/Collectors/CollectCrossTenantAccessPolicyPartners.ps1'
        'src/Collectors/CollectTenantPolicies.ps1'
        'src/Collectors/CollectAccessReviewDefinitions.ps1'
        'src/Collectors/CollectAuthenticationContexts.ps1'
        'src/Collectors/CollectTenantConfiguration.ps1'
        'src/Collectors/CollectAzureSubscriptions.ps1'
        'src/Collectors/CollectAzureManagementGroups.ps1'
        'src/Collectors/CollectAzureRoleDefinitions.ps1'
        'src/Collectors/CollectNamedLocations.ps1'
        'src/Collectors/CollectAuthenticationStrengthPolicies.ps1'
        'src/Collectors/CollectRoleManagementPolicyAssignments.ps1'
        'src/Collectors/CollectAccessPackages.ps1'
        'src/Collectors/CollectAgentIdentityBlueprints.ps1'
        'src/Collectors/CollectAgentIdentityBlueprintPrincipals.ps1'
        'src/Collectors/CollectAgentIdentities.ps1'
        'src/Collectors/CollectAgentUsers.ps1'
        'src/Collectors/CollectPimForGroups.ps1'
        'src/Evidence/EvidenceFileRegistry.ps1'
        'src/Evidence/EvidenceProvider.ps1'
        'src/ConditionalAccess/DeviceFilterTokenizer.ps1'
        'src/ConditionalAccess/DeviceFilterParser.ps1'
        'src/ConditionalAccess/DeviceFilterEvaluator.ps1'
        'src/ConditionalAccess/EvaluateDeviceFilterCondition.ps1'
        'src/ConditionalAccess/ScenarioModel.ps1'
        'src/ConditionalAccess/MatchPolicy.ps1'
        'src/ConditionalAccess/ResolveNamedLocation.ps1'
        'src/ConditionalAccess/ResolveAuthenticationStrength.ps1'
        'src/ConditionalAccess/EvaluateScenario.ps1'
        'src/ConditionalAccess/GenerateCombinatorialScenarios.ps1'
        'src/ConditionalAccess/WhatIfComparison.ps1'
        'src/Controls/ControlRegistry.ps1'
        'src/Controls/EvaluateCrossTenantInboundTrust.ps1'
        'src/Controls/EvaluatePrivilegedRoleAssignment.ps1'
        'src/Controls/EvaluateDefaultUserConsentPolicy.ps1'
        'src/Controls/EvaluateAdminConsentWorkflow.ps1'
        'src/Controls/EvaluateCrossTenantPartnerOverride.ps1'
        'src/Controls/EvaluateAccessReviewCoverage.ps1'
        'src/Controls/EvaluateAccessReviewInstanceHealth.ps1'
        'src/Controls/EvaluateAccessPackagePrivilegedPolicyVetting.ps1'
        'src/Controls/EvaluateAccessPackageExpirationEnforcement.ps1'
        'src/Controls/EvaluateConditionalAccessCombinatorialCoverage.ps1'
        'src/Controls/EvaluateSensitiveGroupProtection.ps1'
        'src/Controls/EvaluateStandingTierZeroAssignment.ps1'
        'src/Controls/EvaluateConditionalAccessAdminCoverage.ps1'
        'src/Controls/EvaluateAppCreationRestriction.ps1'
        'src/Controls/EvaluateSecurityGroupCreationRestriction.ps1'
        'src/Controls/EvaluateAuthenticationContextCoverage.ps1'
        'src/Controls/EvaluateAuthenticationContextEffectiveness.ps1'
        'src/Controls/EvaluateTierZeroActivationDuration.ps1'
        'src/Controls/EvaluateTierZeroActivationJustification.ps1'
        'src/Controls/EvaluateTierZeroPermanentAssignment.ps1'
        'src/Controls/EvaluateTierZeroAssignmentJustification.ps1'
        'src/Controls/EvaluateTierZeroAssignmentMfa.ps1'
        'src/Controls/EvaluateTierZeroActivationNotification.ps1'
        'src/Controls/EvaluateTierZeroAuthContextOrApproval.ps1'
        'src/Controls/DeviationApplication.ps1'
        'src/Controls/AgentIdentityForeignDerivation.ps1'
        'src/Controls/EvaluateAgentBlueprintClientSecrets.ps1'
        'src/Controls/EvaluateForeignAgentIdentityEntraRole.ps1'
        'src/Controls/EvaluateForeignAgentIdentityAzureRole.ps1'
        'src/Controls/EvaluateInternalAgentIdentityEntraRole.ps1'
        'src/Controls/EvaluateInternalAgentIdentityAzureRole.ps1'
        'src/Controls/EvaluateForeignAgentUserEntraRole.ps1'
        'src/Controls/EvaluateForeignAgentUserAzureRole.ps1'
        'src/Controls/EvaluateAgentUserCapGroupOwnership.ps1'
        'src/Controls/EvaluateAgentBlueprintOwnerTier.ps1'
        'src/Controls/EvaluatePimForGroupsStandingMembership.ps1'
        'src/Controls/EvaluatePimForGroupsPermanentAssignment.ps1'
        'src/Controls/EvaluateDeviceCodeFlowRestriction.ps1'
        'src/Controls/EvaluateSecurityInfoRegistrationRestriction.ps1'
        'src/Controls/EvaluateLegacyAuthenticationBlock.ps1'
        'src/Controls/EvaluateDeviceRegistrationMfa.ps1'
        'src/Controls/EvaluatePhishingResistantMfaEnforcement.ps1'
        'src/Controls/EvaluateCombinedRiskPolicy.ps1'
        'src/Controls/EvaluateSignInRiskManagement.ps1'
        'src/Controls/EvaluateUserRiskManagement.ps1'
        'src/Controls/EvaluateBroadMfaEnforcement.ps1'
        'src/Controls/EvaluateTierZeroRoleCaCoverage.ps1'
        'src/Controls/EvaluateGuestInviteRestriction.ps1'
        'src/Controls/EvaluateManagedIdentityEntraRole.ps1'
        'src/Controls/EvaluateManagedIdentityAzureRole.ps1'
        'src/Controls/EvaluateInternalAgentUserEntraRole.ps1'
        'src/Controls/EvaluateInternalAgentUserAzureRole.ps1'
        'src/Controls/EvaluateForeignServicePrincipalEntraRole.ps1'
        'src/Controls/EvaluateForeignServicePrincipalAzureRole.ps1'
        'src/Controls/EvaluateInternalServicePrincipalEntraRole.ps1'
        'src/Controls/EvaluateInternalServicePrincipalAzureRole.ps1'
        'src/Controls/EvaluateAppRegistrationSecrets.ps1'
        'src/Controls/EvaluateHybridUserEntraRole.ps1'
        'src/Controls/EvaluateHybridUserAzureRole.ps1'
        'src/Controls/EvaluateGuestAccessLevel.ps1'
        'src/Reporting/BuildAssessmentDocument.ps1'
        'src/Reporting/RedactionApplication.ps1'
        'src/Reporting/RenderHtmlReport.ps1'
        'src/Reporting/RenderCsvReport.ps1'
        'src/Reporting/RenderConsoleReport.ps1'
        'src/Reporting/CompareAssessment.ps1'
        'src/Reporting/CompareConditionalAccessDrift.ps1'
        'src/Orchestration/BoundedParallelExecution.ps1'
        'src/Orchestration/GraphCollectorDispatch.ps1'
        'src/Orchestration/CollectAndSeal.ps1'
        'src/Orchestration/EvaluateSnapshot.ps1'
        'src/Orchestration/EvaluationPipeline.ps1'
        'src/Orchestration/ReportPipeline.ps1'
        'src/Orchestration/DetermineExitCode.ps1'
        'src/Public/Invoke-EntraPosture.ps1'
        'src/Public/Test-EntraPostureAccess.ps1'
        'src/Public/New-EntraPostureSnapshot.ps1'
        'src/Public/Invoke-EntraPostureEvaluation.ps1'
        'src/Public/New-EntraPostureReport.ps1'
        'src/Public/Compare-EntraPosture.ps1'
        'src/Public/Get-EntraPostureControl.ps1'
        'src/Public/Test-EntraPostureBundle.ps1'
    )

    # The only functions allowed to be exported from the built module. Everything else defined
    # under src/ (Common, Logging, and every non-Public layer added in later phases) stays
    # private. This list must exactly match the function names defined in src/Public/*.ps1 --
    # the build fails otherwise (missing export or unapproved export).
    ApprovedExports = @(
        'Invoke-EntraPosture'
        'Test-EntraPostureAccess'
        'New-EntraPostureSnapshot'
        'Invoke-EntraPostureEvaluation'
        'New-EntraPostureReport'
        'Compare-EntraPosture'
        'Get-EntraPostureControl'
        'Test-EntraPostureBundle'
    )
}
