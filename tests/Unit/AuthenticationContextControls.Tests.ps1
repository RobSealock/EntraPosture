#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 7: AUTHCTX-001/AUTHCTX-002, exercised against the exact fixture
    scenarios 15-feature-parity-matrix.md section 10's own design spec names for each control,
    via a real evidence-file-based provider (same pattern as tests/Unit/Phase7Controls.Tests.ps1),
    not shortcuts.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateAuthenticationContextCoverage.ps1',
        'src/Controls/EvaluateAuthenticationContextEffectiveness.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "authctx-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestContext {
        param([string]$Id, [string]$DisplayName = $null, [bool]$IsAvailable = $true)
        return [ordered]@{
            entityId = $Id; entityType = 'AuthenticationContextClassReference'; tenantScope = 't1'
            displayName = $DisplayName; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ description = $null; isAvailable = $IsAvailable }
        }
    }

    function script:New-TestPolicyAssignment {
        param([string]$Id, [string]$RoleDefinitionId, [bool]$AuthContextEnabled = $true, [string]$ClaimValue = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'RoleManagementPolicyAssignment'; tenantScope = 't1'
            displayName = $null; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                roleDefinitionId = $RoleDefinitionId; enabledRules = @(); isExpirationRequired = $null
                maximumDuration = $null; approvalRequired = $null
                authenticationContextEnabled = $AuthContextEnabled; authenticationContextClaimValue = $ClaimValue
            }
        }
    }

    function script:New-TestCaPolicy {
        param(
            [string]$Id, [string]$State = 'enabled',
            [string[]]$IncludeAuthContexts = @(), [string[]]$ExcludeUsers = @(), [string[]]$ExcludeGroups = @()
        )
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'
            displayName = $Id; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = @(); signInRiskLevels = @(); userRiskLevels = @(); servicePrincipalRiskLevels = @(); insiderRiskLevels = $null
                    users = [ordered]@{
                        includeUsers = @('All'); excludeUsers = $ExcludeUsers; includeGroups = @(); excludeGroups = $ExcludeGroups
                        includeRoles = @(); excludeRoles = @(); includeGuestOrExternalUserTypes = @(); excludeGuestOrExternalUserTypes = @()
                    }
                    applications = [ordered]@{
                        includeApplications = @('All'); excludeApplications = @(); includeUserActions = @()
                        includeAuthenticationContextClassReferences = $IncludeAuthContexts
                    }
                    platforms = [ordered]@{ includePlatforms = @(); excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                    clientApplications = [ordered]@{ includeServicePrincipals = @(); excludeServicePrincipals = @() }
                    authenticationFlowTransferMethods = $null
                }
                grantControls = [ordered]@{ operator = 'AND'; builtInControls = @('mfa'); customAuthenticationFactors = @(); termsOfUse = @(); authenticationStrengthId = $null }
                sessionControls = [ordered]@{
                    signInFrequencyIsEnabled = $null; signInFrequencyValue = $null; signInFrequencyType = $null; signInFrequencyAuthenticationType = $null
                    persistentBrowserIsEnabled = $null; persistentBrowserMode = $null
                    applicationEnforcedRestrictionsIsEnabled = $null; cloudAppSecurityIsEnabled = $null; cloudAppSecurityType = $null
                    disableResilienceDefaults = $null
                }
            }
        }
    }

    function script:New-TestRelationship {
        param([string]$Source, [string]$Target, [string]$RelationshipType, [string]$AssignmentState = 'Active')
        return [ordered]@{
            relationshipId = "$Source::$Target::$RelationshipType"; sourceEntityId = $Source; targetEntityId = $Target
            relationshipType = $RelationshipType; assignmentState = $AssignmentState; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = ($RelationshipType -eq 'TransitiveMemberOf') }
        }
    }
}

Describe 'AUTHCTX-001: Test-EntraPostureAuthenticationContextCoverageControl' {
    It 'Fails when a published, PIM-configured context has zero referencing policies' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1' -DisplayName 'High-Value Apps'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        # No entra-conditional-access.jsonl at all -- zero policies exist.
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-001-NO-REFERENCING-POLICY'
    }

    It 'Passes when at least one Conditional Access policy (any state) references the context' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'enabled' -IncludeAuthContexts @('c1')))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextCoverageControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-001-REFERENCED'
    }

    It 'excludes an unpublished context from evaluation entirely, even if PIM-configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1' -IsAvailable $false))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-001-NO-APPLICABLE-CONTEXTS'
    }

    It 'reports tenant-scoped NotApplicable when no context is both published and PIM-configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1' -IsAvailable $true))
        # No RoleManagementPolicyAssignment references it at all.
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextCoverageControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-001-NO-APPLICABLE-CONTEXTS'
    }
}

Describe 'AUTHCTX-002: Test-EntraPostureAuthenticationContextEffectivenessControl' {
    It 'Passes when the referencing policy is enabled, enforcing, and has no relevant exclusions' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'enabled' -IncludeAuthContexts @('c1')))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @((New-TestRelationship -Source 'user-1' -Target 'role-ga' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-EFFECTIVE'
    }

    It 'Fails with POLICY-DISABLED when the only referencing policy is disabled' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'disabled' -IncludeAuthContexts @('c1')))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @((New-TestRelationship -Source 'user-1' -Target 'role-ga' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-POLICY-DISABLED'
    }

    It 'Fails with POLICY-REPORT-ONLY when the only referencing policy is report-only' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'enabledForReportingButNotEnforced' -IncludeAuthContexts @('c1')))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @((New-TestRelationship -Source 'user-1' -Target 'role-ga' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-POLICY-REPORT-ONLY'
    }

    It 'Fails with ASSIGNEE-EXCLUDED when the policy is enabled but directly excludes an assignee' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'enabled' -IncludeAuthContexts @('c1') -ExcludeUsers @('user-1')))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @((New-TestRelationship -Source 'user-1' -Target 'role-ga' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-ASSIGNEE-EXCLUDED'
    }

    It 'Fails with ASSIGNEE-EXCLUDED when the policy excludes a group an eligible assignee is a transitive member of' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicy -Id 'p1' -State 'enabled' -IncludeAuthContexts @('c1') -ExcludeGroups @('grp-exempt')))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-pim-eligibility.jsonl' -Records @((New-TestRelationship -Source 'user-2' -Target 'role-ga' -RelationshipType 'PimEligible' -AssignmentState 'Eligible'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @((New-TestRelationship -Source 'user-2' -Target 'grp-exempt' -RelationshipType 'TransitiveMemberOf'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-ASSIGNEE-EXCLUDED'
    }

    It 'Passes when at least one of multiple referencing policies covers the full population, despite another being disabled' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @((New-TestPolicyAssignment -Id 'a1' -RoleDefinitionId 'role-ga' -ClaimValue 'c1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p-disabled' -State 'disabled' -IncludeAuthContexts @('c1'))
            (New-TestCaPolicy -Id 'p-effective' -State 'enabled' -IncludeAuthContexts @('c1'))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @((New-TestRelationship -Source 'user-1' -Target 'role-ga' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-EFFECTIVE'
    }

    It 'reports tenant-scoped NotApplicable when no applicable pairing exists' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-contexts.jsonl' -Records @((New-TestContext -Id 'c1'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAuthenticationContextEffectivenessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AUTHCTX-002-NO-APPLICABLE-PAIRINGS'
    }
}
