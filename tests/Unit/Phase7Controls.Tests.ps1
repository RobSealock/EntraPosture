#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 7: "Port/reimplement EntraFalcon-relevant controls in dependency order: fixed-state,
    relational, transitive, then temporal/PIM..." Fixture-based Pass/Fail/NotApplicable coverage
    for the six controls built this phase, one Describe block per control, exercising each
    evaluator function directly against a hand-built evidence directory -- the same lightweight
    pattern tests/Unit/EvidenceProviderIndexing.Tests.ps1 uses, chosen because these evaluators
    only need a Provider handle, not a fully sealed/hashed snapshot.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateDefaultUserConsentPolicy.ps1',
        'src/Controls/EvaluateAdminConsentWorkflow.ps1',
        'src/Controls/EvaluateCrossTenantPartnerOverride.ps1',
        'src/Controls/EvaluateAccessReviewCoverage.ps1',
        'src/Controls/EvaluateAccessReviewInstanceHealth.ps1',
        'src/Controls/EvaluateSensitiveGroupProtection.ps1',
        'src/Controls/EvaluateStandingTierZeroAssignment.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "phase7-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestEntity {
        param([string]$EntityId, [string]$EntityType, [string]$DisplayName = $null, [System.Collections.Specialized.OrderedDictionary]$Properties)
        return [ordered]@{
            entityId = $EntityId; entityType = $EntityType; tenantScope = 't1'
            displayName = $DisplayName; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; properties = $Properties; redacted = $false
        }
    }

    function script:New-TestRelationship {
        param([string]$Source, [string]$Target, [string]$RelationshipType, [string]$AssignmentState = 'Active', [bool]$IsTransitive = $false)
        return [ordered]@{
            relationshipId = "$Source::$Target::$RelationshipType"; sourceEntityId = $Source; targetEntityId = $Target
            relationshipType = $RelationshipType; assignmentState = $AssignmentState; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $IsTransitive }
        }
    }
}

Describe 'AC-001: Test-EntraPostureDefaultUserConsentPolicyControl' {
    It 'Fails when the legacy policy is assigned' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $true; allowedToCreateSecurityGroups = $true; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDefaultUserConsentPolicyControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AC-001-LEGACY-POLICY-ASSIGNED'
    }

    It 'Passes when a restricted (low) policy is assigned' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDefaultUserConsentPolicyControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AC-001-RESTRICTED-POLICY-ASSIGNED'
    }

    It 'Reports NotApplicable when no AuthorizationPolicy entity exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDefaultUserConsentPolicyControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AC-001-NO-POLICY-FOUND'
    }
}

Describe 'AC-002: Test-EntraPostureAdminConsentWorkflowControl' {
    It 'Fails when the workflow is disabled' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-admin-consent-request-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AdminConsentRequestPolicy' -Properties ([ordered]@{
                isEnabled = $false; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 30; reviewerCount = 0
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAdminConsentWorkflowControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AC-002-WORKFLOW-DISABLED'
    }

    It 'Fails when enabled but no reviewers are configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-admin-consent-request-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AdminConsentRequestPolicy' -Properties ([ordered]@{
                isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 30; reviewerCount = 0
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAdminConsentWorkflowControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AC-002-NO-REVIEWERS-CONFIGURED'
    }

    It 'Passes when enabled with at least one reviewer' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-admin-consent-request-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AdminConsentRequestPolicy' -Properties ([ordered]@{
                isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 30; reviewerCount = 2
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAdminConsentWorkflowControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AC-002-WORKFLOW-CONFIGURED'
    }
}

Describe 'XTA-002: Test-EntraPostureCrossTenantPartnerOverrideControl' {
    BeforeAll {
        function script:New-XtaDefault {
            param([bool]$Mfa, [bool]$Compliant, [bool]$Hybrid)
            return New-TestEntity -EntityId 'default' -EntityType 'CrossTenantAccessPolicy' -Properties ([ordered]@{
                inboundTrustIsMfaAccepted = $Mfa; inboundTrustIsCompliantDeviceAccepted = $Compliant; inboundTrustIsHybridAzureADJoinedDeviceAccepted = $Hybrid
            })
        }
        function script:New-XtaPartner {
            param([string]$TenantId, [bool]$Mfa, [bool]$Compliant, [bool]$Hybrid)
            return New-TestEntity -EntityId $TenantId -EntityType 'CrossTenantAccessPolicyPartner' -Properties ([ordered]@{
                isServiceProvider = $false; inboundTrustIsMfaAccepted = $Mfa; inboundTrustIsCompliantDeviceAccepted = $Compliant; inboundTrustIsHybridAzureADJoinedDeviceAccepted = $Hybrid
            })
        }
    }

    It 'Reports NotApplicable when no partners are configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-cross-tenant-access-policy.jsonl' -Records @((New-XtaDefault -Mfa $false -Compliant $false -Hybrid $false))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureCrossTenantPartnerOverrideControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'XTA-002-NO-PARTNERS-CONFIGURED'
    }

    It 'Fails a partner whose trust is widened relative to the default' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-cross-tenant-access-policy.jsonl' -Records @((New-XtaDefault -Mfa $false -Compliant $false -Hybrid $false))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-cross-tenant-access-policy-partners.jsonl' -Records @((New-XtaPartner -TenantId 'partner-1' -Mfa $true -Compliant $false -Hybrid $false))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureCrossTenantPartnerOverrideControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'XTA-002-TRUST-WIDENED'
        $result[0].Scope | Should -Be 'partner-1'
    }

    It 'Passes a partner that is narrower than or equal to the default' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-cross-tenant-access-policy.jsonl' -Records @((New-XtaDefault -Mfa $true -Compliant $true -Hybrid $false))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-cross-tenant-access-policy-partners.jsonl' -Records @((New-XtaPartner -TenantId 'partner-2' -Mfa $true -Compliant $false -Hybrid $false))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureCrossTenantPartnerOverrideControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'XTA-002-NOT-WIDENED'
    }
}

Describe 'AR-001: Test-EntraPostureAccessReviewCoverageControl' {
    It 'Fails all three surfaces when no definitions exist' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 3
        ($result | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be 3
    }

    It 'Passes only the surfaces a definition actually covers' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @(
            (New-TestEntity -EntityId 'def-1' -EntityType 'AccessReviewDefinition' -DisplayName 'Group review' -Properties ([ordered]@{
                descriptionForAdmins = $null; status = 'Active'; scopeQuery = '/groups/abc-123/transitiveMembers'
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewCoverageControl -EvidenceProvider $provider
        ($result | Where-Object { $_.Scope -eq 'Groups' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'PrivilegedRoles' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'Applications' }).Status | Should -Be 'Fail'
    }
}

Describe 'AR-002: Test-EntraPostureAccessReviewInstanceHealthControl' {
    BeforeAll {
        function script:New-ArDefinition {
            param([string]$Id, [bool]$AutoApply = $false, [string]$ScopeQuery = '/groups/abc/transitiveMembers')
            return New-TestEntity -EntityId $Id -EntityType 'AccessReviewDefinition' -Properties ([ordered]@{
                descriptionForAdmins = $null; status = 'Active'; scopeQuery = $ScopeQuery; autoApplyDecisionsEnabled = $AutoApply
            })
        }
        function script:New-ArInstance {
            param([string]$Id, [string]$DefinitionId, [string]$Status, [string]$EndDateTime, [int]$Total = 0, [int]$Reviewed = 0, [int]$NotReviewed = 0, [int]$Applied = 0)
            return New-TestEntity -EntityId $Id -EntityType 'AccessReviewInstance' -Properties ([ordered]@{
                definitionId = $DefinitionId; startDateTime = '2020-01-01T00:00:00Z'; endDateTime = $EndDateTime; status = $Status
                decisionsTotalCount = $Total; decisionsReviewedCount = $Reviewed; decisionsNotReviewedCount = $NotReviewed; decisionsAppliedCount = $Applied
            })
        }
    }

    It 'reports NotApplicable when no AccessReviewDefinition matches an AR-001 surface at all' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AR-002-NO-APPLICABLE-INSTANCES'
    }

    It 'reports NotApplicable when a covering definition exists but has no collected instance yet' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'AR-002-NO-APPLICABLE-INSTANCES'
    }

    It 'Fails an instance past its end date that never reached a terminal status (AR-002-INSTANCE-OVERDUE)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-1' -DefinitionId 'def-1' -Status 'InProgress' -EndDateTime '2020-01-15T00:00:00Z')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AR-002-INSTANCE-OVERDUE'
        $result[0].Scope | Should -Be 'def-1::inst-1'
    }

    It 'Passes an instance that is in progress and not yet past its end date' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-1' -DefinitionId 'def-1' -Status 'InProgress' -EndDateTime '2099-01-15T00:00:00Z')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AR-002-HEALTHY'
    }

    It 'Fails a completed instance whose decisions were never applied when automatic apply is disabled (AR-002-DECISIONS-NOT-APPLIED)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1' -AutoApply $false))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-1' -DefinitionId 'def-1' -Status 'Completed' -EndDateTime '2020-01-15T00:00:00Z' -Total 4 -Reviewed 4 -NotReviewed 0 -Applied 0)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AR-002-DECISIONS-NOT-APPLIED'
    }

    It 'Fails a completed instance with more than 50% of decisions never reviewed (AR-002-MATERIALLY-INCOMPLETE)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1' -AutoApply $true))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-1' -DefinitionId 'def-1' -Status 'Completed' -EndDateTime '2020-01-15T00:00:00Z' -Total 10 -Reviewed 3 -NotReviewed 7 -Applied 3)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AR-002-MATERIALLY-INCOMPLETE'
    }

    It 'Passes a completed, fully-applied, fully-reviewed instance (AR-002-HEALTHY)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @((New-ArDefinition -Id 'def-1' -AutoApply $true))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-1' -DefinitionId 'def-1' -Status 'Completed' -EndDateTime '2020-01-15T00:00:00Z' -Total 10 -Reviewed 10 -NotReviewed 0 -Applied 10)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AR-002-HEALTHY'
    }

    It 'only evaluates definitions that match an AR-001 surface pattern, ignoring non-covering ones' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-definitions.jsonl' -Records @(
            (New-ArDefinition -Id 'def-covering' -ScopeQuery '/groups/abc/transitiveMembers')
            (New-ArDefinition -Id 'def-noncovering' -ScopeQuery '/some/unrelated/query')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-review-instances.jsonl' -Records @(
            (New-ArInstance -Id 'inst-covering' -DefinitionId 'def-covering' -Status 'Completed' -EndDateTime '2020-01-15T00:00:00Z' -Total 2 -Reviewed 2 -NotReviewed 0 -Applied 2)
            (New-ArInstance -Id 'inst-noncovering' -DefinitionId 'def-noncovering' -Status 'InProgress' -EndDateTime '2020-01-15T00:00:00Z')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessReviewInstanceHealthControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Scope | Should -Be 'def-covering::inst-covering'
    }
}

Describe 'GRP-005: Test-EntraPostureSensitiveGroupProtectionControl' {
    It 'Reports NotApplicable when no role-assignable groups exist' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestEntity -EntityId 'group-1' -EntityType 'Group' -DisplayName 'Ordinary Group' -Properties ([ordered]@{ groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $false }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSensitiveGroupProtectionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'GRP-005-NO-ROLE-ASSIGNABLE-GROUPS'
    }

    It 'Fails a role-assignable group with excessive transitive membership' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestEntity -EntityId 'group-1' -EntityType 'Group' -DisplayName 'Role Group' -Properties ([ordered]@{ groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $true }))
        )
        $memberRecords = 1..7 | ForEach-Object { New-TestRelationship -Source "user-$_" -Target 'group-1' -RelationshipType 'TransitiveMemberOf' -IsTransitive $true }
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records $memberRecords
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSensitiveGroupProtectionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'GRP-005-EXCESSIVE-TRANSITIVE-MEMBERSHIP'
    }

    It 'Passes a role-assignable group within the membership bound' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestEntity -EntityId 'group-1' -EntityType 'Group' -DisplayName 'Role Group' -Properties ([ordered]@{ groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $true }))
        )
        $memberRecords = 1..3 | ForEach-Object { New-TestRelationship -Source "user-$_" -Target 'group-1' -RelationshipType 'TransitiveMemberOf' -IsTransitive $true }
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records $memberRecords
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSensitiveGroupProtectionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'GRP-005-MEMBERSHIP-WITHIN-BOUND'
    }
}

Describe 'PIM-002: Test-EntraPostureStandingTierZeroAssignmentControl' {
    It 'Reports NotApplicable when no curated Tier-0 role was activated' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            (New-TestEntity -EntityId 'role-helpdesk' -EntityType 'DirectoryRole' -DisplayName 'Helpdesk Administrator' -Properties ([ordered]@{}))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureStandingTierZeroAssignmentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'PIM-002-NO-TIER-ZERO-ROLES-ACTIVATED'
    }

    It 'Fails a standing Global Administrator assignment with no PimEligible relationship' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            (New-TestEntity -EntityId 'ga-role' -EntityType 'DirectoryRole' -DisplayName 'Global Administrator' -Properties ([ordered]@{}))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestRelationship -Source 'user-standing' -Target 'ga-role' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureStandingTierZeroAssignmentControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-002-STANDING-ASSIGNMENT-OUTSIDE-PIM'
    }

    It 'Passes a Global Administrator assignment that has a matching PimEligible relationship' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            (New-TestEntity -EntityId 'ga-role' -EntityType 'DirectoryRole' -DisplayName 'Global Administrator' -Properties ([ordered]@{}))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestRelationship -Source 'user-governed' -Target 'ga-role' -RelationshipType 'DirectoryRoleAssignment' -AssignmentState 'Active')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-pim-eligibility.jsonl' -Records @(
            (New-TestRelationship -Source 'user-governed' -Target 'ga-role' -RelationshipType 'PimEligible' -AssignmentState 'Eligible')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureStandingTierZeroAssignmentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-002-ASSIGNMENT-GOVERNED-BY-PIM'
    }
}
