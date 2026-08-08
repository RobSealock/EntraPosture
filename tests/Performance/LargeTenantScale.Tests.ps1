#Requires -Version 7.4
#Requires -Modules Pester

<#
    Engineering plan section 12: "Test synthetic large-tenant fixtures for runtime, peak memory,
    output size, and throttle behavior" and "Make all result ordering deterministic
    independently of collection concurrency." Section 14 gate 10 (Performance).

    Focuses on the part of the pipeline Phase 6's indexing work directly targets: evidence-
    provider reads and offline evaluation at scale. Retry/backoff/throttle behavior under load
    is already covered against a real mock server in tests/Security/TransportAllowlist.Tests.ps1
    (Phase 4) -- not duplicated here.

    A synthetic sealed snapshot (thousands of relationship records, built and schema-validated
    directly, not through live HTTP collection -- HTTP round-trips at this volume would make the
    suite slow without testing anything this file is actually about) exercises
    Invoke-EntraPostureSnapshotEvaluation end to end and asserts: correctness at scale (the
    one role with a known member count is evaluated correctly despite thousands of unrelated
    relationships sharing the same file), deterministic ordering, and a generous, non-flaky
    runtime bound.
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
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/ControlRegistry.ps1', 'src/Controls/EvaluateCrossTenantInboundTrust.ps1',
        'src/Controls/EvaluatePrivilegedRoleAssignment.ps1',
        'src/Orchestration/EvaluateSnapshot.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    $script:GaRoleId = '62e90394-69f5-4237-9190-012177145e10'
    $script:OtherRoleCount = 60
    $script:MembersPerOtherRole = 40
    # Deliberately below PRIV-001's Pass range (2-4) so the evaluation-correctness assertion
    # below has an unambiguous expected outcome (Fail, TooFew) to check against.
    $script:GaMemberCount = 1
}

Describe 'Evidence provider and evaluation at large-tenant scale' {
    BeforeAll {
        $script:LargeSnapshotDir = Join-Path ([System.IO.Path]::GetTempPath()) "large-tenant-$([guid]::NewGuid())"
        $stagingPath = New-EntraPostureStagingDirectory -RunRoot ([System.IO.Path]::GetTempPath()) -SnapshotId (Split-Path -Leaf $script:LargeSnapshotDir)
        $script:LargeSnapshotDir = $stagingPath

        # Roles: Global Administrator plus 60 unrelated roles, all real, schema-shaped entities.
        $roleLines = [System.Collections.Generic.List[string]]::new()
        $roleLines.Add((ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{
            entityId = $script:GaRoleId; entityType = 'DirectoryRole'; tenantScope = 'perf-tenant'
            displayName = 'Global Administrator'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = '/v1.0/directoryRoles'; properties = [ordered]@{}; redacted = $false
        })))
        for ($r = 1; $r -le $script:OtherRoleCount; $r++) {
            $roleId = "role-$r"
            $roleLines.Add((ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{
                entityId = $roleId; entityType = 'DirectoryRole'; tenantScope = 'perf-tenant'
                displayName = "Role $r"; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
                sourceEndpoint = '/v1.0/directoryRoles'; properties = [ordered]@{}; redacted = $false
            })))
        }
        [System.IO.File]::WriteAllText((Join-Path $stagingPath 'evidence/entra-roles.jsonl'), (($roleLines.ToArray() -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))

        # Relationships: GA gets exactly $GaMemberCount members; every other role gets
        # $MembersPerOtherRole -- several thousand total relationship records sharing one file,
        # deliberately in scrambled (non-sorted) order to exercise the evidence provider's own
        # sort-at-load-time behavior at scale, not just insertion order.
        $relLines = [System.Collections.Generic.List[string]]::new()
        for ($u = 1; $u -le $script:GaMemberCount; $u++) {
            $userId = "ga-user-$u"
            $relLines.Add((ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{
                relationshipId = "$userId::$($script:GaRoleId)::DirectoryRoleAssignment"; sourceEntityId = $userId; targetEntityId = $script:GaRoleId
                relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'
                provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
                validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
            })))
        }
        for ($r = 1; $r -le $script:OtherRoleCount; $r++) {
            $roleId = "role-$r"
            for ($u = 1; $u -le $script:MembersPerOtherRole; $u++) {
                $userId = "role$r-user-$u"
                $relLines.Add((ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{
                    relationshipId = "$userId::$roleId::DirectoryRoleAssignment"; sourceEntityId = $userId; targetEntityId = $roleId
                    relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'
                    provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
                    validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
                })))
            }
        }
        # Deterministic shuffle (fixed seed) -- scrambles write order without making the test's
        # own outcome depend on wall-clock-seeded randomness.
        $random = [System.Random]::new(42)
        $shuffled = $relLines.ToArray() | Sort-Object { $random.Next() }
        [System.IO.File]::WriteAllText((Join-Path $stagingPath 'evidence/entra-role-assignments.jsonl'), (($shuffled -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
        $script:TotalRelationshipCount = $relLines.Count

        $coverage = [ordered]@{
            collectors = @(
                [ordered]@{ collectorName = 'DirectoryRoleAssignments'; accessRequested = @('RoleManagement.Read.Directory'); rightsPresentInToken = @('RoleManagement.Read.Directory'); rightsExpected = @('RoleManagement.Read.Directory'); accessVerified = $true; evidenceStatus = 'Collected'; affectedControlIds = @('PRIV-001'); affectedReportSections = @('Privileged Roles') }
            )
        }
        $manifestMetadata = [ordered]@{
            toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '1.0.0'; powerShellVersion = $PSVersionTable.PSVersion.ToString()
            tenantScope = 'perf-tenant'; cloud = 'Public'; authMode = 'CertificateAppOnly'
            collectionStartUtc = '2026-01-01T00:00:00Z'; collectionEndUtc = '2026-01-01T00:05:00Z'
        }
        Protect-EntraPostureSnapshot -StagingPath $stagingPath `
            -EvidenceSchemaMap @{ 'evidence/entra-roles.jsonl' = 'entity'; 'evidence/entra-role-assignments.jsonl' = 'relationship' } `
            -ManifestMetadata $manifestMetadata -SnapshotId (Split-Path -Leaf $stagingPath) -Coverage $coverage | Out-Null

        $script:Coverage = $coverage
    }

    AfterAll {
        Remove-Item -LiteralPath $script:LargeSnapshotDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'seals and hashes a multi-thousand-relationship snapshot' {
        # Note: $script:TotalRelationshipCount (and every other BeforeAll-assigned variable) is
        # not available for use in an `It` title string -- Pester evaluates titles during its
        # discovery phase, before any BeforeAll block has run at all, confirmed directly (an
        # earlier version of this title interpolated to a blank number). Titles in this file are
        # deliberately static text for exactly that reason.
        $trust = Test-EntraPostureBundleIntegrity -BundlePath $script:LargeSnapshotDir
        $trust.IsTrusted | Should -BeTrue
    }

    It 'returns the correct, order-independent count for one role among thousands of unrelated relationships' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:LargeSnapshotDir
        $gaAssignments = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $script:GaRoleId
        $gaAssignments.Count | Should -Be $script:GaMemberCount
    }

    It 'returns relationships in deterministic sourceEntityId-independent, relationshipId-ordinal order' {
        $providerA = New-EntraPostureEvidenceProvider -SnapshotPath $script:LargeSnapshotDir
        $allA = Get-EntraPostureRelationship -Provider $providerA -RelationshipType 'DirectoryRoleAssignment'

        $providerB = New-EntraPostureEvidenceProvider -SnapshotPath $script:LargeSnapshotDir
        $allB = Get-EntraPostureRelationship -Provider $providerB -RelationshipType 'DirectoryRoleAssignment'

        @($allA.relationshipId) | Should -Be @($allB.relationshipId)

        $sortedIds = [string[]]@($allA.relationshipId)
        $expectedSorted = $sortedIds.Clone()
        [Array]::Sort([Array]$expectedSorted, [System.Collections.IComparer][System.StringComparer]::Ordinal)
        @($sortedIds) | Should -Be @($expectedSorted)
    }

    It 'evaluates PRIV-001 correctly against thousands of total relationship records within a generous time bound' {
        $evaluatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $results = Invoke-EntraPostureSnapshotEvaluation -SnapshotPath $script:LargeSnapshotDir -Coverage $script:Coverage -EvaluatedAtUtc $evaluatedAtUtc
        $stopwatch.Stop()

        $privResult = $results | Where-Object { $_.controlId -eq 'PRIV-001' }
        $privResult.status | Should -Be 'Fail'
        $privResult.reasonCode | Should -Be 'PRIV-001-TOO-FEW-GLOBAL-ADMINS'

        # Generous, deliberately non-tight bound -- this asserts "does not degrade to
        # obviously-wrong linear-scan-per-lookup behavior at this scale," not a tuned
        # performance benchmark that would make the suite flaky on a loaded CI runner.
        $stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 30
    }
}
