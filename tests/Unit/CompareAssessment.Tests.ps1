#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 9: Compare-EntraPosture's core comparison logic
    (Compare-EntraPostureAssessmentDocument), engineering plan section 10.3's five-category
    classification (a sixth, What If changes, is a documented v1 boundary -- see
    src/Reporting/CompareAssessment.ps1's own DESCRIPTION). Exercises the pure comparison
    function directly with fixture assessment documents -- the bundle-loading/trust-verification
    half of Compare-EntraPosture (the Public command) is exercised end to end by
    tests/Integration/VerticalSlice.Tests.ps1 instead, matching how every other Public command's
    split between "thin wrapper" and "real logic" is tested in this project.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Reporting/CompareAssessment.ps1')

    function script:New-TestResult {
        param([string]$ControlId, [string]$Scope, [string]$Status, [string]$ReasonCode = 'X', [string]$ControlVersion = '1.0.0', [string]$EvaluatorVersion = '0.1.0')
        return [ordered]@{
            controlId = $ControlId; controlVersion = $ControlVersion; evaluatorVersion = $EvaluatorVersion
            scope = $Scope; status = $Status; reasonCode = $ReasonCode; rationale = 'x'
            evidenceReferences = @(); collectionCoverage = 'Complete'; evaluatedAt = '2026-01-01T00:00:00Z'
            remediation = 'x'; correlationId = [guid]::NewGuid().ToString(); deviation = $null
        }
    }

    function script:New-TestDocument {
        param([object[]]$Results = @(), [object[]]$Deviations = @(), [object[]]$Collectors = @())
        return [ordered]@{
            assessmentId = 'assess-1'; snapshotId = 'snap-1'; toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '1.0.0'
            tenantScope = 't1'; cloud = 'Public'; authMode = 'CertificateAppOnly'; collectionStartUtc = ''; collectionEndUtc = ''
            snapshotStatus = 'Sealed'; evaluatedAtUtc = '2026-01-01T00:00:00Z'
            coverage = [ordered]@{ collectors = @($Collectors) }
            results = @($Results); deviations = @($Deviations)
            summary = [ordered]@{ controlResultCount = @($Results).Count; statusCounts = [ordered]@{}; unapprovedFailCount = 0; deviationCount = @($Deviations).Count }
        }
    }
}

Describe 'Compare-EntraPostureAssessmentDocument: result transitions' {
    It 'reports a Pass-to-Fail transition for the same (controlId, scope)' {
        $old = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $new = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail'))
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.ResultTransitions.Count | Should -Be 1
        $comparison.ResultTransitions[0].OldStatus | Should -Be 'Pass'
        $comparison.ResultTransitions[0].NewStatus | Should -Be 'Fail'
    }

    It 'reports no transition when status is unchanged' {
        $old = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $new = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.ResultTransitions.Count | Should -Be 0
    }

    It 'flags VersionChanged when controlVersion differs alongside a status change' {
        $old = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail' -ControlVersion '1.0.0'))
        $new = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass' -ControlVersion '1.1.0'))
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.ResultTransitions[0].VersionChanged | Should -BeTrue
    }

    It 'does not flag VersionChanged when only status changed, versions identical' {
        $old = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail'))
        $new = New-TestDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.ResultTransitions[0].VersionChanged | Should -BeFalse
    }
}

Describe 'Compare-EntraPostureAssessmentDocument: added and removed results' {
    It 'reports a result present only in the new assessment as Added, not a fabricated transition' {
        $old = New-TestDocument -Results @()
        $new = New-TestDocument -Results @((New-TestResult -ControlId 'CA-001' -Scope 'windows::browser' -Status 'Fail'))
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.AddedResults.Count | Should -Be 1
        $comparison.ResultTransitions.Count | Should -Be 0
        $comparison.AddedResults[0].NewStatus | Should -Be 'Fail'
    }

    It 'reports a result present only in the old assessment as Removed' {
        $old = New-TestDocument -Results @((New-TestResult -ControlId 'PIM-002' -Scope 'user-1::role-1' -Status 'Fail'))
        $new = New-TestDocument -Results @()
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.RemovedResults.Count | Should -Be 1
        $comparison.RemovedResults[0].OldStatus | Should -Be 'Fail'
    }
}

Describe 'Compare-EntraPostureAssessmentDocument: coverage changes' {
    It 'reports a collector whose evidenceStatus changed between assessments' {
        $old = New-TestDocument -Collectors @([ordered]@{ collectorName = 'Users'; evidenceStatus = 'Denied' })
        $new = New-TestDocument -Collectors @([ordered]@{ collectorName = 'Users'; evidenceStatus = 'Collected' })
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.CoverageChanges.Count | Should -Be 1
        $comparison.CoverageChanges[0].OldEvidenceStatus | Should -Be 'Denied'
        $comparison.CoverageChanges[0].NewEvidenceStatus | Should -Be 'Collected'
    }

    It 'reports no coverage change when evidenceStatus is unchanged' {
        $old = New-TestDocument -Collectors @([ordered]@{ collectorName = 'Users'; evidenceStatus = 'Collected' })
        $new = New-TestDocument -Collectors @([ordered]@{ collectorName = 'Users'; evidenceStatus = 'Collected' })
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.CoverageChanges.Count | Should -Be 0
    }
}

Describe 'Compare-EntraPostureAssessmentDocument: deviation changes' {
    It 'reports a new deviation as Added' {
        $old = New-TestDocument -Deviations @()
        $new = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2027-01-01'; justification = 'x'; approver = 'admin' })
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.DeviationChanges.Count | Should -Be 1
        $comparison.DeviationChanges[0].ChangeType | Should -Be 'Added'
    }

    It 'reports an expired/removed deviation as Removed' {
        $old = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2027-01-01'; justification = 'x'; approver = 'admin' })
        $new = New-TestDocument -Deviations @()
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.DeviationChanges[0].ChangeType | Should -Be 'Removed'
    }

    It 'reports a changed expiry date on the same deviation as Modified' {
        $old = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2027-01-01'; justification = 'x'; approver = 'admin' })
        $new = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2028-01-01'; justification = 'x'; approver = 'admin' })
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.DeviationChanges[0].ChangeType | Should -Be 'Modified'
    }

    It 'reports no deviation change when nothing about it differs' {
        $old = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2027-01-01'; justification = 'x'; approver = 'admin' })
        $new = New-TestDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; expiryDate = '2027-01-01'; justification = 'x'; approver = 'admin' })
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.DeviationChanges.Count | Should -Be 0
    }
}

Describe 'Compare-EntraPostureAssessmentDocument: summary and empty inputs' {
    It 'produces a zeroed summary for two identical empty assessments' {
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument (New-TestDocument) -NewAssessmentDocument (New-TestDocument)
        $comparison.Summary.ResultTransitionCount | Should -Be 0
        $comparison.Summary.AddedResultCount | Should -Be 0
        $comparison.Summary.RemovedResultCount | Should -Be 0
        $comparison.Summary.CoverageChangeCount | Should -Be 0
        $comparison.Summary.DeviationChangeCount | Should -Be 0
    }

    It 'summary counts match the actual array lengths for a mixed set of changes' {
        $old = New-TestDocument -Results @(
            (New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass')
            (New-TestResult -ControlId 'PIM-002' -Scope 'user-1::role-1' -Status 'Fail')
        )
        $new = New-TestDocument -Results @(
            (New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail')
            (New-TestResult -ControlId 'CA-001' -Scope 'windows::browser' -Status 'Pass')
        )
        $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $old -NewAssessmentDocument $new
        $comparison.Summary.ResultTransitionCount | Should -Be $comparison.ResultTransitions.Count
        $comparison.Summary.AddedResultCount | Should -Be $comparison.AddedResults.Count
        $comparison.Summary.RemovedResultCount | Should -Be $comparison.RemovedResults.Count
        $comparison.ResultTransitions.Count | Should -Be 1
        $comparison.AddedResults.Count | Should -Be 1
        $comparison.RemovedResults.Count | Should -Be 1
    }
}
