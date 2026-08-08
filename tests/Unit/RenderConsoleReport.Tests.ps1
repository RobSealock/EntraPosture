#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 9: the fourth co-equal renderer the engineering plan names ("HTML, JSON, CSV,
    console") -- before this phase, console output was a single Info-level log line.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Reporting/RenderConsoleReport.ps1')

    function script:New-TestAssessmentDocument {
        param([object[]]$Results = @(), [object[]]$Deviations = @(), [object[]]$Collectors = @())
        return [ordered]@{
            assessmentId = 'assess-1'; snapshotId = 'snap-1'; toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '1.0.0'
            tenantScope = 't1'; cloud = 'Public'; authMode = 'CertificateAppOnly'; collectionStartUtc = ''; collectionEndUtc = ''
            snapshotStatus = 'Sealed'; evaluatedAtUtc = '2026-01-01T00:00:00Z'
            coverage = [ordered]@{ collectors = @($Collectors) }
            results = @($Results); deviations = @($Deviations)
            summary = [ordered]@{
                controlResultCount = @($Results).Count
                statusCounts = [ordered]@{
                    Pass = @($Results | Where-Object { $_.status -eq 'Pass' }).Count
                    Fail = @($Results | Where-Object { $_.status -eq 'Fail' }).Count
                    NotApplicable = 0; NotEvaluated = 0; Error = 0
                }
                unapprovedFailCount = @($Results | Where-Object { $_.status -eq 'Fail' -and -not $_.deviation }).Count
                deviationCount = @($Deviations).Count
            }
        }
    }

    function script:New-TestResult {
        param([string]$ControlId, [string]$Scope, [string]$Status, [string]$Rationale = 'x', $Deviation = $null)
        return [ordered]@{
            controlId = $ControlId; controlVersion = '1.0.0'; evaluatorVersion = '0.1.0'
            scope = $Scope; status = $Status; reasonCode = 'X'; rationale = $Rationale
            evidenceReferences = @(); collectionCoverage = 'Complete'; evaluatedAt = '2026-01-01T00:00:00Z'
            remediation = 'x'; correlationId = [guid]::NewGuid().ToString(); deviation = $Deviation
        }
    }
}

Describe 'Remove-EntraPostureTerminalControlCharacter' {
    It 'strips an ANSI escape sequence' {
        $withEscape = "normal$([char]0x1B)[31mred$([char]0x1B)[0m"
        $cleaned = Remove-EntraPostureTerminalControlCharacter -Text $withEscape
        $cleaned | Should -Be 'normal[31mred[0m'
    }

    It 'preserves plain text unchanged' {
        Remove-EntraPostureTerminalControlCharacter -Text 'Global Administrator' | Should -Be 'Global Administrator'
    }

    It 'preserves newlines and tabs' {
        $text = "line1`nline2`ttabbed"
        Remove-EntraPostureTerminalControlCharacter -Text $text | Should -Be $text
    }
}

Describe 'New-EntraPostureConsoleReport' {
    It 'includes the tenant scope, status counts, and unapproved failure count' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail'))
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Match 'Tenant scope:\s+t1'
        $report | Should -Match '0 Pass / 1 Fail'
        $report | Should -Match 'Unapproved failures: 1'
    }

    It 'shows "Fail (Approved Deviation)" rather than plain Fail when a deviation is attached' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail' -Deviation 'dev-1'))
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Match 'Fail \(Approved Deviation\)'
    }

    It 'includes every control result''s controlId and rationale' {
        $doc = New-TestAssessmentDocument -Results @(
            (New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass' -Rationale 'Two admins, within range.')
            (New-TestResult -ControlId 'AC-002' -Scope 'default' -Status 'Fail' -Rationale 'Workflow disabled.')
        )
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Match 'PRIV-001'
        $report | Should -Match 'Two admins, within range\.'
        $report | Should -Match 'AC-002'
        $report | Should -Match 'Workflow disabled\.'
    }

    It 'uses a supplied control title instead of the bare controlId when provided' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc -ControlTitles @{ 'PRIV-001' = 'Global Administrator count is within range' }
        $report | Should -Match 'Global Administrator count is within range'
    }

    It 'includes coverage lines for every collector' {
        $doc = New-TestAssessmentDocument -Collectors @(
            [ordered]@{ collectorName = 'Users'; evidenceStatus = 'Collected'; accessVerified = $true }
            [ordered]@{ collectorName = 'PimEligibility'; evidenceStatus = 'Unavailable'; accessVerified = $false }
        )
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Match 'Users: Collected'
        $report | Should -Match 'PimEligibility: Unavailable'
    }

    It 'omits the Deviations section entirely when there are none' {
        $doc = New-TestAssessmentDocument
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Not -Match 'Deviations:'
    }

    It 'includes the Deviations section when deviations are present' {
        $doc = New-TestAssessmentDocument -Deviations @([ordered]@{ deviationId = 'dev-1'; controlId = 'PRIV-001'; approver = 'admin'; expiryDate = '2027-01-01' })
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Match 'Deviations:'
        $report | Should -Match 'dev-1'
    }

    It 'strips terminal control characters from tenant-controlled fields (e.g. a malicious display name flowing through rationale)' {
        $maliciousRationale = "Safe text$([char]0x1B)[31;1mFAKE ALERT$([char]0x1B)[0m"
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Fail' -Rationale $maliciousRationale))
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Not -Match ([regex]::Escape("$([char]0x1B)["))
        $report | Should -Match 'Safe text'
    }

    It 'uses LF line endings, not CRLF' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId 'PRIV-001' -Scope 'role-1' -Status 'Pass'))
        $report = New-EntraPostureConsoleReport -AssessmentDocument $doc
        $report | Should -Not -Match "`r`n"
    }
}
