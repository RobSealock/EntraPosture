#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 9: "Complete injection... tests." Confirmed neither renderer had a single dedicated
    security test before this file, despite the escaping/formula-injection-defense logic already
    existing (New-EntraPostureHtmlReport, ConvertTo-EntraPostureSafeCsvField) -- every prior
    exercise of these renderers (VerticalSlice.Tests.ps1) used benign fixture data, never a
    genuinely malicious tenant-controlled value. Directly targets the exact two findings Phase 1's
    regression analysis flagged against Conditional Access Validator (reflected/stored XSS via
    unescaped display names; CSV formula injection) to confirm this project's own renderers do not
    repeat them, with a real payload run all the way through, not by code inspection alone.

    Also covers basic HTML accessibility properties (semantic table headers, a declared language,
    text-based status indication alongside color, no external resources) -- the engineering plan's
    "accessibility" item in the same Phase 9 checklist line as injection.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Reporting/RenderHtmlReport.ps1')
    . (Join-Path $script:RepoRoot 'src/Reporting/RenderCsvReport.ps1')

    function script:New-TestAssessmentDocument {
        param([object[]]$Results = @())
        return [ordered]@{
            assessmentId = 'assess-1'; snapshotId = 'snap-1'; toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '1.0.0'
            tenantScope = 't1'; cloud = 'Public'; authMode = 'CertificateAppOnly'; collectionStartUtc = ''; collectionEndUtc = ''
            snapshotStatus = 'Sealed'; evaluatedAtUtc = '2026-01-01T00:00:00Z'
            coverage = [ordered]@{ collectors = @() }
            results = @($Results); deviations = @()
            summary = [ordered]@{ controlResultCount = @($Results).Count; statusCounts = [ordered]@{ Pass = 0; Fail = @($Results).Count; NotApplicable = 0; NotEvaluated = 0; Error = 0 }; unapprovedFailCount = @($Results).Count; deviationCount = 0 }
        }
    }

    function script:New-TestResult {
        param([string]$ControlId = 'PRIV-001', [string]$Scope = 'role-1', [string]$Status = 'Fail', [string]$ReasonCode = 'X', [string]$Rationale = 'x')
        return [ordered]@{
            controlId = $ControlId; controlVersion = '1.0.0'; evaluatorVersion = '0.1.0'
            scope = $Scope; status = $Status; reasonCode = $ReasonCode; rationale = $Rationale
            evidenceReferences = @(); collectionCoverage = 'Complete'; evaluatedAt = '2026-01-01T00:00:00Z'
            remediation = 'x'; correlationId = [guid]::NewGuid().ToString(); deviation = $null
        }
    }
}

Describe 'HTML report: reflected/stored XSS defense (Phase 1 finding against Conditional Access Validator, confirmed not repeated here)' {
    It 'escapes a script tag injected via a control''s rationale field' {
        $payload = '<script>alert(document.cookie)</script>'
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -Rationale $payload))
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc
        $html | Should -Not -Match '<script>alert'
        $html | Should -Match ([regex]::Escape('&lt;script&gt;'))
    }

    It 'escapes an event-handler-attribute injection attempt via the scope field' {
        $payload = '"><img src=x onerror=alert(1)>'
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -Scope $payload))
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc
        $html | Should -Not -Match '<img src=x onerror='
        $html | Should -Match ([regex]::Escape('&quot;&gt;&lt;img'))
    }

    It 'escapes a payload injected via the tenant scope / cloud header fields' {
        $payload = '<svg onload=alert(1)>'
        $doc = New-TestAssessmentDocument
        $doc.tenantScope = $payload
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc
        $html | Should -Not -Match '<svg onload='
        $html | Should -Match ([regex]::Escape('&lt;svg'))
    }

    It 'escapes a payload injected via a control ID (rendered through the ControlTitles lookup path)' {
        $payload = '<script>evil()</script>'
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -ControlId $payload))
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc -ControlTitles @{ $payload = 'Some Title' }
        $html | Should -Not -Match '<script>evil'
    }

    It 'contains no literal script tag anywhere in the rendered output, even with entirely benign data (no JS in the template at all)' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult))
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc
        $html | Should -Not -Match '<script'
    }
}

Describe 'HTML report: no external resources (offline-safe, engineering plan section 10.1)' {
    It 'contains no link tags, externally-sourced scripts, or remote-origin references' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult))
        $html = New-EntraPostureHtmlReport -AssessmentDocument $doc
        $html | Should -Not -Match '<link'
        $html | Should -Not -Match 'src="https?://'
        $html | Should -Not -Match 'href="https?://'
    }
}

Describe 'HTML report: basic accessibility properties' {
    BeforeAll {
        $script:AccessibilityDoc = New-TestAssessmentDocument -Results @((New-TestResult -Status 'Pass'), (New-TestResult -Status 'Fail'))
        $script:AccessibilityHtml = New-EntraPostureHtmlReport -AssessmentDocument $script:AccessibilityDoc
    }

    It 'declares a document language' {
        $script:AccessibilityHtml | Should -Match '<html lang="en">'
    }

    It 'declares a character encoding' {
        $script:AccessibilityHtml | Should -Match '<meta charset="utf-8">'
    }

    It 'every table has header cells (<th>), not bare <td> column labels' {
        $tableBlocks = [regex]::Matches($script:AccessibilityHtml, '<table>.*?</table>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $tableBlocks.Count | Should -BeGreaterThan 0
        foreach ($table in $tableBlocks) {
            $table.Value | Should -Match '<th>'
        }
    }

    It 'status is conveyed through visible text, not color/CSS class alone (a screen reader / no-CSS reader still sees Pass vs Fail)' {
        $script:AccessibilityHtml | Should -Match '>Pass<'
        $script:AccessibilityHtml | Should -Match '>Fail<'
    }

    It 'has a document title' {
        $script:AccessibilityHtml | Should -Match '<title>.+</title>'
    }
}

Describe 'CSV report: formula-injection defense (Phase 1 finding against both source tools, confirmed not repeated here)' {
    It 'neutralizes a rationale field starting with = (the classic =HYPERLINK/=cmd payload shape)' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -Rationale '=HYPERLINK("http://evil.example","click me")'))
        $csv = New-EntraPostureCsvReport -AssessmentDocument $doc
        $csv | Should -Match "'=HYPERLINK"
    }

    It 'neutralizes fields starting with +, -, or @' {
        foreach ($prefix in @('+', '-', '@')) {
            $doc = New-TestAssessmentDocument -Results @((New-TestResult -Rationale "${prefix}cmd|' /C calc'!A1"))
            $csv = New-EntraPostureCsvReport -AssessmentDocument $doc
            $csv | Should -Match ([regex]::Escape("'$prefix"))
        }
    }

    It 'does not alter a field that does not start with a formula-triggering character' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -Rationale 'Ordinary rationale text.'))
        $csv = New-EntraPostureCsvReport -AssessmentDocument $doc
        $csv | Should -Match 'Ordinary rationale text\.'
        $csv | Should -Not -Match "'Ordinary"
    }

    It 'still applies standard RFC 4180 quoting for a field containing a comma' {
        $doc = New-TestAssessmentDocument -Results @((New-TestResult -Rationale 'Contains, a comma'))
        $csv = New-EntraPostureCsvReport -AssessmentDocument $doc
        $csv | Should -Match '"Contains, a comma"'
    }
}
