#Requires -Version 7.4

function Remove-EntraPostureTerminalControlCharacter {
    <#
        .SYNOPSIS
        Strips ASCII control characters (except newline/tab) from a string before it's printed
        to a terminal.

        .DESCRIPTION
        Covers ANSI escape sequences (ESC = 0x1B) and other terminal-manipulation attempts a
        tenant-controlled display name could otherwise carry into a printed console report -- the
        same "tenant-controlled strings are untrusted everywhere they appear" discipline this
        project already applies via HTML-encoding (New-EntraPostureHtmlReport) and CSV
        formula-injection defense (ConvertTo-EntraPostureSafeCsvField), applied to the
        console's own injection surface. A standalone top-level function, not nested inside
        New-EntraPostureConsoleReport -- confirmed during Compare-EntraPosture's own
        authoring this phase that Build-Module.ps1's function-duplicate/export scan searches
        nested scopes too, so nested nothing lives inside a rendering function's body in this
        project by convention now, matching how ConvertTo-EntraPostureSafeCsvField already
        sits alongside New-EntraPostureCsvReport as its own top-level function in the sibling
        CSV renderer file.

        .PARAMETER Text
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure string transformation -- no external side effect despite the Remove- verb.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    return ($Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
}

function New-EntraPostureConsoleReport {
    <#
        .SYNOPSIS
        Renders an assessment document as a plain-text, terminal-readable summary -- the fourth
        of the engineering plan's four co-equal renderers ("HTML, JSON, CSV, console").

        .DESCRIPTION
        Before Phase 9, the only console-facing output was a single Info-level log line ("Report
        written: ...") -- a real gap against the engineering plan's own naming of console as one
        of four renderers to complete, not three plus an incidental log line. This function
        follows the same pattern as every other renderer in this project (New-EntraPostureHtmlReport,
        New-EntraPostureCsvReport): a pure function that returns a string, with no opinion on
        whether the caller writes it to a file, prints it, both, or neither -- New-EntraPostureReport
        does both (writes reports/summary.txt and prints it via Write-Host).

        No HTML/CSV-specific escaping is needed here (a plain-text terminal has no markup-
        injection surface the way a browser or spreadsheet does), but tenant-controlled values are
        still never allowed to contain literal control characters that could manipulate terminal
        rendering (e.g. ANSI escape sequences) -- stripped defensively, since a malicious display
        name is exactly the kind of tenant-controlled string this project's redaction/escaping
        discipline already treats as untrusted everywhere else it appears.

        .PARAMETER AssessmentDocument
        Output of New-EntraPostureAssessmentDocument (optionally redacted).

        .PARAMETER ControlTitles
        Hashtable: controlId -> title, same as New-EntraPostureHtmlReport's parameter of the
        same name.

        .OUTPUTS
        Plain-text summary as a string (LF line endings).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory string rendering -- no external side effect. Printing/writing the returned text is the caller''s responsibility.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$AssessmentDocument,

        [Parameter()]
        [hashtable]$ControlTitles = @{}
    )

    $sb = [System.Text.StringBuilder]::new()
    $sanitize = { param([string]$Text) Remove-EntraPostureTerminalControlCharacter -Text ([string]$Text) }

    [void]$sb.AppendLine('Entra Assessment Report')
    [void]$sb.AppendLine('========================')
    [void]$sb.AppendLine("Tenant scope:        $(& $sanitize $AssessmentDocument.tenantScope)")
    [void]$sb.AppendLine("Cloud:               $(& $sanitize $AssessmentDocument.cloud)")
    [void]$sb.AppendLine("Auth mode:           $(& $sanitize $AssessmentDocument.authMode)")
    [void]$sb.AppendLine("Snapshot status:     $(& $sanitize $AssessmentDocument.snapshotStatus)")
    [void]$sb.AppendLine("Evaluated at (UTC):  $(& $sanitize $AssessmentDocument.evaluatedAtUtc)")
    [void]$sb.AppendLine('')

    $counts = $AssessmentDocument.summary.statusCounts
    [void]$sb.AppendLine("Results: $($counts.Pass) Pass / $($counts.Fail) Fail / $($counts.NotApplicable) NotApplicable / $($counts.NotEvaluated) NotEvaluated / $($counts.Error) Error")
    [void]$sb.AppendLine("Unapproved failures: $($AssessmentDocument.summary.unapprovedFailCount)")
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('Control Results:')
    foreach ($result in @($AssessmentDocument.results)) {
        $title = if ($ControlTitles.ContainsKey($result.controlId)) { $ControlTitles[$result.controlId] } else { $result.controlId }
        $statusText = if ($result.status -eq 'Fail' -and $result.deviation) { 'Fail (Approved Deviation)' } else { [string]$result.status }
        [void]$sb.AppendLine("  [$statusText] $(& $sanitize $result.controlId): $(& $sanitize $title) -- scope=$(& $sanitize $result.scope)")
        [void]$sb.AppendLine("      $(& $sanitize $result.rationale)")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('Coverage:')
    foreach ($collector in @($AssessmentDocument.coverage.collectors)) {
        [void]$sb.AppendLine("  $(& $sanitize $collector.collectorName): $(& $sanitize $collector.evidenceStatus) (accessVerified=$($collector.accessVerified))")
    }

    if (@($AssessmentDocument.deviations).Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Deviations:')
        foreach ($deviation in @($AssessmentDocument.deviations)) {
            [void]$sb.AppendLine("  $(& $sanitize $deviation.deviationId) -- $(& $sanitize $deviation.controlId), approver=$(& $sanitize $deviation.approver), expires $(& $sanitize $deviation.expiryDate)")
        }
    }

    return ($sb.ToString() -replace "`r`n", "`n")
}
