#Requires -Version 7.4

function New-EntraPostureReport {
    <#
        .SYNOPSIS
        Renders an existing assessment as JSON, offline HTML, CSV, and a console summary.

        .DESCRIPTION
        Render-only command (engineering plan section 6.2). Never authenticates or calls the
        network (section 6.3). Every tenant-controlled value in the HTML output is escaped
        (section 10.1) -- see src/Reporting/RenderHtmlReport.ps1's own DESCRIPTION for the
        specific mechanism. Phase 9 added the fourth co-equal renderer the engineering plan names
        ("HTML, JSON, CSV, console") -- a full structured plain-text summary
        (New-EntraPostureConsoleReport), written to reports/summary.txt and printed directly to
        the console here, replacing what before Phase 9 was only a single Info-level log line.
        Console output remains a concise operational summary, never the authoritative record
        (section 10.1); assessment.json is.

        .PARAMETER AssessmentPath
        A directory sealed by Invoke-EntraPostureEvaluation.

        .PARAMETER SnapshotPath
        Optional -- enriches the report header with tenant/cloud/auth-mode context when the
        originating sealed snapshot is still available. See
        Invoke-EntraPostureReportPipeline's own docs for the fully-supported
        render-without-it case.

        .PARAMETER RedactionMode
        .PARAMETER NoConsoleOutput
        Suppresses printing the console summary to the host (e.g. for scripted/CI callers that
        only want the returned object) -- reports/summary.txt is still always written.

        .OUTPUTS
        Ordered dictionary: AssessmentJsonPath, HtmlReportPath, CsvReportPath, ConsoleReportPath.
        $null if -WhatIf was passed or the action was otherwise declined.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]$AssessmentPath,

        [Parameter()]
        [string]$SnapshotPath,

        [Parameter()]
        [ValidateSet('None', 'Identifiers', 'Strict')]
        [string]$RedactionMode = 'None',

        [Parameter()]
        [switch]$NoConsoleOutput
    )

    if (-not $PSCmdlet.ShouldProcess((Join-Path $AssessmentPath 'reports'), 'Write assessment.json / report.html / findings.csv / summary.txt')) {
        return $null
    }

    $reportParams = @{
        AssessmentPath = $AssessmentPath
        RedactionMode  = $RedactionMode
    }
    if ($SnapshotPath) { $reportParams['SnapshotPath'] = $SnapshotPath }

    $result = Invoke-EntraPostureReportPipeline @reportParams

    Write-EntraPostureLog -Level Info -Stage Reporting -Message "Report written: $($result.HtmlReportPath)" | Out-Null

    if (-not $NoConsoleOutput) {
        Write-Host $result.ConsoleReportText
    }

    return [ordered]@{
        AssessmentJsonPath = $result.AssessmentJsonPath
        HtmlReportPath      = $result.HtmlReportPath
        CsvReportPath       = $result.CsvReportPath
        ConsoleReportPath   = $result.ConsoleReportPath
    }
}
