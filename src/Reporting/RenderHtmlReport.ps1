#Requires -Version 7.4

function New-EntraPostureHtmlReport {
    <#
        .SYNOPSIS
        Renders an assessment document as a single self-contained, offline HTML report.

        .DESCRIPTION
        Engineering plan section 10.1: "report.html is self-contained, offline, and contains no
        CDN, fonts, analytics, or network calls... HTML rendering escapes every tenant-controlled
        value and is tested for script/style/URI injection." Every tenant-controlled string
        (control title/rationale, scope, reasonCode, entityId/entityType, tenant scope, cloud)
        is passed through [System.Net.WebUtility]::HtmlEncode before being written into the
        markup -- none of it is ever concatenated in raw. There is no <script> anywhere in this
        template and no code path that could add one (no JS at all means no injection surface
        via script content, only via unescaped markup/attributes, which the encoding above
        closes). Styling is a single inline <style> block; no external stylesheet, font, image,
        or any other resource is referenced.

        .PARAMETER AssessmentDocument
        Output of New-EntraPostureAssessmentDocument (optionally passed through
        Protect-EntraPostureReportRedaction first).

        .PARAMETER ControlTitles
        Hashtable: controlId -> title, for a more readable report (control-result records only
        carry controlId, not the definition's title/category -- the caller supplies this from
        the control registry rather than this function re-loading it itself, keeping report
        rendering free of any registry/disk dependency of its own).

        .OUTPUTS
        Complete HTML document as a string.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory string rendering -- no external side effect. Writing the returned markup to disk is the caller''s responsibility.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$AssessmentDocument,

        [Parameter()]
        [hashtable]$ControlTitles = @{}
    )

    $enc = { param([string]$Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<!DOCTYPE html>`n<html lang=`"en`">`n<head>`n<meta charset=`"utf-8`">`n")
    [void]$sb.Append("<title>Entra Assessment Report</title>`n")
    [void]$sb.Append("<style>`n")
    [void]$sb.Append("body { font-family: sans-serif; margin: 2em; color: #1a1a1a; }`n")
    [void]$sb.Append("table { border-collapse: collapse; width: 100%; margin-bottom: 2em; }`n")
    [void]$sb.Append("th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }`n")
    [void]$sb.Append("th { background: #f0f0f0; }`n")
    [void]$sb.Append(".status-Pass { color: #0a6b0a; font-weight: bold; }`n")
    [void]$sb.Append(".status-Fail { color: #b00020; font-weight: bold; }`n")
    [void]$sb.Append(".status-NotApplicable, .status-NotEvaluated { color: #666; }`n")
    [void]$sb.Append(".status-Error { color: #b00020; font-style: italic; }`n")
    [void]$sb.Append("</style>`n</head>`n<body>`n")

    [void]$sb.Append("<h1>Entra Assessment Report</h1>`n")
    [void]$sb.Append("<table>`n")
    [void]$sb.Append("<tr><th>Tenant scope</th><td>$(& $enc $AssessmentDocument.tenantScope)</td></tr>`n")
    [void]$sb.Append("<tr><th>Cloud</th><td>$(& $enc $AssessmentDocument.cloud)</td></tr>`n")
    [void]$sb.Append("<tr><th>Auth mode</th><td>$(& $enc $AssessmentDocument.authMode)</td></tr>`n")
    [void]$sb.Append("<tr><th>Snapshot status</th><td>$(& $enc $AssessmentDocument.snapshotStatus)</td></tr>`n")
    [void]$sb.Append("<tr><th>Tool / schema / control-registry version</th><td>$(& $enc $AssessmentDocument.toolVersion) / $(& $enc $AssessmentDocument.schemaVersion) / $(& $enc $AssessmentDocument.controlRegistryVersion)</td></tr>`n")
    [void]$sb.Append("<tr><th>Evaluated at (UTC)</th><td>$(& $enc $AssessmentDocument.evaluatedAtUtc)</td></tr>`n")
    [void]$sb.Append("<tr><th>Results: Pass / Fail / NotApplicable / NotEvaluated / Error</th><td>$($AssessmentDocument.summary.statusCounts.Pass) / $($AssessmentDocument.summary.statusCounts.Fail) / $($AssessmentDocument.summary.statusCounts.NotApplicable) / $($AssessmentDocument.summary.statusCounts.NotEvaluated) / $($AssessmentDocument.summary.statusCounts.Error)</td></tr>`n")
    [void]$sb.Append("<tr><th>Unapproved failures</th><td>$($AssessmentDocument.summary.unapprovedFailCount)</td></tr>`n")
    [void]$sb.Append("</table>`n")

    [void]$sb.Append("<h2>Control Results</h2>`n<table>`n")
    [void]$sb.Append("<tr><th>Control</th><th>Scope</th><th>Status</th><th>Reason Code</th><th>Rationale</th><th>Deviation</th></tr>`n")
    foreach ($result in @($AssessmentDocument.results)) {
        $title = if ($ControlTitles.ContainsKey($result.controlId)) { $ControlTitles[$result.controlId] } else { $result.controlId }
        $statusText = if ($result.status -eq 'Fail' -and $result.deviation) { 'Fail -- Approved Deviation' } else { [string]$result.status }
        [void]$sb.Append("<tr>")
        [void]$sb.Append("<td>$(& $enc $result.controlId): $(& $enc $title)</td>")
        [void]$sb.Append("<td>$(& $enc $result.scope)</td>")
        [void]$sb.Append("<td class=`"status-$(& $enc $result.status)`">$(& $enc $statusText)</td>")
        [void]$sb.Append("<td>$(& $enc $result.reasonCode)</td>")
        [void]$sb.Append("<td>$(& $enc $result.rationale)</td>")
        [void]$sb.Append("<td>$(& $enc $result.deviation)</td>")
        [void]$sb.Append("</tr>`n")
    }
    [void]$sb.Append("</table>`n")

    [void]$sb.Append("<h2>Coverage</h2>`n<table>`n")
    [void]$sb.Append("<tr><th>Collector</th><th>Evidence Status</th><th>Access Verified</th></tr>`n")
    foreach ($collector in @($AssessmentDocument.coverage.collectors)) {
        [void]$sb.Append("<tr>")
        [void]$sb.Append("<td>$(& $enc $collector.collectorName)</td>")
        [void]$sb.Append("<td>$(& $enc $collector.evidenceStatus)</td>")
        [void]$sb.Append("<td>$(& $enc $collector.accessVerified)</td>")
        [void]$sb.Append("</tr>`n")
    }
    [void]$sb.Append("</table>`n")

    if (@($AssessmentDocument.deviations).Count -gt 0) {
        [void]$sb.Append("<h2>Deviations</h2>`n<table>`n")
        [void]$sb.Append("<tr><th>ID</th><th>Control</th><th>Scope</th><th>Approver</th><th>Justification</th><th>Expiry</th></tr>`n")
        foreach ($deviation in @($AssessmentDocument.deviations)) {
            [void]$sb.Append("<tr>")
            [void]$sb.Append("<td>$(& $enc $deviation.deviationId)</td>")
            [void]$sb.Append("<td>$(& $enc $deviation.controlId)</td>")
            [void]$sb.Append("<td>$(& $enc $deviation.objectScope)</td>")
            [void]$sb.Append("<td>$(& $enc $deviation.approver)</td>")
            [void]$sb.Append("<td>$(& $enc $deviation.justification)</td>")
            [void]$sb.Append("<td>$(& $enc $deviation.expiryDate)</td>")
            [void]$sb.Append("</tr>`n")
        }
        [void]$sb.Append("</table>`n")
    }

    [void]$sb.Append("</body>`n</html>`n")

    return $sb.ToString()
}
