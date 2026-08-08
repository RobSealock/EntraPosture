#Requires -Version 7.4

function ConvertTo-EntraPostureSafeCsvField {
    <#
        .SYNOPSIS
        Escapes one CSV field: standard RFC 4180 quoting plus formula-injection defense.

        .DESCRIPTION
        Engineering plan section 10.1: "findings.csv is a flat convenience export with
        formula-injection defenses." A field whose first character is '=', '+', '-', '@', a tab,
        or a carriage return is prefixed with a single quote -- the well-known
        OWASP-documented set of characters a spreadsheet application (Excel, Google Sheets, etc.)
        treats as "this cell is a formula" regardless of the column's declared type, which is
        exactly how a tenant-controlled string (e.g. a display name an attacker deliberately set
        to '=HYPERLINK(...)') could execute as a formula for whoever opens the export. The
        leading quote forces the cell to be treated as literal text in every spreadsheet
        application tested against this convention.

        Standard CSV quoting (wrap in double quotes, double any embedded double quote) is
        applied whenever the field contains a comma, double quote, or newline, per RFC 4180 --
        after the formula-injection prefix, so the prefix itself is always inside the quoted
        literal when both apply.

        .PARAMETER Value
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) { $Value = '' }

    if ($Value.Length -gt 0 -and $Value[0] -in @('=', '+', '-', '@', "`t", "`r")) {
        $Value = "'$Value"
    }

    if ($Value -match '[,"\r\n]') {
        $Value = '"' + ($Value -replace '"', '""') + '"'
    }

    return $Value
}

function New-EntraPostureCsvReport {
    <#
        .SYNOPSIS
        Renders an assessment document's control results as a flat CSV export.

        .PARAMETER AssessmentDocument
        Output of New-EntraPostureAssessmentDocument (optionally redacted).

        .OUTPUTS
        CSV text (CRLF line endings per RFC 4180, header row first).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory string rendering -- no external side effect. Writing the returned text to disk is the caller''s responsibility.')]
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$AssessmentDocument
    )

    $columns = @('controlId', 'scope', 'status', 'reasonCode', 'rationale', 'deviation', 'collectionCoverage', 'evaluatedAt')

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(($columns -join ','))

    foreach ($result in @($AssessmentDocument.results)) {
        # @() around the foreach, consistently applied project-wide regardless of whether this
        # specific array's size could ever actually be 1 -- $columns is fixed at 8 today, but
        # relying on "it happens not to be 1 right now" is exactly the kind of latent trap this
        # project has repeatedly found the hard way (see StrictJson.ps1's
        # ConvertTo-EntraPostureOrderedDictionary for the most recent example).
        $fields = @(foreach ($column in $columns) {
            ConvertTo-EntraPostureSafeCsvField -Value ([string]$result[$column])
        })
        $lines.Add(($fields -join ','))
    }

    return (($lines.ToArray()) -join "`r`n") + "`r`n"
}
