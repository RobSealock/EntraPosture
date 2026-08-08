#Requires -Version 7.4

function Test-EntraPostureAssessmentBundleIntegrity {
    <#
        .SYNOPSIS
        Hash/signature trust check for an assessment bundle -- the assessment-bundle analog of
        Test-EntraPostureBundleIntegrity, minus the manifest schema check.

        .DESCRIPTION
        Test-EntraPostureBundleIntegrity hardcodes a 'snapshot-manifest' schema check against
        manifest.json, which is correct for snapshot bundles but does not apply to an assessment
        bundle's manifest.json (a different, not-yet-schema-defined shape -- see
        Invoke-EntraPostureEvaluationPipeline's DESCRIPTION for why). This function reuses
        the exact same hash-recomputation and signature-verification logic (same shared
        primitives: Get-EntraPostureBundleFileInventory, Get-EntraPostureAggregateHash,
        Get-EntraPostureIntegrityAttestationPayload, Test-EntraPostureDetachedSignature)
        without the manifest-schema step, so an assessment bundle can be read back for
        reporting with the same "never trust recorded hashes at face value, always recompute
        from disk" discipline as a snapshot, without incorrectly rejecting it for not matching
        an unrelated schema.

        .PARAMETER BundlePath
        .OUTPUTS
        Ordered dictionary: IsTrusted, Status, Details -- same shape as
        Test-EntraPostureBundleIntegrity, minus Manifest (callers read manifest.json
        themselves; its shape is not this function's concern).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$BundlePath
    )

    $integrityPath = Join-Path $BundlePath 'integrity.json'
    if (-not (Test-Path -LiteralPath $integrityPath -PathType Leaf)) {
        return [ordered]@{ IsTrusted = $false; Status = 'NotSealed'; Details = "integrity.json missing under '$BundlePath' -- this is not a sealed bundle." }
    }

    try {
        $integrityJson = Get-Content -LiteralPath $integrityPath -Raw
        $recordedIntegrity = ConvertFrom-EntraPostureJson -Json $integrityJson
        $integritySchemaResult = Test-EntraPostureSchema -Json $integrityJson -ContractName 'integrity'
        if (-not $integritySchemaResult.IsValid) {
            return [ordered]@{ IsTrusted = $false; Status = 'HashMismatch'; Details = "integrity.json does not conform to its schema (treated as corrupt): $($integritySchemaResult.Errors -join '; ')" }
        }
    } catch {
        return [ordered]@{ IsTrusted = $false; Status = 'HashMismatch'; Details = "integrity.json could not be parsed (treated as corrupt): $($_.Exception.Message)" }
    }

    $actualInventory = Get-EntraPostureBundleFileInventory -BundleRoot $BundlePath -ExcludeDirectoryName 'reports'
    $actualAggregate = $actualInventory | Get-EntraPostureAggregateHash

    $recordedPayload = Get-EntraPostureIntegrityAttestationPayload -Files $recordedIntegrity.files -AggregateHash $recordedIntegrity.aggregateHash -RecordCount $recordedIntegrity.recordCount
    $recordedPayloadJson = ConvertTo-EntraPostureCanonicalJson -InputObject $recordedPayload
    $recordedPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($recordedPayloadJson)

    if ($recordedIntegrity.signatureStatus -eq 'Signed') {
        $p7sPath = Join-Path $BundlePath ($recordedIntegrity.signature.detachedSignatureFile)
        if (-not (Test-Path -LiteralPath $p7sPath -PathType Leaf)) {
            return [ordered]@{ IsTrusted = $false; Status = 'InvalidSignature'; Details = "integrity.json declares signatureStatus 'Signed' but the referenced signature file is missing." }
        }
        $signatureBytes = [System.IO.File]::ReadAllBytes($p7sPath)
        if (-not (Test-EntraPostureDetachedSignature -Content $recordedPayloadBytes -SignatureBytes $signatureBytes)) {
            return [ordered]@{ IsTrusted = $false; Status = 'InvalidSignature'; Details = 'The detached signature does not validate against the recorded integrity attestation payload.' }
        }
    }

    if ($actualAggregate.aggregateHash -ne $recordedIntegrity.aggregateHash) {
        return [ordered]@{ IsTrusted = $false; Status = 'HashMismatch'; Details = "Recomputed aggregate hash ($($actualAggregate.aggregateHash)) does not match the recorded aggregate hash ($($recordedIntegrity.aggregateHash))." }
    }

    $finalStatus = if ($recordedIntegrity.signatureStatus -eq 'Signed') { 'Signed' } else { 'Unsigned' }
    return [ordered]@{ IsTrusted = $true; Status = $finalStatus; Details = 'Bundle hashes match recorded integrity record.' }
}

function Invoke-EntraPostureReportPipeline {
    <#
        .SYNOPSIS
        Render-only pipeline: reads back an already-sealed assessment bundle, optionally
        redacts, and writes assessment.json/report.html/findings.csv into its reports/
        subdirectory. Never authenticates or calls the network (section 6.3).

        .PARAMETER AssessmentPath
        A directory sealed by Invoke-EntraPostureEvaluationPipeline.

        .PARAMETER SnapshotPath
        Optional. The assessment manifest only carries snapshotId and evaluatedAtUtc -- not
        tenantScope/cloud/authMode/collection window -- so when the original sealed snapshot is
        still available (e.g. rendering right after evaluation in the same run), passing its
        path enriches the report header with that context. Rendering an assessment bundle on
        its own, without its originating snapshot present, is a fully supported "render-only"
        case (engineering plan section 6.2) -- those fields are simply left blank rather than
        the render being refused.

        .PARAMETER RedactionMode
        .OUTPUTS
        Ordered dictionary: AssessmentJsonPath, HtmlReportPath, CsvReportPath.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AssessmentPath,

        [Parameter()]
        [string]$SnapshotPath,

        [Parameter()]
        [ValidateSet('None', 'Identifiers', 'Strict')]
        [string]$RedactionMode = 'None'
    )

    $trust = Test-EntraPostureAssessmentBundleIntegrity -BundlePath $AssessmentPath
    if (-not $trust.IsTrusted) {
        throw "Invoke-EntraPostureReportPipeline: refusing to render '$AssessmentPath' -- not trusted (status: $($trust.Status)). $($trust.Details)"
    }

    $manifest = ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath (Join-Path $AssessmentPath 'manifest.json') -Raw)

    $resultLines = @(Get-Content -LiteralPath (Join-Path $AssessmentPath 'results.jsonl') | Where-Object { $_.Trim().Length -gt 0 })
    $results = @(foreach ($line in $resultLines) { ConvertFrom-EntraPostureJson -Json $line })

    $deviationsFilePath = Join-Path $AssessmentPath 'deviations.jsonl'
    $deviationLines = @(Get-Content -LiteralPath $deviationsFilePath -ErrorAction SilentlyContinue | Where-Object { $_.Trim().Length -gt 0 })
    $deviations = @(foreach ($line in $deviationLines) { ConvertFrom-EntraPostureJson -Json $line })

    if ($SnapshotPath) {
        $snapshotManifest = Get-EntraPostureTrustedSnapshot -BundlePath $SnapshotPath
        $coveragePath = Join-Path $SnapshotPath 'coverage.json'
        $coverage = if (Test-Path -LiteralPath $coveragePath -PathType Leaf) {
            ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $coveragePath -Raw)
        } else {
            [ordered]@{ collectors = @() }
        }
    } else {
        $snapshotManifest = [ordered]@{
            snapshotId         = $manifest.snapshotId
            tenantScope        = ''
            cloud              = ''
            authMode           = ''
            collectionStartUtc = ''
            collectionEndUtc   = ''
            status             = ''
        }
        $coverage = [ordered]@{ collectors = @() }
    }

    $assessmentDocument = New-EntraPostureAssessmentDocument -SnapshotManifest $snapshotManifest -EvaluationId $manifest.evaluationId `
        -Coverage $coverage -Results $results -Deviations $deviations -EvaluatedAtUtc $manifest.evaluatedAtUtc

    $redacted = Protect-EntraPostureReportRedaction -AssessmentDocument $assessmentDocument -RedactionMode $RedactionMode

    $controlTitles = @{}
    foreach ($control in (Get-EntraPostureControlRegistry)) { $controlTitles[$control.controlId] = $control.title }

    $reportsDir = Join-Path $AssessmentPath 'reports'
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null

    $assessmentJsonPath = Join-Path $reportsDir 'assessment.json'
    [System.IO.File]::WriteAllText($assessmentJsonPath, (ConvertTo-EntraPostureCanonicalJson -InputObject $redacted), [System.Text.UTF8Encoding]::new($false))

    $htmlPath = Join-Path $reportsDir 'report.html'
    $html = New-EntraPostureHtmlReport -AssessmentDocument $redacted -ControlTitles $controlTitles
    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($false))

    $csvPath = Join-Path $reportsDir 'findings.csv'
    $csv = New-EntraPostureCsvReport -AssessmentDocument $redacted
    [System.IO.File]::WriteAllText($csvPath, $csv, [System.Text.UTF8Encoding]::new($false))

    $consolePath = Join-Path $reportsDir 'summary.txt'
    $console = New-EntraPostureConsoleReport -AssessmentDocument $redacted -ControlTitles $controlTitles
    [System.IO.File]::WriteAllText($consolePath, $console, [System.Text.UTF8Encoding]::new($false))

    return [ordered]@{
        AssessmentJsonPath = $assessmentJsonPath
        HtmlReportPath      = $htmlPath
        CsvReportPath       = $csvPath
        ConsoleReportPath   = $consolePath
        ConsoleReportText   = $console
    }
}
