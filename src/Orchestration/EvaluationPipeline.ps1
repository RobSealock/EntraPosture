#Requires -Version 7.4

function Invoke-EntraPostureEvaluationPipeline {
    <#
        .SYNOPSIS
        Evaluate-only pipeline: trust-gate a sealed snapshot, evaluate it entirely offline,
        apply deviations, and seal the resulting assessment bundle.

        .DESCRIPTION
        Engineering plan section 8.3: "the snapshot and each derived assessment are separately
        immutable and sealed." This function seals the assessments/<evaluation-id>/ bundle
        (manifest.json, results.jsonl, deviations.jsonl, summary.json, integrity.json) using the
        same generic SHA-256/integrity primitives Protect-EntraPostureSnapshot uses
        (Get-EntraPostureBundleFileInventory, Get-EntraPostureAggregateHash,
        Get-EntraPostureIntegrityAttestationPayload, New-EntraPostureDetachedSignature),
        which are shape-agnostic and were never specific to the snapshot bundle despite where
        they happen to live in src/. Unlike the snapshot manifest, this assessment manifest.json
        has no dedicated schema yet (00-open-questions.md's Phase 5 section notes this as a
        deliberate, deferred-to-Phase-9 scope boundary) -- it is still written and hashed, just
        not schema-validated the way results.jsonl/deviations.jsonl entries individually are.

        Never calls the network -- Get-EntraPostureEvidenceProvider only reads from the
        already-on-disk, already-trust-verified snapshot (ADR-019).

        .PARAMETER SnapshotPath
        .PARAMETER RunRoot
        Parent directory under which assessments/<evaluation-id>/ is created.

        .PARAMETER Deviations
        Array of ordered dictionaries matching deviation.schema.json. Defaults to none.

        .PARAMETER SigningCertificate
        Optional detached-signing certificate for the assessment bundle.

        .OUTPUTS
        Ordered dictionary: AssessmentPath, EvaluationId, SnapshotManifest, Coverage, Results
        (post-deviation), Deviations.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$SnapshotPath,

        [Parameter(Mandatory)]
        [string]$RunRoot,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Deviations = @(),

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate
    )

    $snapshotManifest = Get-EntraPostureTrustedSnapshot -BundlePath $SnapshotPath

    $coveragePath = Join-Path $SnapshotPath 'coverage.json'
    $coverage = if (Test-Path -LiteralPath $coveragePath -PathType Leaf) {
        ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $coveragePath -Raw)
    } else {
        [ordered]@{ collectors = @() }
    }

    $evaluatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $rawResults = Invoke-EntraPostureSnapshotEvaluation -SnapshotPath $SnapshotPath -Coverage $coverage -EvaluatedAtUtc $evaluatedAtUtc
    $finalResults = Set-EntraPostureControlResultDeviation -Results $rawResults -Deviations $Deviations -AsOfDate (Get-Date).ToUniversalTime().Date

    $evaluationId = New-EntraPostureCorrelationId
    $assessmentPath = Join-Path $RunRoot "assessment-$evaluationId"
    New-Item -ItemType Directory -Path $assessmentPath -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $assessmentPath 'logs') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $assessmentPath 'reports') -Force | Out-Null

    $resultsFailures = [System.Collections.Generic.List[string]]::new()
    $resultLines = @(foreach ($result in $finalResults) {
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $result
        $validation = Test-EntraPostureSchema -Json $json -ContractName 'control-result'
        if (-not $validation.IsValid) {
            $resultsFailures.Add("controlId '$($result.controlId)' scope '$($result.scope)': $($validation.Errors -join '; ')")
        }
        $json
    })
    if ($resultsFailures.Count -gt 0) {
        throw "Invoke-EntraPostureEvaluationPipeline: $($resultsFailures.Count) control result(s) failed schema validation:`n  $($resultsFailures -join "`n  ")"
    }
    [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'results.jsonl'), (($resultLines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))

    $deviationFailures = [System.Collections.Generic.List[string]]::new()
    $deviationLines = @(foreach ($deviation in $Deviations) {
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $deviation
        $validation = Test-EntraPostureSchema -Json $json -ContractName 'deviation'
        if (-not $validation.IsValid) {
            $deviationFailures.Add("deviationId '$($deviation.deviationId)': $($validation.Errors -join '; ')")
        }
        $json
    })
    if ($deviationFailures.Count -gt 0) {
        throw "Invoke-EntraPostureEvaluationPipeline: $($deviationFailures.Count) deviation(s) failed schema validation:`n  $($deviationFailures -join "`n  ")"
    }
    if ($deviationLines.Count -gt 0) {
        [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'deviations.jsonl'), (($deviationLines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    } else {
        [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'deviations.jsonl'), '', [System.Text.UTF8Encoding]::new($false))
    }

    $manifest = [ordered]@{
        evaluationId    = $evaluationId
        snapshotId      = $snapshotManifest.snapshotId
        evaluatedAtUtc  = $evaluatedAtUtc
    }
    [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'manifest.json'), (ConvertTo-EntraPostureCanonicalJson -InputObject $manifest), [System.Text.UTF8Encoding]::new($false))

    $statusCounts = [ordered]@{
        Pass          = @($finalResults | Where-Object { $_.status -eq 'Pass' }).Count
        Fail          = @($finalResults | Where-Object { $_.status -eq 'Fail' }).Count
        NotApplicable = @($finalResults | Where-Object { $_.status -eq 'NotApplicable' }).Count
        NotEvaluated  = @($finalResults | Where-Object { $_.status -eq 'NotEvaluated' }).Count
        Error         = @($finalResults | Where-Object { $_.status -eq 'Error' }).Count
    }
    $summary = [ordered]@{ evaluationId = $evaluationId; statusCounts = $statusCounts }
    [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'summary.json'), (ConvertTo-EntraPostureCanonicalJson -InputObject $summary), [System.Text.UTF8Encoding]::new($false))

    $fileInventory = Get-EntraPostureBundleFileInventory -BundleRoot $assessmentPath -ExcludeDirectoryName 'reports'
    $aggregate = $fileInventory | Get-EntraPostureAggregateHash
    $attestationPayload = Get-EntraPostureIntegrityAttestationPayload -Files $fileInventory -AggregateHash $aggregate.aggregateHash -RecordCount $aggregate.recordCount
    $attestationJson = ConvertTo-EntraPostureCanonicalJson -InputObject $attestationPayload
    $attestationBytes = [System.Text.Encoding]::UTF8.GetBytes($attestationJson)

    $signatureStatus = 'Unsigned'
    $signatureRecord = $null
    if ($SigningCertificate) {
        $signatureBytes = New-EntraPostureDetachedSignature -Content $attestationBytes -Certificate $SigningCertificate
        [System.IO.File]::WriteAllBytes((Join-Path $assessmentPath 'integrity.p7s'), $signatureBytes)
        $signatureStatus = 'Signed'
        $signatureRecord = [ordered]@{ detachedSignatureFile = 'integrity.p7s'; certificateThumbprint = $SigningCertificate.Thumbprint }
    }

    $integrityRecord = [ordered]@{
        files           = $fileInventory
        aggregateHash   = $aggregate.aggregateHash
        recordCount     = $aggregate.recordCount
        signatureStatus = $signatureStatus
        signature       = $signatureRecord
    }
    $integrityJson = ConvertTo-EntraPostureCanonicalJson -InputObject $integrityRecord
    $integrityValidation = Test-EntraPostureSchema -Json $integrityJson -ContractName 'integrity'
    if (-not $integrityValidation.IsValid) {
        throw "Invoke-EntraPostureEvaluationPipeline: internal error -- constructed integrity record failed its own schema: $($integrityValidation.Errors -join '; ')"
    }
    [System.IO.File]::WriteAllText((Join-Path $assessmentPath 'integrity.json'), $integrityJson, [System.Text.UTF8Encoding]::new($false))

    return [ordered]@{
        AssessmentPath   = $assessmentPath
        EvaluationId     = $evaluationId
        SnapshotManifest = $snapshotManifest
        Coverage         = $coverage
        Results          = $finalResults
        Deviations       = $Deviations
    }
}
