#Requires -Version 7.4

function Invoke-EntraPostureEvaluation {
    <#
        .SYNOPSIS
        Evaluates a sealed snapshot against the native control registry, entirely offline.

        .DESCRIPTION
        Evaluate-only command (engineering plan section 6.2). Trust-gates -SnapshotPath (Phase
        3's exit criterion: invalid/unsealed data cannot reach evaluators), evaluates fixed/
        relational controls (Phase 5's XTA-001/PRIV-001 -- Conditional Access-specific
        evaluation is Phase 8), applies any supplied deviations, and seals the resulting
        assessments/<evaluation-id>/ bundle. Never authenticates or calls the network (ADR-019).

        .PARAMETER SnapshotPath
        A directory sealed by New-EntraPostureSnapshot.

        .PARAMETER RunRoot
        Parent directory under which assessments/<evaluation-id>/ is created. Defaults to
        -SnapshotPath's own parent directory.

        .PARAMETER DeviationsPath
        Optional JSONL file, each line matching deviation.schema.json.

        .PARAMETER SigningCertificate
        Optional detached-signing certificate for the assessment bundle.

        .OUTPUTS
        Ordered dictionary: AssessmentPath, EvaluationId, Results, Coverage.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SnapshotPath,

        [Parameter()]
        [string]$RunRoot,

        [Parameter()]
        [string]$DeviationsPath,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate
    )

    if (-not $RunRoot) {
        $RunRoot = Split-Path -Parent $SnapshotPath
    }

    $deviations = @()
    if ($DeviationsPath -and (Test-Path -LiteralPath $DeviationsPath -PathType Leaf)) {
        $lines = @(Get-Content -LiteralPath $DeviationsPath | Where-Object { $_.Trim().Length -gt 0 })
        $deviations = @(foreach ($line in $lines) { ConvertFrom-EntraPostureJson -Json $line })
    }

    $pipelineParams = @{
        SnapshotPath = $SnapshotPath
        RunRoot      = $RunRoot
        Deviations   = $deviations
    }
    if ($SigningCertificate) { $pipelineParams['SigningCertificate'] = $SigningCertificate }

    return Invoke-EntraPostureEvaluationPipeline @pipelineParams
}
