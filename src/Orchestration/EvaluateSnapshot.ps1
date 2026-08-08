#Requires -Version 7.4

function Invoke-EntraPostureSnapshotEvaluation {
    <#
        .SYNOPSIS
        Evaluates a sealed, trusted snapshot against the native control registry, entirely
        offline. ADR-019: evaluators never call live APIs -- this function's only input is
        already-on-disk evidence, and it has no code path capable of making a network call.

        .DESCRIPTION
        For each registered control: if coverage.json shows every one of that control's
        requiredEvidenceDomains at evidenceStatus 'Collected', the control's evaluator function
        is invoked and each of its raw findings is completed into a full ControlResult record
        (controlId/controlVersion/evaluatorVersion/evaluatedAt/correlationId/remediation filled
        in from the control definition and this call, not from the evaluator itself). If
        coverage is insufficient, a single synthetic NotEvaluated result is produced instead,
        using the reasonCode '<controlId>-EVIDENCE-NOT-COLLECTED' that both of this project's
        Phase 5 controls declare for exactly this purpose -- the evaluator function itself is
        never even invoked in that case (engineering plan section 6.3: evaluators depend only
        on the evidence-provider and control contracts; they are not responsible for deciding
        whether they should run at all). If the evaluator function throws, a single synthetic
        Error result is produced instead, using that control's '<controlId>-EVALUATOR-ERROR'
        reasonCode, with the exception's sanitized message in the rationale.

        .PARAMETER SnapshotPath
        Root directory of an already-trust-verified sealed snapshot (caller must have already
        called Get-EntraPostureTrustedSnapshot on it).

        .PARAMETER Coverage
        The snapshot's parsed coverage.json content.

        .PARAMETER EvaluatedAtUtc
        ISO 8601 UTC timestamp string, shared by every result produced in this call.

        .OUTPUTS
        Array of ordered dictionaries matching control-result.schema.json, deviation always
        null (deviation application is a separate, later step -- Set-EntraPostureControlResultDeviation).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [string]$SnapshotPath,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Coverage,

        [Parameter(Mandatory)]
        [string]$EvaluatedAtUtc
    )

    $versionInfo = Get-EntraPostureToolVersionInfo
    $controlRegistry = Get-EntraPostureControlRegistry
    $evidenceProvider = New-EntraPostureEvidenceProvider -SnapshotPath $SnapshotPath

    $coverageByDomain = @{}
    foreach ($collectorCoverage in @($Coverage.collectors)) {
        foreach ($controlId in @($collectorCoverage.affectedControlIds)) {
            if (-not $coverageByDomain.ContainsKey($controlId)) { $coverageByDomain[$controlId] = @() }
            $coverageByDomain[$controlId] += $collectorCoverage.evidenceStatus
        }
    }

    $allResults = @(foreach ($control in $controlRegistry) {
        # @() around the whole if/else -- see src/Orchestration/CollectAndSeal.ps1's
        # $armGrantedForCoverage for why this specific pattern (a branch that can yield 0 or 1
        # elements) needs it even though every current use below happens to re-wrap defensively.
        $statusesForControl = @(if ($coverageByDomain.ContainsKey($control.controlId)) { $coverageByDomain[$control.controlId] } else { @() })
        $collectionCoverage = if (@($statusesForControl).Count -gt 0 -and (@($statusesForControl | Where-Object { $_ -ne 'Collected' }).Count -eq 0)) { 'Complete' } else { 'Partial' }

        if ($collectionCoverage -ne 'Complete') {
            $reasonCode = @($control.reasonCodes | Where-Object { $_.resultStatus -eq 'NotEvaluated' } | Select-Object -First 1).code
            [ordered]@{
                controlId          = $control.controlId
                controlVersion     = $control.version
                evaluatorVersion   = $versionInfo.ToolVersion
                scope              = 'tenant'
                status             = 'NotEvaluated'
                reasonCode         = $reasonCode
                rationale          = 'Required evidence domain(s) were not fully collected for this snapshot; see coverage.json.'
                evidenceReferences = @()
                collectionCoverage = $collectionCoverage
                evaluatedAt        = $EvaluatedAtUtc
                remediation        = $control.remediation
                correlationId      = (New-EntraPostureCorrelationId)
                deviation          = $null
            }
            continue
        }

        try {
            $findings = & $control.evaluatorFunctionName -EvidenceProvider $evidenceProvider
        } catch {
            $errorReasonCode = @($control.reasonCodes | Where-Object { $_.resultStatus -eq 'Error' } | Select-Object -First 1).code
            [ordered]@{
                controlId          = $control.controlId
                controlVersion     = $control.version
                evaluatorVersion   = $versionInfo.ToolVersion
                scope              = 'tenant'
                status             = 'Error'
                reasonCode         = $errorReasonCode
                rationale          = "Evaluator threw: $($_.Exception.Message)"
                evidenceReferences = @()
                collectionCoverage = $collectionCoverage
                evaluatedAt        = $EvaluatedAtUtc
                remediation        = $control.remediation
                correlationId      = (New-EntraPostureCorrelationId)
                deviation          = $null
            }
            continue
        }

        foreach ($finding in @($findings)) {
            [ordered]@{
                controlId          = $control.controlId
                controlVersion     = $control.version
                evaluatorVersion   = $versionInfo.ToolVersion
                scope              = $finding.Scope
                status             = $finding.Status
                reasonCode         = $finding.ReasonCode
                rationale          = $finding.Rationale
                evidenceReferences = @($finding.EvidenceReferences)
                collectionCoverage = $collectionCoverage
                evaluatedAt        = $EvaluatedAtUtc
                remediation        = $control.remediation
                correlationId      = (New-EntraPostureCorrelationId)
                deviation          = $null
            }
        }
    })

    return ,@($allResults)
}
