#Requires -Version 7.4

function Get-EntraPostureAssessmentBundleDocument {
    <#
        .SYNOPSIS
        Reads a sealed, already-trust-verified assessment bundle back into an assessment
        document -- the shared bundle-loading step behind both Compare-EntraPosture and
        Invoke-EntraPostureReportPipeline.

        .DESCRIPTION
        Deliberately a standalone, named, non-nested function rather than a helper defined inside
        Compare-EntraPosture's own body -- confirmed directly that a function nested inside a
        src/Public/*.ps1 command still gets swept into Build-Module.ps1's export-validation scan
        (its AST search for function definitions searches nested scopes, not just top level), so
        a nested helper there is treated as an unapproved additional export and fails the build.
        This function lives in src/Reporting/ instead, the same place every other piece of
        report-rendering logic already lives, matching the project's established "Public/ files
        are thin wrappers, logic lives in the owning internal module" convention.

        Does not itself call Test-EntraPostureAssessmentBundleIntegrity -- callers must have
        already verified trust, the same "exactly one place responsible for the trust check"
        discipline New-EntraPostureEvidenceProvider's own DESCRIPTION documents for snapshots.

        .PARAMETER BundlePath
        .PARAMETER SnapshotPathForContext
        Optional. When supplied, enriches the returned document with the originating snapshot's
        tenantScope/cloud/authMode/coverage context (see Compare-EntraPosture's own
        DESCRIPTION for why this is optional, not required).

        .OUTPUTS
        Ordered dictionary matching New-EntraPostureAssessmentDocument's shape.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$BundlePath,

        [Parameter()]
        [string]$SnapshotPathForContext
    )

    $manifest = ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath (Join-Path $BundlePath 'manifest.json') -Raw)
    $resultLines = @(Get-Content -LiteralPath (Join-Path $BundlePath 'results.jsonl') | Where-Object { $_.Trim().Length -gt 0 })
    $results = @(foreach ($line in $resultLines) { ConvertFrom-EntraPostureJson -Json $line })
    $deviationsPath = Join-Path $BundlePath 'deviations.jsonl'
    $deviationLines = @(Get-Content -LiteralPath $deviationsPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim().Length -gt 0 })
    $deviations = @(foreach ($line in $deviationLines) { ConvertFrom-EntraPostureJson -Json $line })

    if ($SnapshotPathForContext) {
        $snapshotManifest = Get-EntraPostureTrustedSnapshot -BundlePath $SnapshotPathForContext
        $coveragePath = Join-Path $SnapshotPathForContext 'coverage.json'
        $coverage = if (Test-Path -LiteralPath $coveragePath -PathType Leaf) {
            ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $coveragePath -Raw)
        } else {
            [ordered]@{ collectors = @() }
        }
    } else {
        $snapshotManifest = [ordered]@{ snapshotId = $manifest.snapshotId; tenantScope = $null; cloud = ''; authMode = ''; collectionStartUtc = ''; collectionEndUtc = ''; status = '' }
        $coverage = [ordered]@{ collectors = @() }
    }

    return New-EntraPostureAssessmentDocument -SnapshotManifest $snapshotManifest -EvaluationId $manifest.evaluationId `
        -Coverage $coverage -Results $results -Deviations $deviations -EvaluatedAtUtc $manifest.evaluatedAtUtc
}

function Compare-EntraPostureAssessmentDocument {
    <#
        .SYNOPSIS
        Compares two assessment documents (New-EntraPostureAssessmentDocument's output shape),
        classifying every difference into distinct categories -- the core comparison logic behind
        the public Compare-EntraPosture command.

        .DESCRIPTION
        Engineering plan section 10.3: "correlates objects by immutable IDs; classifies evidence
        changes, result transitions, coverage changes, deviation changes, What If changes, and
        evaluator/control-version-caused changes separately."

        Correlation key for control results is (controlId, scope) -- the pair that together
        identifies "this control's finding about this specific object/relationship," matching
        every control's own per-scope result shape (e.g. PIM-002's scope is a
        "principalId::roleId" pair, AR-001's scope is a surface name, PRIV-001's scope is a role
        ID -- there is no single simpler natural key across every control). A (controlId, scope)
        pair present in only one assessment is reported as Added/Removed rather than forced into
        a transition -- forcing a comparison against a status that never existed would fabricate
        a transition that didn't happen (e.g. a brand-new CA-001 scenario result, or an object
        that was deleted from the tenant between snapshots, is not "the same finding changing
        status").

        A transition where controlVersion or evaluatorVersion differs between the two results is
        flagged with VersionChanged=$true -- called out separately per the engineering plan's own
        explicit "evaluator/control-version-caused changes" category, since a Fail-to-Pass
        transition caused by a control definition becoming less strict is a materially different
        finding than the same transition caused by an actual tenant configuration change, and
        conflating the two would misrepresent what actually happened.

        "What If changes" (the engineering plan's sixth named category) is not produced by this
        function -- no persisted historical What-If comparison data exists yet for this project to
        diff between two runs (Phase 8's What-If harness, src/ConditionalAccess/WhatIfComparison.ps1,
        is an ad hoc live-comparison utility, not something whose output is written into an
        assessment bundle for later comparison). A documented v1 boundary, not a silent omission --
        see this project's own 00-open-questions.md Phase 9 section.

        .PARAMETER OldAssessmentDocument
        .PARAMETER NewAssessmentDocument
        Both from New-EntraPostureAssessmentDocument (or read back from a rendered
        assessment.json).

        .OUTPUTS
        Ordered dictionary: ResultTransitions, AddedResults, RemovedResults, CoverageChanges,
        DeviationChanges, Summary.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$OldAssessmentDocument,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$NewAssessmentDocument
    )

    function script:Get-ResultKey {
        param($Result)
        return "$($Result.controlId)::$($Result.scope)"
    }

    $oldResultsByKey = @{}
    foreach ($result in @($OldAssessmentDocument.results)) { $oldResultsByKey[(Get-ResultKey -Result $result)] = $result }
    $newResultsByKey = @{}
    foreach ($result in @($NewAssessmentDocument.results)) { $newResultsByKey[(Get-ResultKey -Result $result)] = $result }

    $allKeys = @(@($oldResultsByKey.Keys) + @($newResultsByKey.Keys) | Select-Object -Unique)

    $resultTransitions = [System.Collections.Generic.List[object]]::new()
    $addedResults = [System.Collections.Generic.List[object]]::new()
    $removedResults = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $allKeys) {
        $hasOld = $oldResultsByKey.ContainsKey($key)
        $hasNew = $newResultsByKey.ContainsKey($key)

        if ($hasOld -and -not $hasNew) {
            $old = $oldResultsByKey[$key]
            $removedResults.Add([ordered]@{ ControlId = $old.controlId; Scope = $old.scope; OldStatus = $old.status; EvidenceReferences = @($old.evidenceReferences) })
            continue
        }
        if (-not $hasOld -and $hasNew) {
            $new = $newResultsByKey[$key]
            $addedResults.Add([ordered]@{ ControlId = $new.controlId; Scope = $new.scope; NewStatus = $new.status; EvidenceReferences = @($new.evidenceReferences) })
            continue
        }

        $old = $oldResultsByKey[$key]
        $new = $newResultsByKey[$key]

        if ($old.status -ne $new.status) {
            $resultTransitions.Add([ordered]@{
                ControlId        = $new.controlId
                Scope            = $new.scope
                OldStatus        = $old.status
                NewStatus        = $new.status
                OldReasonCode    = $old.reasonCode
                NewReasonCode    = $new.reasonCode
                VersionChanged   = ($old.controlVersion -ne $new.controlVersion) -or ($old.evaluatorVersion -ne $new.evaluatorVersion)
                OldControlVersion = $old.controlVersion
                NewControlVersion = $new.controlVersion
                # Carried through so drift-event correlation (Compare-EntraPostureConditionalAccessDrift,
                # VNext build order item 10) can answer "which result transitions does this specific
                # policy change explain" -- the engineering plan's own drift definition (review plan
                # line ~1090): "a snapshot change identifies the fact, affected control/case, and
                # old/new result." Prefers the new result's own references (evidence as of the newer
                # snapshot); falls back to the old result's when the new one is empty (e.g. a
                # NotEvaluated/Error transition that carries no evidence references of its own).
                EvidenceReferences = @(if (@($new.evidenceReferences).Count -gt 0) { $new.evidenceReferences } else { $old.evidenceReferences })
            })
        }
    }

    # -- Coverage changes (per-collector evidenceStatus) --
    $oldCoverageByName = @{}
    foreach ($collector in @($OldAssessmentDocument.coverage.collectors)) { $oldCoverageByName[$collector.collectorName] = $collector }
    $newCoverageByName = @{}
    foreach ($collector in @($NewAssessmentDocument.coverage.collectors)) { $newCoverageByName[$collector.collectorName] = $collector }
    $allCollectorNames = @(@($oldCoverageByName.Keys) + @($newCoverageByName.Keys) | Select-Object -Unique)

    $coverageChanges = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $allCollectorNames) {
        $oldStatus = if ($oldCoverageByName.ContainsKey($name)) { $oldCoverageByName[$name].evidenceStatus } else { $null }
        $newStatus = if ($newCoverageByName.ContainsKey($name)) { $newCoverageByName[$name].evidenceStatus } else { $null }
        if ($oldStatus -ne $newStatus) {
            $coverageChanges.Add([ordered]@{ CollectorName = $name; OldEvidenceStatus = $oldStatus; NewEvidenceStatus = $newStatus })
        }
    }

    # -- Deviation changes (by deviationId) --
    $oldDeviationsById = @{}
    foreach ($deviation in @($OldAssessmentDocument.deviations)) { $oldDeviationsById[$deviation.deviationId] = $deviation }
    $newDeviationsById = @{}
    foreach ($deviation in @($NewAssessmentDocument.deviations)) { $newDeviationsById[$deviation.deviationId] = $deviation }
    $allDeviationIds = @(@($oldDeviationsById.Keys) + @($newDeviationsById.Keys) | Select-Object -Unique)

    $deviationChanges = [System.Collections.Generic.List[object]]::new()
    foreach ($deviationId in $allDeviationIds) {
        $hasOld = $oldDeviationsById.ContainsKey($deviationId)
        $hasNew = $newDeviationsById.ContainsKey($deviationId)

        if ($hasOld -and -not $hasNew) {
            $deviationChanges.Add([ordered]@{ DeviationId = $deviationId; ChangeType = 'Removed'; ControlId = $oldDeviationsById[$deviationId].controlId })
            continue
        }
        if (-not $hasOld -and $hasNew) {
            $deviationChanges.Add([ordered]@{ DeviationId = $deviationId; ChangeType = 'Added'; ControlId = $newDeviationsById[$deviationId].controlId })
            continue
        }

        $old = $oldDeviationsById[$deviationId]
        $new = $newDeviationsById[$deviationId]
        if (($old.expiryDate -ne $new.expiryDate) -or ($old.justification -ne $new.justification) -or ($old.approver -ne $new.approver)) {
            $deviationChanges.Add([ordered]@{ DeviationId = $deviationId; ChangeType = 'Modified'; ControlId = $new.controlId })
        }
    }

    $resultTransitionsArray = @($resultTransitions.ToArray())
    $addedResultsArray = @($addedResults.ToArray())
    $removedResultsArray = @($removedResults.ToArray())
    $coverageChangesArray = @($coverageChanges.ToArray())
    $deviationChangesArray = @($deviationChanges.ToArray())

    return [ordered]@{
        ResultTransitions = $resultTransitionsArray
        AddedResults      = $addedResultsArray
        RemovedResults    = $removedResultsArray
        CoverageChanges   = $coverageChangesArray
        DeviationChanges  = $deviationChangesArray
        Summary           = [ordered]@{
            ResultTransitionCount = $resultTransitionsArray.Count
            AddedResultCount      = $addedResultsArray.Count
            RemovedResultCount    = $removedResultsArray.Count
            CoverageChangeCount   = $coverageChangesArray.Count
            DeviationChangeCount  = $deviationChangesArray.Count
        }
    }
}
