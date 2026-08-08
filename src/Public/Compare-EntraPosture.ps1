#Requires -Version 7.4

function Compare-EntraPosture {
    <#
        .SYNOPSIS
        Compares two sealed assessment bundles, classifying every difference into distinct
        categories: result transitions, added/removed results, coverage changes, and deviation
        changes.

        .DESCRIPTION
        Comparison command (engineering plan section 6.2/10.3). Never authenticates or calls the
        network -- reads two already-sealed, trust-verified assessment bundles entirely offline,
        the same discipline New-EntraPostureReport's render pipeline already follows.

        Both bundles are independently verified via Test-EntraPostureAssessmentBundleIntegrity
        before anything is read from them -- a tampered or unsealed bundle on either side refuses
        to compare, the same "invalid/unsealed data cannot reach evaluators" principle applied to
        comparison instead of evaluation.

        Cross-tenant rejection (section 10.3) requires knowing each side's tenantScope, which an
        assessment bundle's own manifest.json does not carry (only evaluationId/snapshotId/
        evaluatedAtUtc) -- tenantScope lives in the *originating snapshot's* manifest. Passing
        -OldSnapshotPath/-NewSnapshotPath enriches the comparison with that context and enforces
        the cross-tenant check; omitting either is a fully supported "compare without the
        originating snapshot" case (the same precedent New-EntraPostureReport's optional
        -SnapshotPath already established) -- the check is simply skipped, not silently assumed
        safe, and this function's own output says so explicitly via TenantCheckPerformed.

        VNext build order item 10 (drift detection, deliberately built last per the project
        owner's own explicit instruction this session): when BOTH -OldSnapshotPath/
        -NewSnapshotPath are supplied (that same optional pair), this command additionally
        computes CA-specific drift events via Compare-EntraPostureConditionalAccessDrift -- a
        structural diff of ConditionalAccessPolicy evidence (added/removed/modified, with a
        scope-change flag) plus CA-002's own generated-scenario-set drift, each correlated
        against ResultTransitions so a drift event answers "which control/case did this affect,
        and what was the old/new result," not just "something changed." Omitting either snapshot
        path skips this analysis entirely (ConditionalAccessDriftPerformed=$false) --
        evidence-level diffing needs the actual snapshot evidence, not just the evaluated
        assessment results, the same "context we don't have, we don't fake" posture the tenant
        check already established for this same parameter pair.

        .PARAMETER OldAssessmentPath
        .PARAMETER NewAssessmentPath
        Two sealed assessment bundle directories (from Invoke-EntraPostureEvaluation).

        .PARAMETER OldSnapshotPath
        .PARAMETER NewSnapshotPath
        Optional. The snapshot bundles each assessment was evaluated from -- supplies tenantScope
        for the cross-tenant check. Independently optional (you can supply one without the
        other; the check is skipped whenever either side's tenant is unknown).

        .PARAMETER AllowCrossTenant
        Explicit override to compare two assessments with different tenantScope values anyway.
        Has no effect (and is not needed) when tenant context isn't available at all.

        .OUTPUTS
        Ordered dictionary: OldEvaluationId, NewEvaluationId, TenantCheckPerformed,
        ResultTransitions, AddedResults, RemovedResults, CoverageChanges, DeviationChanges,
        Summary, ConditionalAccessDriftPerformed, ConditionalAccessDriftEvents,
        ConditionalAccessDriftSummary, ExpectedCaseAnalysisSkipped,
        ExpectedCaseAnalysisSkipReason.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$OldAssessmentPath,

        [Parameter(Mandatory)]
        [string]$NewAssessmentPath,

        [Parameter()]
        [string]$OldSnapshotPath,

        [Parameter()]
        [string]$NewSnapshotPath,

        [Parameter()]
        [switch]$AllowCrossTenant
    )

    $oldTrust = Test-EntraPostureAssessmentBundleIntegrity -BundlePath $OldAssessmentPath
    if (-not $oldTrust.IsTrusted) {
        throw "Compare-EntraPosture: refusing to compare -- '$OldAssessmentPath' is not trusted (status: $($oldTrust.Status)). $($oldTrust.Details)"
    }
    $newTrust = Test-EntraPostureAssessmentBundleIntegrity -BundlePath $NewAssessmentPath
    if (-not $newTrust.IsTrusted) {
        throw "Compare-EntraPosture: refusing to compare -- '$NewAssessmentPath' is not trusted (status: $($newTrust.Status)). $($newTrust.Details)"
    }

    $oldDocument = Get-EntraPostureAssessmentBundleDocument -BundlePath $OldAssessmentPath -SnapshotPathForContext $OldSnapshotPath
    $newDocument = Get-EntraPostureAssessmentBundleDocument -BundlePath $NewAssessmentPath -SnapshotPathForContext $NewSnapshotPath

    $tenantCheckPerformed = [bool]($OldSnapshotPath -and $NewSnapshotPath)
    if ($tenantCheckPerformed -and -not $AllowCrossTenant -and $oldDocument.tenantScope -ne $newDocument.tenantScope) {
        throw "Compare-EntraPosture: refusing to compare assessments from different tenants ('$($oldDocument.tenantScope)' vs '$($newDocument.tenantScope)') without -AllowCrossTenant."
    }

    $comparison = Compare-EntraPostureAssessmentDocument -OldAssessmentDocument $oldDocument -NewAssessmentDocument $newDocument

    $conditionalAccessDriftPerformed = [bool]($OldSnapshotPath -and $NewSnapshotPath)
    $driftResult = $null
    if ($conditionalAccessDriftPerformed) {
        $oldEvidenceProvider = New-EntraPostureEvidenceProvider -SnapshotPath $OldSnapshotPath
        $newEvidenceProvider = New-EntraPostureEvidenceProvider -SnapshotPath $NewSnapshotPath
        $driftResult = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldEvidenceProvider -NewEvidenceProvider $newEvidenceProvider `
            -OldSnapshotId $oldDocument.snapshotId -NewSnapshotId $newDocument.snapshotId -ResultTransitions $comparison.ResultTransitions
    }

    return [ordered]@{
        OldEvaluationId      = $oldDocument.assessmentId
        NewEvaluationId      = $newDocument.assessmentId
        TenantCheckPerformed = $tenantCheckPerformed
        ResultTransitions    = $comparison.ResultTransitions
        AddedResults         = $comparison.AddedResults
        RemovedResults       = $comparison.RemovedResults
        CoverageChanges      = $comparison.CoverageChanges
        DeviationChanges     = $comparison.DeviationChanges
        Summary              = $comparison.Summary
        ConditionalAccessDriftPerformed = $conditionalAccessDriftPerformed
        ConditionalAccessDriftEvents    = if ($driftResult) { $driftResult.DriftEvents } else { @() }
        ConditionalAccessDriftSummary   = if ($driftResult) { $driftResult.Summary } else { $null }
        ExpectedCaseAnalysisSkipped     = if ($driftResult) { $driftResult.ExpectedCaseAnalysisSkipped } else { $null }
        ExpectedCaseAnalysisSkipReason  = if ($driftResult) { $driftResult.ExpectedCaseAnalysisSkipReason } else { $null }
    }
}
