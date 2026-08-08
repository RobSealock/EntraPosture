#Requires -Version 7.4

function Test-EntraPostureAccessReviewInstanceHealthControl {
    <#
        .SYNOPSIS
        AR-002's evaluator: for each AccessReviewDefinition that AR-001 would confirm coverage
        for, checks whether its most recently collected instance is overdue, has unapplied
        decisions, or is materially incomplete.

        .DESCRIPTION
        Relational and temporal, gated on AR-001 exactly the way AUTHCTX-002 gates on AUTHCTX-001
        (15-feature-parity-matrix.md's own words: "the same gating relationship AR-002 has to
        AR-001"): only definitions matching one of AR-001's three surface patterns are
        applicable, reusing the identical substring patterns Test-
        EntraPostureAccessReviewCoverageControl uses (duplicated locally rather than shared
        via a helper -- this project's evaluators are each self-contained, e.g. AUTHCTX-002 does
        not call into AUTHCTX-001 either).

        Only the most recent instance per definition is evaluated (the collector itself only
        ever fetches one) -- the matrix leaves "should historical instances also be evaluated"
        as an explicitly open, unresolved Phase 7 question; this project's scope decision is
        "most recent only," matching every other control's applicable-set sizing.

        Overdue determination compares the instance's endDateTime against the wall clock at
        EVALUATION time ([DateTime]::UtcNow), not collection time -- the only time-relative check
        in this project's control registry. This is a deliberate, documented consequence, not an
        oversight: re-evaluating the same sealed snapshot later can change this specific result
        even though nothing about the evidence itself changed. ADR-019 ("evaluators never call
        live APIs") is not violated -- reading the local clock is not a network call.

        The "materially incomplete" 50% not-reviewed threshold and the "not overdue and not yet
        terminal" -> Pass default are both this project's own reasoned judgment calls, not
        Microsoft directives -- see AR-002.psd1's provenance notes, matching the precedent set by
        PRIV-001's 2-4 admin range and PIM-003's 4-hour threshold.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AR-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per (definition, instance) pair evaluated, or a single NotApplicable element
        if none are applicable.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    # Not-reviewed threshold above which a completed/auto-reviewed instance is judged materially
    # incomplete. A project-owned round number, not a Microsoft directive -- see this function's
    # own DESCRIPTION and AR-002.psd1's provenance notes.
    $materiallyIncompleteThreshold = 0.5

    $definitions = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessReviewDefinition'
    $instances = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessReviewInstance'

    # Same surface patterns as AR-001 (Test-EntraPostureAccessReviewCoverageControl) -- the
    # union of all three, since AR-002's applicability gate is "covers any AR-001 surface at
    # all," not which specific one.
    $coveragePatterns = @('rolemanagement', 'roleassignmentscheduleinstances', 'roleeligibilityscheduleinstances', '/groups', 'serviceprincipals', 'approleassign')

    $coveringDefinitions = @($definitions | Where-Object {
        $query = [string]$_.properties.scopeQuery
        if ([string]::IsNullOrWhiteSpace($query)) { return $false }
        $queryLower = $query.ToLowerInvariant()
        foreach ($pattern in $coveragePatterns) {
            if ($queryLower.Contains($pattern)) { return $true }
        }
        return $false
    })

    $applicablePairs = @(foreach ($definition in $coveringDefinitions) {
        $instance = $instances | Where-Object { [string]$_.properties.definitionId -eq $definition.entityId } | Select-Object -First 1
        if (-not $instance) { continue }
        [ordered]@{ Definition = $definition; Instance = $instance }
    })

    if (@($applicablePairs).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AR-002-NO-APPLICABLE-INSTANCES'
                Rationale          = 'No AccessReviewDefinition matching an AR-001 governance surface has any collected instance yet to evaluate.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $now = [DateTime]::UtcNow
    $terminalStates = @('Completed', 'AutoReviewed')

    $evaluationResults = @(foreach ($pair in $applicablePairs) {
        $definition = $pair.Definition
        $instance = $pair.Instance
        $status = [string]$instance.properties.status
        $isTerminal = $terminalStates -contains $status

        $endDateTime = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$instance.properties.endDateTime)) {
            $endDateTime = [DateTime]::Parse([string]$instance.properties.endDateTime, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        }

        $totalCount = [int]$instance.properties.decisionsTotalCount
        $notReviewedCount = [int]$instance.properties.decisionsNotReviewedCount
        $appliedCount = [int]$instance.properties.decisionsAppliedCount
        $autoApplyEnabled = [bool]$definition.properties.autoApplyDecisionsEnabled

        $evidenceRef = @(
            [ordered]@{ entityId = $definition.entityId; entityType = 'AccessReviewDefinition' }
            [ordered]@{ entityId = $instance.entityId; entityType = 'AccessReviewInstance' }
        )
        $scope = "$($definition.entityId)::$($instance.entityId)"

        if (-not $isTerminal -and $endDateTime -and $now -gt $endDateTime) {
            [ordered]@{
                Scope              = $scope
                Status             = 'Fail'
                ReasonCode         = 'AR-002-INSTANCE-OVERDUE'
                Rationale          = "Access review instance's scheduled end date ($($instance.properties.endDateTime)) has passed but its status is still '$status', not a terminal completed state."
                EvidenceReferences = $evidenceRef
            }
        } elseif ($isTerminal -and -not $autoApplyEnabled -and $totalCount -gt 0 -and $appliedCount -eq 0) {
            [ordered]@{
                Scope              = $scope
                Status             = 'Fail'
                ReasonCode         = 'AR-002-DECISIONS-NOT-APPLIED'
                Rationale          = "Access review instance completed with $totalCount decision(s) recorded, but automatic apply is disabled and none of them have been applied."
                EvidenceReferences = $evidenceRef
            }
        } elseif ($isTerminal -and $totalCount -gt 0 -and ($notReviewedCount / $totalCount) -gt $materiallyIncompleteThreshold) {
            $percent = [Math]::Round(($notReviewedCount / $totalCount) * 100, 0)
            [ordered]@{
                Scope              = $scope
                Status             = 'Fail'
                ReasonCode         = 'AR-002-MATERIALLY-INCOMPLETE'
                Rationale          = "Access review instance completed with $percent% ($notReviewedCount of $totalCount) of decisions never reviewed, above this project's $($materiallyIncompleteThreshold * 100)% threshold."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $scope
                Status             = 'Pass'
                ReasonCode         = 'AR-002-HEALTHY'
                Rationale          = "Access review instance is not overdue and shows no unapplied or materially incomplete decisions as of evaluation time."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
