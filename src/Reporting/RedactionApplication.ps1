#Requires -Version 7.4

function Protect-EntraPostureReportRedaction {
    <#
        .SYNOPSIS
        Applies export-time redaction to an assessment document, per engineering plan section
        10.2's three modes.

        .DESCRIPTION
        Evaluation always runs against unredacted evidence (section 10.2: "Evaluation always
        uses unredacted normalized evidence") -- this function only ever runs on an
        already-fully-evaluated assessment document, at export/report time, never before or
        during evaluation. Pseudonymization is internally consistent within one call: the same
        real entityId always maps to the same pseudonym everywhere it appears in the document
        (results[].scope and results[].evidenceReferences[].entityId), via a first-seen-order
        counter keyed by entityType so pseudonyms read as "User-3", "DirectoryRole-1", etc.
        rather than opaque numbers.

        Modes:
          - 'None': returned unchanged.
          - 'Identifiers': every entityId-shaped value (scope, evidenceReferences[].entityId)
            is replaced by its pseudonym.
          - 'Strict': everything 'Identifiers' does, plus each result's free-text 'rationale' is
            replaced by a generic reasonCode-derived sentence, since the original rationale text
            in this project's two Phase 5 controls includes specific counts/details that would
            otherwise survive identifier pseudonymization intact.

        Does not enforce a control's own declared evidenceRedactionPolicy floor (the minimum
        mode a specific control's evidence supports without losing actionability) -- every
        result in the document is redacted uniformly according to -RedactionMode regardless of
        its owning control's floor. Enforcing that per-control floor is real, deliberately
        deferred work (noted in 00-open-questions.md's Phase 5 section), not an oversight.

        .PARAMETER AssessmentDocument
        Output of New-EntraPostureAssessmentDocument.

        .PARAMETER RedactionMode
        .OUTPUTS
        A new assessment document (the input is never mutated).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$AssessmentDocument,

        [Parameter(Mandatory)]
        [ValidateSet('None', 'Identifiers', 'Strict')]
        [string]$RedactionMode
    )

    if ($RedactionMode -eq 'None') {
        return $AssessmentDocument
    }

    $pseudonymMap = @{}
    $sequenceByType = @{}

    $getPseudonym = {
        param([string]$EntityId, [string]$EntityType)
        $key = "$EntityType|$EntityId"
        if (-not $pseudonymMap.ContainsKey($key)) {
            if (-not $sequenceByType.ContainsKey($EntityType)) {
                $sequenceByType[$EntityType] = 0
            }
            $sequenceByType[$EntityType]++
            $pseudonymMap[$key] = "$EntityType-$($sequenceByType[$EntityType])"
        }
        return $pseudonymMap[$key]
    }

    $redactedResults = @(foreach ($result in $AssessmentDocument.results) {
        $updated = [ordered]@{}
        foreach ($key in $result.Keys) { $updated[$key] = $result[$key] }

        $redactedRefs = @(foreach ($ref in @($result.evidenceReferences)) {
            [ordered]@{
                entityId   = & $getPseudonym $ref.entityId $ref.entityType
                entityType = $ref.entityType
            }
        })
        $updated['evidenceReferences'] = $redactedRefs

        # scope is redacted using the first evidence reference's entityType as a best-effort
        # type label when scope itself equals that reference's entityId (true for both of this
        # project's Phase 5 controls, whose scope is always the primary evaluated entity's own
        # entityId) -- falls back to a generic 'Scope' type bucket otherwise, rather than
        # guessing incorrectly.
        $scopeType = 'Scope'
        $matchingRef = @($result.evidenceReferences) | Where-Object { $_.entityId -eq $result.scope } | Select-Object -First 1
        if ($matchingRef) { $scopeType = $matchingRef.entityType }
        $updated['scope'] = & $getPseudonym $result.scope $scopeType

        if ($RedactionMode -eq 'Strict') {
            $updated['rationale'] = "Detail withheld under Strict redaction; see reasonCode '$($result.reasonCode)'."
        }

        $updated
    })

    $redactedDocument = [ordered]@{}
    foreach ($key in $AssessmentDocument.Keys) { $redactedDocument[$key] = $AssessmentDocument[$key] }
    $redactedDocument['results'] = $redactedResults

    return $redactedDocument
}
