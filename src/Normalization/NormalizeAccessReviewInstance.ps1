#Requires -Version 7.4

function ConvertTo-EntraPostureAccessReviewInstanceEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph accessReviewInstance object (GET /v1.0/identityGovernance/
        accessReviews/definitions/{id}/instances) plus its raw accessReviewInstanceDecisionItem
        collection (GET .../instances/{id}/decisions) into a single canonical Entity record.

        .DESCRIPTION
        VNext build order item 9 (AR-002). 15-feature-parity-matrix.md's own AR-002 design states
        explicitly: "do NOT store individual reviewer identities or per-principal decision
        outcomes; this control reports on process health, not on who-approved-what." This
        function is where that redaction actually happens -- RawDecisions is accepted only to be
        aggregated into counts; no element of it (principal, reviewedBy, justification, etc.) is
        copied into the returned record. This is the sole place in the codebase that ever reads
        an accessReviewInstanceDecisionItem, so the raw decisions array is never persisted to
        disk in any form.

        Field allowlist: id, startDateTime, endDateTime, status (raw pass-through), plus
        DefinitionId (the parent definition's id, supplied by the caller -- an
        accessReviewInstance's own JSON body does not carry a back-reference to it) and four
        aggregate decision counts derived from RawDecisions:
          - decisionsTotalCount: count of decision items returned.
          - decisionsReviewedCount: decision -in ('Approve', 'Deny', 'DontKnow') -- anything
            other than the reviewer never having acted at all.
          - decisionsNotReviewedCount: decision -eq 'NotReviewed', or missing/null (treated the
            same as NotReviewed -- a decision item that doesn't even report its own decision
            value is not evidence of a completed review).
          - decisionsAppliedCount: applyResult -ne 'New' and not missing/null -- Microsoft's
            documented applyResult enum uses 'New' specifically to mean "not yet applied";
            anything else (AppliedSuccessfully, AppliedWithUnknownFailure,
            AppliedSuccessfullyButObjectNotFound, ApplyNotSupported) means the apply step ran.

        .PARAMETER RawInstance
        .PARAMETER DefinitionId
        .PARAMETER RawDecisions
        Array of ordered dictionaries (accessReviewInstanceDecisionItem), or $null/empty if the
        decisions call was never made or returned nothing.

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawInstance,

        [Parameter(Mandatory)]
        [string]$DefinitionId,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$RawDecisions = @(),

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawInstance.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawInstance['id'])) {
        throw 'ConvertTo-EntraPostureAccessReviewInstanceEntity: raw access review instance record has no id.'
    }

    $decisions = @($RawDecisions)
    $reviewedStates = @('Approve', 'Deny', 'DontKnow')

    $reviewedCount = 0
    $appliedCount = 0
    foreach ($decision in $decisions) {
        $decisionValue = if ($decision.Contains('decision')) { [string]$decision['decision'] } else { $null }
        if ($reviewedStates -contains $decisionValue) { $reviewedCount++ }

        $applyResult = if ($decision.Contains('applyResult')) { [string]$decision['applyResult'] } else { $null }
        if (-not [string]::IsNullOrEmpty($applyResult) -and $applyResult -ne 'New') { $appliedCount++ }
    }

    return [ordered]@{
        entityId         = [string]$RawInstance['id']
        entityType       = 'AccessReviewInstance'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            definitionId               = $DefinitionId
            startDateTime              = if ($RawInstance.Contains('startDateTime')) { $RawInstance['startDateTime'] } else { $null }
            endDateTime                = if ($RawInstance.Contains('endDateTime')) { $RawInstance['endDateTime'] } else { $null }
            status                     = if ($RawInstance.Contains('status')) { $RawInstance['status'] } else { $null }
            decisionsTotalCount        = $decisions.Count
            decisionsReviewedCount     = $reviewedCount
            decisionsNotReviewedCount  = $decisions.Count - $reviewedCount
            decisionsAppliedCount      = $appliedCount
        }
        redacted         = $false
    }
}
