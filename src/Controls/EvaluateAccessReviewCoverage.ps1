#Requires -Version 7.4

function Test-EntraPostureAccessReviewCoverageControl {
    <#
        .SYNOPSIS
        AR-001's evaluator: checks whether any collected AccessReviewDefinition's scopeQuery
        matches each of three governance-surface patterns (privileged roles, groups,
        applications).

        .DESCRIPTION
        Relational: the applicable unit is "does any definition cover this surface," which
        cannot be answered from a single AccessReviewDefinition in isolation. Surface detection
        is case-insensitive substring matching against scopeQuery -- see AR-001.psd1's header
        comment for the documented simplifications versus the matrix's fuller design. Always
        produces exactly three results (one per surface), even when zero definitions exist at
        all (every surface Fails in that case, which is the correct outcome, not a special
        case this function needs to branch on separately).

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AR-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Always three elements.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    # No @() wrapper around the call -- Get-EntraPostureEntity already comma-protects its
    # return (`return ,@($index.Records)`); wrapping the call site in @() too double-wraps it
    # into a 1-element array whose sole element is the real records array, confirmed directly
    # (a Count of 1 instead of the real record count) while building this control's tests. See
    # EvaluateSensitiveGroupProtection.ps1's identical comment for the full empirical writeup.
    $definitions = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AccessReviewDefinition'

    # Substring patterns against the real Microsoft Graph accessReviewScheduleDefinition
    # scope.query shapes documented for each reviewable surface -- see AR-001.psd1's header
    # comment: not independently re-verified against a live tenant this session.
    $surfaces = @(
        [ordered]@{ Name = 'PrivilegedRoles'; Patterns = @('rolemanagement', 'roleassignmentscheduleinstances', 'roleeligibilityscheduleinstances'); FailCode = 'AR-001-NO-REVIEW-PRIVILEGED-ROLES'; Label = 'privileged Entra role assignments' }
        [ordered]@{ Name = 'Groups';          Patterns = @('/groups');                                                                                FailCode = 'AR-001-NO-REVIEW-GROUPS';           Label = 'group membership' }
        [ordered]@{ Name = 'Applications';    Patterns = @('serviceprincipals', 'approleassign');                                                     FailCode = 'AR-001-NO-REVIEW-APPLICATIONS';     Label = 'application access' }
    )

    $evaluationResults = @(foreach ($surface in $surfaces) {
        $matchingDefinitions = @($definitions | Where-Object {
            $query = [string]$_.properties.scopeQuery
            if ([string]::IsNullOrWhiteSpace($query)) { return $false }
            $queryLower = $query.ToLowerInvariant()
            foreach ($pattern in $surface.Patterns) {
                if ($queryLower.Contains($pattern)) { return $true }
            }
            return $false
        })

        if (@($matchingDefinitions).Count -eq 0) {
            [ordered]@{
                Scope              = $surface.Name
                Status             = 'Fail'
                ReasonCode         = $surface.FailCode
                Rationale          = "No AccessReviewDefinition's scope query targets $($surface.Label)."
                EvidenceReferences = @()
            }
        } else {
            $evidenceRef = @(foreach ($def in $matchingDefinitions) { [ordered]@{ entityId = $def.entityId; entityType = 'AccessReviewDefinition' } })
            [ordered]@{
                Scope              = $surface.Name
                Status             = 'Pass'
                ReasonCode         = 'AR-001-COVERAGE-CONFIRMED'
                Rationale          = "At least one AccessReviewDefinition's scope query targets $($surface.Label)."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
