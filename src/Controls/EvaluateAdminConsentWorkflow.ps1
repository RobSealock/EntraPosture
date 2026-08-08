#Requires -Version 7.4

function Test-EntraPostureAdminConsentWorkflowControl {
    <#
        .SYNOPSIS
        AC-002's evaluator: checks the tenant's AdminConsentRequestPolicy isEnabled and
        reviewerCount.

        .DESCRIPTION
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AC-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AdminConsentRequestPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AdminConsentRequestPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AC-002-NO-POLICY-FOUND'
                Rationale          = 'No AdminConsentRequestPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $isEnabled = [bool]$policy.properties.isEnabled
        $reviewerCount = [int]$policy.properties.reviewerCount

        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AdminConsentRequestPolicy' })

        if (-not $isEnabled) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'AC-002-WORKFLOW-DISABLED'
                Rationale          = 'The admin consent request workflow is disabled -- a user who cannot self-consent to an application has no path to request review.'
                EvidenceReferences = $evidenceRef
            }
        } elseif ($reviewerCount -eq 0) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'AC-002-NO-REVIEWERS-CONFIGURED'
                Rationale          = 'The admin consent request workflow is enabled but has zero reviewers configured -- requests have no one to act on them.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'AC-002-WORKFLOW-CONFIGURED'
                Rationale          = "The admin consent request workflow is enabled with $reviewerCount reviewer(s) configured."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
