#Requires -Version 7.4

function Test-EntraPostureDefaultUserConsentPolicyControl {
    <#
        .SYNOPSIS
        AC-001's evaluator: checks the tenant's AuthorizationPolicy
        permissionGrantPoliciesAssigned for the built-in legacy (broad) policy ID.

        .DESCRIPTION
        Engineering plan section 6.3: evaluators depend only on the evidence-provider and
        control contracts. Never produces NotEvaluated or Error status -- those are assigned by
        the orchestration layer, per AC-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AuthorizationPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AC-001-NO-POLICY-FOUND'
                Rationale          = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    # @() around the whole foreach -- see EvaluateCrossTenantInboundTrust.ps1's identical
    # comment for why a foreach-as-expression assignment needs the outer wrap even when the
    # common case (exactly one policy) would otherwise collapse to a bare scalar.
    $evaluationResults = @(foreach ($policy in $policies) {
        $assignedPolicies = @($policy.properties.permissionGrantPoliciesAssigned)
        $hasLegacyPolicy = [bool]($assignedPolicies | Where-Object { [string]$_ -like '*.microsoft-user-default-legacy' })

        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if ($hasLegacyPolicy) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'AC-001-LEGACY-POLICY-ASSIGNED'
                Rationale          = 'The default user role''s permission grant policy includes the built-in legacy policy, allowing any user to consent to any non-admin-required permission for any application.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'AC-001-RESTRICTED-POLICY-ASSIGNED'
                Rationale          = 'The default user role''s permission grant policy does not include the built-in legacy policy.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
