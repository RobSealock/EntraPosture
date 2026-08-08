#Requires -Version 7.4

function Test-EntraPostureAppCreationRestrictionControl {
    <#
        .SYNOPSIS
        USR-001's evaluator: checks the tenant's AuthorizationPolicy allowedToCreateApps.

        .DESCRIPTION
        Engineering plan section 6.3: evaluators depend only on the evidence-provider and
        control contracts. Never produces NotEvaluated or Error status -- those are assigned by
        the orchestration layer, per USR-001.psd1's expectedResultSemantics.

        Unlike AC-002's isEnabled check (EvaluateAdminConsentWorkflow.ps1), this deliberately
        does NOT use a bare [bool] cast on the raw property value: [bool]$null casts to $false,
        which for this field would silently read as "restricted" when Microsoft's own documented
        default for an absent/unset allowedToCreateApps is true ("unrestricted"). The check below
        instead treats only an explicit $false as restricted, so a missing field lands on the
        Fail side (matching the real permissive default) rather than the Pass side.

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
                ReasonCode         = 'USR-001-NO-POLICY-FOUND'
                Rationale          = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $isExplicitlyRestricted = $policy.properties.allowedToCreateApps -eq $false

        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if ($isExplicitlyRestricted) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'USR-001-APP-CREATION-RESTRICTED'
                Rationale          = 'allowedToCreateApps is explicitly false -- non-admin users cannot register application registrations.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'USR-001-APP-CREATION-UNRESTRICTED'
                Rationale          = 'allowedToCreateApps is true (or absent from evidence, which Microsoft documents as defaulting to true) -- non-admin users can register application registrations without any administrative role.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
