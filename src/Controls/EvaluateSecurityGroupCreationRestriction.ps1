#Requires -Version 7.4

function Test-EntraPostureSecurityGroupCreationRestrictionControl {
    <#
        .SYNOPSIS
        GRP-001's evaluator: checks the tenant's AuthorizationPolicy
        allowedToCreateSecurityGroups.

        .DESCRIPTION
        Engineering plan section 6.3: evaluators depend only on the evidence-provider and
        control contracts. Never produces NotEvaluated or Error status -- those are assigned by
        the orchestration layer, per GRP-001.psd1's expectedResultSemantics.

        Same null-handling reasoning as USR-001's sibling evaluator
        (EvaluateAppCreationRestriction.ps1's own DESCRIPTION) -- only an explicit $false counts
        as restricted; a missing field is treated as the documented permissive default ($true),
        not silently cast to "restricted".

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
                ReasonCode         = 'GRP-001-NO-POLICY-FOUND'
                Rationale          = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $isExplicitlyRestricted = $policy.properties.allowedToCreateSecurityGroups -eq $false

        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if ($isExplicitlyRestricted) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'GRP-001-GROUP-CREATION-RESTRICTED'
                Rationale          = 'allowedToCreateSecurityGroups is explicitly false -- non-admin users cannot create security groups.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'GRP-001-GROUP-CREATION-UNRESTRICTED'
                Rationale          = 'allowedToCreateSecurityGroups is true (or absent from evidence, which Microsoft documents as defaulting to true) -- non-admin users can create security groups without any administrative role.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
