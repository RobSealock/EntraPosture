#Requires -Version 7.4

function Test-EntraPostureAuthenticationContextCoverageControl {
    <#
        .SYNOPSIS
        AUTHCTX-001's evaluator: for each published, PIM-role-activation-configured
        authentication context, checks whether any Conditional Access policy (any state)
        actually references it.

        .DESCRIPTION
        Relational: correlates three evidence domains (AuthenticationContextClassReference,
        RoleManagementPolicyAssignment, ConditionalAccessPolicy) -- no single type determines the
        result. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per AUTHCTX-001.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per applicable context, or a single NotApplicable element if none are
        applicable.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $contexts = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthenticationContextClassReference'
    $publishedContexts = @($contexts | Where-Object { [bool]$_.properties.isAvailable })

    $policyAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'RoleManagementPolicyAssignment'
    $authContextAssignments = @($policyAssignments | Where-Object {
        [bool]$_.properties.authenticationContextEnabled -and -not [string]::IsNullOrEmpty([string]$_.properties.authenticationContextClaimValue)
    })
    $configuredClaimValues = @($authContextAssignments | ForEach-Object { [string]$_.properties.authenticationContextClaimValue } | Select-Object -Unique)

    $applicableContexts = @($publishedContexts | Where-Object { $configuredClaimValues -contains $_.entityId })

    if (@($applicableContexts).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AUTHCTX-001-NO-APPLICABLE-CONTEXTS'
                Rationale          = 'No authentication context is both published (isAvailable=true) and configured as a PIM role-activation requirement.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $caPolicies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    # Union across every policy regardless of state (§ AUTHCTX-001's own expectedResultSemantics:
    # "in any state -- enabled, disabled, or report-only" -- whether the referencing policy is
    # actually *effective* is AUTHCTX-002's job, not this control's).
    $referencedContextIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $caPolicies) {
        foreach ($refId in @($policy.properties.conditions.applications.includeAuthenticationContextClassReferences)) {
            $referencedContextIds.Add([string]$refId) | Out-Null
        }
    }

    $evaluationResults = @(foreach ($context in $applicableContexts) {
        $isReferenced = $referencedContextIds.Contains($context.entityId)
        $rolesRequiringContext = @($authContextAssignments | Where-Object { [string]$_.properties.authenticationContextClaimValue -eq $context.entityId })

        $evidenceRef = @([ordered]@{ entityId = $context.entityId; entityType = 'AuthenticationContextClassReference' })
        foreach ($assignment in $rolesRequiringContext) {
            $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        }

        if (-not $isReferenced) {
            [ordered]@{
                Scope              = $context.entityId
                Status             = 'Fail'
                ReasonCode         = 'AUTHCTX-001-NO-REFERENCING-POLICY'
                Rationale          = "Authentication context '$($context.displayName)' ($($context.entityId)) is published and required for PIM activation on $($rolesRequiringContext.Count) role(s), but no Conditional Access policy in the tenant references it."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $context.entityId
                Status             = 'Pass'
                ReasonCode         = 'AUTHCTX-001-REFERENCED'
                Rationale          = "Authentication context '$($context.displayName)' ($($context.entityId)) is referenced by at least one Conditional Access policy."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
