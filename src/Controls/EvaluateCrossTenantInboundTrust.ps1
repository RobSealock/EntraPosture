#Requires -Version 7.4

function Test-EntraPostureCrossTenantInboundTrustControl {
    <#
        .SYNOPSIS
        XTA-001's evaluator: checks the tenant's default CrossTenantAccessPolicy inboundTrust
        settings for MFA trust without an accompanying device-trust signal.

        .DESCRIPTION
        Engineering plan section 6.3: "Evaluators depend only on the evidence-provider and
        control contracts" -- this function never authenticates, never calls the network, and
        never assumes anything about collection coverage (the orchestration layer only invokes
        this function at all once coverage.json confirms CrossTenantAccessPolicy evidence was
        fully Collected; this function has no code path that could observe or need to know
        that itself).

        Never produces NotEvaluated or Error status -- those are assigned by the orchestration
        layer (coverage gate and exception handling, respectively), per XTA-001.psd1's
        expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per applicable CrossTenantAccessPolicy entity (in practice, exactly one --
        every tenant has a single default policy).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'CrossTenantAccessPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope               = 'tenant'
                Status              = 'NotApplicable'
                ReasonCode          = 'XTA-001-NO-POLICY-FOUND'
                Rationale           = 'No CrossTenantAccessPolicy entity was present in the evidence set.'
                EvidenceReferences  = @()
            }
        )
        return ,@($results)
    }

    # The whole foreach must be wrapped in the outer @() -- assigning a foreach-as-expression's
    # output performs its own enumeration and silently collapses a single-element result back to
    # its bare scalar, the same class of bug Phase 3 found for if/else-as-expression assignment.
    # This is the common case here (there is normally exactly one CrossTenantAccessPolicy).
    $evaluationResults = @(foreach ($policy in $policies) {
        $isMfaAccepted = [bool]$policy.properties.inboundTrustIsMfaAccepted
        $isCompliantDeviceAccepted = [bool]$policy.properties.inboundTrustIsCompliantDeviceAccepted
        $isHybridJoinedDeviceAccepted = [bool]$policy.properties.inboundTrustIsHybridAzureADJoinedDeviceAccepted

        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'CrossTenantAccessPolicy' })

        if ($isMfaAccepted -and -not $isCompliantDeviceAccepted -and -not $isHybridJoinedDeviceAccepted) {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Fail'
                ReasonCode         = 'XTA-001-MFA-WITHOUT-DEVICE-TRUST'
                Rationale          = "Default cross-tenant inbound trust accepts external MFA claims (isMfaAccepted=true) without requiring a compliant or hybrid Azure AD joined device."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $policy.entityId
                Status             = 'Pass'
                ReasonCode         = 'XTA-001-DEVICE-TRUST-OR-MFA-NOT-TRUSTED'
                Rationale          = "Default cross-tenant inbound trust either does not accept external MFA claims, or requires a device-trust signal alongside them."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
