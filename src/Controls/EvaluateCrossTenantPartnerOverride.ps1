#Requires -Version 7.4

function Test-EntraPostureCrossTenantPartnerOverrideControl {
    <#
        .SYNOPSIS
        XTA-002's evaluator: compares each CrossTenantAccessPolicyPartner's inboundTrust flags
        against the tenant's default CrossTenantAccessPolicy, per partner.

        .DESCRIPTION
        Relational: reads both entity types via the evidence provider and correlates them --
        neither type alone determines the result. Never produces NotEvaluated or Error status --
        assigned by the orchestration layer, per XTA-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per configured partner, or a single NotApplicable element if none are
        configured.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $defaultPolicies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'CrossTenantAccessPolicy'
    $partners = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'CrossTenantAccessPolicyPartner'

    $defaultPolicy = $defaultPolicies | Select-Object -First 1

    if (-not $defaultPolicy -or @($partners).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'XTA-002-NO-PARTNERS-CONFIGURED'
                Rationale          = if (-not $defaultPolicy) { 'No CrossTenantAccessPolicy default entity was present in the evidence set, so no partner comparison can be made.' } else { 'No CrossTenantAccessPolicyPartner entities were present in the evidence set -- no partner overrides are configured.' }
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $defaultMfa = [bool]$defaultPolicy.properties.inboundTrustIsMfaAccepted
    $defaultCompliantDevice = [bool]$defaultPolicy.properties.inboundTrustIsCompliantDeviceAccepted
    $defaultHybridJoin = [bool]$defaultPolicy.properties.inboundTrustIsHybridAzureADJoinedDeviceAccepted

    $evaluationResults = @(foreach ($partner in $partners) {
        $partnerMfa = [bool]$partner.properties.inboundTrustIsMfaAccepted
        $partnerCompliantDevice = [bool]$partner.properties.inboundTrustIsCompliantDeviceAccepted
        $partnerHybridJoin = [bool]$partner.properties.inboundTrustIsHybridAzureADJoinedDeviceAccepted

        $widened = ($partnerMfa -and -not $defaultMfa) `
            -or ($partnerCompliantDevice -and -not $defaultCompliantDevice) `
            -or ($partnerHybridJoin -and -not $defaultHybridJoin)

        $evidenceRef = @(
            [ordered]@{ entityId = $partner.entityId; entityType = 'CrossTenantAccessPolicyPartner' }
            [ordered]@{ entityId = $defaultPolicy.entityId; entityType = 'CrossTenantAccessPolicy' }
        )

        if ($widened) {
            [ordered]@{
                Scope              = $partner.entityId
                Status             = 'Fail'
                ReasonCode         = 'XTA-002-TRUST-WIDENED'
                Rationale          = "Partner tenant $($partner.entityId)'s inbound trust settings accept a signal (MFA, compliant device, or hybrid-joined device) the tenant-wide default does not."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $partner.entityId
                Status             = 'Pass'
                ReasonCode         = 'XTA-002-NOT-WIDENED'
                Rationale          = "Partner tenant $($partner.entityId)'s inbound trust settings are equal to or more restrictive than the tenant-wide default."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
