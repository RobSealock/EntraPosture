@{
    <#
        Predicate control (Phase 5's "one predicate control" vertical-slice exit criterion):
        evaluates a single CrossTenantAccessPolicy entity's inboundTrust settings. Keys are
        deliberately camelCase, matching control-definition.schema.json exactly -- see
        src/Controls/ControlRegistry.ps1's Get-EntraPostureControlRegistry for why (this
        file is "serialized to JSON for schema validation," not consumed as a PowerShell-style
        PascalCase data structure).
    #>
    controlId   = 'XTA-001'
    version     = '1.0.0'
    title       = 'Cross-tenant inbound trust does not accept external MFA claims without device-based verification'
    description = "Checks the tenant's default cross-tenant access policy inboundTrust settings: whether externally-asserted MFA claims (isMfaAccepted) are trusted without also requiring the device to be marked compliant or Hybrid Azure AD joined."
    rationale   = 'Accepting an external tenant''s MFA claim at face value, with no accompanying device-trust signal, means this tenant''s access decisions depend entirely on a partner tenant''s own MFA policy rigor, which cannot be independently verified or enforced. Pairing MFA trust with a device-compliance or hybrid-join requirement narrows that exposure to devices this tenant (or a trusted partner IT function) can actually attest to.'
    severity    = 3
    category    = 'Cross-Tenant Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('CrossTenantAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable when the tenant''s default cross-tenant access policy was collected -- every tenant has exactly one.'

    reasonCodes = @(
        @{ code = 'XTA-001-MFA-WITHOUT-DEVICE-TRUST';   resultStatus = 'Fail';         description = 'inboundTrust.isMfaAccepted is true while both isCompliantDeviceAccepted and isHybridAzureADJoinedDeviceAccepted are false.' }
        @{ code = 'XTA-001-DEVICE-TRUST-OR-MFA-NOT-TRUSTED'; resultStatus = 'Pass';     description = 'Either isMfaAccepted is false, or at least one device-trust signal (compliant or hybrid-joined) is also required.' }
        @{ code = 'XTA-001-NO-POLICY-FOUND';             resultStatus = 'NotApplicable'; description = 'No CrossTenantAccessPolicy entity was present in the evidence set (unexpected in a real tenant, but handled defensively).' }
        @{ code = 'XTA-001-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'CrossTenantAccessPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'XTA-001-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail when inboundTrust.isMfaAccepted is true and neither device-trust flag is true. Pass when isMfaAccepted is false, or when at least one device-trust flag is true alongside it. NotApplicable only if no policy entity exists at all. NotEvaluated/Error are never produced by the evaluator function itself -- they are assigned by the orchestration layer based on collection coverage and evaluator execution outcome, respectively (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPostureCrossTenantInboundTrustControl'
    evidenceRedactionPolicy = 'None'

    remediation = "Require a device-trust signal alongside externally-accepted MFA claims: in the Microsoft Entra admin center, under Cross-tenant access settings > Default settings > Inbound access > Trust settings, enable 'Trust multi-factor authentication from Microsoft Entra tenants' only in combination with 'Trust compliant devices' and/or 'Trust hybrid Azure AD joined devices', or scope MFA trust to specific, reviewed partner organizations instead of the tenant-wide default."

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-access-overview'
        'https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-access-settings-b2b-collaboration'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Clean-room control authored directly from Microsoft Learn cross-tenant access guidance, not ported from EntraFalcon or Conditional Access Validator source code. The two references above were not independently re-fetched/re-verified as live URLs during this Phase 5 authoring session -- flagged in 00-open-questions.md for a follow-up citation-verification pass before this control is treated as release-ready.'
    }

    externalMappings = @()

    baselineDependency = $null
}
