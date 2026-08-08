@{
    <#
        Relational control (Phase 7, second tier): composes two evidence objects -- the tenant
        default CrossTenantAccessPolicy and each CrossTenantAccessPolicyPartner override -- to
        determine whether a partner-specific configuration is more permissive than the default.
        Cannot be evaluated from either object alone. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.

        Simplified from 15-feature-parity-matrix.md section 6's full XTA-002 design: that design
        also checks b2bDirectConnectInbound/Outbound and automaticUserConsentSettings widening,
        neither of which is in this project's current CrossTenantAccessPolicyPartner evidence
        field allowlist (src/Normalization/NormalizeCrossTenantAccessPolicyPartner.ps1 -- deliberately
        mirrors the default policy's inboundTrust-only field set). This control checks only the
        inbound-trust dimension both objects actually carry. Documented as a known, deliberate
        v1 boundary in 00-open-questions.md's Phase 7 section.
    #>
    controlId   = 'XTA-002'
    version     = '1.0.0'
    title       = 'Partner-Specific Cross-Tenant Inbound Trust More Permissive Than the Default'
    description = "For each external organization with a customized cross-tenant access configuration, checks whether the partner-specific inboundTrust settings (isMfaAccepted, isCompliantDeviceAccepted, isHybridAzureADJoinedDeviceAccepted) grant trust the tenant-wide default policy does not."
    rationale   = "Because an unconfigured partner silently inherits the tenant-wide default, a partner-specific override is by construction a deliberate widening or narrowing decision. A widening reintroduces XTA-001's exposure scoped to one specific external organization instead of all of them -- easy to set up for a specific integration reason and then never revisit."
    severity    = 2
    category    = 'Cross-Tenant Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('CrossTenantAccessPolicy', 'CrossTenantAccessPolicyPartner')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per configured CrossTenantAccessPolicyPartner entity. A tenant with zero configured partners produces zero results -- a legitimate empty set, not NotEvaluated, since Graph never returns an uncustomized (default-inheriting) partner as a distinct object.'

    reasonCodes = @(
        @{ code = 'XTA-002-TRUST-WIDENED';       resultStatus = 'Fail';         description = 'At least one of the partner''s three inboundTrust flags is true while the corresponding default-policy flag is false.' }
        @{ code = 'XTA-002-NOT-WIDENED';         resultStatus = 'Pass';         description = 'None of the partner''s inboundTrust flags is true where the corresponding default-policy flag is false (equal or more restrictive than the default).' }
        @{ code = 'XTA-002-NO-PARTNERS-CONFIGURED'; resultStatus = 'NotApplicable'; description = 'No CrossTenantAccessPolicyPartner entities were present -- a legitimate empty result set, not a coverage gap.' }
        @{ code = 'XTA-002-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'CrossTenantAccessPolicy or CrossTenantAccessPolicyPartner evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'XTA-002-EVALUATOR-ERROR';      resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per configured partner. Fail if any of the partner''s three inboundTrust flags is true where the default policy''s corresponding flag is false. Pass if the partner is equal to or more restrictive than the default on all three flags. NotApplicable (a single tenant-scoped result, not per-partner) only when zero partners are configured at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureCrossTenantPartnerOverrideControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'For each flagged partner, confirm the relationship is still required and documented with an owner and review date. Narrow the override back toward the default where the widening is no longer justified, or record an approved deviation with owner and expiry if it must remain.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview'
        'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Clean-room control authored directly from Microsoft Learn cross-tenant access guidance and 15-feature-parity-matrix.md section 6''s XTA-002 design, narrowed to the inbound-trust dimension this project''s current evidence supports (see this file''s own comment above). References not independently re-fetched/re-verified as live URLs during this Phase 7 authoring session.'
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration'
        asOfDate          = '2026-04-24'
        citationStrength  = 'DirectQuote'
    }
}
