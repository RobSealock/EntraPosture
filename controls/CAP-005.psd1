@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-005'
    version     = '1.0.0'
    title       = 'No Phishing-Resistant MFA Enforced'
    description = 'Checks whether any enabled Conditional Access policy requires an authentication strength whose allowedCombinations is a non-empty subset of {windowsHelloForBusiness, fido2, x509CertificateMultiFactor} -- Microsoft''s phishing-resistant method set.'
    rationale   = 'Ordinary MFA (e.g. push notification, SMS) remains vulnerable to real-time phishing/adversary-in-the-middle attacks that a phishing-resistant method (FIDO2, certificate-based auth, Windows Hello for Business) is specifically designed to prevent -- Microsoft recommends phishing-resistant MFA for high-value scenarios explicitly for this reason.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy', 'AuthenticationStrengthPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
        @{ scope = 'Policy.Read.AuthenticationMethod'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-005-PHISHING-RESISTANT-MFA-ENFORCED';     resultStatus = 'Pass';        description = 'At least one enabled policy requires a phishing-resistant authentication strength.' }
        @{ code = 'CAP-005-PHISHING-RESISTANT-MFA-NOT-ENFORCED'; resultStatus = 'Fail';         description = 'No enabled policy requires a phishing-resistant authentication strength.' }
        @{ code = 'CAP-005-EVIDENCE-NOT-COLLECTED';              resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy or AuthenticationStrengthPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-005-EVALUATOR-ERROR';                     resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy''s authenticationStrengthId resolves to an AuthenticationStrengthPolicy whose allowedCombinations is a non-empty subset of the three phishing-resistant methods; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPosturePhishingResistantMfaEnforcementControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy requiring the built-in "Phishing-resistant MFA" authentication strength (or an equivalent custom one) for sensitive scenarios.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
        'https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Matched by allowed-combination subset rather than by displayName/policyType so a custom equivalent strength is also counted -- the three-method phishing-resistant set confirmed live against the Conditional Access Authentication Strengths overview page and the authenticationMethodModes enum, re-checked 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-005' }
    )

    baselineDependency = $null
}
