@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'APP-001'
    version     = '1.0.0'
    title       = 'App Registrations with Secrets'
    description = 'For each Application entity, checks whether it has at least one password credential (client secret) configured.'
    rationale   = 'A client secret is a long-lived, exportable, plaintext-equivalent credential -- Microsoft''s own recommended guidance is to prefer certificate-based or federated (workload identity federation) credentials, which are not directly exportable, over password-based secrets wherever possible.'
    severity    = 1
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Application')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected Application entity -- always applicable to every app registration. NotApplicable (a single tenant-scoped result) only if the tenant has no app registrations at all.'

    reasonCodes = @(
        @{ code = 'APP-001-HAS-PASSWORD-CREDENTIAL'; resultStatus = 'Fail';         description = 'The app registration has at least one password credential configured.' }
        @{ code = 'APP-001-NO-PASSWORD-CREDENTIAL';  resultStatus = 'Pass';        description = 'The app registration has no password credential configured.' }
        @{ code = 'APP-001-NO-APPLICATIONS';         resultStatus = 'NotApplicable'; description = 'No Application entity was present in the evidence set.' }
        @{ code = 'APP-001-EVIDENCE-NOT-COLLECTED';  resultStatus = 'NotEvaluated'; description = 'Application evidence was not fully collected for this snapshot.' }
        @{ code = 'APP-001-EVALUATOR-ERROR';         resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected Application entity. Fail when passwordCredentialCount is greater than zero, Pass when it is zero. NotApplicable (single tenant-scoped result) only if zero app registrations exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureAppRegistrationSecretsControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the password credential and switch to certificate-based authentication or workload identity federation, per Microsoft''s own recommended guidance.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Same aggregate-count-not-raw-array pattern AGT-001 already established for the identical field on AgentIdentityBlueprint (a different entity type, same underlying /applications resource family).'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'APP-001' }
    )

    baselineDependency = $null
}
