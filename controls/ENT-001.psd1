@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        5 -- the confirm-medium pass). Keys deliberately camelCase.
    #>
    controlId   = 'ENT-001'
    version     = '1.0.0'
    title       = 'Enterprise Applications with Client Credentials'
    description = 'For each ServicePrincipal entity, checks whether it has at least one key or password credential configured directly on the service principal itself.'
    rationale   = 'A credential added directly to a service principal (independently of its application registration''s own credentials, which APP-001 already checks) is a durable, exportable authentication secret -- the same concern APP-001/AGT-001 already apply to application registrations and agent identity blueprints, applied here to the enterprise-application (service principal) object itself.'
    severity    = 1
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected ServicePrincipal entity -- always applicable to every enterprise application. NotApplicable (a single tenant-scoped result) only if the tenant has no service principals at all.'

    reasonCodes = @(
        @{ code = 'ENT-001-HAS-CLIENT-CREDENTIAL';   resultStatus = 'Fail';         description = 'The service principal has at least one key or password credential configured.' }
        @{ code = 'ENT-001-NO-CLIENT-CREDENTIAL';    resultStatus = 'Pass';        description = 'The service principal has no key or password credential configured.' }
        @{ code = 'ENT-001-NO-SERVICE-PRINCIPALS';   resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was present in the evidence set.' }
        @{ code = 'ENT-001-EVIDENCE-NOT-COLLECTED';  resultStatus = 'NotEvaluated'; description = 'ServicePrincipal evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-001-EVALUATOR-ERROR';         resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected ServicePrincipal entity. Fail when either keyCredentialCount or passwordCredentialCount is greater than zero, Pass when both are zero. NotApplicable (single tenant-scoped result) only if zero service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureEnterpriseAppClientCredentialsControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the credential from the service principal and switch to certificate-based authentication or workload identity federation, per Microsoft''s own recommended guidance.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. keyCredentials/passwordCredentials confirmed present on the default, unfiltered GET /v1.0/servicePrincipals response, re-verified live 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-001' }
    )

    baselineDependency = $null
}
