@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        5 -- the confirm-medium pass). Keys deliberately camelCase.
    #>
    controlId   = 'APP-002'
    version     = '1.0.0'
    title       = 'App Registrations Missing App Instance Property Lock'
    description = 'For each multitenant Application entity (signInAudience other than AzureADMyOrg), checks whether App Instance Property Lock (servicePrincipalLockConfiguration.isEnabled) is enabled.'
    rationale   = 'Without App Instance Property Lock, an admin in ANY customer tenant that consents to this multitenant application can modify sensitive properties (credentials, token encryption key) of the service principal created in their own tenant -- the specific application-hijacking risk Microsoft''s own published guidance names this feature as existing to close.'
    severity    = 1
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Application')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per multitenant Application entity (signInAudience other than AzureADMyOrg). NotApplicable (a single tenant-scoped result) if the tenant has no multitenant app registrations at all.'

    reasonCodes = @(
        @{ code = 'APP-002-INSTANCE-LOCK-ENABLED';         resultStatus = 'Pass';        description = 'App Instance Property Lock is enabled on this multitenant application.' }
        @{ code = 'APP-002-INSTANCE-LOCK-MISSING';         resultStatus = 'Fail';         description = 'App Instance Property Lock is not enabled on this multitenant application.' }
        @{ code = 'APP-002-NO-MULTITENANT-APPLICATIONS';   resultStatus = 'NotApplicable'; description = 'No multitenant Application entity was present in the evidence set.' }
        @{ code = 'APP-002-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'Application evidence was not fully collected for this snapshot.' }
        @{ code = 'APP-002-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per multitenant Application entity. Pass if appInstancePropertyLockEnabled is true, Fail otherwise. A single-tenant Application produces no result for it (out of population, not Pass/Fail). NotApplicable (single tenant-scoped result) only if zero multitenant applications exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureAppInstancePropertyLockControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Enable App Instance Property Lock on the multitenant application''s servicePrincipalLockConfiguration, locking at minimum the credentials and token encryption key properties.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipallockconfiguration?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Scoped to multitenant applications only, a real narrowing this pass identified from Microsoft''s own documentation (the feature is specifically framed as protecting "the multitenant app") rather than applying it to every application indiscriminately -- see this control''s own evaluator DESCRIPTION.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'APP-002' }
    )

    baselineDependency = $null
}
