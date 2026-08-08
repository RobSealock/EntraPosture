@{
    <#
        VNext build order item 2, new-evidence phase (batch 6, 2026-08-08). Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'ENT-008'
    version     = '1.0.0'
    title       = 'Foreign Enterprise Applications Owning Objects'
    description = 'For each ServicePrincipal entity confirmed foreign (appOwnerOrganizationId differs from this tenant), checks whether it owns any object (application, service principal, or other directory object) in this tenant.'
    rationale   = 'A service principal representing an application your tenant does not own should not also be able to create, own, or modify objects inside your directory -- ownership grants edit rights over the owned object (adding credentials, changing configuration), so a foreign principal holding it is a cross-tenant blast-radius concern distinct from, and additive to, ENT-006/007''s role-holding checks.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per ServicePrincipal entity confirmed foreign. NotApplicable (a single tenant-scoped result) if no ServicePrincipal was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'ENT-008-FOREIGN-OWNS-OBJECT';           resultStatus = 'Fail';         description = 'The foreign service principal owns at least one object in this tenant.' }
        @{ code = 'ENT-008-FOREIGN-OWNS-NOTHING';          resultStatus = 'Pass';        description = 'The foreign service principal owns no object in this tenant.' }
        @{ code = 'ENT-008-NO-FOREIGN-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was confirmed foreign in the evidence set.' }
        @{ code = 'ENT-008-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'ServicePrincipal evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-008-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity confirmed foreign. Fail if it owns one or more objects in this tenant (an OwnerOf relationship with it as the source), Pass otherwise. NotApplicable (single tenant-scoped result) only if zero foreign service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignServicePrincipalOwnedObjectsControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned application was granted ownership of an object in this tenant. Remove the ownership grant; if the foreign principal genuinely needs to modify the object, use a narrower, auditable delegation instead of directory ownership.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-ownedobjects?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity -- consolidates EF-EAP-008 ("Ownership over app registrations"), EF-EAP-009 ("Ownership of other service principals"), and EF-EAP-011 ("App owns app registration") into one canonical finding, the same "one canonical ID, not fragmented by owned-object type" pattern already established for GRP-005. Owned objects collected via GET /v1.0/servicePrincipals/{id}/ownedObjects, scoped to foreign service principals only in CollectServicePrincipals.ps1''s N+1 fetch (2026-08-08, VNext build order item 2 batch 6, the new-evidence phase) to bound cost -- ordinary tenant-internal service principals owning objects is not this control''s concern (see ENT-003 for the internal-owner-quality check).'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-008' }
    )

    baselineDependency = $null
}
