@{
    <#
        VNext build order item 2, the 109-row backlog continuation (batch 17, 2026-08-09). The
        last of the originally-deferred 10-item ranked list to become buildable -- see
        Invoke-EntraPostureCollectAndSeal's own .PARAMETER KnownAbusedAppListPath and
        EvaluateKnownAbusedApp.ps1's own header comment for the coverage/architecture reasoning.
        Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'ENT-013'
    version     = '1.0.0'
    title       = 'Known Abused Enterprise Applications'
    description = 'For each enterprise application (service principal) in the tenant, checks whether its own appId matches an entry in a locally vendored, operator-refreshed list of applications observed being abused in real-world compromises (huntresslabs/rogueapps).'
    rationale   = 'Attackers reuse the same small set of legitimate-but-abusable applications (mailbox export tools, mass-mail senders, contact-exfiltration utilities) across many unrelated compromises because they already have the OAuth permissions needed and rarely draw scrutiny; a tenant that has consented to one of these is at meaningfully elevated risk regardless of whether it was consented to maliciously or by a user who did not realize what the app does.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'KnownAbusedApp', 'KnownAbusedAppListMetadata')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'One result per ServicePrincipal entity, but only when local known-abused-app reference data was actually available for this snapshot; a single tenant-scoped NotApplicable result otherwise (no ServicePrincipal entity in evidence, OR no known-abused-app reference data available -- the two are deliberately indistinguishable to a report reader here: both mean "nothing was actually checked," not "checked and clean"). Gating for this control is collector-driven, not requiredEvidenceDomains-driven (Invoke-EntraPostureSnapshotEvaluation''s own coverage-to-control mapping keys off each COLLECTOR''s own declared AffectedControlIds, not a control''s requiredEvidenceDomains list -- confirmed directly, the hard way, after an earlier draft of this control relied on the latter and produced a result with a null reasonCode). CollectServicePrincipals.ps1 alone declares ENT-013 in its own AffectedControlIds, deliberately NOT CollectRoleAssignmentScopes.ps1-style "KnownAbusedAppList" -- so this control always evaluates (never NotEvaluated) purely on ServicePrincipal''s own coverage, and the evaluator itself decides NotApplicable vs. a real check based on whether KnownAbusedApp entities are actually present. The one exception: when a local list WAS configured but failed to parse, Invoke-EntraPostureCollectAndSeal''s own KnownAbusedAppList coverage record (Malformed) also carries ENT-013 in its own affectedControlIds, so THAT genuine failure does correctly make this control NotEvaluated (and the whole snapshot Partial) -- only "never configured at all" is designed to stay invisible to the exit code.'

    reasonCodes = @(
        @{ code = 'ENT-013-KNOWN-ABUSED-APP-MATCH';    resultStatus = 'Fail';         description = 'The enterprise application''s appId matches an entry in the local known-abused-app list. Presence does not confirm malicious intent in this tenant -- manual review required.' }
        @{ code = 'ENT-013-NO-KNOWN-ABUSED-APP-MATCH'; resultStatus = 'Pass';        description = 'The enterprise application does not match any entry in the local known-abused-app list.' }
        @{ code = 'ENT-013-NO-SERVICE-PRINCIPALS';     resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was present in the evidence set.' }
        @{ code = 'ENT-013-NO-REFERENCE-DATA';         resultStatus = 'NotApplicable'; description = 'No known-abused-app reference data was available for this snapshot (Update-EntraPostureKnownAbusedAppList was never run, or -KnownAbusedAppListPath was never configured) -- nothing was actually checked.' }
        @{ code = 'ENT-013-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'ServicePrincipal evidence itself was not fully collected for this snapshot, or a configured known-abused-app list existed but failed to parse.' }
        @{ code = 'ENT-013-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity, Fail if its appId matches a KnownAbusedApp entity''s own entityId (also the app''s appId), Pass otherwise -- but only when at least one KnownAbusedApp entity is present in evidence at all; if none are (the reference list was never configured for this snapshot), a single tenant-scoped NotApplicable result is returned instead of evaluating every service principal as a vacuous Pass, so a report reader can tell "nothing to check against" apart from "checked, found nothing." A single tenant-scoped NotApplicable result also covers zero ServicePrincipal entities. NotEvaluated is assigned by the orchestration layer only for a genuine collection failure -- ServicePrincipal itself not fully collected, or a configured known-abused-app list that failed to parse -- never for the optional list simply being unconfigured, by design (see this control''s own applicability field for the collector-level mechanics).'

    evaluatorFunctionName  = 'Test-EntraPostureKnownAbusedAppControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Investigate the flagged application''s actual usage in this tenant: who consented to it, when, and what it has accessed since. If it is not a deliberate, sanctioned business tool, revoke its consent grants and disable/delete the service principal. If it is sanctioned, document why and consider whether its own granted permissions can be narrowed.'

    references = @(
        'https://github.com/huntresslabs/rogueapps'
        'https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic -- this project''s own deferral reason ("no citable malicious-app signature source") was resolved by the project owner surfacing huntresslabs/rogueapps (MPL-2.0, actively maintained) rather than by re-deriving EntraFalcon''s own unconfirmed data source. That dataset''s own README states presence means "observed in adversarial contexts," narrower than this control''s "known malicious" title -- carried forward explicitly in this control''s own rationale, every Fail''s Rationale text, and the refresh cmdlet''s own disclaimer, rather than silently presented as a confirmed-malicious determination. The evidence-collection design (a local-file read at collection time, contributing no coverage record at all when unconfigured rather than a misleading ''Unavailable'') was a deliberate architecture decision made specifically to avoid this optional domain silently changing every other assessment''s default exit code -- see 00-open-questions.md''s own build log for the full reasoning.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-013' }
    )

    baselineDependency = $null
}
