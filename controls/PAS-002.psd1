@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Reuses the
        GroupSetting evidence/collector infrastructure COL-003 already built. Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PAS-002'
    version     = '1.0.0'
    title       = 'Custom Banned Password List Provides Limited Protection'
    description = 'Once the custom banned password list check (PAS-001) is confirmed enabled, checks whether the list contains at least 10 entries.'
    rationale   = 'An enabled but sparsely populated banned password list provides minimal practical protection over Microsoft''s own global list alone.'
    severity    = 1
    category    = 'Passwords'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. NotApplicable when the banned password check itself (PAS-001) is disabled -- list strength is not meaningfully evaluable in that state.'

    reasonCodes = @(
        @{ code = 'PAS-002-BANNED-PASSWORD-LIST-TOO-SHORT';      resultStatus = 'Fail';         description = 'The custom banned password list contains fewer than 10 entries.' }
        @{ code = 'PAS-002-BANNED-PASSWORD-LIST-SUFFICIENT';     resultStatus = 'Pass';        description = 'The custom banned password list contains 10 or more entries.' }
        @{ code = 'PAS-002-BANNED-PASSWORD-CHECK-DISABLED';      resultStatus = 'NotApplicable'; description = 'The banned password check itself is disabled (see PAS-001).' }
        @{ code = 'PAS-002-EVIDENCE-NOT-COLLECTED';              resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'PAS-002-EVALUATOR-ERROR';                     resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. NotApplicable if banned password checking is disabled; otherwise Fail if the list has fewer than 10 entries (including zero, the documented default for an uncustomized template), Pass if 10 or more. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureBannedPasswordListStrengthControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Add organization-specific terms (company name, product names, common local passwords) to the custom banned password list.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity. 10-entry threshold and the "skip when disabled" gate independently re-derived from EntraFalcon''s own publicly visible check_Tenant.psm1; underlying field/template confirmed against live documentation, re-fetched 2026-08-08. bannedPasswordListEntryCount is an aggregated count, never the raw banned password list itself, per this project''s own redaction discipline.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PAS-002' }
    )

    baselineDependency = $null
}
