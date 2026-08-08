@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Reuses the
        GroupSetting evidence/collector infrastructure COL-003 already built -- see
        NormalizeGroupSettings.ps1's own header comment for the "Password Rule Settings"
        groupSettingTemplate field citations. Keys deliberately camelCase -- see XTA-001.psd1's
        header comment for why.
    #>
    controlId   = 'PAS-001'
    version     = '1.0.0'
    title       = 'Custom Banned Password List Not Used'
    description = 'Checks the tenant''s "Password Rule Settings" group settings for EnableBannedPasswordCheck. Fails if explicitly disabled; passes if enabled or if the tenant has never customized this template (Microsoft''s own documented default is enabled).'
    rationale   = 'A custom banned password list blocks passwords that are weak in this specific organization''s context (company name, product names, local terms) that Microsoft''s own global list cannot anticipate.'
    severity    = 2
    category    = 'Passwords'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once GroupSettings evidence has been collected.'

    reasonCodes = @(
        @{ code = 'PAS-001-BANNED-PASSWORD-CHECK-DISABLED'; resultStatus = 'Fail';         description = 'The tenant''s custom banned password list check (EnableBannedPasswordCheck) is explicitly disabled.' }
        @{ code = 'PAS-001-BANNED-PASSWORD-CHECK-ENABLED';  resultStatus = 'Pass';        description = 'The custom banned password list check is enabled, or no customized Password Rule Settings object exists (documented default is enabled).' }
        @{ code = 'PAS-001-EVIDENCE-NOT-COLLECTED';         resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'PAS-001-EVALUATOR-ERROR';                resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail only if a "Password Rule Settings" groupSetting object exists and explicitly sets EnableBannedPasswordCheck to false; Pass otherwise (including no such object at all, per its own documented default). NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureBannedPasswordCheckControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Enable the custom banned password list check and populate it with organization-specific terms.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (a new, no-README-counterpart finding derived directly from EntraFalcon''s check_Tenant.psm1, not a port of its source logic). EnableBannedPasswordCheck field/template/default independently confirmed against live documentation, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PAS-001' }
    )

    baselineDependency = $null
}
