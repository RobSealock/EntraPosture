@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Reuses the
        GroupSetting evidence/collector infrastructure COL-003 already built. Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PAS-004'
    version     = '1.0.0'
    title       = 'Weak Account Lockout Settings'
    description = 'Checks whether the tenant''s account lockout settings (LockoutThreshold, LockoutDurationInSeconds) are at least as strict as Microsoft''s own documented secure defaults (threshold=10, duration=60s).'
    rationale   = 'A lockout threshold set too high, or a lockout duration set too short, weakens smart lockout''s protection against online password-guessing attacks.'
    severity    = 1
    category    = 'Passwords'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once GroupSettings evidence has been collected.'

    reasonCodes = @(
        @{ code = 'PAS-004-LOCKOUT-SETTINGS-WEAK';           resultStatus = 'Fail';         description = 'Configured lockout threshold/duration are weaker than Microsoft''s documented defaults, or could not be parsed.' }
        @{ code = 'PAS-004-LOCKOUT-SETTINGS-STRICT-ENOUGH';  resultStatus = 'Pass';        description = 'Configured lockout threshold/duration are at least as strict as Microsoft''s documented defaults.' }
        @{ code = 'PAS-004-DEFAULT-LOCKOUT-SETTINGS';        resultStatus = 'Pass';        description = 'No customized Password Rule Settings object exists; Microsoft''s documented secure defaults apply.' }
        @{ code = 'PAS-004-EVIDENCE-NOT-COLLECTED';          resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'PAS-004-EVALUATOR-ERROR';                 resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Pass if no customized settings object exists (defaults apply) or if LockoutThreshold <= 10 and LockoutDurationInSeconds >= 60; Fail otherwise. Deliberately simpler than a full attempts-per-hour estimate (Microsoft does not publish the exact lockout-duration escalation curve, so this project does not attempt to replicate that unverifiable approximation) -- a direct threshold/duration comparison against documented defaults is the citable subset. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureAccountLockoutSettingsControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set LockoutThreshold to 10 or fewer failed attempts and LockoutDurationInSeconds to 60 seconds or more on the tenant''s Password Rule Settings.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own attempts-per-hour estimation logic (that source''s own comment states the underlying lockout-duration escalation curve is undocumented by Microsoft and therefore approximated) -- this project instead does a direct, citable comparison against Microsoft''s own documented defaults (threshold=10, duration=60s), confirmed live 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PAS-004' }
    )

    baselineDependency = $null
}
