@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Reuses the
        GroupSetting evidence/collector infrastructure COL-003 already built. Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PAS-003'
    version     = '1.0.0'
    title       = 'Password Protection for On-Premises Not Enforced'
    description = 'Once the custom banned password list check (PAS-001) is confirmed enabled, checks whether it is enforced (not just audited) for the on-premises Active Directory environment.'
    rationale   = 'Audit mode logs violations without blocking weak/banned passwords set on-premises -- only Enforce mode actually prevents them, closing the gap a hybrid environment would otherwise leave in the cloud-side banned password protection.'
    severity    = 1
    category    = 'Passwords'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. NotApplicable when the banned password check itself (PAS-001) is disabled.'

    reasonCodes = @(
        @{ code = 'PAS-003-ON-PREMISES-NOT-ENFORCED';       resultStatus = 'Fail';         description = 'On-premises password protection is not both enabled and set to Enforce mode.' }
        @{ code = 'PAS-003-ON-PREMISES-ENFORCED';           resultStatus = 'Pass';        description = 'On-premises password protection is enabled and set to Enforce mode.' }
        @{ code = 'PAS-003-BANNED-PASSWORD-CHECK-DISABLED'; resultStatus = 'NotApplicable'; description = 'The banned password check itself is disabled (see PAS-001).' }
        @{ code = 'PAS-003-EVIDENCE-NOT-COLLECTED';         resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'PAS-003-EVALUATOR-ERROR';                resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. NotApplicable if banned password checking is disabled; otherwise Fail unless EnableBannedPasswordCheckOnPremises is true AND BannedPasswordCheckOnPremisesMode is Enforce -- the documented default mode is Audit, so an uncustomized template Fails, not Passes. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureOnPremisesPasswordProtectionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set BannedPasswordCheckOnPremisesMode to Enforce on the tenant''s Password Rule Settings, and confirm the on-premises password filter proxy service is installed and running.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity. BannedPasswordCheckOnPremisesMode''s documented default (Audit, not Enforce) confirmed against live documentation, re-fetched 2026-08-08 -- a real absence-handling direction independently verified, not assumed.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PAS-003' }
    )

    baselineDependency = $null
}
