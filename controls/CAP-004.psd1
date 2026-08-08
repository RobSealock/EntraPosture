@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-004'
    version     = '1.0.0'
    title       = 'No MFA Required for Joining/Registering a Device'
    description = 'Checks whether any enabled Conditional Access policy requires MFA when a user joins or registers a device (conditions.applications.includeUserActions contains urn:user:registerdevice, with an MFA-satisfying grant).'
    rationale   = 'An unprotected device-join/registration action lets a compromised session enroll an attacker-controlled device, which can then be used to satisfy device-based Conditional Access requirements elsewhere in the tenant.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-004-DEVICE-REGISTRATION-MFA-REQUIRED';     resultStatus = 'Pass';        description = 'At least one enabled policy requires MFA for device join/registration.' }
        @{ code = 'CAP-004-DEVICE-REGISTRATION-MFA-NOT-REQUIRED'; resultStatus = 'Fail';         description = 'No enabled policy requires MFA for device join/registration.' }
        @{ code = 'CAP-004-EVIDENCE-NOT-COLLECTED';               resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-004-EVALUATOR-ERROR';                      resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy targets urn:user:registerdevice with builtInControls containing mfa or a set authenticationStrengthId; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureDeviceRegistrationMfaControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy targeting the register device user action with an MFA grant control.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. includeUserActions literal value confirmed live against the conditionalAccessApplications Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-004' }
    )

    baselineDependency = $null
}
