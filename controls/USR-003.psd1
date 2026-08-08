@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-003'
    version     = '1.0.0'
    title       = 'Users Can Read BitLocker Recovery Key of Owned Devices'
    description = 'Checks the tenant''s AuthorizationPolicy.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice setting.'
    rationale   = 'A BitLocker recovery key lets anyone who obtains it decrypt the associated device''s entire disk offline -- allowing the device''s own registered user (or anyone who compromises that user''s account) to read it widens the exposure of a credential that should otherwise be tightly held.'
    severity    = 1
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one). Evaluated directly from the tenant-wide policy setting regardless of current device count -- the setting is a standing capability. NotApplicable (a single tenant-scoped result) if the singleton is missing from evidence entirely.'

    reasonCodes = @(
        @{ code = 'USR-003-BITLOCKER-KEY-READ-ALLOWED';    resultStatus = 'Fail';         description = 'Users are allowed to read the BitLocker recovery key of devices they own.' }
        @{ code = 'USR-003-BITLOCKER-KEY-READ-RESTRICTED'; resultStatus = 'Pass';        description = 'Users are not allowed to read the BitLocker recovery key of devices they own.' }
        @{ code = 'USR-003-NO-POLICY-FOUND';               resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'USR-003-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-003-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity (in practice exactly one). Fail if allowedToReadBitlockerKeysForOwnedDevice is true, Pass if false. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureBitlockerKeyReadAccessControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'In the Microsoft Entra admin center: Devices > Device settings > set "Restrict users from recovering the BitLocker key(s) for their owned devices" to Yes.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic -- that source additionally gates on a non-zero tenant device count via its own Device evidence, which this project deliberately does not replicate: the policy setting is a standing capability independent of whether any device currently exists, and no Device evidence domain exists in this project. allowedToReadBitlockerKeysForOwnedDevice confirmed present on the existing default GET /v1.0/policies/authorizationPolicy response, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-003' }
    )

    baselineDependency = $null
}
