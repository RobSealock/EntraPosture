@{
    <#
        VNext build order item 2, the 109-row backlog continuation (batch 14, 2026-08-08). Azure
        RBAC sibling of USR-010 -- same "weak" definition, same reasoning; see
        EvaluateWeakProtectionAzureRole.ps1's own header comment. Keys deliberately camelCase --
        see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-011'
    version     = '1.0.0'
    title       = 'Weak Protection of Privileged Users (Azure)'
    description = 'For each enabled user holding a curated Tier-0 Azure RBAC role (directly or through a group), checks whether their registered authentication methods are passwordless-capable.'
    rationale   = 'A privileged account protected only by a phishable factor (SMS, voice call, software OTP, or no MFA at all) is a disproportionately attractive target -- compromising it grants full control over every Azure resource in scope, and weaker factors are the ones attackers most reliably defeat via SIM-swap, OTP relay, or MFA-fatigue prompting.'
    severity    = 2
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AzureRoleAssignment', 'User', 'TransitiveMemberOf', 'UserRegistrationDetails')
    requiredPermissions     = @(
        @{ scope = 'Microsoft.Authorization/roleAssignments/read'; confirmed = $true }
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
        @{ scope = 'AuditLog.Read.All'; confirmed = $true }
    )

    applicability = 'One result per enabled Tier-0 Azure role holder. A single tenant-scoped NotApplicable result if no such user exists in evidence -- including when no Azure RBAC evidence was collected at all (no -ArmScope supplied).'

    reasonCodes = @(
        @{ code = 'USR-011-NOT-PASSWORDLESS-CAPABLE'; resultStatus = 'Fail';         description = 'The Tier-0 Azure role holder has not registered a passwordless-capable strong authentication method.' }
        @{ code = 'USR-011-NO-REGISTRATION-EVIDENCE';  resultStatus = 'Fail';         description = 'The Tier-0 Azure role holder has no UserRegistrationDetails record in the collected evidence.' }
        @{ code = 'USR-011-PASSWORDLESS-CAPABLE';      resultStatus = 'Pass';        description = 'The Tier-0 Azure role holder has registered a passwordless-capable strong authentication method.' }
        @{ code = 'USR-011-NO-TIER-ZERO-USERS';        resultStatus = 'NotApplicable'; description = 'No enabled user holds a curated Tier-0 Azure RBAC role, directly or through a group.' }
        @{ code = 'USR-011-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'AzureRoleAssignment, User, TransitiveMemberOf, or UserRegistrationDetails evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-011-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per enabled user holding a curated Tier-0 Azure RBAC role (Owner, User Access Administrator, Role Based Access Control Administrator -- USR-009''s own curated list), directly or through a group''s TransitiveMemberOf membership -- the same population USR-009 counts. Fail if that user''s UserRegistrationDetails record has isPasswordlessCapable -ne $true (including a user with no registration record at all); Pass if isPasswordlessCapable -eq $true. A single tenant-scoped NotApplicable result if no such user exists in evidence. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureWeakProtectionAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Register a passwordless, phishing-resistant authentication method (FIDO2 security key, Windows Hello for Business, or Microsoft Entra certificate-based authentication) for every Tier-0 Azure role holder, and require it via a Conditional Access policy using the built-in Phishing-resistant MFA or Passwordless MFA authentication strength for privileged Azure resource access.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, Azure RBAC sibling of USR-010 -- see that control''s own provenance notes for why "weak" was independently and citably defined via isPasswordlessCapable rather than re-deriving EntraFalcon''s own unconfirmed "Is protected" check. Reuses entirely pre-existing evidence (AzureRoleAssignment/User/TransitiveMemberOf from USR-009, UserRegistrationDetails from USR-012) -- zero new collection.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-011' }
    )

    baselineDependency = $null
}
