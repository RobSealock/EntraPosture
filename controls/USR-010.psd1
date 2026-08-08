@{
    <#
        VNext build order item 2, the 109-row backlog continuation (batch 14, 2026-08-08). "Weak"
        is defined as isPasswordlessCapable -ne $true on the user's own UserRegistrationDetails
        record -- see EvaluateWeakProtectionEntraRole.ps1's own header comment for why this
        Microsoft-computed field was chosen over self-curated methodsRegistered string matching.
        Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-010'
    version     = '1.0.0'
    title       = 'Weak Protection of Privileged Users (Entra ID)'
    description = 'For each enabled user holding a curated Tier-0 Entra ID role (directly or through a role-assignable group), checks whether their registered authentication methods are passwordless-capable.'
    rationale   = 'A privileged account protected only by a phishable factor (SMS, voice call, software OTP, or no MFA at all) is a disproportionately attractive target -- compromising it grants tenant-wide control, and weaker factors are the ones attackers most reliably defeat via SIM-swap, OTP relay, or MFA-fatigue prompting.'
    severity    = 3
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'DirectoryRoleAssignment', 'User', 'TransitiveMemberOf', 'UserRegistrationDetails')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
        @{ scope = 'AuditLog.Read.All'; confirmed = $true }
    )

    applicability = 'One result per enabled Tier-0 Entra ID role holder. A single tenant-scoped NotApplicable result if no such user exists in evidence.'

    reasonCodes = @(
        @{ code = 'USR-010-NOT-PASSWORDLESS-CAPABLE'; resultStatus = 'Fail';         description = 'The Tier-0 role holder has not registered a passwordless-capable strong authentication method.' }
        @{ code = 'USR-010-NO-REGISTRATION-EVIDENCE';  resultStatus = 'Fail';         description = 'The Tier-0 role holder has no UserRegistrationDetails record in the collected evidence.' }
        @{ code = 'USR-010-PASSWORDLESS-CAPABLE';      resultStatus = 'Pass';        description = 'The Tier-0 role holder has registered a passwordless-capable strong authentication method.' }
        @{ code = 'USR-010-NO-TIER-ZERO-USERS';        resultStatus = 'NotApplicable'; description = 'No enabled user holds a curated Tier-0 Entra ID role, directly or through a role-assignable group.' }
        @{ code = 'USR-010-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'DirectoryRole, DirectoryRoleAssignment, User, TransitiveMemberOf, or UserRegistrationDetails evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-010-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per enabled user holding a curated Tier-0 Entra ID role (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator), directly or through a role-assignable group''s TransitiveMemberOf membership -- the same population USR-006 counts and USR-007 checks for hybrid sync. Fail if that user''s UserRegistrationDetails record has isPasswordlessCapable -ne $true (including a user with no registration record at all -- missing evidence never becomes a clean result); Pass if isPasswordlessCapable -eq $true. A single tenant-scoped NotApplicable result if no such user exists in evidence. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureWeakProtectionEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Register a passwordless, phishing-resistant authentication method (FIDO2 security key, Windows Hello for Business, or Microsoft Entra certificate-based authentication) for every Tier-0 role holder, and require it via a Conditional Access policy using the built-in Phishing-resistant MFA or Passwordless MFA authentication strength for privileged role access.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity. The matrix''s own raw-row mapping (EF-USR-010, "Is protected") was not re-derived here -- EntraFalcon''s own source for what "protected" checks was not confirmable, so this control''s definition of "weak protection" was built independently and citably from Microsoft''s own isPasswordlessCapable field semantics instead, documented fully in the evaluator''s own header comment. Reuses entirely pre-existing evidence (DirectoryRole/DirectoryRoleAssignment/User/TransitiveMemberOf from USR-006/USR-007, UserRegistrationDetails from USR-012) -- zero new collection.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-010' }
    )

    baselineDependency = $null
}
