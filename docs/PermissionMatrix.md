# Permission matrix

Generated directly from every collector's own declared `RequiredPermissions` in
`src/Collectors/*.ps1` (via `Get-EntraPosture*CollectorRequirement`), not hand-maintained
separately -- this is the authoritative list this tool's own preflight check
(`Test-EntraPostureAccess`) enforces at runtime, current as of Phase 9. If it ever drifts from
the source, the source is correct and this file is stale.

## Microsoft Graph permissions

Grant these as **Application permissions** (certificate/app-only auth) or **Delegated
permissions** (interactive auth) on your app registration, then grant admin consent. All are
read-only (`*.Read.*` / `*.Read.All`), matching this tool's read-only design (ADR: no write
operation exists anywhere in this codebase).

| Permission | Collector(s) | Report section | Controls fed |
|---|---|---|---|
| `RoleManagement.Read.Directory` | DirectoryRoleAssignments, PimEligibility, RoleAssignmentScopes | Privileged Roles, Conditional Access | PRIV-001, PIM-001, PIM-002, CA-001, USR-006, USR-010, CAP-011 |
| `Policy.Read.All` | ConditionalAccessPolicies, CrossTenantAccessPolicy, CrossTenantAccessPolicyPartners, TenantPolicies, NamedLocations | Conditional Access, Cross-Tenant Access, Consent and Authorization | CA-001, XTA-001, XTA-002, AC-001, AC-002, USR-001/002/003/004, GRP-001/004, PAS-005 |
| `User.Read.All` | Users | Identity | USR-006/007/008/009/010/011 |
| `Group.Read.All` | Groups | Identity | GRP-003/004/005, USR-006, USR-009/010/011 |
| `GroupMember.Read.All` | Groups | Identity | GRP-005, USR-009/010/011 |
| `Application.Read.All` | Applications, ServicePrincipals, ServicePrincipalApiPermissions | Applications | APP-001/002/003, ENT-001/003/004/006/007/008/009/010/011/012/013, AGT-002/003/006/007, MAI-001/002/003 |
| `AdministrativeUnit.Read.All` | AdministrativeUnits | Identity | *(breadth collector -- no control depends on it directly yet)* |
| `AccessReview.Read.All` | AccessReviewDefinitions | Access Reviews | AR-001, AR-002 |
| `AuthenticationContext.Read.All` | AuthenticationContexts | Conditional Access | AUTHCTX-001, AUTHCTX-002 |
| `Organization.Read.All` | TenantConfiguration | Tenant Configuration | *(breadth collector -- no control depends on it directly yet)* |
| `Policy.Read.AuthenticationMethod` | AuthenticationStrengthPolicies | Conditional Access | *(feeds `Resolve-EntraPostureAuthenticationStrengthRequirement`, not a control directly -- see `00-open-questions.md` item 5)* |
| `RoleManagementPolicy.Read.Directory` | RoleManagementPolicyAssignments | Privileged Roles, Conditional Access | AUTHCTX-001, AUTHCTX-002, PIM-003, PIM-004, PIM-005, PIM-006, PIM-007, PIM-008, PIM-009 |
| `EntitlementManagement.Read.All` | AccessPackages | Entitlement Management | EM-001, EM-002 |
| `AgentIdentityBlueprint.Read.All` | AgentIdentityBlueprints | Agent Identities | AGT-001, AGT-017 |
| `AgentIdentityBlueprintPrincipal.Read.All` | AgentIdentityBlueprintPrincipals | Agent Identities | AGT-004, AGT-005, AGT-008, AGT-009, AGT-011, AGT-012, AGT-017 |
| `AgentIdentity.Read.All` | AgentIdentities | Agent Identities | AGT-004, AGT-005, AGT-008, AGT-009 |
| `User.ReadBasic.All` | AgentUsers | Agent Identities | AGT-011, AGT-012, AGT-015 |
| `Directory.Read.All` | AgentUsers (ownedObjects N+1 only), ServicePrincipalApiPermissions (oauth2PermissionGrants half only) | Agent Identities, Applications | AGT-015; ENT-005/010, AGT-003/007 |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | PimForGroups | PIM | PIMG-001 |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` | PimForGroups | PIM | PIMG-001, PIMG-002 |
| `GroupSettings.Read.All` | GroupSettings | External Collaboration, Passwords, Groups | COL-003, PAS-001/002/003/004, GRP-002 |
| `AuditLog.Read.All` | UserSignInActivity | Identity | USR-005 (also requires the tenant to be licensed for Entra ID P1 or P2 -- see below) |
| `AuditLog.Read.All` | UserRegistrationDetails | Identity | USR-012, USR-010, USR-011 (Microsoft's own documented recommendation for bulk per-user MFA-registration auditing, over the per-user `/authentication/methods` endpoint -- see `00-open-questions.md` §41) |

**Live What-If comparison** (the ad hoc `scripts/Compare-WhatIf.ps1` utility, not part of the
core assessment pipeline) additionally calls `POST /identity/conditionalAccess/evaluate`, whose
documented least-privileged scope is `Policy.Read.ConditionalAccess` -- already satisfied by
`Policy.Read.All` above if you've granted that. **This action also requires Conditional Access to
be licensed in the tenant (Entra ID P1 or higher)** regardless of permission grant -- confirmed
directly against a real tenant lacking that license (a clean `403 AccessDenied` naming the
licensing gate, not a permission error).

## Known Global Reader coverage gap

**Role-assignment-scoped Access Review definitions are not readable by Global Reader.** Per
Microsoft's own documented supported-roles list for that specific query, only Security Reader,
Identity Governance Administrator, Privileged Role Administrator, or Security Administrator can
read them -- confirmed directly (`15-feature-parity-matrix.md` §7). A Global-Reader-only identity
will show `AccessReviewDefinitions` as `Collected` (the definitions-list endpoint itself doesn't
gate on this), but any *future* control checking privileged-role-scoped review coverage
specifically would need an elevated role. Every other permission above is fully covered by Global
Reader.

**Agent identity listing requires the Agent ID Administrator role, not Global Reader, for a
nonowner in delegated scenarios.** Confirmed directly against the live "List agentIdentity
objects" Microsoft Graph reference page (re-fetched 2026-08-07): a Global-Reader-shaped identity
that is not itself an owner of a given blueprint/agent identity will see `AgentIdentityBlueprints`,
`AgentIdentityBlueprintPrincipals`, and `AgentIdentities` as `Denied` even with the correct app
permission scopes granted, unless also assigned Agent ID Administrator (or is an owner). PIM-for-
Groups (`PimForGroups`) is a separate gap of a different kind: `PrivilegedEligibilitySchedule.Read.
AzureADGroup`/`PrivilegedAssignmentSchedule.Read.AzureADGroup` are permission scopes distinct from
every scope Global Reader is typically granted by default, independent of whether Global Reader's
built-in role would itself be sufficient once granted (for role-assignable groups specifically, it
is). **`AgentUsers`'s ownedObjects half (AGT-015) has no application-permission path at all** --
confirmed directly against the live "List ownedObjects" Graph reference page, which lists
Application permission as "Not supported" for that specific relationship -- so AGT-015 evidence is
structurally unavailable for any `CertificateAppOnly` run regardless of role or granted scopes.
**`UserSignInActivity` (USR-005) has a real, separate dependency beyond permission entirely**: even
with `AuditLog.Read.All` granted, the `signInActivity` property requires the tenant itself to be
licensed for Microsoft Entra ID P1 or P2 -- an unlicensed tenant will see this collector fail at
collection time (a real API error despite adequate permission, per this project's own
partial-evidence handling), surfacing as `USR-005-EVIDENCE-NOT-COLLECTED`, never a silent Pass.
**`ServicePrincipalApiPermissions` declares both `Application.Read.All` and `Directory.Read.All`
as required** even though only its delegated-permission half (`oauth2PermissionGrants`) actually
needs `Directory.Read.All` -- the application-permission half (`appRoleAssignments`) is fully
satisfied by `Application.Read.All` alone. Granting only one of the two still leaves this whole
evidence domain short of its own declared requirement (`evidenceStatus` `Incomplete`, not
`Collected`), so every control depending on it -- `ENT-004`/`005`/`009`/`010`,
`AGT-002`/`003`/`006`/`007`, `MAI-001` -- is affected, not just the delegated-permission half's
own controls. Grant both scopes together to collect this domain fully.
**`ENT-013` needs no Graph/ARM permission of its own beyond `Application.Read.All`** (already
required for `ServicePrincipals`) -- its own reference data (`KnownAbusedAppList`) is a local
file read, not a tenant API call, so there's no permission to grant for it at all. It always
evaluates off `ServicePrincipals`' own coverage; with no local list configured, it reports
`NotApplicable`, never `NotEvaluated` or a silent Pass -- see the README's own "Reference data
refresh" section and `Update-EntraPostureKnownAbusedAppList`.
**`RoleAssignmentScopes` (CAP-011) is fully covered by Global Reader**, unlike several of the
gaps above -- the live "List unifiedRoleAssignments" Graph reference page names Global Reader
directly as a supported built-in role for `GET /roleManagement/directory/roleAssignments`, and
its own `RoleManagement.Read.Directory` requirement is already granted by every identity that
also collects `DirectoryRoleAssignments`.

## Azure Resource Manager permissions (optional -- only needed if you pass `-ArmScope`)

Azure RBAC collection is skipped entirely, not silently incomplete, when `-ArmScope` is omitted.
When you do supply it, the app's **service principal** needs an Azure role assignment (the
built-in **Reader** role satisfies all four) granting these actions at the scope(s) you assess:

| Action | Collector | Report section | Controls fed |
|---|---|---|---|
| `Microsoft.Resources/subscriptions/read` | AzureSubscriptions | Azure RBAC | *(breadth collector -- no control depends on it directly)* |
| `Microsoft.Management/managementGroups/read` | AzureManagementGroups | Azure RBAC | *(breadth collector -- no control depends on it directly)* |
| `Microsoft.Authorization/roleAssignments/read` | AzureRoleAssignments | Azure RBAC | AGT-005/009/012/014, MAI-003, ENT-007/012, USR-008/009/011 |
| `Microsoft.Authorization/roleDefinitions/read` | AzureRoleDefinitions | Azure RBAC | *(breadth collector -- no control depends on it directly)* |

A Graph-only run with no `-ArmScope` skips Azure RBAC collection entirely, not silently -- every
control fed by `AzureRoleAssignments` above degrades to `NotEvaluated` (missing evidence), never a
silent Pass, and every other control in the assessment is unaffected.

## What a narrower grant actually gets you

This tool never refuses to run because a permission is missing -- every collector's evidence
independently degrades to `Denied` (permission-only preflight failure) or `Unavailable`
(permission present, but the live call itself failed, e.g. a licensing gate) without blocking any
other collector. A narrower grant simply means a `Partial` snapshot with specific, named coverage
gaps in `coverage.json` and the report's own Coverage section -- never a silent, misleadingly
"clean" result. See `docs/SecurityAndStorage.md` for how `Partial` status is surfaced and cannot
be confused with "no findings."
