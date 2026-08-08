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
| `RoleManagement.Read.Directory` | DirectoryRoleAssignments, PimEligibility | Privileged Roles | PRIV-001, PIM-002, CA-001 |
| `Policy.Read.All` | ConditionalAccessPolicies, CrossTenantAccessPolicy, CrossTenantAccessPolicyPartners, TenantPolicies, NamedLocations | Conditional Access, Cross-Tenant Access, Consent and Authorization | CA-001, XTA-001, XTA-002, AC-001, AC-002, USR-001, GRP-001 |
| `User.Read.All` | Users | Identity | *(breadth collector -- no control depends on it directly yet)* |
| `Group.Read.All` | Groups | Identity | GRP-005 |
| `GroupMember.Read.All` | Groups | Identity | GRP-005 |
| `Application.Read.All` | Applications, ServicePrincipals | Applications | *(breadth collector -- no control depends on it directly yet)* |
| `AdministrativeUnit.Read.All` | AdministrativeUnits | Identity | *(breadth collector -- no control depends on it directly yet)* |
| `AccessReview.Read.All` | AccessReviewDefinitions | Access Reviews | AR-001, AR-002 |
| `AuthenticationContext.Read.All` | AuthenticationContexts | Conditional Access | AUTHCTX-001/002 not yet built (see `00-open-questions.md`) |
| `Organization.Read.All` | TenantConfiguration | Tenant Configuration | *(breadth collector -- no control depends on it directly yet)* |
| `Policy.Read.AuthenticationMethod` | AuthenticationStrengthPolicies | Conditional Access | *(feeds `Resolve-EntraPostureAuthenticationStrengthRequirement`, not a control directly -- see `00-open-questions.md` item 5)* |
| `RoleManagementPolicy.Read.Directory` | RoleManagementPolicyAssignments | Privileged Roles, Conditional Access | AUTHCTX-001, AUTHCTX-002, PIM-003, PIM-004, PIM-005, PIM-006, PIM-007, PIM-008, PIM-009 |
| `EntitlementManagement.Read.All` | AccessPackages | Entitlement Management | EM-001, EM-002 |

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

## Azure Resource Manager permissions (optional -- only needed if you pass `-ArmScope`)

Azure RBAC collection is skipped entirely, not silently incomplete, when `-ArmScope` is omitted.
When you do supply it, the app's **service principal** needs an Azure role assignment (the
built-in **Reader** role satisfies all four) granting these actions at the scope(s) you assess:

| Action | Collector | Report section |
|---|---|---|
| `Microsoft.Resources/subscriptions/read` | AzureSubscriptions | Azure RBAC |
| `Microsoft.Management/managementGroups/read` | AzureManagementGroups | Azure RBAC |
| `Microsoft.Authorization/roleAssignments/read` | AzureRoleAssignments | Azure RBAC |
| `Microsoft.Authorization/roleDefinitions/read` | AzureRoleDefinitions | Azure RBAC |

No control currently depends on Azure RBAC evidence directly (breadth/discovery collectors only,
per each collector's own `AffectedControlIds`) -- collecting it populates the report's Azure RBAC
section and is available for future controls, but a Graph-only run with no `-ArmScope` is a fully
supported, complete-for-what-it-attempts assessment.

## What a narrower grant actually gets you

This tool never refuses to run because a permission is missing -- every collector's evidence
independently degrades to `Denied` (permission-only preflight failure) or `Unavailable`
(permission present, but the live call itself failed, e.g. a licensing gate) without blocking any
other collector. A narrower grant simply means a `Partial` snapshot with specific, named coverage
gaps in `coverage.json` and the report's own Coverage section -- never a silent, misleadingly
"clean" result. See `docs/SecurityAndStorage.md` for how `Partial` status is surfaced and cannot
be confused with "no findings."
