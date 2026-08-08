#Requires -Version 7.4

function Get-EntraPostureTierZeroAzureRoleId {
    <#
        .SYNOPSIS
        The curated set of Azure RBAC built-in role definition GUIDs this project treats as
        Tier-0 -- privileged enough on their own to escalate to full control of the assigned
        scope, independent of any other role held.

        .DESCRIPTION
        Unlike this project's curated Tier-0 *Entra ID* role list (three built-in roles, reused
        unchanged everywhere a Tier-0 Entra role check is needed), no equivalent Azure RBAC list
        existed anywhere in this project before USR-009 -- every existing Azure-role control
        (ENT-007/012, MAI-003, AGT-005/009/012) checks "holds any Azure role assignment at all,"
        deliberately not tier-graded (see those controls' own provenance notes). This list was
        curated specifically for USR-009 by independently reading each candidate role's own live,
        authoritative JSON permission grant (Azure's own "Built-in roles for Privileged" reference
        page, re-fetched 2026-08-08) -- not by trusting a comparable community tool's own
        categorization at face value, even though that tool's own list was the starting candidate
        set.

        Included, both confirmed to have an unrestricted path to grant themselves (or anyone) full
        control, including further role assignment rights:
        - Owner (`8e3af657-a8ff-443c-a75c-2fe8c4bcb635`) -- `Actions: ["*"]`, no NotActions at
          all. Unrestricted.
        - User Access Administrator (`18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`) -- `Microsoft.
          Authorization/*`, which includes creating custom roles and assigning any role
          (including Owner) to any principal at any scope it holds the role at.
        - Role Based Access Control Administrator (`f58310d9-a9f6-439a-9e8d-f62e7b41a168`) --
          narrower than User Access Administrator (no `Microsoft.Authorization/*`, just
          `roleAssignments/write`/`/delete` plus `*/read`), but that one action alone is
          sufficient to assign the Owner role to itself or any other principal; Azure RBAC's own
          `roleAssignments/write` action carries no built-in "cannot grant a role more privileged
          than your own" restriction, so this role is functionally an escalation path to Owner
          despite lacking the broader authorization-management surface.

        Deliberately excluded, each with a specific, checked reason rather than a guess:
        - Contributor (`b24988ac-6180-42a0-ab88-20f7382dd24c`) -- its own live JSON explicitly
          lists `Microsoft.Authorization/*/Write`, `Microsoft.Authorization/*/Delete`, and
          `Microsoft.Authorization/elevateAccess/Action` as `NotActions` -- Contributor is
          expressly *blocked* from writing role assignments and from the specific
          tenant-root-scope elevation action. High-impact (full resource CRUD), but structurally
          not a privilege-escalation path the way the three roles above are.
        - Reservations Administrator (`a8889054-8d42-49c9-bc1c-52486c10e7cd`) -- does carry
          `Microsoft.Authorization/roleAssignments/write`, but its own `assignableScopes` is
          `["/providers/Microsoft.Capacity"]` -- a fixed, narrow resource-provider namespace, not
          general subscription/resource-group scope. Its role-assignment rights are themselves
          scoped to that namespace in normal usage, not a general escalation path.

        .OUTPUTS
        String[] of Azure RBAC role definition GUIDs.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param ()

    return @(
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'  # Owner
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'  # User Access Administrator
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168'  # Role Based Access Control Administrator
    )
}
