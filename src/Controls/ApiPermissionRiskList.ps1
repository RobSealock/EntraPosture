#Requires -Version 7.4

function Get-EntraPostureDangerousApplicationPermissionId {
    <#
        .SYNOPSIS
        The curated set of Microsoft Graph application-permission (app role) GUIDs this project
        treats as "extensive" -- privileged enough on their own that a service principal holding
        one is a real, standing escalation path, independent of whether it also holds an explicit
        directory role.

        .DESCRIPTION
        Deliberately a single "Dangerous" tier, not the full multi-tier (Dangerous/High/Medium/
        Low) risk-scoring system a comparable community tool (EntraFalcon) maintains internally
        -- that system's own full table runs to 200+ entries across both permission types and was
        judged out of scope to independently re-verify entry-by-entry for this pass. This
        project's own, smaller "Dangerous" tier was curated by cross-referencing EntraFalcon's own
        publicly visible "Dangerous"-tier entries (fetched directly from its GitHub repository,
        `modules/shared_Functions.psm1`, `$global:GLOBALApiPermissionCategorizationList`) as a
        starting candidate list, then independently reasoning about and spot-verifying each GUID
        against Microsoft's own live "Microsoft Graph permissions reference" page (re-fetched
        2026-08-08) before inclusion -- 4 of 4 spot-checked GUIDs (both application and delegated
        variants of AppRoleAssignment.ReadWrite.All and Application.ReadWrite.All) matched
        exactly. One EntraFalcon candidate (Application.ReadUpdate.All) was deliberately excluded
        here after its GUID could not be independently confirmed against Microsoft's own primary
        documentation within this pass -- this project's own discipline throughout VNext build
        order item 2 has been to exclude rather than guess when a claim can't be directly
        verified.

        Every permission below grants a standing path to escalate privilege or take over the
        directory outright, independent of any explicit role assignment:
        - RoleManagement.ReadWrite.Directory -- grant any Entra ID directory role, including
          Global Administrator, to any principal.
        - AppRoleAssignment.ReadWrite.All -- grant any application permission (including this
          same list's own other entries) to any service principal, a direct self-escalation path.
        - Application.ReadWrite.All -- create, modify, or add credentials to any app registration
          in the tenant, effectively impersonating any other application.
        - RoleAssignmentSchedule.ReadWrite.Directory / RoleEligibilitySchedule.ReadWrite.Directory
          -- create standing (active) or PIM-eligible assignments to any Entra ID directory role.
        - PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup /
          PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup / PrivilegedAccess.ReadWrite.
          AzureADGroup -- the same three role-assignment escalation paths, scoped to PIM-for-
          Groups instead of directory roles directly.
        - Domain.ReadWrite.All -- add or verify a custom domain, a documented enabler of
          federation-based tenant-takeover techniques.

        .OUTPUTS
        String[] of application-permission (app role) GUIDs.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param ()

    return @(
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'  # RoleManagement.ReadWrite.Directory
        '06b708a9-e830-4db3-a914-8e69da51d44f'  # AppRoleAssignment.ReadWrite.All
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'  # Application.ReadWrite.All
        'dd199f4a-f148-40a4-a2ec-f0069cc799ec'  # RoleAssignmentSchedule.ReadWrite.Directory
        'fee28b28-e1f3-4841-818e-2704dc62245f'  # RoleEligibilitySchedule.ReadWrite.Directory
        '41202f2c-f7ab-45be-b001-85c9728b9d69'  # PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
        '618b6020-bca8-4de6-99f6-ef445fa4d857'  # PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
        '2f6817f8-7b12-4f0f-bc18-eeaf60705a9e'  # PrivilegedAccess.ReadWrite.AzureADGroup
        '7e05723c-0bb0-42da-be95-ae9f08a6e53c'  # Domain.ReadWrite.All
    )
}

function Get-EntraPostureDangerousDelegatedPermissionName {
    <#
        .SYNOPSIS
        The curated set of Microsoft Graph delegated-permission names this project treats as
        "extensive" -- the delegated-scope counterpart to
        Get-EntraPostureDangerousApplicationPermissionId.

        .DESCRIPTION
        Named, not GUID-keyed, because oauth2PermissionGrant's own 'scope' property (what
        CollectServicePrincipalApiPermissions.ps1 actually reads) is a space-delimited string of
        permission *names*, confirmed directly against the live "List a service principal's
        oauth2PermissionGrants" Graph reference page (re-fetched 2026-08-08) -- there is no GUID
        to resolve or verify for this half, unlike application permissions' own appRoleId. Same
        nine underlying permissions and the same "standing directory-takeover/escalation path"
        rationale as the application-permission tier's own DESCRIPTION -- delegated grants of the
        same-named permission carry the identical risk, scoped to whichever user consented (or
        was administratively granted) rather than the app's own service identity.

        .OUTPUTS
        String[] of delegated-permission names.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param ()

    return @(
        'RoleManagement.ReadWrite.Directory'
        'AppRoleAssignment.ReadWrite.All'
        'Application.ReadWrite.All'
        'RoleAssignmentSchedule.ReadWrite.Directory'
        'RoleEligibilitySchedule.ReadWrite.Directory'
        'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup'
        'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup'
        'PrivilegedAccess.ReadWrite.AzureADGroup'
        'Domain.ReadWrite.All'
    )
}
