#Requires -Version 7.4

function Get-EntraPostureEvidenceFileRegistry {
    <#
        .SYNOPSIS
        The single authoritative mapping from entity/relationship type to its evidence JSONL
        filename and governing schema contract.

        .DESCRIPTION
        One source of truth used by both directions of the evidence pipeline: orchestration's
        collection step (which file to append a freshly-collected record to) and the
        evidence-provider's read step (which file to load a given type back from). Filenames
        for the types already illustrated in engineering plan section 8.1's example bundle tree
        ('azure-role-assignments.jsonl', 'azure-role-definitions.jsonl',
        'entra-conditional-access.jsonl') match that example exactly; the remaining entries
        follow the same 'entra-'/'azure-' prefix convention -- section 8.1 states the example
        list is generated from the schema registry, not a closed set.

        .OUTPUTS
        Array of ordered dictionaries: RecordKind ('Entity'/'Relationship'), TypeName (the
        entityType/relationshipType enum value), RelativePath (under a snapshot's evidence/
        directory), ContractName (Get-EntraPostureSchemaPath's ValidateSet).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param ()

    # Leading comma: see EvidenceProvider.ps1's Get-EntraPostureEvidenceRecord for why every
    # array-returning function in this project's Evidence layer uses `,@(...)`, not `@(...)`
    # alone, at its return site -- this registry happens to always have more than one entry
    # today, so the 1-element-collapse bug wouldn't currently trigger here, but fixing it only
    # once it does would be exactly the kind of latent, easy-to-reintroduce bug this comment
    # exists to prevent.
    return ,@(
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'DirectoryRole';                        RelativePath = 'evidence/entra-roles.jsonl';                              ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Relationship'; TypeName = 'DirectoryRoleAssignment';               RelativePath = 'evidence/entra-role-assignments.jsonl';                   ContractName = 'relationship' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AzureRoleAssignment';                  RelativePath = 'evidence/azure-role-assignments.jsonl';                   ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'ConditionalAccessPolicy';              RelativePath = 'evidence/entra-conditional-access.jsonl';                 ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'CrossTenantAccessPolicy';              RelativePath = 'evidence/entra-cross-tenant-access-policy.jsonl';         ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'User';                                 RelativePath = 'evidence/entra-users.jsonl';                              ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'Group';                                RelativePath = 'evidence/entra-groups.jsonl';                             ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Relationship'; TypeName = 'TransitiveMemberOf';                   RelativePath = 'evidence/entra-group-memberships.jsonl';                  ContractName = 'relationship' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'Application';                          RelativePath = 'evidence/entra-applications.jsonl';                       ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'ServicePrincipal';                     RelativePath = 'evidence/entra-service-principals.jsonl';                 ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'ManagedIdentity';                      RelativePath = 'evidence/entra-managed-identities.jsonl';                 ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AdministrativeUnit';                   RelativePath = 'evidence/entra-administrative-units.jsonl';               ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Relationship'; TypeName = 'PimEligible';                          RelativePath = 'evidence/entra-pim-eligibility.jsonl';                    ContractName = 'relationship' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'CrossTenantAccessPolicyPartner';       RelativePath = 'evidence/entra-cross-tenant-access-policy-partners.jsonl'; ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AuthorizationPolicy';                  RelativePath = 'evidence/entra-authorization-policy.jsonl';               ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AdminConsentRequestPolicy';            RelativePath = 'evidence/entra-admin-consent-request-policy.jsonl';       ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AccessReviewDefinition';               RelativePath = 'evidence/entra-access-review-definitions.jsonl';          ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AccessReviewInstance';                 RelativePath = 'evidence/entra-access-review-instances.jsonl';            ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AccessPackage';                        RelativePath = 'evidence/entra-access-packages.jsonl';                    ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AccessPackageAssignmentPolicy';        RelativePath = 'evidence/entra-access-package-assignment-policies.jsonl'; ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AccessPackageAssignment';              RelativePath = 'evidence/entra-access-package-assignments.jsonl';         ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AuthenticationContextClassReference';  RelativePath = 'evidence/entra-authentication-contexts.jsonl';            ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'Organization';                         RelativePath = 'evidence/entra-organization.jsonl';                       ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'SecurityDefaultsPolicy';               RelativePath = 'evidence/entra-security-defaults-policy.jsonl';           ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'NamedLocation';                        RelativePath = 'evidence/entra-named-locations.jsonl';                    ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AuthenticationStrengthPolicy';         RelativePath = 'evidence/entra-authentication-strength-policies.jsonl';   ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'RoleManagementPolicyAssignment';       RelativePath = 'evidence/entra-role-management-policy-assignments.jsonl'; ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AzureSubscription';                    RelativePath = 'evidence/azure-subscriptions.jsonl';                      ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AzureManagementGroup';                 RelativePath = 'evidence/azure-management-groups.jsonl';                  ContractName = 'entity' }
        [ordered]@{ RecordKind = 'Entity';       TypeName = 'AzureRoleDefinition';                  RelativePath = 'evidence/azure-role-definitions.jsonl';                   ContractName = 'entity' }
    )
}
