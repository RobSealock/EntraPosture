#Requires -Version 7.4

function Test-EntraPostureManagedIdentityExtensiveApiPrivilegeControl {
    <#
        .SYNOPSIS
        MAI-001's evaluator: thin wrapper over Get-EntraPostureExtensiveApiPrivilegeControlResult
        for every ManagedIdentity entity's application (app role) permissions.

        .DESCRIPTION
        See Get-EntraPostureExtensiveApiPrivilegeControlResult's own DESCRIPTION for the shared
        logic every "Extensive API Privileges" control (ENT-004/005/009/010, AGT-002/003/006/007,
        MAI-001) reuses. Application permissions only, no foreign/internal split, and no
        Delegated-permission sibling control -- a managed identity authenticates via a
        client-credentials-shaped flow with no interactive user context, so it can only ever hold
        application permissions, never delegated ones, and has no meaningful "foreign" concept
        (it is an Azure-resource-backed identity, inherently tenant-local), matching MAI-002/003's
        own already-established precedent for this same population.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    return Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $EvidenceProvider `
        -PermissionType 'Application' -PopulationEntityType 'ManagedIdentity' -ForeignFilter 'All' `
        -ControlId 'MAI-001' -PopulationLabel 'managed identity'
}
