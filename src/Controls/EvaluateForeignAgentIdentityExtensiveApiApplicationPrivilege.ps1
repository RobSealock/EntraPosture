#Requires -Version 7.4

function Test-EntraPostureForeignAgentIdentityExtensiveApiApplicationPrivilegeControl {
    <#
        .SYNOPSIS
        AGT-002's evaluator: thin wrapper over Get-EntraPostureExtensiveApiPrivilegeControlResult
        for foreign AgentIdentity entities' application (app role) permissions.

        .DESCRIPTION
        See Get-EntraPostureExtensiveApiPrivilegeControlResult's own DESCRIPTION for the shared
        logic every "Extensive API Privileges" control (ENT-004/005/009/010, AGT-002/003/006/007,
        MAI-001) reuses.

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
        -PermissionType 'Application' -PopulationEntityType 'AgentIdentity' -ForeignFilter 'Foreign' `
        -ControlId 'AGT-002' -PopulationLabel 'foreign agent identity'
}
