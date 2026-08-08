#Requires -Version 7.4

function Get-EntraPostureControl {
    <#
        .SYNOPSIS
        Discovers native controls and their external mappings from the control registry.

        .DESCRIPTION
        Control-discovery command (engineering plan section 6.2). Lists every control under
        controls/ (ADR-013: each is a .psd1 definition plus an explicit, statically-bound
        evaluator function, no embedded scriptblocks or dynamic loading), optionally filtered
        to one -ControlId.

        .PARAMETER ControlId
        Optional. Returns every control when omitted.

        .OUTPUTS
        Array of ordered dictionaries matching control-definition.schema.json.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ControlId
    )

    if ($ControlId) {
        return Get-EntraPostureControlDefinition -ControlId $ControlId
    }

    return Get-EntraPostureControlRegistry
}
