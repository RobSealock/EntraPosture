#Requires -Version 7.4

function Get-EntraPostureToolVersionInfo {
    <#
        .SYNOPSIS
        Returns the tool/schema/control-registry version triple pinned into every snapshot
        manifest (engineering plan ADR-017).

        .DESCRIPTION
        Kept as one manually-maintained constant rather than read back from
        build/BuildManifest.psd1 at runtime -- the built module has no dependency on its own
        build manifest file existing on disk after packaging (ADR-004's no-runtime-discovery
        rule applies here too), so this is the single place all three versions are bumped
        together. ToolVersion must be kept in sync with BuildManifest.psd1's ModuleMetadata.ModuleVersion
        by hand; nothing currently cross-checks the two automatically.

        .OUTPUTS
        Ordered dictionary: ToolVersion, SchemaVersion, ControlRegistryVersion.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return [ordered]@{
        ToolVersion            = '0.1.0'
        SchemaVersion          = '1.0.0'
        ControlRegistryVersion = '1.0.0'
    }
}
