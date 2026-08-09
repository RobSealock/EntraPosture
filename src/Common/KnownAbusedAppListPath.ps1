#Requires -Version 7.4

function Get-EntraPostureKnownAbusedAppListPath {
    <#
        .SYNOPSIS
        Resolves the default local file locations for the vendored `rogueapps.toml` copy and its
        refresh sidecar metadata.

        .DESCRIPTION
        Same dual dev-tree/built-tree resolution as Get-EntraPostureSchemaPath (see that
        function's own DESCRIPTION for why two candidate roots are probed), with one difference:
        that function requires the target file to already exist to resolve at all, since a
        schema file always ships with the module. This file does not always exist yet -- a fresh
        checkout before the first Update-EntraPostureKnownAbusedAppList -Fetch -Save, or an
        install where the seed copy was stripped -- so this function resolves the *directory*
        that should hold it (preferring a candidate root that already exists, falling back to the
        dev-tree location if neither does) and returns file paths under it regardless of whether
        those files exist yet.

        Deliberately NOT under src/, controls/, or schemas/ -- those three are copied into dist/
        and content-hash-verified by Build-Module.ps1's own build-output check; a file this
        project's own refresh cmdlet rewrites at runtime cannot live inside that verified
        footprint. data/ is copied into dist/ as a working seed (see Build-Module.ps1's own data/
        copy step) but is never hashed or verified to match source.

        .OUTPUTS
        Ordered dictionary: TomlPath, MetaPath (both plain strings; existence is not checked or
        implied).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    $candidateRoots = @(
        (Join-Path $PSScriptRoot '../../data')  # dev tree: dot-sourced from src/Common/
        (Join-Path $PSScriptRoot 'data')         # built tree: dist/ (or wherever installed) sibling
    )

    $resolvedRoot = $null
    foreach ($root in $candidateRoots) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            $resolvedRoot = $root
            break
        }
    }
    if (-not $resolvedRoot) {
        $resolvedRoot = $candidateRoots[0]
    }

    return [ordered]@{
        TomlPath = Join-Path $resolvedRoot 'known-abused-apps.toml'
        MetaPath = Join-Path $resolvedRoot 'known-abused-apps.meta.json'
    }
}
