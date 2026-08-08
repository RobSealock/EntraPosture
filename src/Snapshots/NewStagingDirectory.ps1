#Requires -Version 7.4

function New-EntraPostureStagingDirectory {
    <#
        .SYNOPSIS
        Creates a unique staging directory with the snapshot/ bundle subtree, ready for
        collectors to write evidence into.

        .DESCRIPTION
        Engineering plan section 8.3: "Collection writes to a unique staging directory...
        Interrupted staging data cannot be evaluated as trusted evidence." This function only
        creates the directory skeleton (section 8.1's snapshot/ layout under evidence/, whatif/,
        logs/) -- it does not write manifest.json, coverage.json, or integrity.json, since those
        are only ever written by Protect-EntraPostureSnapshot after validation succeeds. A
        staging directory with no manifest.json/integrity.json is, by construction, never
        mistakable for a sealed bundle.

        .PARAMETER RunRoot
        Parent directory under which the staging directory is created.

        .PARAMETER SnapshotId
        Used as the staging directory's name so it is traceable back to the eventual sealed
        snapshot ID. Caller-supplied (not generated here) so the same ID can be threaded through
        logs emitted before sealing completes.

        .OUTPUTS
        The full path to the created staging directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$RunRoot,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$')]
        [string]$SnapshotId
    )

    $stagingPath = Join-Path $RunRoot "staging-$SnapshotId"

    if (Test-Path -LiteralPath $stagingPath) {
        throw "New-EntraPostureStagingDirectory: '$stagingPath' already exists. Snapshot IDs must be unique; reusing one risks mixing staging data from two different collection runs."
    }

    if (-not $PSCmdlet.ShouldProcess($stagingPath, 'Create staging directory')) {
        return $null
    }

    $subdirs = @(
        $stagingPath
        (Join-Path $stagingPath 'evidence')
        (Join-Path $stagingPath 'whatif')
        (Join-Path $stagingPath 'logs')
    )
    foreach ($dir in $subdirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    return $stagingPath
}
