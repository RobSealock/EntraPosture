#Requires -Version 7.4

function Get-EntraPostureFileHash {
    <#
        .SYNOPSIS
        Computes the lowercase hex SHA-256 hash of a single file.

        .DESCRIPTION
        Thin, deliberately narrow wrapper around Get-FileHash: fixes the algorithm to SHA-256
        (engineering plan section 8.4) and normalizes the output to lowercase hex, since
        Get-FileHash returns uppercase by default and this project's hash manifests must be
        byte-comparable without a case-insensitive comparison step.

        .PARAMETER Path
        Path to the file to hash.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Get-EntraPostureFileHash: '$Path' does not exist or is not a file."
    }

    $result = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    return $result.Hash.ToLowerInvariant()
}
