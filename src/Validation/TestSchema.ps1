#Requires -Version 7.4

function Get-EntraPostureSchemaPath {
    <#
        .SYNOPSIS
        Resolves a contract name to its schema file path under schemas/.

        .DESCRIPTION
        Single source of truth for the name-to-file mapping so callers never hardcode a path.
        This source file's own $PSScriptRoot means two different things depending on how it is
        loaded: dot-sourced directly from src/Validation/ during development, $PSScriptRoot is
        that folder and schemas/ is two levels up (repo root); loaded as part of the single
        concatenated .psm1 produced by build/Build-Module.ps1, $PSScriptRoot is the build output
        directory itself, and schemas/ is a direct sibling there instead (Build-Module.ps1
        copies schemas/ alongside the built module specifically so this second case resolves --
        confirmed directly that without that copy, this function resolved to a path one level
        ABOVE the repo root when invoked through an Import-Module'd built module). Both
        candidates are probed, in that order; the first one that actually exists on disk wins.
        This is deliberately NOT "runtime discovery" in ADR-004's forbidden sense -- it never
        decides *which* files to load, only *where* one specific, already-known filename
        happens to live under either of exactly two fixed, hardcoded layouts.

        .PARAMETER ContractName
        One of the registered contract names (matches the schema file's base name before
        '.schema.json').
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet(
            'entity', 'relationship', 'snapshot-manifest', 'resolved-profile', 'coverage',
            'control-definition', 'control-result', 'deviation', 'comparison', 'integrity',
            'error-record', 'whatif-scenario', 'whatif-result', 'drift-event'
        )]
        [string]$ContractName
    )

    $candidateRoots = @(
        (Join-Path $PSScriptRoot '../../schemas')  # dev tree: dot-sourced from src/Validation/
        (Join-Path $PSScriptRoot 'schemas')         # built tree: dist/ (or wherever installed) sibling
    )

    foreach ($root in $candidateRoots) {
        $candidatePath = Join-Path $root "$ContractName.schema.json"
        if (Test-Path -LiteralPath $candidatePath) {
            return (Resolve-Path -LiteralPath $candidatePath).Path
        }
    }

    throw "Get-EntraPostureSchemaPath: schema file not found for contract '$ContractName' under any candidate root ($($candidateRoots -join ', '))."
}

function Test-EntraPostureSchema {
    <#
        .SYNOPSIS
        Validates JSON text against a named contract schema, returning a structured result
        instead of PowerShell's default noisy non-terminating-error behavior.

        .DESCRIPTION
        Wraps the built-in Test-Json cmdlet (which writes validation failures to the error
        stream and returns a bare boolean) so every caller in this project gets one consistent,
        capturable shape: IsValid plus an Errors array of plain strings. Never throws on an
        invalid document -- an invalid document is an expected, representable outcome, not an
        exceptional one. Only throws if the schema file itself is missing or unreadable, or the
        supplied JSON text is not parseable at all (Test-Json cannot even attempt validation).

        .PARAMETER Json
        Raw JSON text to validate.

        .PARAMETER ContractName
        Which registered schema to validate against (see Get-EntraPostureSchemaPath).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$Json,

        [Parameter(Mandatory)]
        [string]$ContractName
    )

    $schemaPath = Get-EntraPostureSchemaPath -ContractName $ContractName

    $isValid = Test-Json -Json $Json -SchemaFile $schemaPath -ErrorAction SilentlyContinue -ErrorVariable validationErrors

    $errorMessages = @()
    if ($validationErrors) {
        $errorMessages = @($validationErrors | ForEach-Object {
            # Test-Json's error message is prefixed with a generic wrapper sentence; strip it
            # down to just the schema-specific detail so downstream consumers (and Pester
            # assertions) don't have to pattern-match a PowerShell-version-specific preamble.
            $msg = $_.Exception.Message
            if ($msg -match 'The JSON is not valid with the schema:\s*(.+)$') {
                $Matches[1]
            } else {
                $msg
            }
        })
    }

    return [ordered]@{
        IsValid      = [bool]$isValid
        ContractName = $ContractName
        Errors       = $errorMessages
    }
}
