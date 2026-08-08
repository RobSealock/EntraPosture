#Requires -Version 7.4

function Get-EntraPostureControlDefinitionRoot {
    <#
        .SYNOPSIS
        Resolves the controls/ directory, probing both the dev-tree and built-module layouts.

        .DESCRIPTION
        Same two-candidate probing strategy as Get-EntraPostureSchemaPath (see that
        function's DESCRIPTION for the full rationale) -- $PSScriptRoot means something
        different depending on whether this code is dot-sourced from src/Controls/ during
        development or loaded as part of the single concatenated .psm1 build/Build-Module.ps1
        produces, and build/Build-Module.ps1 copies controls/ alongside the built module
        specifically so the second candidate resolves once installed/distributed.

        .OUTPUTS
        Absolute path to the controls/ directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $candidateRoots = @(
        (Join-Path $PSScriptRoot '../../controls')  # dev tree: dot-sourced from src/Controls/
        (Join-Path $PSScriptRoot 'controls')         # built tree: dist/ (or wherever installed) sibling
    )

    foreach ($root in $candidateRoots) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            return (Resolve-Path -LiteralPath $root).Path
        }
    }

    throw "Get-EntraPostureControlDefinitionRoot: no controls/ directory found under any candidate root ($($candidateRoots -join ', '))."
}

function Get-EntraPostureControlRegistry {
    <#
        .SYNOPSIS
        Loads, converts, and schema-validates every control definition under controls/.

        .DESCRIPTION
        Engineering plan section 9.1: ".psd1 definition." Each file's hashtable literal uses
        camelCase top-level keys matching control-definition.schema.json exactly (e.g.
        'controlId', not 'ControlId') -- deliberate, not a style inconsistency with this
        project's usual PascalCase .psd1 convention (see BuildManifest.psd1): the schema's own
        description says these files are "serialized to JSON for schema validation," and this
        project has consistently chosen to make a data structure's own keys already match its
        JSON contract rather than adding a case-translation layer (the same choice
        Get-EntraPostureAggregateHash made in Phase 3 for the same reason).

        Import-PowerShellDataFile returns a plain (unordered) Hashtable tree, which
        ConvertTo-EntraPostureCanonicalJson explicitly rejects (ADR-014: only ordered
        dictionaries are accepted for canonical records) -- every parsed definition is
        recursively converted via ConvertTo-EntraPostureOrderedDictionary first. Key order
        from a plain Hashtable is unspecified, which is fine here: schema validation is
        order-independent, and control definitions are not currently hashed.

        Every file is validated before this function returns anything -- a single malformed
        control definition fails the whole registry load with the complete list of problems,
        not just the first one found, matching Protect-EntraPostureSnapshot's "collect every
        failure before throwing" discipline elsewhere in this project.

        Does NOT re-verify that each control's evaluatorFunctionName resolves to a real
        function -- ADR-013 makes that a build-time gate (build/Build-Module.ps1 checks it
        against the same function inventory it already builds to detect duplicate names), so a
        built module that passed its own build can never reach this function with a dangling
        evaluatorFunctionName. Re-checking it here would duplicate that enforcement without
        adding any actual safety.

        .OUTPUTS
        Array of ordered dictionaries matching control-definition.schema.json, sorted by
        filename for deterministic ordering.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param ()

    $controlsRoot = Get-EntraPostureControlDefinitionRoot
    $files = @(Get-ChildItem -LiteralPath $controlsRoot -Filter '*.psd1' -File | Sort-Object Name)

    $failures = [System.Collections.Generic.List[string]]::new()
    $definitions = [System.Collections.Generic.List[object]]::new()

    foreach ($file in $files) {
        $raw = $null
        try {
            $raw = Import-PowerShellDataFile -Path $file.FullName
        } catch {
            $failures.Add("'$($file.Name)' could not be parsed as a PowerShell data file: $($_.Exception.Message)")
            continue
        }

        $ordered = ConvertTo-EntraPostureOrderedDictionary -InputObject $raw
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $ordered
        $result = Test-EntraPostureSchema -Json $json -ContractName 'control-definition'

        if (-not $result.IsValid) {
            $failures.Add("'$($file.Name)' failed control-definition schema validation: $($result.Errors -join '; ')")
            continue
        }

        $definitions.Add($ordered)
    }

    if ($failures.Count -gt 0) {
        $summary = $failures -join "`n  "
        throw "Get-EntraPostureControlRegistry: $($failures.Count) control definition file(s) under '$controlsRoot' failed to load:`n  $summary"
    }

    # Leading comma: see src/Evidence/EvidenceProvider.ps1 for the full rationale -- `return
    # ,@(...)` protects against a 1-element list.ToArray() silently collapsing to its bare
    # scalar element at the caller's assignment site.
    return ,@($definitions.ToArray())
}

function Get-EntraPostureControlDefinition {
    <#
        .SYNOPSIS
        Looks up exactly one control definition by ID from the registry.

        .DESCRIPTION
        Throws if the ID is not found, and throws (rather than silently returning the first
        match) if more than one definition claims the same controlId -- a duplicated control ID
        is a registry integrity problem, never a value to resolve by picking one arbitrarily.

        .PARAMETER ControlId
        .OUTPUTS
        Ordered dictionary matching control-definition.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$ControlId
    )

    # Assigned to a variable before piping -- Get-EntraPostureControlRegistry returns via the
    # leading-comma pattern, and piping that return value directly into Where-Object would
    # deliver the whole array as a single $_ instead of iterating its elements (confirmed
    # directly during Phase 5's evidence-provider work; see EvidenceProvider.ps1's
    # Get-EntraPostureEvidenceRecord for the full empirical writeup of this exact failure mode).
    $registry = Get-EntraPostureControlRegistry
    $matchingEntries = @($registry | Where-Object { $_.controlId -eq $ControlId })

    if ($matchingEntries.Count -eq 0) {
        throw "Get-EntraPostureControlDefinition: no control definition found with controlId '$ControlId'."
    }
    if ($matchingEntries.Count -gt 1) {
        throw "Get-EntraPostureControlDefinition: $($matchingEntries.Count) control definitions claim controlId '$ControlId' -- control IDs must be unique across the registry."
    }

    return $matchingEntries[0]
}
