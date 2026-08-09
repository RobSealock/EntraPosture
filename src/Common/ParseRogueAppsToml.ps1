#Requires -Version 7.4

function ConvertFrom-EntraPostureRogueAppsToml {
    <#
        .SYNOPSIS
        Parses the `huntresslabs/rogueapps` project's `data/rogueapps.toml` file (or a local
        vendored copy of it) into an array of ordered dictionaries.

        .DESCRIPTION
        This is deliberately NOT a general-purpose TOML parser -- it accepts exactly the subset
        of TOML syntax `rogueapps.toml` actually uses (confirmed directly against the live file,
        re-fetched 2026-08-08, all ~350 lines read): a flat sequence of `[[apps]]` array-of-table
        headers, each optionally followed by one or more `[[apps.permissions]]` sub-table
        headers, `key = "double-quoted string"` scalar assignments, and `key = [...]`
        double-quoted-string-array assignments (single-line or spanning multiple lines with one
        element per line). No inline tables, no non-string scalars (numbers/booleans/dates as
        native TOML types -- `dateAdded` is a quoted string, not a TOML date), no dotted keys
        outside the two fixed table names, and no inline (same-line) comments appear anywhere in
        the real data.

        This project's own "verify precisely, fail rather than guess" discipline applies here
        directly: any line that doesn't match one of the handful of recognized shapes throws
        immediately, rather than silently skipping or misparsing it -- if a future upstream
        change introduces TOML syntax this function doesn't understand (an inline table, a
        non-string scalar, a same-line comment), Update-EntraPostureKnownAbusedAppList's own
        -Fetch step surfaces that as a clear parse error, not a silently incomplete or wrong
        result.

        .PARAMETER RawToml
        The full file content as a single string.

        .OUTPUTS
        Array of ordered dictionaries, one per `[[apps]]` block: appId, appDisplayName,
        appOwnerOrganizationId, appPublisherName, appPublisherId, description, tags (string[]),
        references (string[]), mitreTTP (string[]), contributors (string[]), dateAdded,
        permissions (ordered-dictionary[] of resource/permission/type).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RawToml
    )

    # Parses one TOML double-quoted basic string starting at $Line[$StartIndex] (which must be
    # the opening '"'). Returns @{ Value; EndIndex } where EndIndex is the position of the
    # closing '"'. A pure function -- no outer-scope mutation -- deliberately kept free of the
    # nested-closure-mutates-outer-state pattern the rest of this project avoids in evaluators
    # too (see EvaluateAzureLeastPrivilege.ps1's own "assign before use" discipline for the same
    # underlying reason: PowerShell scoping surprises are cheap to avoid and expensive to debug).
    function script:ConvertFrom-RogueAppsTomlBasicString {
        param([Parameter(Mandatory)][string]$Line, [Parameter(Mandatory)][int]$StartIndex)
        if ($Line[$StartIndex] -ne '"') {
            throw "ConvertFrom-EntraPostureRogueAppsToml: expected opening '`"' at position $StartIndex in line: $Line"
        }
        $sb = [System.Text.StringBuilder]::new()
        $i = $StartIndex + 1
        while ($true) {
            if ($i -ge $Line.Length) {
                throw "ConvertFrom-EntraPostureRogueAppsToml: unterminated string starting at position $StartIndex in line: $Line"
            }
            $ch = $Line[$i]
            if ($ch -eq '"') {
                return @{ Value = $sb.ToString(); EndIndex = $i }
            }
            if ($ch -eq '\') {
                if ($i + 1 -ge $Line.Length) {
                    throw "ConvertFrom-EntraPostureRogueAppsToml: dangling escape at end of line: $Line"
                }
                $next = $Line[$i + 1]
                $unescaped = switch ($next) {
                    '"' { '"' }
                    '\' { '\' }
                    'n' { "`n" }
                    't' { "`t" }
                    'r' { "`r" }
                    default { throw "ConvertFrom-EntraPostureRogueAppsToml: unsupported escape sequence '\$next' in line: $Line" }
                }
                [void]$sb.Append($unescaped)
                $i += 2
                continue
            }
            [void]$sb.Append($ch)
            $i += 1
        }
    }

    $lines = @($RawToml -split "`r?`n")
    $apps = [System.Collections.Generic.List[object]]::new()
    $currentApp = $null
    $currentPermission = $null

    $lineIndex = 0
    while ($lineIndex -lt $lines.Count) {
        $trimmed = $lines[$lineIndex].Trim()
        $lineIndex++

        if ($trimmed.Length -eq 0) { continue }
        if ($trimmed.StartsWith('#')) { continue }

        if ($trimmed -eq '[[apps]]') {
            if ($null -ne $currentApp) {
                if ($null -ne $currentPermission) { $currentApp.permissions.Add($currentPermission); $currentPermission = $null }
                if ([string]::IsNullOrWhiteSpace([string]$currentApp.appId)) {
                    throw 'ConvertFrom-EntraPostureRogueAppsToml: an [[apps]] block has no appId.'
                }
                $currentApp.permissions = @($currentApp.permissions.ToArray())
                $apps.Add($currentApp)
            }
            $currentApp = [ordered]@{
                appId = $null; appDisplayName = $null; appOwnerOrganizationId = $null
                appPublisherName = $null; appPublisherId = $null; description = $null
                tags = @(); references = @(); mitreTTP = @(); contributors = @(); dateAdded = $null
                permissions = [System.Collections.Generic.List[object]]::new()
            }
            $currentPermission = $null
            continue
        }

        if ($trimmed -eq '[[apps.permissions]]') {
            if ($null -eq $currentApp) {
                throw 'ConvertFrom-EntraPostureRogueAppsToml: [[apps.permissions]] encountered before any [[apps]] block.'
            }
            if ($null -ne $currentPermission) { $currentApp.permissions.Add($currentPermission) }
            $currentPermission = [ordered]@{ resource = $null; permission = $null; type = $null }
            continue
        }

        $eqIndex = $trimmed.IndexOf('=')
        if ($eqIndex -lt 1) {
            throw "ConvertFrom-EntraPostureRogueAppsToml: unrecognized line (not a table header or key = value assignment): $trimmed"
        }
        $key = $trimmed.Substring(0, $eqIndex).Trim()
        $valuePart = $trimmed.Substring($eqIndex + 1).Trim()

        $targetDict = if ($null -ne $currentPermission) { $currentPermission } elseif ($null -ne $currentApp) { $currentApp } else {
            throw "ConvertFrom-EntraPostureRogueAppsToml: key '$key' assigned before any [[apps]] block: $trimmed"
        }
        if (-not $targetDict.Contains($key)) {
            throw "ConvertFrom-EntraPostureRogueAppsToml: unrecognized key '$key' for this table."
        }

        if ($valuePart.StartsWith('"')) {
            $parsed = ConvertFrom-RogueAppsTomlBasicString -Line $valuePart -StartIndex 0
            if ($parsed.EndIndex -ne ($valuePart.Length - 1)) {
                throw "ConvertFrom-EntraPostureRogueAppsToml: expected a single-line double-quoted string for '$key' but found trailing content: $valuePart"
            }
            $targetDict[$key] = $parsed.Value
            continue
        }

        if ($valuePart.StartsWith('[')) {
            $arrayValues = [System.Collections.Generic.List[string]]::new()
            $rest = $valuePart.Substring(1).Trim()
            $closed = $false

            while ($true) {
                if ($rest.StartsWith(']')) { $closed = $true; break }
                if ($rest.Length -eq 0) {
                    if ($lineIndex -ge $lines.Count) {
                        throw "ConvertFrom-EntraPostureRogueAppsToml: unterminated array for key '$key' (reached end of file)."
                    }
                    $rest = $lines[$lineIndex].Trim()
                    $lineIndex++
                    continue
                }
                if ($rest.StartsWith(',')) { $rest = $rest.Substring(1).Trim(); continue }
                if ($rest.StartsWith('"')) {
                    $parsedElement = ConvertFrom-RogueAppsTomlBasicString -Line $rest -StartIndex 0
                    $arrayValues.Add($parsedElement.Value)
                    $rest = $rest.Substring($parsedElement.EndIndex + 1).Trim()
                    continue
                }
                throw "ConvertFrom-EntraPostureRogueAppsToml: unsupported array element for key '$key': $rest"
            }
            if (-not $closed) {
                throw "ConvertFrom-EntraPostureRogueAppsToml: array for key '$key' never closed with ']'."
            }
            $targetDict[$key] = $arrayValues.ToArray()
            continue
        }

        throw "ConvertFrom-EntraPostureRogueAppsToml: unsupported value for key '$key' (only quoted strings and string arrays are supported): $valuePart"
    }

    if ($null -ne $currentApp) {
        if ($null -ne $currentPermission) { $currentApp.permissions.Add($currentPermission) }
        if ([string]::IsNullOrWhiteSpace([string]$currentApp.appId)) {
            throw 'ConvertFrom-EntraPostureRogueAppsToml: an [[apps]] block has no appId.'
        }
        $currentApp.permissions = @($currentApp.permissions.ToArray())
        $apps.Add($currentApp)
    }

    return ,@($apps.ToArray())
}
