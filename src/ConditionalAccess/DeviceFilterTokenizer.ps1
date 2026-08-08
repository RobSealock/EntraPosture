#Requires -Version 7.4

function Get-EntraPostureDeviceFilterToken {
    <#
        .SYNOPSIS
        Tokenizes a Conditional Access device-filter rule string (`conditions.devices.
        deviceFilter.rule`) into a flat token array -- the first stage of the device-filter
        parser (VNext build order item 5, the device-filter half re-scoped out on 2026-08-07).

        .DESCRIPTION
        Grammar confirmed live against Microsoft's own "Filter for devices as a condition in
        Conditional Access policy" page (re-fetched 2026-08-07) and the dynamic-membership-group
        rules page it explicitly points to for full syntax ("rules for dynamic membership groups
        for groups in Microsoft Entra ID"). The two pages share one grammar (operators,
        precedence, quoting, -and/-or/-not, parentheses) but NOT one property vocabulary --
        confirmed directly by comparing both pages' own property tables, which use different
        names for analogous device attributes (e.g. this project's device-filter table uses
        `device.trustType`/`device.operatingSystem`; the dynamic-group table uses
        `device.deviceTrustType`/`device.deviceOSType`). This tokenizer, and every other file in
        this device-filter subsystem, targets the CA-specific vocabulary only (see
        EvaluateDeviceFilterCondition.ps1's own property table), not the dynamic-group one.

        Recognized token kinds: LParen '(', RParen ')', LBracket '[', RBracket ']', Comma ',',
        Operator (one of the fixed set below, always hyphen-prefixed -- an unhyphenated operator
        form the dynamic-group page mentions in passing is a documented, deliberate boundary here,
        not silently accepted, since every real example on either page always uses the hyphen),
        Identifier (a dotted property reference like `device.isCompliant`, or the bare keywords
        `true`/`false`/`null`), String (double-quoted, with the two documented escape forms:
        embedded double-quotes escaped with a backtick, embedded single-quotes escaped by
        doubling them).

        Throws on any character sequence it cannot classify, and on a rule exceeding Microsoft's
        own documented 3,072-character limit -- both real, explicit failures, not silently
        ignored or truncated.

        .PARAMETER Rule
        The raw device-filter rule string.

        .OUTPUTS
        Array of ordered dictionaries: Type ('LParen'/'RParen'/'LBracket'/'RBracket'/'Comma'/
        'Operator'/'Identifier'/'String'), Value (the token's own text, or for String tokens the
        already-unescaped string content).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [string]$Rule
    )

    if ($Rule.Length -gt 3072) {
        throw "Get-EntraPostureDeviceFilterToken: rule length ($($Rule.Length)) exceeds Microsoft's documented 3072-character limit."
    }

    $knownOperators = @(
        '-eq', '-ne', '-startsWith', '-notStartsWith', '-endsWith', '-notEndsWith',
        '-contains', '-notContains', '-match', '-notMatch', '-in', '-notIn',
        '-and', '-or', '-not'
    )

    $tokens = [System.Collections.Generic.List[object]]::new()
    $i = 0
    $length = $Rule.Length

    while ($i -lt $length) {
        $ch = $Rule[$i]

        if ([char]::IsWhiteSpace($ch)) {
            $i++
            continue
        }

        $singleCharToken = switch ($ch) {
            '(' { 'LParen' }
            ')' { 'RParen' }
            '[' { 'LBracket' }
            ']' { 'RBracket' }
            ',' { 'Comma' }
            default { $null }
        }
        if ($singleCharToken) {
            $tokens.Add([ordered]@{ Type = $singleCharToken; Value = [string]$ch })
            $i++
            continue
        }

        if ($ch -eq '"') {
            $sb = [System.Text.StringBuilder]::new()
            $i++
            $closed = $false
            while ($i -lt $length) {
                $c = $Rule[$i]
                if ($c -eq '`' -and ($i + 1) -lt $length -and $Rule[$i + 1] -eq '"') {
                    [void]$sb.Append('"')
                    $i += 2
                    continue
                }
                if ($c -eq "'" -and ($i + 1) -lt $length -and $Rule[$i + 1] -eq "'") {
                    [void]$sb.Append("'")
                    $i += 2
                    continue
                }
                if ($c -eq '"') {
                    $closed = $true
                    $i++
                    break
                }
                [void]$sb.Append($c)
                $i++
            }
            if (-not $closed) {
                throw "Get-EntraPostureDeviceFilterToken: unterminated string literal starting near position $i in rule '$Rule'."
            }
            $tokens.Add([ordered]@{ Type = 'String'; Value = $sb.ToString() })
            continue
        }

        if ($ch -eq '-') {
            $match = [regex]::Match($Rule.Substring($i), '^-[A-Za-z]+')
            if (-not $match.Success) {
                throw "Get-EntraPostureDeviceFilterToken: unrecognized '-' token near position $i in rule '$Rule'."
            }
            $text = $match.Value
            if ($knownOperators -notcontains $text) {
                throw "Get-EntraPostureDeviceFilterToken: unrecognized operator '$text' near position $i in rule '$Rule'."
            }
            $tokens.Add([ordered]@{ Type = 'Operator'; Value = $text })
            $i += $text.Length
            continue
        }

        if ([char]::IsLetter($ch) -or $ch -eq '_') {
            $match = [regex]::Match($Rule.Substring($i), '^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*')
            $text = $match.Value
            $tokens.Add([ordered]@{ Type = 'Identifier'; Value = $text })
            $i += $text.Length
            continue
        }

        throw "Get-EntraPostureDeviceFilterToken: unrecognized character '$ch' near position $i in rule '$Rule'."
    }

    return ,@($tokens.ToArray())
}
