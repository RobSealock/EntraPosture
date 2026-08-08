#Requires -Version 7.4

function Get-EntraPostureDeviceFilterAstValue {
    <#
        .SYNOPSIS
        Parses one value (string, boolean/null keyword, or array literal) from a device-filter
        token stream -- one production of the device-filter grammar
        (ConvertTo-EntraPostureDeviceFilterAst's own DESCRIPTION has the full grammar).

        .DESCRIPTION
        A standalone top-level function, not nested inside ConvertTo-EntraPostureDeviceFilterAst
        -- this project's build (Build-Module.ps1's AST-based duplicate-name/export scan) sweeps
        nested functions in any src/ file, a rule already learned the hard way twice before (see
        00-open-questions.md items 7/8) and applied proactively here instead of a third time.
        Every Get-EntraPostureDeviceFilterAst* function in this file threads parser state via
        -State (a single mutable ordered dictionary: Tokens, Position) rather than nested
        closures, for the same reason.

        .PARAMETER State
        Ordered dictionary: Tokens (token array), Position (current index, mutated in place --
        OrderedDictionary is a reference type, so callers observe the advanced position).

        .PARAMETER Rule
        The original raw rule string, for error messages only.

        .OUTPUTS
        Ordered dictionary: Kind ('String'/'Boolean'/'Null'/'Array'), Value.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $t = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    if (-not $t) { throw "Get-EntraPostureDeviceFilterAstValue: unexpected end of rule while parsing a value in '$Rule'." }

    if ($t.Type -eq 'LBracket') {
        $State.Position++
        $items = [System.Collections.Generic.List[object]]::new()
        $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
        if ($next -and $next.Type -ne 'RBracket') {
            $items.Add((Get-EntraPostureDeviceFilterAstValue -State $State -Rule $Rule))
            $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
            while ($next -and $next.Type -eq 'Comma') {
                $State.Position++
                $items.Add((Get-EntraPostureDeviceFilterAstValue -State $State -Rule $Rule))
                $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
            }
        }
        $closeTok = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
        if (-not $closeTok -or $closeTok.Type -ne 'RBracket') {
            throw "Get-EntraPostureDeviceFilterAstValue: expected ']' to close array literal in '$Rule'."
        }
        $State.Position++
        return [ordered]@{ Kind = 'Array'; Value = @($items.ToArray() | ForEach-Object { $_.Value }) }
    }

    if ($t.Type -eq 'String') {
        $State.Position++
        return [ordered]@{ Kind = 'String'; Value = $t.Value }
    }

    if ($t.Type -eq 'Identifier') {
        $State.Position++
        switch ($t.Value.ToLowerInvariant()) {
            'true' { return [ordered]@{ Kind = 'Boolean'; Value = $true } }
            'false' { return [ordered]@{ Kind = 'Boolean'; Value = $false } }
            'null' { return [ordered]@{ Kind = 'Null'; Value = $null } }
            default { throw "Get-EntraPostureDeviceFilterAstValue: unexpected identifier '$($t.Value)' where a value was expected in '$Rule'." }
        }
    }

    throw "Get-EntraPostureDeviceFilterAstValue: unexpected token type '$($t.Type)' where a value was expected in '$Rule'."
}

function Get-EntraPostureDeviceFilterAstComparison {
    <#
        .SYNOPSIS
        Parses one leaf comparison node (`device.<property> <operator> <value>`) from a
        device-filter token stream.

        .DESCRIPTION
        Only the ten operators Microsoft's own CA device-filter property table documents as
        supported for any device-filter property are accepted here (-eq/-ne/-startsWith/
        -notStartsWith/-endsWith/-notEndsWith/-contains/-notContains/-in/-notIn) -- -match/
        -notMatch are tokenized by the shared tokenizer (valid in the general grammar) but
        rejected here specifically, since no property in this project's device-filter property
        table (EvaluateDeviceFilterCondition.ps1) documents either as supported. Per-property
        operator whitelisting (e.g. deviceId only supports Equals/NotEquals/In/NotIn) is enforced
        one layer up, in EvaluateDeviceFilterCondition.ps1, not here -- this function only
        enforces what's valid for device filters as a whole.

        .PARAMETER State
        .PARAMETER Rule

        .OUTPUTS
        Ordered dictionary: NodeType='Comparison', Property (the 'device.' prefix stripped),
        Operator, Value (from Get-EntraPostureDeviceFilterAstValue).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $supportedOperators = @('-eq', '-ne', '-startsWith', '-notStartsWith', '-endsWith', '-notEndsWith', '-contains', '-notContains', '-in', '-notIn')

    $propTok = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    if (-not $propTok -or $propTok.Type -ne 'Identifier') {
        throw "Get-EntraPostureDeviceFilterAstComparison: expected a 'device.<property>' reference in '$Rule'."
    }
    $State.Position++
    $parts = $propTok.Value -split '\.', 2
    if ($parts.Count -ne 2 -or $parts[0] -ne 'device') {
        throw "Get-EntraPostureDeviceFilterAstComparison: expected a property reference prefixed with 'device.', got '$($propTok.Value)' in '$Rule'."
    }

    $opTok = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    if (-not $opTok -or $opTok.Type -ne 'Operator') {
        throw "Get-EntraPostureDeviceFilterAstComparison: expected a comparison operator after '$($propTok.Value)' in '$Rule'."
    }
    if ($opTok.Value -in @('-and', '-or', '-not')) {
        throw "Get-EntraPostureDeviceFilterAstComparison: '$($opTok.Value)' is a logical operator, not a comparison operator, unexpected after '$($propTok.Value)' in '$Rule'."
    }
    if ($supportedOperators -notcontains $opTok.Value) {
        throw "Get-EntraPostureDeviceFilterAstComparison: operator '$($opTok.Value)' is not supported for Conditional Access device filters (only $($supportedOperators -join ', ') are documented for this context) in '$Rule'."
    }
    $State.Position++

    $value = Get-EntraPostureDeviceFilterAstValue -State $State -Rule $Rule
    return [ordered]@{ NodeType = 'Comparison'; Property = $parts[1]; Operator = $opTok.Value; Value = $value }
}

function Get-EntraPostureDeviceFilterAstPrimary {
    <#
        .SYNOPSIS
        Parses a parenthesized sub-expression or a leaf comparison -- the grammar's `primary`
        production.

        .PARAMETER State
        .PARAMETER Rule

        .OUTPUTS
        Ordered dictionary AST node.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $t = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    if (-not $t) { throw "Get-EntraPostureDeviceFilterAstPrimary: unexpected end of rule in '$Rule'." }

    if ($t.Type -eq 'LParen') {
        $State.Position++
        $inner = Get-EntraPostureDeviceFilterAstOr -State $State -Rule $Rule
        $closeTok = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
        if (-not $closeTok -or $closeTok.Type -ne 'RParen') {
            throw "Get-EntraPostureDeviceFilterAstPrimary: expected ')' in '$Rule'."
        }
        $State.Position++
        return $inner
    }

    return Get-EntraPostureDeviceFilterAstComparison -State $State -Rule $Rule
}

function Get-EntraPostureDeviceFilterAstNot {
    <#
        .SYNOPSIS
        Parses an optional unary `-not` prefix -- the grammar's `notExpr` production, one level
        below `-and` in precedence.

        .PARAMETER State
        .PARAMETER Rule

        .OUTPUTS
        Ordered dictionary AST node (a Not-wrapped node, or its operand unchanged if no `-not`
        was present).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $t = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    if ($t -and $t.Type -eq 'Operator' -and $t.Value -eq '-not') {
        $State.Position++
        return [ordered]@{ NodeType = 'Not'; Operand = (Get-EntraPostureDeviceFilterAstNot -State $State -Rule $Rule) }
    }
    return Get-EntraPostureDeviceFilterAstPrimary -State $State -Rule $Rule
}

function Get-EntraPostureDeviceFilterAstAnd {
    <#
        .SYNOPSIS
        Parses a left-associative chain of `-and`-joined operands -- the grammar's `andExpr`
        production, binding tighter than `-or`.

        .PARAMETER State
        .PARAMETER Rule

        .OUTPUTS
        Ordered dictionary AST node.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $left = Get-EntraPostureDeviceFilterAstNot -State $State -Rule $Rule
    $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    while ($next -and $next.Type -eq 'Operator' -and $next.Value -eq '-and') {
        $State.Position++
        $right = Get-EntraPostureDeviceFilterAstNot -State $State -Rule $Rule
        $left = [ordered]@{ NodeType = 'And'; Left = $left; Right = $right }
        $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    }
    return $left
}

function Get-EntraPostureDeviceFilterAstOr {
    <#
        .SYNOPSIS
        Parses a left-associative chain of `-or`-joined operands -- the grammar's `orExpr`
        production, the lowest-precedence (outermost) level, and the parser's overall entry
        point.

        .PARAMETER State
        .PARAMETER Rule

        .OUTPUTS
        Ordered dictionary AST node.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$State,

        [Parameter(Mandatory)]
        [string]$Rule
    )

    $tokens = $State.Tokens
    $left = Get-EntraPostureDeviceFilterAstAnd -State $State -Rule $Rule
    $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    while ($next -and $next.Type -eq 'Operator' -and $next.Value -eq '-or') {
        $State.Position++
        $right = Get-EntraPostureDeviceFilterAstAnd -State $State -Rule $Rule
        $left = [ordered]@{ NodeType = 'Or'; Left = $left; Right = $right }
        $next = if ($State.Position -lt $tokens.Count) { $tokens[$State.Position] } else { $null }
    }
    return $left
}

function ConvertTo-EntraPostureDeviceFilterAst {
    <#
        .SYNOPSIS
        Parses a Conditional Access device-filter rule string into an abstract syntax tree, via
        Get-EntraPostureDeviceFilterToken -- the second stage of the device-filter parser
        (VNext build order item 5).

        .DESCRIPTION
        Recursive-descent, implemented as a chain of standalone top-level Get-
        EntraPostureDeviceFilterAst* functions (Or -> And -> Not -> Primary -> Comparison ->
        Value) rather than nested closures -- see Get-EntraPostureDeviceFilterAstValue's own
        DESCRIPTION for why. This function is just the entry point: tokenize, initialize parser
        state, delegate to Get-EntraPostureDeviceFilterAstOr, and confirm no trailing tokens
        remain.

        Operator precedence (highest to lowest binding), confirmed directly against the
        dynamic-membership-rules page's own "Operator precedence" list (re-fetched 2026-08-07):
        the comparison operators themselves (they form leaf nodes, not a combinator level), then
        `-not`, then `-and`, then `-or`. `-any`/`-all` (that page's collection-quantifier
        operators) are deliberately unsupported -- no CA-specific device-filter property is a
        multi-value collection requiring them (see EvaluateDeviceFilterCondition.ps1's property
        table: physicalIds/systemLabels use Contains/NotContains directly instead).

        .PARAMETER Rule
        The raw device-filter rule string.

        .OUTPUTS
        Ordered dictionary AST root. Node shapes:
          Comparison: { NodeType='Comparison'; Property=<string, 'device.' prefix stripped>;
            Operator=<string>; Value=<ordered: Kind ('String'/'Boolean'/'Null'/'Array'), Value> }
          Not: { NodeType='Not'; Operand=<ast> }
          And / Or: { NodeType='And'|'Or'; Left=<ast>; Right=<ast> }
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$Rule
    )

    # No @() wrapper -- Get-EntraPostureDeviceFilterToken already comma-protects its return
    # (`return ,@($tokens.ToArray())`); wrapping the call site in @() too double-wraps the result,
    # confirmed directly (a 3-token rule collapsed to Count=1, with PowerShell's array member-
    # enumeration then concatenating all three tokens' Type/Value into one string) while building
    # this parser's own tests -- the same bug class as EvaluateDeviceFilterCondition.ps1's own
    # header comment and every other project file that cites this pattern.
    $tokens = Get-EntraPostureDeviceFilterToken -Rule $Rule
    if (@($tokens).Count -eq 0) {
        throw "ConvertTo-EntraPostureDeviceFilterAst: empty rule."
    }

    $state = [ordered]@{ Tokens = $tokens; Position = 0 }
    $ast = Get-EntraPostureDeviceFilterAstOr -State $state -Rule $Rule

    if ($state.Position -lt $tokens.Count) {
        $leftover = $tokens[$state.Position]
        throw "ConvertTo-EntraPostureDeviceFilterAst: unexpected trailing token '$($leftover.Value)' after a complete expression in '$Rule'."
    }

    return $ast
}
