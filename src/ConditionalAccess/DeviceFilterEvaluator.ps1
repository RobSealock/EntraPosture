#Requires -Version 7.4

function Test-EntraPostureDeviceFilterAstMatch {
    <#
        .SYNOPSIS
        Evaluates a parsed device-filter AST (from ConvertTo-EntraPostureDeviceFilterAst)
        against a synthetic device's already-resolved attribute values -- the third stage of the
        device-filter parser (VNext build order item 5).

        .DESCRIPTION
        "Already-resolved" is load-bearing: this function does not itself know about device
        registration state or Intune management -- EvaluateDeviceFilterCondition.ps1's caller is
        responsible for pre-resolving each property to either its real value or $null per this
        project's own derived nullability model (see that file's own DESCRIPTION), before calling
        here. This function's only job is standard three-valued comparison semantics given
        whatever values it's handed.

        Null-propagation semantics (this project's own synthesis from two direct Microsoft
        quotes, not a single literal quote -- see EvaluateDeviceFilterCondition.ps1's own
        DESCRIPTION for the full citation trail): a comparison against a $null actual value
        evaluates false for every positive operator (Equals, StartsWith, EndsWith, Contains, In)
        and true for every negative one (NotEquals, NotStartsWith, NotEndsWith, NotContains,
        NotIn) -- EXCEPT when the compared value is itself the literal `null` keyword (Kind
        'Null'), in which case Equals-against-null is true and NotEquals-against-null is false
        (Microsoft's own documented null-check idiom, `property -eq null`, confirmed directly
        against the dynamic-membership-rules page's "Use of null values" section).

        String comparisons are case-insensitive (Ordinal, not culture-aware, to avoid
        locale-dependent casing rules for what are Microsoft-defined enum-like values in
        practice) -- confirmed against the dynamic-membership-rules page's own statement that
        "Regex and string operations aren't case sensitive," read as covering every string
        comparison operator this function implements, not narrowly scoped to -match alone (this
        project's device-filter grammar deliberately excludes -match/-notMatch entirely -- see
        DeviceFilterParser.ps1 -- so there is no narrower reading available to test this
        interpretation against).

        `-contains`/`-notContains` mean different things depending on whether the actual value is
        a scalar string or a string collection (physicalIds/systemLabels) -- confirmed directly
        against the CA device-filter page's own explicit note: substring match for scalar string
        attributes, whole-element match for string-collection attributes. Dispatched here purely
        on the .NET type of the actual value handed in (array vs scalar), not on the property
        name, so this function stays property-agnostic.

        .PARAMETER Ast
        A parsed AST node from ConvertTo-EntraPostureDeviceFilterAst.

        .PARAMETER DeviceAttributes
        Ordered dictionary: property name (without the 'device.' prefix) -> already-resolved
        value ($null, a scalar string, or a string[] for collection-typed properties).

        .OUTPUTS
        Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Ast,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$DeviceAttributes
    )

    switch ($Ast.NodeType) {
        'And' {
            return (Test-EntraPostureDeviceFilterAstMatch -Ast $Ast.Left -DeviceAttributes $DeviceAttributes) -and
                   (Test-EntraPostureDeviceFilterAstMatch -Ast $Ast.Right -DeviceAttributes $DeviceAttributes)
        }
        'Or' {
            return (Test-EntraPostureDeviceFilterAstMatch -Ast $Ast.Left -DeviceAttributes $DeviceAttributes) -or
                   (Test-EntraPostureDeviceFilterAstMatch -Ast $Ast.Right -DeviceAttributes $DeviceAttributes)
        }
        'Not' {
            return -not (Test-EntraPostureDeviceFilterAstMatch -Ast $Ast.Operand -DeviceAttributes $DeviceAttributes)
        }
        'Comparison' {
            $actual = if ($DeviceAttributes.Contains($Ast.Property)) { $DeviceAttributes[$Ast.Property] } else { $null }
            return Test-EntraPostureDeviceFilterComparison -Operator $Ast.Operator -Actual $actual -Expected $Ast.Value
        }
        default {
            throw "Test-EntraPostureDeviceFilterAstMatch: unrecognized AST node type '$($Ast.NodeType)'."
        }
    }
}

function Test-EntraPostureDeviceFilterComparison {
    <#
        .SYNOPSIS
        Evaluates one leaf comparison (`device.<property> <operator> <value>`) given an
        already-resolved actual value -- extracted from Test-EntraPostureDeviceFilterAstMatch's
        own Comparison-node branch into a standalone function so its null-propagation and
        collection-vs-scalar semantics can be unit tested directly, independent of AST traversal.

        .PARAMETER Operator
        One of the ten operators DeviceFilterParser.ps1 accepts.

        .PARAMETER Actual
        The already-resolved actual value ($null, a scalar string, or a string[]).

        .PARAMETER Expected
        An ordered dictionary from Get-EntraPostureDeviceFilterAstValue: Kind
        ('String'/'Boolean'/'Null'/'Array'), Value.

        .OUTPUTS
        Boolean.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]$Operator,

        [Parameter()]
        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Expected
    )

    $positiveOperators = @('-eq', '-startsWith', '-endsWith', '-contains', '-in')

    if ($null -eq $Actual) {
        if ($Operator -eq '-eq') { return $Expected.Kind -eq 'Null' }
        if ($Operator -eq '-ne') { return $Expected.Kind -ne 'Null' }
        return $positiveOperators -notcontains $Operator
    }

    $expectedString = if ($Expected.Kind -eq 'Boolean') { if ($Expected.Value) { 'true' } else { 'false' } } else { [string]$Expected.Value }

    switch ($Operator) {
        '-eq' {
            if ($Actual -is [array]) { return $false }
            return [string]::Equals([string]$Actual, $expectedString, [StringComparison]::OrdinalIgnoreCase)
        }
        '-ne' {
            if ($Actual -is [array]) { return $true }
            return -not [string]::Equals([string]$Actual, $expectedString, [StringComparison]::OrdinalIgnoreCase)
        }
        '-startsWith' { return ([string]$Actual).StartsWith($expectedString, [StringComparison]::OrdinalIgnoreCase) }
        '-notStartsWith' { return -not ([string]$Actual).StartsWith($expectedString, [StringComparison]::OrdinalIgnoreCase) }
        '-endsWith' { return ([string]$Actual).EndsWith($expectedString, [StringComparison]::OrdinalIgnoreCase) }
        '-notEndsWith' { return -not ([string]$Actual).EndsWith($expectedString, [StringComparison]::OrdinalIgnoreCase) }
        '-contains' {
            if ($Actual -is [array]) {
                return @($Actual | Where-Object { [string]::Equals([string]$_, $expectedString, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
            }
            return ([string]$Actual).IndexOf($expectedString, [StringComparison]::OrdinalIgnoreCase) -ge 0
        }
        '-notContains' {
            if ($Actual -is [array]) {
                return @($Actual | Where-Object { [string]::Equals([string]$_, $expectedString, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0
            }
            return ([string]$Actual).IndexOf($expectedString, [StringComparison]::OrdinalIgnoreCase) -lt 0
        }
        '-in' {
            $expectedList = @($Expected.Value)
            return @($expectedList | Where-Object { [string]::Equals([string]$_, [string]$Actual, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        }
        '-notIn' {
            $expectedList = @($Expected.Value)
            return @($expectedList | Where-Object { [string]::Equals([string]$_, [string]$Actual, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0
        }
        default {
            throw "Test-EntraPostureDeviceFilterComparison: unrecognized operator '$Operator'."
        }
    }
}
