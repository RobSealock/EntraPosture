#Requires -Version 7.4

function Get-EntraPostureDeviceFilterPropertyDefinition {
    <#
        .SYNOPSIS
        The fixed table of every Microsoft-documented Conditional Access device-filter property:
        its supported operators and whether it's scalar-string or string-collection typed.

        .DESCRIPTION
        Confirmed directly against Microsoft's "Filter for devices as a condition in Conditional
        Access policy" page's own "Supported operators and device properties for filters" table
        (re-fetched 2026-08-07) -- not the dynamic-membership-group device property table, which
        uses different property names for analogous attributes (see DeviceFilterTokenizer.ps1's
        own DESCRIPTION for the confirmed discrepancy). deviceId/mdmAppId are GUID-typed and only
        support Equals/NotEquals/In/NotIn (no partial-string operators) -- physicalIds/
        systemLabels are string-collection typed and only support Contains/NotContains, per the
        page's own explicit note that Contains means whole-element match for these two, not
        substring match. Every other named property plus extensionAttribute1-15 supports the
        full set of ten operators this project's device-filter grammar accepts.

        .OUTPUTS
        Ordered dictionary: property name -> ordered dictionary { Operators (string[]),
        IsCollection (bool), IsExtensionAttribute (bool) }.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    $fullStringOps = @('-eq', '-ne', '-startsWith', '-notStartsWith', '-endsWith', '-notEndsWith', '-contains', '-notContains', '-in', '-notIn')
    $equalityOnlyOps = @('-eq', '-ne')
    $identifierOps = @('-eq', '-ne', '-in', '-notIn')
    $collectionOps = @('-contains', '-notContains')

    $definitions = [ordered]@{
        deviceId               = [ordered]@{ Operators = $identifierOps; IsCollection = $false; IsExtensionAttribute = $false }
        displayName             = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        deviceOwnership         = [ordered]@{ Operators = $equalityOnlyOps; IsCollection = $false; IsExtensionAttribute = $false }
        enrollmentProfileName   = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        isCompliant             = [ordered]@{ Operators = $equalityOnlyOps; IsCollection = $false; IsExtensionAttribute = $false }
        manufacturer            = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        mdmAppId                = [ordered]@{ Operators = $identifierOps; IsCollection = $false; IsExtensionAttribute = $false }
        model                   = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        operatingSystem         = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        operatingSystemVersion  = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $false }
        physicalIds             = [ordered]@{ Operators = $collectionOps; IsCollection = $true; IsExtensionAttribute = $false }
        profileType              = [ordered]@{ Operators = $equalityOnlyOps; IsCollection = $false; IsExtensionAttribute = $false }
        systemLabels            = [ordered]@{ Operators = $collectionOps; IsCollection = $true; IsExtensionAttribute = $false }
        trustType                = [ordered]@{ Operators = $equalityOnlyOps; IsCollection = $false; IsExtensionAttribute = $false }
    }
    for ($n = 1; $n -le 15; $n++) {
        $definitions["extensionAttribute$n"] = [ordered]@{ Operators = $fullStringOps; IsCollection = $false; IsExtensionAttribute = $true }
    }

    return $definitions
}

function Test-EntraPostureDeviceFilterCondition {
    <#
        .SYNOPSIS
        Evaluates a Conditional Access policy's `conditions.devices.deviceFilter` against a
        synthetic device, applying Microsoft's registration/Intune-management applicability
        semantics -- the top-level entry point for this project's device-filter subsystem (VNext
        build order item 5).

        .DESCRIPTION
        Property-level nullability model, this project's own synthesis from two direct Microsoft
        quotes on the "Filter for devices" page (re-fetched 2026-08-07), not a single literal
        quote: (1) "For a device that is unregistered with Microsoft Entra ID, all device
        properties are considered as null values"; (2) a separate warning specific to extension
        attributes: "Devices must be Microsoft Intune managed, compliant, or Microsoft Entra
        hybrid joined for a value to be available in extensionAttributes1-15 at the time of the
        Conditional Access policy evaluation." Combined, these two quotes -- not the page's own
        summary applicability table, which only shows outcomes for simple single-operator rules,
        not compound and/or expressions -- imply a per-PROPERTY nullability rule that generalizes
        correctly to any compound rule, and was verified by hand against every row of that
        summary table before being trusted (documented in 00-open-questions.md's item for this
        build-order item):
          - Unregistered device: every property (all 14 named ones plus extensionAttribute1-15)
            resolves to null.
          - Registered device: every non-extensionAttribute property resolves to its real value.
            extensionAttribute1-15 resolves to its real value only if the device is Intune
            managed, compliant, or hybrid-joined -- otherwise it too resolves to null, even
            though the device is registered.
        This function computes that per-property resolution, then delegates the actual boolean
        evaluation to Test-EntraPostureDeviceFilterAstMatch -- this function owns applicability
        semantics, not comparison semantics.

        Per-property operator validation (Get-EntraPostureDeviceFilterPropertyDefinition) is
        also enforced here, at evaluation time, rather than being silently ignored -- a real
        tenant's own policy authoring UI should never produce an invalid property/operator
        combination, but evidence is trusted data from a live API response, not hand-authored
        input; a schema-violating combination is a real, explicit error, not a defensive check
        for a scenario that can't happen.

        .PARAMETER Mode
        'include' or 'exclude', from conditions.devices.deviceFilter.mode.

        .PARAMETER Rule
        The raw rule string, from conditions.devices.deviceFilter.rule.

        .PARAMETER IsDeviceRegistered
        Whether the synthetic scenario's device is registered with Microsoft Entra ID at all.

        .PARAMETER IsIntuneManaged
        .PARAMETER IsCompliantDevice
        .PARAMETER IsHybridJoined
        Any one of these three being true satisfies the extensionAttribute availability gate,
        per the direct quote above.

        .PARAMETER DeviceAttributes
        Ordered dictionary: property name (without the 'device.' prefix, e.g. 'isCompliant') ->
        the device's real value (string, or string[] for physicalIds/systemLabels) -- used only
        when that property's nullability gate (above) resolves to "available."

        .OUTPUTS
        Boolean: whether this device-filter condition is satisfied for this scenario (mode
        already applied -- true means the policy's device-filter condition passes, matching this
        project's other Test-EntraPostureConditionalAccessPolicyMatch dimension checks).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('include', 'exclude')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$Rule,

        [Parameter()]
        [bool]$IsDeviceRegistered = $false,

        [Parameter()]
        [bool]$IsIntuneManaged = $false,

        [Parameter()]
        [bool]$IsCompliantDevice = $false,

        [Parameter()]
        [bool]$IsHybridJoined = $false,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$DeviceAttributes = [ordered]@{}
    )

    $propertyDefinitions = Get-EntraPostureDeviceFilterPropertyDefinition
    $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule $Rule

    # No @() wrapper -- see Get-EntraPostureDeviceFilterComparisonNode's own DESCRIPTION for
    # why (it already comma-protects its return; this project has now hit the double-@()-wrap
    # bug three separate times this build-order item alone).
    $comparisonNodes = Get-EntraPostureDeviceFilterComparisonNode -Ast $ast
    foreach ($node in $comparisonNodes) {
        if (-not $propertyDefinitions.Contains($node.Property)) {
            throw "Test-EntraPostureDeviceFilterCondition: unrecognized device-filter property 'device.$($node.Property)' in rule '$Rule'."
        }
        $definition = $propertyDefinitions[$node.Property]
        if ($definition.Operators -notcontains $node.Operator) {
            throw "Test-EntraPostureDeviceFilterCondition: operator '$($node.Operator)' is not valid for device-filter property 'device.$($node.Property)' (supported: $($definition.Operators -join ', ')) in rule '$Rule'."
        }
    }

    $extensionAttributesAvailable = $IsIntuneManaged -or $IsCompliantDevice -or $IsHybridJoined

    $resolvedAttributes = [ordered]@{}
    foreach ($propertyName in $propertyDefinitions.Keys) {
        $definition = $propertyDefinitions[$propertyName]
        $available = if (-not $IsDeviceRegistered) {
            $false
        } elseif ($definition.IsExtensionAttribute) {
            $extensionAttributesAvailable
        } else {
            $true
        }
        $resolvedAttributes[$propertyName] = if ($available -and $DeviceAttributes.Contains($propertyName)) { $DeviceAttributes[$propertyName] } else { $null }
    }

    $ruleResult = Test-EntraPostureDeviceFilterAstMatch -Ast $ast -DeviceAttributes $resolvedAttributes

    if ($Mode -eq 'include') { return $ruleResult }
    return -not $ruleResult
}

function Get-EntraPostureDeviceFilterComparisonNode {
    <#
        .SYNOPSIS
        Flattens every Comparison leaf node out of a device-filter AST, depth-first -- used by
        Test-EntraPostureDeviceFilterCondition to validate every property/operator pair in a
        rule before evaluating it.

        .PARAMETER Ast
        A parsed AST node (or sub-node) from ConvertTo-EntraPostureDeviceFilterAst.

        .OUTPUTS
        Array of Comparison-kind AST nodes.

        .DESCRIPTION
        Each recursive call already returns a comma-protected array as its own single pipeline
        object -- callers (including this function's own recursive calls to itself) must capture
        it with plain assignment or a bare `return`, never re-wrap it in @() or ,@(), or the
        result silently collapses to a 1-element array whose sole element is the real array
        (confirmed directly: a 3-node result's own .Type/.Value looked like a single
        space-joined string via PowerShell's array member-enumeration, not 3 separate objects).
        Confirmed the hard way three times in this same build-order item (DeviceFilterParser.ps1,
        this function's own two recursive branches, and its caller in Test-
        EntraPostureDeviceFilterCondition) before being fixed everywhere at once.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Ast
    )

    switch ($Ast.NodeType) {
        'Comparison' { return ,@($Ast) }
        'Not' { return Get-EntraPostureDeviceFilterComparisonNode -Ast $Ast.Operand }
        default {
            $leftNodes = Get-EntraPostureDeviceFilterComparisonNode -Ast $Ast.Left
            $rightNodes = Get-EntraPostureDeviceFilterComparisonNode -Ast $Ast.Right
            return ,@(@($leftNodes) + @($rightNodes))
        }
    }
}
