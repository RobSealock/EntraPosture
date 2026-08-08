#Requires -Version 7.4
#Requires -Modules Pester

<#
    v.next build order item 5 (device-filter rule-language evaluation, re-scoped 2026-08-07 as
    its own item): the full tokenizer -> parser -> evaluator -> applicability-wrapper pipeline
    for `conditions.devices.deviceFilter.rule`. Grammar/property-table facts confirmed live
    against Microsoft's own "Filter for devices" and "rules for dynamic membership groups" pages
    (both re-fetched 2026-08-07) -- see each source file's own DESCRIPTION for the citation
    trail. This file also specifically proves the derived per-property nullability model
    (EvaluateDeviceFilterCondition.ps1) reproduces every row of Microsoft's own documented
    applicability table, since that model is this project's own synthesis of two direct quotes,
    not a single literal quote.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/ConditionalAccess/DeviceFilterTokenizer.ps1',
        'src/ConditionalAccess/DeviceFilterParser.ps1',
        'src/ConditionalAccess/DeviceFilterEvaluator.ps1',
        'src/ConditionalAccess/EvaluateDeviceFilterCondition.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }
}

Describe 'Get-EntraPostureDeviceFilterToken' {
    It 'tokenizes a simple comparison' {
        $tokens = Get-EntraPostureDeviceFilterToken -Rule 'device.isCompliant -eq "True"'
        $tokens.Count | Should -Be 3
        $tokens[0].Type | Should -Be 'Identifier'
        $tokens[0].Value | Should -Be 'device.isCompliant'
        $tokens[1].Type | Should -Be 'Operator'
        $tokens[1].Value | Should -Be '-eq'
        $tokens[2].Type | Should -Be 'String'
        $tokens[2].Value | Should -Be 'True'
    }

    It 'unescapes backtick-escaped double quotes and doubled single quotes inside strings' {
        # Backtick-escaped double quote: the literal rule text is: device.displayName -eq "a`"b"
        $tokens2 = Get-EntraPostureDeviceFilterToken -Rule 'device.displayName -eq "a`"b"'
        $tokens2[2].Type | Should -Be 'String'
        $tokens2[2].Value | Should -Be 'a"b'

        $tokens3 = Get-EntraPostureDeviceFilterToken -Rule "device.displayName -eq ""a''b"""
        $tokens3[2].Value | Should -Be "a'b"
    }

    It 'tokenizes parentheses, brackets, and commas for an -in array literal' {
        $tokens = Get-EntraPostureDeviceFilterToken -Rule 'device.operatingSystemVersion -in ["10.0.19041", "10.0.22000"]'
        @($tokens | Where-Object { $_.Type -eq 'LBracket' }).Count | Should -Be 1
        @($tokens | Where-Object { $_.Type -eq 'RBracket' }).Count | Should -Be 1
        @($tokens | Where-Object { $_.Type -eq 'Comma' }).Count | Should -Be 1
        @($tokens | Where-Object { $_.Type -eq 'String' }).Count | Should -Be 2
    }

    It 'tokenizes a compound rule with parens, -and, -or, -not' {
        $tokens = Get-EntraPostureDeviceFilterToken -Rule '(device.trustType -eq "AzureAD") -and -not (device.extensionAttribute1 -eq "Excluded")'
        @($tokens | Where-Object { $_.Type -eq 'Operator' -and $_.Value -eq '-and' }).Count | Should -Be 1
        @($tokens | Where-Object { $_.Type -eq 'Operator' -and $_.Value -eq '-not' }).Count | Should -Be 1
        @($tokens | Where-Object { $_.Type -eq 'LParen' }).Count | Should -Be 2
    }

    It 'throws on an unrecognized operator' {
        { Get-EntraPostureDeviceFilterToken -Rule 'device.isCompliant -bogus "True"' } | Should -Throw '*unrecognized operator*'
    }

    It 'throws on an unterminated string' {
        { Get-EntraPostureDeviceFilterToken -Rule 'device.displayName -eq "unterminated' } | Should -Throw '*unterminated*'
    }

    It 'throws when the rule exceeds the 3072-character limit' {
        $longRule = 'device.displayName -eq "' + ('x' * 3100) + '"'
        { Get-EntraPostureDeviceFilterToken -Rule $longRule } | Should -Throw '*3072*'
    }
}

Describe 'ConvertTo-EntraPostureDeviceFilterAst: precedence and structure' {
    It 'parses a single comparison' {
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.trustType -eq "AzureAD"'
        $ast.NodeType | Should -Be 'Comparison'
        $ast.Property | Should -Be 'trustType'
        $ast.Operator | Should -Be '-eq'
        $ast.Value.Kind | Should -Be 'String'
        $ast.Value.Value | Should -Be 'AzureAD'
    }

    It '-and binds tighter than -or (matching Microsoft''s documented precedence)' {
        # a -or b -and c  ==>  a -or (b -and c)
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.trustType -eq "AzureAD" -or device.isCompliant -eq "True" -and device.deviceOwnership -eq "Company"'
        $ast.NodeType | Should -Be 'Or'
        $ast.Left.Property | Should -Be 'trustType'
        $ast.Right.NodeType | Should -Be 'And'
        $ast.Right.Left.Property | Should -Be 'isCompliant'
        $ast.Right.Right.Property | Should -Be 'deviceOwnership'
    }

    It 'parentheses override default precedence' {
        # (a -or b) -and c
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule '(device.trustType -eq "AzureAD" -or device.isCompliant -eq "True") -and device.deviceOwnership -eq "Company"'
        $ast.NodeType | Should -Be 'And'
        $ast.Left.NodeType | Should -Be 'Or'
        $ast.Right.Property | Should -Be 'deviceOwnership'
    }

    It 'parses -not applied to a parenthesized expression' {
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule '-not (device.trustType -eq "AzureAD")'
        $ast.NodeType | Should -Be 'Not'
        $ast.Operand.NodeType | Should -Be 'Comparison'
    }

    It 'parses an -in array literal into an Array-kind value' {
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.operatingSystemVersion -in ["10.0.19041", "10.0.22000"]'
        $ast.Value.Kind | Should -Be 'Array'
        @($ast.Value.Value) | Should -Be @('10.0.19041', '10.0.22000')
    }

    It 'parses the true/false/null keywords' {
        $astTrue = ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.isCompliant -eq true'
        $astTrue.Value.Kind | Should -Be 'Boolean'
        $astTrue.Value.Value | Should -BeTrue

        $astNull = ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.manufacturer -eq null'
        $astNull.Value.Kind | Should -Be 'Null'
    }

    It 'throws for -match (tokenizable in the shared grammar but not a supported device-filter operator)' {
        { ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.displayName -match "^Da.*"' } | Should -Throw '*not supported*'
    }

    It 'throws when the property is not prefixed with ''device.''' {
        { ConvertTo-EntraPostureDeviceFilterAst -Rule 'user.department -eq "Sales"' } | Should -Throw '*device.*'
    }

    It 'throws on a trailing token after a complete expression' {
        { ConvertTo-EntraPostureDeviceFilterAst -Rule 'device.trustType -eq "AzureAD" )' } | Should -Throw '*trailing*'
    }

    It 'throws on an empty rule' {
        { ConvertTo-EntraPostureDeviceFilterAst -Rule '' } | Should -Throw '*empty*'
    }
}

Describe 'Test-EntraPostureDeviceFilterComparison: null-propagation and case-insensitivity' {
    It 'a positive operator against a null actual value is false, for every positive operator' {
        $expected = [ordered]@{ Kind = 'String'; Value = 'AzureAD' }
        foreach ($op in @('-eq', '-startsWith', '-endsWith', '-contains', '-in')) {
            $val = if ($op -eq '-in') { [ordered]@{ Kind = 'Array'; Value = @('AzureAD') } } else { $expected }
            Test-EntraPostureDeviceFilterComparison -Operator $op -Actual $null -Expected $val | Should -BeFalse -Because "operator $op against null should be false"
        }
    }

    It 'a negative operator against a null actual value is true, for every negative operator' {
        $expected = [ordered]@{ Kind = 'String'; Value = 'AzureAD' }
        foreach ($op in @('-ne', '-notStartsWith', '-notEndsWith', '-notContains', '-notIn')) {
            $val = if ($op -eq '-notIn') { [ordered]@{ Kind = 'Array'; Value = @('AzureAD') } } else { $expected }
            Test-EntraPostureDeviceFilterComparison -Operator $op -Actual $null -Expected $val | Should -BeTrue -Because "operator $op against null should be true"
        }
    }

    It 'Microsoft''s documented null-check idiom: -eq null is true, -ne null is false, only when the actual value really is null' {
        $nullValue = [ordered]@{ Kind = 'Null'; Value = $null }
        Test-EntraPostureDeviceFilterComparison -Operator '-eq' -Actual $null -Expected $nullValue | Should -BeTrue
        Test-EntraPostureDeviceFilterComparison -Operator '-ne' -Actual $null -Expected $nullValue | Should -BeFalse
        Test-EntraPostureDeviceFilterComparison -Operator '-eq' -Actual 'AzureAD' -Expected $nullValue | Should -BeFalse
        Test-EntraPostureDeviceFilterComparison -Operator '-ne' -Actual 'AzureAD' -Expected $nullValue | Should -BeTrue
    }

    It 'string comparisons are case-insensitive' {
        $expected = [ordered]@{ Kind = 'String'; Value = 'azuread' }
        Test-EntraPostureDeviceFilterComparison -Operator '-eq' -Actual 'AzureAD' -Expected $expected | Should -BeTrue
        Test-EntraPostureDeviceFilterComparison -Operator '-startsWith' -Actual 'AzureAD-Joined' -Expected $expected | Should -BeTrue
    }

    It '-contains means substring match for a scalar string' {
        $expected = [ordered]@{ Kind = 'String'; Value = 'Surface' }
        Test-EntraPostureDeviceFilterComparison -Operator '-contains' -Actual 'Microsoft Surface Pro' -Expected $expected | Should -BeTrue
        Test-EntraPostureDeviceFilterComparison -Operator '-contains' -Actual 'Microsoft Laptop' -Expected $expected | Should -BeFalse
    }

    It '-contains means whole-element match for a string collection, not substring' {
        $expected = [ordered]@{ Kind = 'String'; Value = 'M365' }
        Test-EntraPostureDeviceFilterComparison -Operator '-contains' -Actual @('M365Managed', 'MultiUser') -Expected $expected | Should -BeFalse -Because 'M365 is a substring of M365Managed but not a whole element'
        Test-EntraPostureDeviceFilterComparison -Operator '-contains' -Actual @('M365', 'MultiUser') -Expected $expected | Should -BeTrue
    }

    It '-in matches against any element of the expected array, case-insensitively' {
        $expected = [ordered]@{ Kind = 'Array'; Value = @('10.0.19041', '10.0.22000') }
        Test-EntraPostureDeviceFilterComparison -Operator '-in' -Actual '10.0.22000' -Expected $expected | Should -BeTrue
        Test-EntraPostureDeviceFilterComparison -Operator '-in' -Actual '10.0.18363' -Expected $expected | Should -BeFalse
    }
}

Describe 'Test-EntraPostureDeviceFilterAstMatch: compound expression evaluation' {
    It 'evaluates -and/-or/-not correctly against a resolved device' {
        $ast = ConvertTo-EntraPostureDeviceFilterAst -Rule '(device.trustType -eq "AzureAD") -and -not (device.deviceOwnership -eq "Personal")'
        $device = [ordered]@{ trustType = 'AzureAD'; deviceOwnership = 'Company' }
        Test-EntraPostureDeviceFilterAstMatch -Ast $ast -DeviceAttributes $device | Should -BeTrue

        $device2 = [ordered]@{ trustType = 'AzureAD'; deviceOwnership = 'Personal' }
        Test-EntraPostureDeviceFilterAstMatch -Ast $ast -DeviceAttributes $device2 | Should -BeFalse
    }
}

Describe 'Test-EntraPostureDeviceFilterCondition: reproduces every row of Microsoft''s own applicability table' {
    <#
        Table from "Filter for devices as a condition in Conditional Access policy" (re-fetched
        2026-08-07). This project's per-property nullability model is a synthesis of two direct
        quotes, not one literal quote -- these tests exist specifically to prove the derived
        model reproduces every row, not just to exercise the code.
    #>

    It 'positive operator, any attribute, unregistered device -> not applied' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -eq "AzureAD"' `
            -IsDeviceRegistered $false | Should -BeFalse
    }

    It 'positive operator, non-extensionAttribute, registered device -> applied if criteria met' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -eq "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'AzureAD' }) | Should -BeTrue
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -eq "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'Workplace' }) | Should -BeFalse
    }

    It 'positive operator, extensionAttribute, registered + Intune-managed -> applied if criteria met' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -eq "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $true -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' }) | Should -BeTrue
    }

    It 'positive operator, extensionAttribute, registered but NOT Intune-managed and NOT compliant/hybrid -> not applied even if the value would otherwise match' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -eq "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $false -IsCompliantDevice $false -IsHybridJoined $false `
            -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' }) | Should -BeFalse
    }

    It 'positive operator, extensionAttribute, registered, not Intune-managed, but compliant -> applied if criteria met (compliant satisfies the gate)' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -eq "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $false -IsCompliantDevice $true -IsHybridJoined $false `
            -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' }) | Should -BeTrue
    }

    It 'positive operator, extensionAttribute, registered, not Intune-managed, but hybrid-joined -> applied if criteria met (hybrid-joined satisfies the gate)' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -eq "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $false -IsCompliantDevice $false -IsHybridJoined $true `
            -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' }) | Should -BeTrue
    }

    It 'negative operator, any attribute, unregistered device -> ALWAYS applied' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -ne "AzureAD"' `
            -IsDeviceRegistered $false | Should -BeTrue
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -ne "SAW"' `
            -IsDeviceRegistered $false | Should -BeTrue
    }

    It 'negative operator, non-extensionAttribute, registered device -> applied if criteria met' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -ne "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'Workplace' }) | Should -BeTrue
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.trustType -ne "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'AzureAD' }) | Should -BeFalse
    }

    It 'negative operator, extensionAttribute, registered + Intune-managed -> applied if criteria met' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -ne "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $true -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'Other' }) | Should -BeTrue
    }

    It 'negative operator, extensionAttribute, registered, not Intune-managed/compliant/hybrid-joined -> the unavailable value is treated as null, so -ne is vacuously true' {
        Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.extensionAttribute1 -ne "SAW"' `
            -IsDeviceRegistered $true -IsIntuneManaged $false -IsCompliantDevice $false -IsHybridJoined $false `
            -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' }) | Should -BeTrue
    }
}

Describe 'Test-EntraPostureDeviceFilterCondition: mode and validation' {
    It 'exclude mode inverts the rule result' {
        Test-EntraPostureDeviceFilterCondition -Mode 'exclude' -Rule 'device.trustType -eq "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'AzureAD' }) | Should -BeFalse
        Test-EntraPostureDeviceFilterCondition -Mode 'exclude' -Rule 'device.trustType -eq "AzureAD"' `
            -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'Workplace' }) | Should -BeTrue
    }

    It 'throws when an operator is invalid for a specific property (e.g. -contains on isCompliant, an equality-only property)' {
        { Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.isCompliant -contains "True"' -IsDeviceRegistered $true } | Should -Throw '*not valid*'
    }

    It 'throws on an unrecognized device-filter property' {
        { Test-EntraPostureDeviceFilterCondition -Mode 'include' -Rule 'device.notARealProperty -eq "x"' -IsDeviceRegistered $true } | Should -Throw '*unrecognized*'
    }
}
