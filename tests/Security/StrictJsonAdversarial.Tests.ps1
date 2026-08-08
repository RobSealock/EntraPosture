#Requires -Version 7.4
#Requires -Modules Pester

<#
    Adversarial tests (engineering plan section 14 item 8): hostile/malformed JSON that a
    naive parser would silently misinterpret rather than reject.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
}

Describe 'ConvertFrom-EntraPostureJson adversarial inputs' {

    It 'rejects a duplicate key at the top level' {
        { ConvertFrom-EntraPostureJson -Json '{"a":1,"b":2,"a":3}' } | Should -Throw '*duplicate*'
    }

    It 'rejects a duplicate key nested inside an object' {
        { ConvertFrom-EntraPostureJson -Json '{"outer":{"x":1,"x":2}}' } | Should -Throw '*duplicate*'
    }

    It 'rejects a duplicate key inside an object nested in an array' {
        { ConvertFrom-EntraPostureJson -Json '[{"a":1},{"a":1,"a":2}]' } | Should -Throw '*duplicate*'
    }

    It 'does NOT falsely reject the same key name reused at different nesting levels' {
        { ConvertFrom-EntraPostureJson -Json '{"x":1,"nested":{"x":2}}' } | Should -Not -Throw
    }

    It 'rejects malformed JSON (unclosed object)' {
        { ConvertFrom-EntraPostureJson -Json '{"a":' } | Should -Throw
    }

    It 'rejects a trailing comma' {
        { ConvertFrom-EntraPostureJson -Json '{"a":1,}' } | Should -Throw
    }

    It 'rejects a JSON comment' {
        { ConvertFrom-EntraPostureJson -Json "{`"a`":1 // comment`n}" } | Should -Throw
    }

    It 'rejects nesting deeper than the configured MaxDepth' {
        $deep = ('[' * 100) + (']' * 100)
        { ConvertFrom-EntraPostureJson -Json $deep -MaxDepth 10 } | Should -Throw
    }

    It 'returns the project canonical ordered-dictionary type for valid input, recursively' {
        $result = ConvertFrom-EntraPostureJson -Json '{"a":{"b":1}}'
        $result.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
        $result.a.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
    }

    It 'preserves insertion order from the source JSON text' {
        $result = ConvertFrom-EntraPostureJson -Json '{"z":1,"a":2}'
        @($result.Keys) | Should -Be @('z', 'a')
    }

    It 'round-trips through canonicalization losslessly for well-formed input' {
        . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
        $original = '{"b":1,"a":{"nested":true,"arr":[1,2,3]}}'
        $parsed = ConvertFrom-EntraPostureJson -Json $original
        $canonical = ConvertTo-EntraPostureCanonicalJson -InputObject $parsed
        $reparsed = ConvertFrom-EntraPostureJson -Json $canonical
        (ConvertTo-EntraPostureCanonicalJson -InputObject $reparsed) | Should -Be $canonical
    }
}
