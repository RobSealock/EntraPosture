#Requires -Version 7.4
#Requires -Modules Pester

<#
    Golden tests (engineering plan section 14 item 3): byte-deterministic canonical
    serialization and hashing. "Ordinary ConvertTo-Json output is not a hash contract" --
    these tests exist specifically to keep that guarantee true over time.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/FileHash.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/AggregateHash.ps1')
}

Describe 'ConvertTo-EntraPostureCanonicalJson' {

    It 'produces byte-identical output across repeated calls with the same input' {
        $record = [ordered]@{ b = 'second'; a = 'first'; n = 42; nested = [ordered]@{ x = 1; y = 2 } }
        $json1 = ConvertTo-EntraPostureCanonicalJson -InputObject $record
        $json2 = ConvertTo-EntraPostureCanonicalJson -InputObject $record
        $json2 | Should -Be $json1
    }

    It 'preserves declared property order rather than alphabetizing' {
        $record = [ordered]@{ zebra = 1; apple = 2 }
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $record
        $json.IndexOf('"zebra"') | Should -BeLessThan $json.IndexOf('"apple"')
    }

    It 'produces fully compact output with no insignificant whitespace' {
        $record = [ordered]@{ a = 1; b = @(1, 2, 3) }
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $record
        $json | Should -Be '{"a":1,"b":[1,2,3]}'
    }

    It 'rejects a plain (unordered) hashtable' {
        { ConvertTo-EntraPostureCanonicalJson -InputObject @{ a = 1 } } | Should -Throw '*hashtable*'
    }

    It 'rejects a PSCustomObject' {
        { ConvertTo-EntraPostureCanonicalJson -InputObject ([pscustomobject]@{ a = 1 }) } | Should -Throw '*PSCustomObject*'
    }

    It 'rejects NaN' {
        { ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{ x = [double]::NaN }) } | Should -Throw '*non-finite*'
    }

    It 'rejects positive and negative Infinity' {
        { ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{ x = [double]::PositiveInfinity }) } | Should -Throw '*non-finite*'
        { ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{ x = [double]::NegativeInfinity }) } | Should -Throw '*non-finite*'
    }

    It 'round-trips null as explicit null, not an absent key' {
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{ a = $null })
        $json | Should -Be '{"a":null}'
    }

    It 'represents an empty array as [] rather than omitting the key' {
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject ([ordered]@{ items = @() })
        $json | Should -Be '{"items":[]}'
    }
}

Describe 'Get-EntraPostureFileHash' {
    It 'computes the correct, lowercase SHA-256 for known content' {
        $tmp = New-TemporaryFile
        try {
            [System.IO.File]::WriteAllText($tmp.FullName, 'hello world', [System.Text.UTF8Encoding]::new($false))
            $hash = Get-EntraPostureFileHash -Path $tmp.FullName
            $hash | Should -Be 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
            $hash | Should -Be $hash.ToLowerInvariant()
        } finally {
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-EntraPostureAggregateHash' {
    It 'is independent of input entry order' {
        $a = @([ordered]@{relativePath='b/f.json';byteSize=100;fileHash='h2'}, [ordered]@{relativePath='a/f.json';byteSize=50;fileHash='h1'})
        $b = @([ordered]@{relativePath='a/f.json';byteSize=50;fileHash='h1'}, [ordered]@{relativePath='b/f.json';byteSize=100;fileHash='h2'})
        (($a | Get-EntraPostureAggregateHash).aggregateHash) | Should -Be (($b | Get-EntraPostureAggregateHash).aggregateHash)
    }

    It 'normalizes backslash path separators before hashing' {
        $withBackslash = @([ordered]@{relativePath='b\f.json';byteSize=100;fileHash='h2'}, [ordered]@{relativePath='a/f.json';byteSize=50;fileHash='h1'})
        $withForwardSlash = @([ordered]@{relativePath='b/f.json';byteSize=100;fileHash='h2'}, [ordered]@{relativePath='a/f.json';byteSize=50;fileHash='h1'})
        (($withBackslash | Get-EntraPostureAggregateHash).aggregateHash) | Should -Be (($withForwardSlash | Get-EntraPostureAggregateHash).aggregateHash)
    }

    It 'rejects an exact duplicate path' {
        $dup = @([ordered]@{relativePath='x.json';byteSize=1;fileHash='h'}, [ordered]@{relativePath='x.json';byteSize=1;fileHash='h'})
        { $dup | Get-EntraPostureAggregateHash } | Should -Throw '*duplicate path*'
    }

    It 'rejects a case-only path collision, correctly distinguished from an exact duplicate' {
        $collision = @([ordered]@{relativePath='X.json';byteSize=1;fileHash='h'}, [ordered]@{relativePath='x.json';byteSize=1;fileHash='h'})
        { $collision | Get-EntraPostureAggregateHash } | Should -Throw '*case-only path collision*'
    }

    It 'rejects an empty entry set' {
        { @() | Get-EntraPostureAggregateHash } | Should -Throw '*at least one entry*'
    }
}
