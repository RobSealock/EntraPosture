#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 6, "bounded collection concurrency" (engineering plan section 12:
    "Use bounded collection concurrency, default four, with central throttling... Make all result
    ordering deterministic independently of collection concurrency"). These tests exercise the
    actual properties that requirement names -- genuine bounded concurrency, not just "the
    function returns the right values" -- not just re-running the existing orchestration suite
    and trusting it happened to still pass.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Orchestration/BoundedParallelExecution.ps1')

    # Records each invocation's own start/end tick count so tests can directly verify overlap
    # (genuine concurrency) rather than inferring it indirectly from elapsed wall-clock time alone.
    function script:Test-BpeSleepAndRecord {
        param([int]$Milliseconds, [string]$Tag)
        $start = [System.Diagnostics.Stopwatch]::GetTimestamp()
        Start-Sleep -Milliseconds $Milliseconds
        $end = [System.Diagnostics.Stopwatch]::GetTimestamp()
        return [ordered]@{ Tag = $Tag; StartTicks = $start; EndTicks = $end }
    }

    function script:Test-BpeThrowIfMarked {
        param([string]$Tag, [bool]$ShouldThrow)
        if ($ShouldThrow) { throw "deliberate failure for $Tag" }
        return [ordered]@{ Tag = $Tag }
    }
}

Describe 'Invoke-EntraPostureBoundedParallel: genuine bounded concurrency' {
    It 'runs work items with real time overlap, not sequentially' {
        $sets = 1..4 | ForEach-Object { @{ Milliseconds = 150; Tag = "item-$_" } }
        $results = Invoke-EntraPostureBoundedParallel -CommandName 'Test-BpeSleepAndRecord' -ParameterSets $sets -ThrottleLimit 4 -FunctionNamePattern 'Test-Bpe*'

        # Overlap check: at least one pair of items must have intervals that intersect -- true
        # sequential execution can never produce this, since each item's own 150ms window would
        # start only after the previous one's ended.
        $intervals = @($results | ForEach-Object { $_.Result })
        $anyOverlap = $false
        for ($i = 0; $i -lt $intervals.Count; $i++) {
            for ($j = $i + 1; $j -lt $intervals.Count; $j++) {
                $a = $intervals[$i]; $b = $intervals[$j]
                if ($a.StartTicks -lt $b.EndTicks -and $b.StartTicks -lt $a.EndTicks) { $anyOverlap = $true }
            }
        }
        $anyOverlap | Should -BeTrue -Because 'four 150ms items at ThrottleLimit 4 must overlap in time if genuinely concurrent'
    }

    It 'bounds actual concurrency to ThrottleLimit -- 8 items at throttle 4 take roughly 2 batches, not 1 or 8' {
        $sets = 1..8 | ForEach-Object { @{ Milliseconds = 150; Tag = "item-$_" } }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Invoke-EntraPostureBoundedParallel -CommandName 'Test-BpeSleepAndRecord' -ParameterSets $sets -ThrottleLimit 4 -FunctionNamePattern 'Test-Bpe*' | Out-Null
        $sw.Stop()

        # Unbounded (all 8 at once) would be ~150-250ms; fully sequential would be ~1200ms+.
        # Genuinely bounded to 4 concurrent should land around 2 batches, ~250-600ms.
        $sw.ElapsedMilliseconds | Should -BeGreaterThan 250 -Because 'true concurrency bounded to 4 needs at least two ~150ms batches for 8 items'
        $sw.ElapsedMilliseconds | Should -BeLessThan 1100 -Because 'this must not have silently fallen back to fully sequential execution'
    }
}

Describe 'Invoke-EntraPostureBoundedParallel: deterministic result ordering' {
    It 'returns results in -ParameterSets input order regardless of which item finishes first' {
        # Deliberately reverse-order sleep durations: the LAST parameter set finishes FIRST if
        # anything is naively returning results in completion order instead of input order.
        $sets = @(
            @{ Milliseconds = 300; Tag = 'slow-first' }
            @{ Milliseconds = 10; Tag = 'fast-second' }
        )
        $results = Invoke-EntraPostureBoundedParallel -CommandName 'Test-BpeSleepAndRecord' -ParameterSets $sets -ThrottleLimit 4 -FunctionNamePattern 'Test-Bpe*'

        $results.Count | Should -Be 2
        $results[0].Result.Tag | Should -Be 'slow-first'
        $results[1].Result.Tag | Should -Be 'fast-second'
    }

    It 'returns an empty array for an empty -ParameterSets without invoking anything' {
        $results = Invoke-EntraPostureBoundedParallel -CommandName 'Test-BpeSleepAndRecord' -ParameterSets @() -ThrottleLimit 4 -FunctionNamePattern 'Test-Bpe*'
        @($results).Count | Should -Be 0
    }
}

Describe 'Invoke-EntraPostureBoundedParallel: per-item error isolation' {
    It 'reports one failing item''s error without affecting any other item''s success' {
        $sets = @(
            @{ Tag = 'ok-1'; ShouldThrow = $false }
            @{ Tag = 'fails'; ShouldThrow = $true }
            @{ Tag = 'ok-2'; ShouldThrow = $false }
        )
        $results = Invoke-EntraPostureBoundedParallel -CommandName 'Test-BpeThrowIfMarked' -ParameterSets $sets -ThrottleLimit 4 -FunctionNamePattern 'Test-Bpe*'

        $results.Count | Should -Be 3
        $results[0].Success | Should -BeTrue
        $results[0].Result.Tag | Should -Be 'ok-1'
        $results[1].Success | Should -BeFalse
        $results[1].ErrorMessage | Should -Match 'deliberate failure for fails'
        $results[2].Success | Should -BeTrue
        $results[2].Result.Tag | Should -Be 'ok-2'
    }
}
