#Requires -Version 7.4
#Requires -Modules Pester

<#
    Confirms every one of this project's eight Public commands is fully implemented -- no
    Assert-EntraPostureNotImplemented stub marker remains anywhere in the exported command
    set (see src/Common/AssertNotImplemented.ps1 for that marker's original rationale). Phase 5
    implemented seven of the eight; Compare-EntraPosture was the last, implemented in Phase 9
    (comparison) -- this file's own "still pending implementation" Describe block, which used to
    list it, is now retired along with the stub it tested, not left behind as dead scaffolding.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    Get-Module -Name EntraPosture -All | Remove-Module -Force -ErrorAction SilentlyContinue
    & (Join-Path $script:RepoRoot 'build/Build-Module.ps1') -OutputPath (Join-Path $script:RepoRoot 'tests/.tmp-stub-test-build') -Clean | Out-Null
    Import-Module (Join-Path $script:RepoRoot 'tests/.tmp-stub-test-build/EntraPosture.psd1') -Force
}

AfterAll {
    Remove-Module -Name EntraPosture -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $script:RepoRoot 'tests/.tmp-stub-test-build') -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Every Public command is fully implemented (Phase 9: the last stub, Compare-EntraPosture, is gone)' {
    It '<_> is exported and its body no longer calls Assert-EntraPostureNotImplemented' -ForEach @(
        'Invoke-EntraPosture'
        'Test-EntraPostureAccess'
        'New-EntraPostureSnapshot'
        'Invoke-EntraPostureEvaluation'
        'New-EntraPostureReport'
        'Get-EntraPostureControl'
        'Test-EntraPostureBundle'
        'Compare-EntraPosture'
    ) {
        # Deliberately does NOT invoke these commands -- several have Mandatory parameters, and
        # calling with missing ones would make PowerShell prompt interactively in a
        # non-interactive test run rather than throw, hanging the test. Inspecting the
        # function's own source text for the stub's marker call proves the real implementation
        # replaced Assert-EntraPostureNotImplemented without needing to invoke anything.
        $command = Get-Command -Name $_ -Module EntraPosture
        $command | Should -Not -BeNullOrEmpty
        $command.ScriptBlock.ToString() | Should -Not -Match 'Assert-EntraPostureNotImplemented'
    }
}
