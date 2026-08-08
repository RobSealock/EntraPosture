#Requires -Version 7.4
#Requires -Modules Pester

<#
    Contract test: engineering plan Phase 2 exit criterion -- "two clean builds are
    byte-equivalent before signing and export only the approved commands."
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    $script:BuildScript = Join-Path $script:RepoRoot 'build/Build-Module.ps1'
    $script:Build1Path = Join-Path $script:RepoRoot 'tests/.tmp-build1'
    $script:Build2Path = Join-Path $script:RepoRoot 'tests/.tmp-build2'
}

AfterAll {
    Remove-Item -LiteralPath $script:Build1Path -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:Build2Path -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Build-Module determinism and export contract' {

    BeforeAll {
        & $script:BuildScript -OutputPath $script:Build1Path -Clean | Out-Null
        Start-Sleep -Seconds 1
        & $script:BuildScript -OutputPath $script:Build2Path -Clean | Out-Null
    }

    It 'produces a byte-identical .psm1 across two clean builds' {
        $hash1 = (Get-FileHash -LiteralPath (Join-Path $script:Build1Path 'EntraPosture.psm1') -Algorithm SHA256).Hash
        $hash2 = (Get-FileHash -LiteralPath (Join-Path $script:Build2Path 'EntraPosture.psm1') -Algorithm SHA256).Hash
        $hash2 | Should -Be $hash1
    }

    It 'produces a byte-identical .psd1 across two clean builds' {
        $hash1 = (Get-FileHash -LiteralPath (Join-Path $script:Build1Path 'EntraPosture.psd1') -Algorithm SHA256).Hash
        $hash2 = (Get-FileHash -LiteralPath (Join-Path $script:Build2Path 'EntraPosture.psd1') -Algorithm SHA256).Hash
        $hash2 | Should -Be $hash1
    }

    It 'exports exactly the approved command set, nothing more and nothing less' {
        Get-Module -Name EntraPosture -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $script:Build1Path 'EntraPosture.psd1') -Force

        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:RepoRoot 'build/BuildManifest.psd1')
        $expected = @($manifest.ApprovedExports | Sort-Object)
        $actual = @((Get-Command -Module EntraPosture).Name | Sort-Object)

        $actual | Should -Be $expected

        Remove-Module -Name EntraPosture -Force -ErrorAction SilentlyContinue
    }

    It 'does not leak private helper functions into the caller session' {
        Get-Module -Name EntraPosture -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $script:Build1Path 'EntraPosture.psd1') -Force

        Get-Command -Name 'New-EntraPostureErrorRecord' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command -Name 'Assert-EntraPostureNotImplemented' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty

        Remove-Module -Name EntraPosture -Force -ErrorAction SilentlyContinue
    }

    It 'reports Unsigned status when built without a signing certificate' {
        $hashManifest = Get-Content -LiteralPath (Join-Path $script:Build1Path 'BUILD-HASHES.json') -Raw | ConvertFrom-Json
        $hashManifest.SignStatus | Should -Be 'Unsigned'
    }
}

Describe 'Build-Module rebuild into an existing (non--Clean) output directory' {
    <#
        Confirmed directly (via a real live-tenant run of the built module, not caught by any
        prior test): Copy-Item -Recurse nests the *source directory itself* inside an
        already-existing destination instead of copying its contents into it. The Describe block
        above always passes -Clean, which wipes $OutputPath first, so the destination never
        pre-exists and this bug class can't trigger there -- this Describe specifically rebuilds
        twice *without* -Clean, into the same already-populated output directory, which is the
        actual condition that shipped 6 of 8 controls as permanently unreadable by the built
        module across every rebuild after the first, undetected until a live run surfaced it.
    #>
    BeforeAll {
        $script:RebuildPath = Join-Path $script:RepoRoot 'tests/.tmp-rebuild-no-clean'
        Remove-Item -LiteralPath $script:RebuildPath -Recurse -Force -ErrorAction SilentlyContinue
        & $script:BuildScript -OutputPath $script:RebuildPath | Out-Null
        # No -Clean here -- $script:RebuildPath already exists with a prior build's controls/ and
        # schemas/ directories, which is exactly the condition that triggered the nesting bug.
        & $script:BuildScript -OutputPath $script:RebuildPath | Out-Null
    }

    AfterAll {
        Remove-Item -LiteralPath $script:RebuildPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'does not nest controls/ inside itself on a second non--Clean build' {
        Test-Path -LiteralPath (Join-Path $script:RebuildPath 'controls/controls') | Should -BeFalse
    }

    It 'still has every control file at the top level of controls/ after a second non--Clean build' {
        $sourceControlNames = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'controls') -Filter '*.psd1' -File | Select-Object -ExpandProperty Name | Sort-Object)
        $builtControlNames = @(Get-ChildItem -LiteralPath (Join-Path $script:RebuildPath 'controls') -Filter '*.psd1' -File | Select-Object -ExpandProperty Name | Sort-Object)
        $builtControlNames | Should -Be $sourceControlNames
    }

    It 'does not nest schemas/ inside itself on a second non--Clean build' {
        Test-Path -LiteralPath (Join-Path $script:RebuildPath 'schemas/schemas') | Should -BeFalse
    }

    It 'loads the full control registry (matching source count) from a twice-rebuilt, non--Clean output directory' {
        Get-Module -Name EntraPosture -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $script:RebuildPath 'EntraPosture.psd1') -Force

        $sourceControlCount = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'controls') -Filter '*.psd1' -File).Count
        $registry = & (Get-Module EntraPosture) { Get-EntraPostureControlRegistry }
        @($registry).Count | Should -Be $sourceControlCount

        Remove-Module -Name EntraPosture -Force -ErrorAction SilentlyContinue
    }
}
