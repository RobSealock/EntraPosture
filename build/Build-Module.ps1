#Requires -Version 7.4

<#
    .SYNOPSIS
    Assembles the EntraPosture module deterministically from the declared source order in
    BuildManifest.psd1.

    .DESCRIPTION
    Implements engineering plan section 6.1's build discipline: explicit source order, no
    runtime discovery, and hard failure on unexpected source files, duplicate function names,
    or unapproved exports. Produces a single compiled .psm1, a hand-written deterministic .psd1
    (New-ModuleManifest is deliberately not used -- it embeds a build timestamp/username in its
    generated header, which would make two clean builds byte-different), and a SHA-256 hash
    manifest for both.

    .PARAMETER RepoRoot
    Repository root containing src/ and build/. Defaults to the parent of this script's folder.

    .PARAMETER OutputPath
    Where to write the built module. Defaults to <RepoRoot>/dist.

    .PARAMETER SigningCertificateThumbprint
    Optional. If supplied, the built .psm1 and .psd1 are signed via Set-AuthenticodeSignature
    using a certificate found in Cert:\CurrentUser\My or Cert:\LocalMachine\My. If omitted, the
    build produces an explicitly Unsigned artifact -- engineering plan ADR-028 requires unsigned
    status to remain visible, never silently assumed signed.

    .PARAMETER Clean
    Remove any existing OutputPath contents before building.

    .EXAMPLE
    ./build/Build-Module.ps1 -Clean
#>
[CmdletBinding()]
param (
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputPath,
    [string]$SigningCertificateThumbprint,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

function ConvertTo-Lf {
    param([Parameter(Mandatory)][string]$Text)
    return ($Text -replace "`r`n", "`n")
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

# ---------------------------------------------------------------------------
# 1. Load the build manifest
# ---------------------------------------------------------------------------
$manifestPath = Join-Path $PSScriptRoot 'BuildManifest.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Build manifest not found: $manifestPath"
}
$buildManifest = Import-PowerShellDataFile -Path $manifestPath
$declaredFiles = @($buildManifest.SourceFiles)
$approvedExports = @($buildManifest.ApprovedExports) | Sort-Object
$meta = $buildManifest.ModuleMetadata

Write-Host "[*] Loaded build manifest: $($declaredFiles.Count) declared source file(s), $($approvedExports.Count) approved export(s)."

# ---------------------------------------------------------------------------
# 2. Discover actual files under src/ and cross-check against the declaration
# ---------------------------------------------------------------------------
$srcRoot = Join-Path $RepoRoot 'src'
$actualFiles = Get-ChildItem -Path $srcRoot -Recurse -Filter '*.ps1' -File |
    ForEach-Object { ($_.FullName.Substring($RepoRoot.Length + 1)) -replace '\\', '/' } |
    Sort-Object

$unexpected = @($actualFiles | Where-Object { $_ -notin $declaredFiles })
if ($unexpected.Count -gt 0) {
    throw "Build failed: unexpected source file(s) exist under src/ but are not declared in BuildManifest.psd1:`n  $($unexpected -join "`n  ")`nAdd them to SourceFiles in the declared load order, or remove them."
}

$missing = @($declaredFiles | Where-Object { $_ -notin $actualFiles })
if ($missing.Count -gt 0) {
    throw "Build failed: BuildManifest.psd1 declares source file(s) that do not exist on disk:`n  $($missing -join "`n  ")"
}

Write-Host "[+] Source file declaration matches disk exactly ($($actualFiles.Count) file(s))."

# ---------------------------------------------------------------------------
# 3. Parse every declared file, extract function definitions, detect duplicates
# ---------------------------------------------------------------------------
$functionOwner = @{}       # function name -> declaring file
$functionsPerFile = @{}    # file -> [string[]] function names defined in it

foreach ($relPath in $declaredFiles) {
    $fullPath = Join-Path $RepoRoot $relPath
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($fullPath, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $msgs = $parseErrors | ForEach-Object { $_.Message }
        throw "Build failed: parse error(s) in '$relPath':`n  $($msgs -join "`n  ")"
    }

    $funcDefs = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    $namesInFile = @()
    foreach ($fn in $funcDefs) {
        $name = $fn.Name
        $namesInFile += $name

        if ($functionOwner.ContainsKey($name)) {
            throw "Build failed: duplicate function name '$name' defined in both '$($functionOwner[$name])' and '$relPath'."
        }
        $functionOwner[$name] = $relPath
    }
    $functionsPerFile[$relPath] = $namesInFile
}

Write-Host "[+] No duplicate function names across $($declaredFiles.Count) source file(s) ($($functionOwner.Count) function(s) total)."

# ---------------------------------------------------------------------------
# 4. Validate exports: only src/Public/*.ps1 functions may export, and the set
#    must exactly match BuildManifest.psd1's ApprovedExports
# ---------------------------------------------------------------------------
$publicFunctionNames = @()
foreach ($relPath in $declaredFiles) {
    if ($relPath -like 'src/Public/*') {
        $publicFunctionNames += $functionsPerFile[$relPath]
    }
}
$publicFunctionNames = @($publicFunctionNames | Sort-Object)

$declaredButMissing = @($approvedExports | Where-Object { $_ -notin $publicFunctionNames })
if ($declaredButMissing.Count -gt 0) {
    throw "Build failed: BuildManifest.psd1's ApprovedExports lists function(s) not defined anywhere in src/Public/:`n  $($declaredButMissing -join "`n  ")"
}

$unapproved = @($publicFunctionNames | Where-Object { $_ -notin $approvedExports })
if ($unapproved.Count -gt 0) {
    throw "Build failed: src/Public/ defines function(s) not listed in ApprovedExports (unapproved export):`n  $($unapproved -join "`n  ")"
}

Write-Host "[+] Export set matches ApprovedExports exactly ($($approvedExports.Count) function(s))."

# ---------------------------------------------------------------------------
# 4b. ADR-013: every control's evaluatorFunctionName must resolve to a real function declared
#     somewhere in the module's own source order -- a control cannot supply a scriptblock, path,
#     expression, or dynamic module, and this is the build-time enforcement of that rule (the
#     control-definition schema documents this exact check as living here, not at runtime).
#     Plain Import-PowerShellDataFile is deliberately used instead of the module's own
#     schema-validation pipeline -- this script builds the module and cannot depend on the
#     module already being importable to validate itself.
# ---------------------------------------------------------------------------
$controlsRoot = Join-Path $RepoRoot 'controls'
if (Test-Path -LiteralPath $controlsRoot -PathType Container) {
    $controlFiles = @(Get-ChildItem -LiteralPath $controlsRoot -Filter '*.psd1' -File | Sort-Object Name)
    $unresolvedEvaluators = [System.Collections.Generic.List[string]]::new()

    foreach ($controlFile in $controlFiles) {
        $controlData = Import-PowerShellDataFile -Path $controlFile.FullName
        $evaluatorName = $controlData['evaluatorFunctionName']
        if ([string]::IsNullOrWhiteSpace($evaluatorName)) {
            $unresolvedEvaluators.Add("'$($controlFile.Name)' has no evaluatorFunctionName.")
            continue
        }
        if (-not $functionOwner.ContainsKey($evaluatorName)) {
            $unresolvedEvaluators.Add("'$($controlFile.Name)' declares evaluatorFunctionName '$evaluatorName', which does not match any function defined in the declared source order.")
        }
    }

    if ($unresolvedEvaluators.Count -gt 0) {
        throw "Build failed: $($unresolvedEvaluators.Count) control(s) reference an evaluator function that does not statically resolve (ADR-013):`n  $($unresolvedEvaluators -join "`n  ")"
    }

    Write-Host "[+] Every control's evaluatorFunctionName resolves to a real declared function ($($controlFiles.Count) control file(s))."
}

# ---------------------------------------------------------------------------
# 5. Assemble the deterministic .psm1
# ---------------------------------------------------------------------------
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("# THIS FILE IS BUILD-GENERATED. Do not edit directly -- edit files under src/ and re-run build/Build-Module.ps1.`n")
[void]$sb.Append("# Assembled deterministically from build/BuildManifest.psd1's declared source order.`n`n")

foreach ($relPath in $declaredFiles) {
    $fullPath = Join-Path $RepoRoot $relPath
    $content = ConvertTo-Lf (Get-Content -LiteralPath $fullPath -Raw)
    [void]$sb.Append("# ---- source: $relPath ----`n")
    [void]$sb.Append($content.TrimEnd())
    [void]$sb.Append("`n`n")
}

[void]$sb.Append("Export-ModuleMember -Function $($approvedExports -join ', ')`n")

$psm1Content = ConvertTo-Lf $sb.ToString()

# ---------------------------------------------------------------------------
# 6. Assemble the deterministic .psd1 (hand-written -- New-ModuleManifest embeds
#    a non-deterministic timestamp/username header that would break byte-equivalence)
# ---------------------------------------------------------------------------
$moduleName = $meta.Name
$exportListLiteral = "'" + ($approvedExports -join "', '") + "'"

$psd1Content = @"
# THIS FILE IS BUILD-GENERATED. Do not edit directly -- edit build/BuildManifest.psd1 and re-run build/Build-Module.ps1.
@{
    RootModule        = '$moduleName.psm1'
    ModuleVersion     = '$($meta.ModuleVersion)'
    GUID              = '$($meta.Guid)'
    Author            = '$($meta.Author)'
    CompanyName       = '$($meta.CompanyName)'
    Description       = '$($meta.Description)'
    PowerShellVersion = '$($meta.PowerShellVersion)'
    FunctionsToExport = @($exportListLiteral)
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
"@
$psd1Content = ConvertTo-Lf $psd1Content

# ---------------------------------------------------------------------------
# 7. Write output
# ---------------------------------------------------------------------------
if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot 'dist'
}

if ($Clean -and (Test-Path -LiteralPath $OutputPath)) {
    Remove-Item -LiteralPath $OutputPath -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$psm1Path = Join-Path $OutputPath "$moduleName.psm1"
$psd1Path = Join-Path $OutputPath "$moduleName.psd1"
Write-Utf8NoBom -Path $psm1Path -Content $psm1Content
Write-Utf8NoBom -Path $psd1Path -Content $psd1Content

Write-Host "[+] Wrote $psm1Path"
Write-Host "[+] Wrote $psd1Path"

# ---------------------------------------------------------------------------
# 7b. Copy non-source asset directories (schemas/, controls/) alongside the built module.
#     Get-EntraPostureSchemaPath and the control-registry loader both need to resolve these
#     at runtime, and $PSScriptRoot for code running from the single concatenated .psm1 is
#     OutputPath itself -- a fundamentally different relative depth than $PSScriptRoot for the
#     same code dot-sourced from its original src/<Layer>/ location during development. Both of
#     those functions probe a dev-tree-relative candidate AND a build-output-sibling candidate;
#     this copy is what makes the second candidate actually exist once the module is installed
#     or distributed away from its source checkout (confirmed directly: without this copy,
#     Get-EntraPostureSchemaPath resolves to a nonexistent path one level ABOVE the repo root
#     when invoked through an Import-Module'd built module, since dist/'s '../..' lands outside
#     the repo entirely).
#
#     The destination is removed before copying, every time -- confirmed directly (via a real
#     live-tenant run of the built module, not a unit test) that Copy-Item -Recurse nests the
#     *source directory itself* inside an already-existing destination instead of copying its
#     contents into it. Every rebuild after the first therefore left the original build's stale
#     controls/*.psd1 sitting at the path Get-EntraPostureControlDefinitionRoot's built-tree
#     candidate actually resolves (dist/controls, read non-recursively), while silently writing a
#     correct-but-never-read copy one level deeper at dist/controls/controls/*.psd1. Only 2 of 8
#     controls (the two present in the very first build) were ever actually evaluated by the
#     distributed module as a result -- undetected until now because every test in this project
#     dot-sources source files directly, or resolves Get-EntraPostureControlDefinitionRoot's
#     *first* (dev-tree) candidate successfully before ever trying the built-tree one. Removing
#     the destination first makes every rebuild idempotent regardless of prior build state, and
#     also correctly drops any file removed from source (e.g. a renamed/retired control) instead
#     of leaving it behind forever.
# ---------------------------------------------------------------------------
foreach ($assetDir in @('schemas', 'controls')) {
    $sourceDir = Join-Path $RepoRoot $assetDir
    $destDir = Join-Path $OutputPath $assetDir
    if (Test-Path -LiteralPath $sourceDir) {
        if (Test-Path -LiteralPath $destDir) {
            Remove-Item -LiteralPath $destDir -Recurse -Force
        }
        Copy-Item -Path $sourceDir -Destination $destDir -Recurse -Force
        Write-Host "[+] Copied $assetDir/ into build output."
    }
}

# Verify the copy actually landed where runtime resolution reads it from (top-level of
# dest, non-recursive -- the same shape Get-EntraPostureControlDefinitionRoot's built-tree
# candidate and Get-EntraPostureControlRegistry's non-recursive Get-ChildItem use), not just
# that Copy-Item reported success -- the exact gap that let the nesting bug above ship
# undetected across multiple builds.
#
# Compares file content hashes, not just names -- confirmed directly that a names-only check has
# its own blind spot: rebuilding twice without -Clean when the *set* of control files hasn't
# changed (only an existing file's content has) leaves the untouched, stale top-level copy from
# the first build with the exact right file names, so a names-only Compare-Object would pass
# while the built module still reads outdated control definitions. Hashing every file closes that
# gap; the destination-removal fix above is still the actual root-cause fix (this check exists as
# defense in depth, not as a substitute for it).
$builtControlsDir = Join-Path $OutputPath 'controls'
$builtControlFiles = @(Get-ChildItem -LiteralPath $builtControlsDir -Filter '*.psd1' -File -ErrorAction SilentlyContinue | Sort-Object Name)
$sourceControlNames = @($controlFiles.Name | Sort-Object)
$builtControlNames = @($builtControlFiles.Name | Sort-Object)
if (@(Compare-Object -ReferenceObject $sourceControlNames -DifferenceObject $builtControlNames).Count -gt 0) {
    throw "Build-Module.ps1: build output 'controls/' ($($builtControlNames.Count) file(s): $($builtControlNames -join ', ')) does not match source 'controls/' ($($sourceControlNames.Count) file(s): $($sourceControlNames -join ', ')) -- the copy in step 7b did not produce what the built module will actually read at runtime."
}

$hashMismatches = [System.Collections.Generic.List[string]]::new()
foreach ($sourceFile in $controlFiles) {
    $builtFile = $builtControlFiles | Where-Object { $_.Name -eq $sourceFile.Name } | Select-Object -First 1
    $sourceHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash
    $builtHash = (Get-FileHash -LiteralPath $builtFile.FullName -Algorithm SHA256).Hash
    if ($sourceHash -ne $builtHash) {
        $hashMismatches.Add($sourceFile.Name)
    }
}
if ($hashMismatches.Count -gt 0) {
    throw "Build-Module.ps1: build output 'controls/' has stale content for $($hashMismatches.Count) file(s) (name matches source, SHA-256 does not): $($hashMismatches -join ', ') -- the copy in step 7b did not produce what the built module will actually read at runtime."
}

Write-Host "[+] Build output 'controls/' verified to match source exactly, by content hash ($($builtControlNames.Count) file(s))."

# ---------------------------------------------------------------------------
# 8. Optional signing (unsigned status stays visible if this is skipped, per ADR-028)
# ---------------------------------------------------------------------------
$signStatus = 'Unsigned'
if ($SigningCertificateThumbprint) {
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $SigningCertificateThumbprint } |
        Select-Object -First 1

    if (-not $cert) {
        throw "Build failed: no certificate with thumbprint '$SigningCertificateThumbprint' found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
    }

    foreach ($fileToSign in @($psm1Path, $psd1Path)) {
        $result = Set-AuthenticodeSignature -FilePath $fileToSign -Certificate $cert
        if ($result.Status -ne 'Valid') {
            throw "Build failed: signing '$fileToSign' did not produce a valid signature (status: $($result.Status))."
        }
    }
    $signStatus = 'Signed'
    Write-Host "[+] Signed build output with certificate thumbprint $SigningCertificateThumbprint."
} else {
    Write-Host "[i] No -SigningCertificateThumbprint supplied. Build output is Unsigned (visible, not assumed)."
}

# ---------------------------------------------------------------------------
# 9. SHA-256 hash manifest for reproducibility verification
# ---------------------------------------------------------------------------
$outputFiles = @($psm1Path, $psd1Path) | Sort-Object
$hashEntries = foreach ($f in $outputFiles) {
    $h = Get-FileHash -LiteralPath $f -Algorithm SHA256
    [ordered]@{
        RelativePath = [System.IO.Path]::GetFileName($f)
        Sha256       = $h.Hash.ToLowerInvariant()
    }
}

$hashManifest = [ordered]@{
    Module       = $moduleName
    Version      = $meta.ModuleVersion
    SignStatus   = $signStatus
    Files        = $hashEntries
}

$hashManifestPath = Join-Path $OutputPath 'BUILD-HASHES.json'
$hashManifestJson = ($hashManifest | ConvertTo-Json -Depth 5)
Write-Utf8NoBom -Path $hashManifestPath -Content (ConvertTo-Lf $hashManifestJson)

Write-Host "[+] Wrote $hashManifestPath"
foreach ($entry in $hashEntries) {
    Write-Host "    $($entry.RelativePath): $($entry.Sha256)"
}

Write-Host "[+] Build complete. Output: $OutputPath"

return [pscustomobject]@{
    OutputPath  = $OutputPath
    Psm1Path    = $psm1Path
    Psd1Path    = $psd1Path
    SignStatus  = $signStatus
    Hashes      = $hashEntries
}
