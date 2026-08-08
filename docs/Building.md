# Building and testing

## Build

```powershell
./build/Build-Module.ps1 -Clean
```

Produces `dist/EntraPosture.psm1`, `dist/EntraPosture.psd1`, and `dist/BUILD-HASHES.json`. The
build fails hard (non-zero exit via `throw`) on:

- a file under `src/` not declared in `build/BuildManifest.psd1`'s `SourceFiles`
- a declared source file missing from disk
- two files defining a function with the same name
- a function in `src/Public/` not listed in `ApprovedExports`, or an `ApprovedExports` entry with
  no matching function

To sign the output, pass `-SigningCertificateThumbprint <thumbprint>` with a certificate available
under `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`. Without it, the build is explicitly
`Unsigned` (recorded in `BUILD-HASHES.json`, not silently assumed either way).

## Test

```powershell
Invoke-Pester -Path ./tests -Output Detailed
```

`tests/Security/DelegatedAuthNetwork.Tests.ps1` is tagged `Network`: it makes real outbound
HTTPS calls to Microsoft's production token endpoint (with intentionally invalid credentials, to
exercise real AADSTS error parsing end-to-end -- see the file header for why this is deliberate,
not a mistake). In an offline environment, exclude it:

```powershell
Invoke-Pester -Path ./tests -ExcludeTag Network
```

## Lint

```powershell
Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

## Adding a new source file

1. Create the file under the appropriate `src/<Layer>/` folder.
2. Add its path to `build/BuildManifest.psd1`'s `SourceFiles`, in the position that respects
   load-order dependencies (a file that calls a function must be listed after the file that
   defines it — PowerShell resolves calls at invocation time, not parse time, but explicit order
   is still required per engineering plan section 6.1's build discipline).
3. If it's a new public command, add its function name to `ApprovedExports` too.
4. Run the build — it will fail loudly if any of the above was missed.

## CI

Not yet wired to a specific platform (deferred 2026-08-06 pending the org's actual internal CI
tooling — see the Phase 2 decision record). `build/Build-Module.ps1`, `Invoke-Pester`, and
`Invoke-ScriptAnalyzer` above are self-contained and can be called from any CI platform's script
step without modification once one is chosen.
