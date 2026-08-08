# Third-party notices

**This project has zero third-party runtime dependencies.** Confirmed directly: no `#Requires
-Modules` declaration and no `Import-Module` call for any external module anywhere under `src/`
or `build/` (the only match for either search string project-wide is a docstring sentence that
mentions the phrase "Import-Module'd" in prose, not an actual import statement).

## Runtime

- **PowerShell 7.4 or later** and the .NET runtime it ships with (the base class library --
  `System.Net.Http`, `System.Security.Cryptography`, `System.Text.Json`-adjacent APIs via
  `Utf8JsonWriter`, etc.) are the only things this module depends on to run. Neither is vendored
  or redistributed by this project; you provide your own PowerShell 7.4+ installation.
- No PowerShell Gallery package, no NuGet package, no vendored third-party script or binary is
  included in, or downloaded by, the built module (`dist/EntraPosture.psm1`) at any point,
  including at runtime -- this project's own design explicitly excludes "no runtime-downloaded
  code" as a security property, not merely a current state.

## Development and test tooling (not shipped, not a runtime dependency)

These are used only to build and test this repository -- they are never present in, referenced
by, or required by the built `dist/` module itself:

- **Pester** -- the test framework this project's entire test suite is written against.
- **PSScriptAnalyzer** -- the static-analysis/lint gate this project's own CI-equivalent checks
  run against (`PSScriptAnalyzerSettings.psd1`).

Neither is a licensing or attribution concern for anyone *using* the built module -- they never
ship with it.

## Reference implementations consulted during design (not reused code)

Per this project's own clean-room policy (every control's `.psd1` `provenance.disposition` field
records this explicitly, control by control), several open-source community tools were read for
architectural and domain-knowledge reference during design -- Conditional Access Validator,
EntraFalcon, caOptics, CA Insight, and others named throughout this project's engineering
planning documents -- but no source code from any of them is included in, or was copied into,
this project. Where a control's logic was informed by reviewing one of these tools' documented
behavior, that is recorded in the control's own `provenance` field as `Reimplement`, with notes
explaining what was and wasn't taken from the original. None are runtime or build dependencies.
