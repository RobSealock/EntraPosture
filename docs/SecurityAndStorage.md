# Security and storage guidance

## Credential handling

- **No client secret support exists anywhere in this codebase, by design.** Only two auth modes:
  certificate app-only (client-credentials with a JWT client assertion, non-exportable private
  key recommended) and delegated interactive (authorization-code + PKCE via your system browser,
  never an embedded webview). If you're looking for where to configure a client secret, there
  isn't one -- this is deliberate, not missing.
- **Access tokens are never written to disk.** The token cache (`src/Authentication/TokenCache.ps1`)
  is an in-process-memory-only structure with no code path capable of persisting a token at all --
  not persistence disabled by a setting, but no writer to disable. Tokens are gone when the
  PowerShell session ends.
- **Certificates are supplied by the caller as an already-loaded `X509Certificate2` object.** This
  tool never reads a `.pfx`/private key file itself, never prompts for or handles a certificate
  password, and never writes certificate material anywhere. How you load and protect your
  certificate (OS certificate store, encrypted file, HSM) is entirely up to you.
- **Diagnostic text is filtered before it can reach a log, error, or thrown exception.**
  `Test-EntraPostureSafeDiagnosticText` rejects any string matching a bearer-token, `Bearer `
  header, or token-bearing-query-string shape at the single point every diagnostic message in this
  project passes through -- confirmed with dedicated tests, including one that deliberately tried
  to leak a token-shaped string through an HTTP error path and confirmed it was blocked.
- **Audit records name the matched allowlist template, never the literal request path or
  Authorization header** -- confirmed directly: a request carrying a real (test) bearer token
  produces an audit record that does not contain it, even in the raw log file.

## Network behavior

- **Every outbound request is checked against a fixed, explicit allowlist** (`src/Transport/EndpointAllowlist.ps1`)
  before it's sent -- host, path template, HTTP method, and (for POST) an explicit
  read-only classification. A request to anything not on this list is refused before any network
  call happens, confirmed by tests asserting zero requests reach the mock server for a
  non-allowlisted path.
- **No telemetry, no phone-home version checks, no runtime-downloaded code, no automatic
  updates.** Every network call this tool makes is either a Microsoft Graph/ARM API call you
  explicitly triggered, or the OAuth token endpoint during authentication. Nothing else.
- **Retries use bounded exponential backoff with full jitter**, honoring a server's `Retry-After`
  header exactly when present -- confirmed against real 429 responses in a mock server, with a
  loop-detection backstop against a paginating API that returns a repeating `@odata.nextLink`.

## What gets written to disk, and where

Running `Invoke-EntraPosture -RunRoot <path>` creates, under `<path>`:

- `staging-<snapshotId>/` -- the sealed **snapshot** bundle: raw-normalized evidence (JSONL),
  `manifest.json`, `coverage.json`, `integrity.json`, and (if you passed `-SigningCertificate`) a
  detached PKCS#7 signature. This is real tenant configuration data -- role assignments, group
  membership, Conditional Access policies, users, applications, and everything else the granted
  permissions allowed collecting. Treat it with the same sensitivity as the tenant's own admin
  center.
- `assessment-<evaluationId>/` -- the sealed **assessment** bundle: `results.jsonl` (control
  outcomes), `deviations.jsonl`, its own `manifest.json`/`integrity.json`, and a `reports/`
  subdirectory containing `assessment.json`, `report.html`, `findings.csv`, and `summary.txt` once
  rendered.

**This tool has no retention or auto-cleanup logic at all.** Every run's bundles persist under
`-RunRoot` until you delete them yourself. If you run this repeatedly (e.g. on a schedule), plan
your own retention policy -- old snapshots/assessments are not an oversight to report, they're
data you asked to be kept.

## Redaction modes

`New-EntraPostureReport -RedactionMode <None|Identifiers|Strict>` controls what identity
information survives into the *rendered report* (`assessment.json`/`report.html`/`findings.csv`).
The underlying sealed snapshot/assessment bundles are never redacted in place -- redaction is a
render-time transform, confirmed by dedicated tests asserting `None` keeps real identifiers and
`Identifiers` pseudonymizes `scope`/`entityId` in the rendered output while the source bundle is
untouched either way. Choose `Identifiers` or `Strict` before sharing a report outside the people
who already have access to the tenant itself.

## Integrity and trust

- **Every sealed bundle (snapshot and assessment) carries a recomputed, not just recorded, hash
  check.** `Test-EntraPostureBundle` always recomputes the aggregate hash from the files
  actually on disk and compares it against what was recorded at sealing time -- a tampered file
  is detected even if the attacker also rewrote `integrity.json` to match, because a stale
  signature (if signing was used) won't validate against the forged payload. Confirmed with a
  test that does exactly this: tamper a result, rewrite the integrity record to match, and
  confirm detection still fires.
- **`Partial` status is a distinct, always-visible field, never inferred or hidden.** A snapshot
  that couldn't collect everything it was asked to is sealed as `status: Partial` with a specific
  `partialReason` naming exactly which collector(s) failed and why (including the underlying
  Graph/ARM error detail as of Phase 9's transport fix, not just a bare HTTP status code) --
  this is the concrete mechanism behind this project's core exit criterion: **reports cannot
  confuse lack of evidence with lack of findings.** A control that couldn't be evaluated shows
  `NotEvaluated`, never a silently-omitted row, and never a false `Pass`.
- **Unsigned status stays visible, never silently assumed signed.** If you don't pass
  `-SigningCertificate`, the bundle is sealed as explicitly `Unsigned` -- hash verification still
  works (tamper-evident), but there's no cryptographic attestation of *who* produced it without a
  signature.

## Offline safety

`report.html` is fully self-contained: no external stylesheet, font, script, or image reference of
any kind, confirmed by a dedicated test asserting no `<link>`, no external `src=`/`href=` pointing
at `http(s)://`. It's safe to open on a machine with no network access at all. Every
tenant-controlled string rendered into it (display names, rationale text, scope identifiers) is
HTML-encoded before being written into the markup -- confirmed with real injection-attempt
payloads (script tags, event-handler-attribute breakouts) run through the actual renderer, not
just reviewed by inspection. `findings.csv` similarly neutralizes formula-injection payloads
(`=`, `+`, `-`, `@`-prefixed fields) before a spreadsheet application could interpret them as
formulas.
