# v.next — deliberately deferred beyond this release

Every item below was deferred with a documented reason at the time, not silently skipped. Full
detail (real bugs, alternatives considered, exact scope boundaries) for each is in this project's
own `00-open-questions.md` working log, organized by the phase that made the decision. This file
is the curated, forward-looking summary; that file is the detailed record of *why*.

## Reviewing external reference repos before building

EntraFalcon, caOptics, CA Insight, and Conditional Access Validator each already solve some slice
of what's listed below. For items where one of them maps closely onto the same problem, reading
its implementation *before* writing this project's own version is worth doing -- not to copy or
port code (every control here stays `Reimplement` in its `.psd1` `provenance.disposition`, the
same clean-room posture used throughout this project so far), but to surface edge cases and bugs
up front instead of finding them the slow way through our own test cycles, and to have a concrete
basis for a "did we do this better or worse" comparison once built (`PRIV-001.psd1`'s provenance
notes already do an informal version of this).

This is a read-for-comparison practice, not a licensing question -- it applies the same way
regardless of which repo's license is more or less permissive, since nothing is being copied or
derived. The two places it earns its keep most:

- **The remaining ~150 feature-parity-matrix rows** -- most (197 of 220) trace back to EntraFalcon;
  its actual per-finding logic is a direct reference for what each row needs to check, subject to
  the same re-verification-against-current-Microsoft-docs discipline every control has gotten so
  far (Phase 1 already found real bugs in EntraFalcon's source -- pagination truncation, stale
  default assumptions -- so "EntraFalcon does X" is a lead to verify, not a citation to trust).
- **The full combinatorial CA gap-analysis engine** -- the single highest-effort item below;
  caOptics' permutation/gap-detection algorithm is the closest existing solution to this exact
  problem, and the project's own review plan already flagged it as warranting "the deepest review."

Any control whose build was informed by this kind of review should say so in its `provenance.notes`
field, same as `PRIV-001` already does -- not a new mechanism, just applying the existing one
deliberately instead of incidentally.

## Suggested build order (least to most effort)

1. **Azure RBAC scope-discovery dedup** -- contained fix, no new evidence domain, no new collector.
2. **A first slice of the remaining ~150 matrix rows** -- rows that need zero new evidence domains
   or collectors, cross-checked against EntraFalcon's equivalent logic per above. **Started
   2026-08-07**: `USR-001` and `GRP-001` done. **Resumed and substantially extended 2026-08-08**
   across four batches (`00-open-questions.md` §35): `CAP-001`-`010` (Conditional Access
   policy-shape checks), `COL-002`, `MAI-002`/`003`, `AGT-013`/`014` (resolved from "blocked"),
   four normalizer field extensions (`ServicePrincipal.appOwnerOrganizationId`, `Application.
   passwordCredentialCount`, `User.onPremisesSyncEnabled`, `AuthorizationPolicy.guestUserRoleId`),
   then `ENT-006`/`007`/`011`/`012`, `APP-001`, `USR-007`/`008`, `COL-001`. 23 new controls total
   this pass (58 now ship, up from 35). `CAP-011` and `USR-013` deliberately excluded/deferred --
   see §35 for why. Several EF-GRP-* rows initially thought buildable turned out to already be
   consolidated into the existing `GRP-005`, not separate findings -- caught before building
   duplicates, also in §35. See `00-open-questions.md` §20 for the original evaluation-pipeline
   bug this slice first surfaced (`AffectedControlIds` is load-bearing for per-control
   evidence-completeness, not just descriptive) -- §35 found three more instances of the same
   bug class. ~125 rows remain (of the original ~150 estimate), a mix of Medium-confidence
   candidates (field capture uncertain) and rows needing genuinely new evidence.
3. ~~**Workload identity / service-principal CA scenarios**~~ -- **done 2026-08-07**, see the
   "Conditional Access subsystem" section below.
4. ~~**Named-location resolution**~~ -- **done 2026-08-07**, see the "Conditional Access
   subsystem" section below.
5. ~~**Device-filter rule-language evaluation**~~ -- **done 2026-08-07**, see the "Conditional
   Access subsystem" section below. Full tokenizer -> recursive-descent parser -> AST evaluator
   pipeline, wired into the simulation engine as a fifth matched policy dimension. The
   `authenticationStrength` method-set resolution half of this item was already done earlier the
   same day (cheaper -- only needed a new collector + ID resolution, not a parser). See
   `16-ca-evaluation-semantics.md`'s device-filter subsection and `00-open-questions.md` item 32.
6. ~~**Bounded collection concurrency**~~ -- **done 2026-08-07**, see the "Collection and
   infrastructure" section below.
7. ~~**`AUTHCTX-001`/`002`**~~ -- **done 2026-08-07**, see the "Native controls not yet built"
   section below (moved out of that list) and `00-open-questions.md` item 7.
8. ~~**`PIM-003` through `PIM-009`**~~ -- **done 2026-08-07**, see the "Native controls not yet
   built" section below. Piggybacked on the `RoleManagementPolicyAssignment` evidence domain item
   7 built, but needed a real extension first -- see `00-open-questions.md` item 8 for why (three
   of the seven controls target a materially different PIM setting than item 7's evidence
   captured, confirmed against Microsoft's own PIM role-settings documentation before writing any
   control, not assumed by analogy).
9. ~~**`AR-002`**~~ -- **done 2026-08-07**, see the "Native controls not yet built" section below.
   New `AccessReviewInstance` evidence domain (`accessReviewInstance`/`accessReviewInstanceDecisionItem`,
   a real two-level N+1: definitions -> instances -> decisions, dispatched through
   `Invoke-EntraPostureBoundedParallel`), plus an `autoApplyDecisionsEnabled` extension to the
   existing `AccessReviewDefinition` evidence. Only the most recent instance per AR-001-covering
   definition is evaluated (historical instances explicitly deferred); decisions are aggregated to
   counts at normalization time and never persisted raw, per the matrix's own redaction
   requirement. See `00-open-questions.md` item 27.
10. ~~**Drift detection**~~ -- **done 2026-08-07**, see the "Conditional Access subsystem" section
    below. Built deliberately last, per explicit instruction, after every other build-order item.
    New `schemas/drift-event.schema.json` + `Compare-EntraPostureConditionalAccessDrift`
    (`src/Reporting/CompareConditionalAccessDrift.ps1`), wired into the public
    `Compare-EntraPosture` command whenever both `-OldSnapshotPath`/`-NewSnapshotPath` are
    supplied. Implements the review plan's own drift categories (policy added/removed/changed,
    object scope changed as a sub-flag of policy-changed, and CA-002's own generated-scenario-set
    drift for "expected case changed") and its own drift definition ("a snapshot change
    identifies the fact, affected control/case, and old/new result") via correlation against
    `ResultTransitions`. See `00-open-questions.md` item 33.

**This completes the full "Suggested build order" list below -- every item (1 through 13, plus
the unnumbered device-filter item) is now done or explicitly resolved to a design-only outcome
(item 13) per the project owner's own choice.**
11. ~~**Entitlement management (`EM-001`/`EM-002`)**~~ -- **done 2026-08-07**, see the "Native
    controls not yet built" section below. Admitted into v1 scope by a deviation record
    (`00-open-questions.md` item 28) before any code was written, per the matrix's own explicit
    gate. New `AccessPackage`/`AccessPackageAssignmentPolicy`/`AccessPackageAssignment` evidence
    domain; "privileged resource role" reuses existing Group/AzureRoleAssignment evidence rather
    than a second definition. See `00-open-questions.md` item 29.
12. ~~**Full combinatorial CA gap-analysis engine**~~ -- **done 2026-08-07**, see the "Conditional
    Access subsystem" section below. New `CA-002` control + a policy-induced equivalence-
    partitioning case generator (`Get-EntraPostureConditionalAccessCombinatorialScenario`),
    reviewed against caOptics'/CA Insight's own published algorithm descriptions (design only, no
    source read) before being designed independently, built entirely on Phase 8's existing
    simulation engine -- no new evidence domain or collector. See `00-open-questions.md` item 30.
13. ~~**Agent identity (`AGT-*`) and PIM-for-Groups**~~ -- **done 2026-08-07**, see the "Native
    controls not yet built" section below. All 9 of the design spec's designable `AGT-*` findings
    (`AGT-001`, `004`, `005`, `008`, `009`, `011`, `012`, `015`, `017`) plus both `PIMG-001`/
    `PIMG-002` are built. New `AgentIdentityBlueprint`/`AgentIdentityBlueprintPrincipal`/
    `AgentIdentity`/`AgentUser` evidence domains, the `OwnerOf` and `PimActive` relationship types
    (both reserved in the schema since Phase 3, first real use here), and a `PimForGroups`
    collector reusing `PimEligible` with a Group target instead of minting a new type. The
    remaining 8 `AGT-*` findings (`002`/`003`/`006`/`007`'s extensive-API-privilege architecture
    fork, `010`/`016`'s inactive-threshold gap, `013`/`014`'s platform-reachability question) stay
    unbuilt for the same unresolved-design reasons the spec itself named, not overlooked. See
    `00-open-questions.md` item 34.

**Not an effort question at all:** live What-If validation (`scripts/Compare-WhatIf.ps1`) is fully
built and tested against a mock server; what's missing is a tenant licensed for Entra ID P1+, not
engineering time.

## Native controls not yet built

- ~~**`AR-002`**~~ (access review health: staleness, unapplied decisions, incomplete response rates)
  -- **done 2026-08-07** (build order item 9). New `AccessReviewInstance` evidence domain
  (status, decision counts, plus an `autoApplyDecisionsEnabled` extension to
  `AccessReviewDefinition`), gated on AR-001 exactly as `AUTHCTX-002` gates on `AUTHCTX-001`.
  Only the most recent instance per covering definition is evaluated; a project-owned 50%
  not-reviewed threshold and evaluation-time (not collection-time) overdue determination are both
  explicitly documented judgment calls, not Microsoft directives. See `00-open-questions.md`
  item 27.
- ~~**`AUTHCTX-001`/`AUTHCTX-002`**~~ (authentication context functional coverage -- is a
  configured context actually enforced by a live, enabled Conditional Access policy) -- **done
  2026-08-07** (build order item 7). New `RoleManagementPolicyAssignment` evidence domain
  (`RoleManagementPolicy.Read.Directory` -- a genuinely new permission, Global Reader confirmed
  sufficient, no coverage gap) resolves each directory role's PIM activation-policy rules
  (`GET /policies/roleManagementPolicyAssignments`, `$expand=policy($expand=rules)`, one call, no
  N+1). `AUTHCTX-001` checks whether a published, PIM-required authentication context is
  referenced by any Conditional Access policy at all; `AUTHCTX-002` checks whether at least one
  referencing policy is actually enabled and covers the role's full eligible/active assignee
  population (direct user exclusion and group-membership exclusion via already-collected
  `TransitiveMemberOf` evidence; role-based exclusion is a documented, deliberate v1 boundary, not
  implemented -- see `AUTHCTX-002.psd1`'s own provenance notes). See `00-open-questions.md` item 7
  for the full citation trail and a real correction this pass made to the original VNext.md
  framing (the "two listed dependencies" language conflated this item's actual dependency with
  `PIM-003`-`009`'s).
- ~~**`PIM-003` through `PIM-009`**~~ (PIM activation-setting checks: duration, justification,
  MFA on activation, notifications, authentication context/approval requirements) -- **done
  2026-08-07** (build order item 8). Item 7's framing turned out to be half right: `PIM-003`
  (activation duration), `PIM-004` (activation justification), and `PIM-009` (authentication
  context/approval) genuinely needed nothing new. `PIM-005` (permanent active assignments),
  `PIM-006` (justification on direct assignment), and `PIM-007` (MFA on direct assignment) target
  a *different* PIM setting -- an admin creating a direct/permanent active assignment, not an
  eligible user self-activating -- confirmed directly against Microsoft's own PIM role-settings
  admin-UI documentation before writing any control, which meant extending
  `NormalizeRoleManagementPolicyAssignment.ps1` to also capture the Admin/Assignment-level
  Expiration/Enablement rules (same already-fetched API response, no new call). `PIM-008`
  (notifications) is the one control in this family whose threshold is this project's own
  judgment call rather than a Microsoft directive, stated as such in its own provenance notes
  rather than given the same citation strength as the other six. See `00-open-questions.md` item
  8 for the full writeup.
- ~~**Entitlement management (`EM-001`/`EM-002`)**~~ -- **done 2026-08-07** (build order item
  11). Was marked "Deferred to v.next" in the matrix that designed it
  (`15-feature-parity-matrix.md` §8); admitted into v1 scope by an explicit deviation record
  (`00-open-questions.md` item 28), following the engineering plan §3's own template
  (reason/approver/impact/migration/tests/rollback), before any `EM-001`/`EM-002` code was
  written. See `00-open-questions.md` item 29 for the build itself.
- ~~**Agent identity (`AGT-*`) and PIM-for-Groups**~~ -- **done 2026-08-07** (build order item
  13). 9 of the design spec's 17 `AGT-*` findings (the ones the spec itself marked designable)
  plus both `PIMG-001`/`PIMG-002` are built. See `00-open-questions.md` item 34 for the build
  itself, including a real correction of the design spec's own speculation: `agentIdentity
  .agentIdentityBlueprintId` turned out to hold the blueprint's `appId`, not either object's own
  `id` (confirmed live against the `agentIdentity` resource page before writing the correlation
  logic), and PIMG-002 reads a flat `endDateTime` field directly rather than the nested
  `scheduleInfo.expiration.type` the spec guessed at before that endpoint was actually checked.
  The remaining 8 findings stay unbuilt for the same reasons `15-feature-parity-matrix.md` §11's
  own "Not yet designable" section already named.
- **The remaining rows** of the 220-row feature-parity matrix beyond what was actually built
  (`15-feature-parity-matrix.md` catalogs every one, with disposition) -- each would need the
  same schema-valid definition + tested evaluator + honest evidence-availability check every
  built control got, not a bulk mechanical port. `USR-001`/`GRP-001` done 2026-08-07 (build order
  item 2, two more than the ~150 estimate this bullet originally cited).

## Conditional Access subsystem

- ~~**Full combinatorial gap-analysis**~~ (caOptics/CA-Insight-style bulk permutation across every
  condition dimension) -- **done 2026-08-07** (build order item 12). `CA-002` generalizes
  `CA-001`'s fixed 16-scenario grid two ways: every curated Tier-0 role (not just Global
  Administrator), and a scenario set generated deterministically from this tenant's own collected
  policies (platform, clientAppType, location-trust, signInRiskLevel, userRiskLevel) via
  policy-induced equivalence partitioning, bounded by an explicit, honestly-thrown
  `-MaxScenarios` rather than silent sampling. Also closes a "strong control" definition gap
  `CA-001` itself still has (literal `mfa` builtInControls only, missing the
  authenticationStrength-satisfies-MFA path) -- flagged, not retroactively fixed in `CA-001`. See
  `00-open-questions.md` item 30.
- ~~**Drift detection**~~ (policy added/removed/changed, effective coverage changed, expected
  case changed, object scope changed) -- **done 2026-08-07** (build order item 10, built last per
  explicit instruction). New `schemas/drift-event.schema.json`; `Get-EntraPostureFieldDifference`
  (a generic recursive dict/array/scalar diff, arrays compared as unordered sets since Graph
  doesn't document condition-array ordering as stable) drives policy-level `PolicyAdded`/
  `PolicyRemoved`/`PolicyModified` events (with an `isScopeChange` flag for `conditions.users.*`
  changes -- "object scope changed" is this flag, not a separate top-level category);
  `Get-EntraPostureConditionalAccessCombinatorialScenario`'s own scenario set is regenerated
  against each snapshot and diffed for `ExpectedCaseAdded`/`ExpectedCaseRemoved` (CA-002-specific
  -- CA-001's fixed grid never drifts). "Effective coverage changed" is answered by correlating
  each drift event against the pre-existing `ResultTransitions` via `EvidenceReferences`/`Scope`,
  not reimplemented. Wired into the public `Compare-EntraPosture` command whenever both
  snapshot paths are supplied. See `00-open-questions.md` item 33.
- ~~**Named-location resolution**~~ -- **done 2026-08-07** (build order item 4). New
  `namedLocations` collector (`Policy.Read.All`, already a granted scope) plus
  `Resolve-EntraPostureNamedLocationId` (`src/ConditionalAccess/ResolveNamedLocation.ps1`)
  resolves a raw IP/country against collected `NamedLocation` evidence into matching location
  ID(s) and a trusted flag; `LocationId` is now an array on both scenario constructors (a real IP
  can fall inside multiple overlapping ranges at once), and `'AllTrusted'` resolves against the
  scenario's real trust status instead of requiring a literal string match. See
  `16-ca-evaluation-semantics.md`'s new "Named-location resolution" subsection for the full
  citation trail.
- ~~**Workload identity / service-principal sign-in scenarios**~~ -- **done 2026-08-07** (build
  order item 3). `New-EntraPostureConditionalAccessWorkloadIdentityScenario` +
  `Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch` model service-principal
  sign-ins against `conditions.clientApplications`/`servicePrincipalRiskLevels`/locations, per
  Microsoft's own workload-identity CA documentation (re-fetched 2026-08-07) -- a deliberately
  narrower condition surface than user scenarios (no platform/client-app-type/device-compliance/
  user-risk, since Microsoft's own policy-authoring UI doesn't expose those for this assignment
  mode). See `16-ca-evaluation-semantics.md`'s new "Workload identity" subsection under §8 for
  the full per-dimension citation trail.
- ~~**Device-filter rule-language evaluation**~~ -- **done 2026-08-07** (build order item 5's
  remaining half, re-scoped out of the same day's `authenticationStrength` work and then built).
  New `src/ConditionalAccess/DeviceFilterTokenizer.ps1`/`DeviceFilterParser.ps1`/
  `DeviceFilterEvaluator.ps1`/`EvaluateDeviceFilterCondition.ps1`, wired into
  `Test-EntraPostureConditionalAccessPolicyMatch` as a fifth matched dimension. See
  `16-ca-evaluation-semantics.md`'s device-filter subsection under §8 and `00-open-questions.md`
  item 32 for the full citation trail, including the derived per-property nullability model
  verified against every row of Microsoft's own documented applicability table.
- ~~**`authenticationStrength` method-set resolution**~~ -- **done 2026-08-07** (build order item
  5). New `AuthenticationStrengthPolicies` collector (`Policy.Read.AuthenticationMethod` -- a
  genuinely new permission scope, not a reused one, and a second documented Global Reader coverage
  gap alongside Access Reviews) plus `Resolve-EntraPostureAuthenticationStrengthRequirement`
  resolves a matched policy's `AuthenticationStrengthId` into its real `allowedCombinations` and
  whether it satisfies MFA (`requirementsSatisfied`). See `16-ca-evaluation-semantics.md`'s new
  subsection for the full citation trail.
- **Live What-If validation was attempted but blocked by tenant licensing** in this project's own
  test tenant (no Entra ID P1) -- the harness itself is built and tested against a mock server;
  actually validating `16-ca-evaluation-semantics.md`'s cited semantics against Microsoft's real
  API needs a P1-or-higher-licensed tenant.

## Collection and infrastructure

- ~~**Bounded collection concurrency**~~ (engineering plan's own "default four" target) -- **done
  2026-08-07** (build order item 6). `Invoke-EntraPostureBoundedParallel`
  (`src/Orchestration/BoundedParallelExecution.ps1`) runs work via a bounded
  `RunspacePool` (throttle 4), returning results in input order regardless of completion order --
  the engineering plan's own "deterministic... independently of collection concurrency"
  requirement is enforced by construction (the caller merges sequentially over an already-ordered
  result array, never over a thread-shared mutable collection). Applied at two levels: the ~16
  independent Graph collectors in `CollectAndSeal.ps1` (via the extracted
  `Invoke-EntraPostureGraphCollectorDispatch`), and Groups' own real N+1 fetch pattern
  (`Invoke-EntraPostureGroupTransitiveMemberFetch`, one call per group). ARM per-scope
  role-assignment/role-definition collection stays sequential -- out of scope for this item, not
  an oversight. See `00-open-questions.md` item 6 for the actual mechanism (PowerShell's
  `-Parallel`/runspace primitives don't share function definitions with the calling scope at all,
  confirmed directly, which shaped the design) and the verification approach (tests proving real
  time-overlap and bounded throttling, not just "the numbers came out right").
- ~~**Azure RBAC scope discovery has no structural-overlap deduplication**~~ -- **done
  2026-08-07** (build-order item 1). The exact-string scope dedup this item originally described
  is still true (a subscription's scope string is never equal to an ancestor management group's,
  so both still get queried), and true structural dedup -- skipping a covered descendant scope
  entirely -- still isn't built, since that needs a management-group/subscription hierarchy this
  project doesn't collect. What *was* fixed: the resulting duplicate-entity symptom (the same
  role assignment, defined at a management group, coming back once as a direct record and once as
  an inherited copy with an identical `entityId`) is now deduplicated after collection in
  `Invoke-EntraPostureCollectAndSeal`. See `00-open-questions.md` §19 for why the fuller
  hierarchy-walking fix was scoped out as materially more work than this item's original sizing.
- **PIM for Groups collector** -- permission scope
  (`PrivilegedAssignmentSchedule.Read.AzureADGroup`) was confirmed early; the collector itself
  was never built, pending the same BETA-status triage as agent identities.
- **Comparison's "What If changes" category** -- `Compare-EntraPosture` classifies five of the
  engineering plan's six named comparison categories; no persisted historical What-If comparison
  data model exists yet for a sixth category to diff against.

## Judgment calls flagged for future verification, not open bugs

- `PRIV-001`'s 2-4 Global Administrator range, `GRP-005`'s 5-member transitive-membership
  threshold, and `PIM-002`'s curated Tier-0 role set are each documented as reasoned heuristics
  in their own `.psd1` `provenance` notes, not pinned Microsoft citations -- worth validating
  against real tenant data or a specific Microsoft guidance citation before being treated as
  final.
- Several controls' Microsoft Learn reference URLs (recorded in each `.psd1`'s `references`
  field) were not independently re-fetched/re-verified as still-live during the session that
  authored them -- a standing, tracked follow-up, not a per-control repeat of the same note here.
