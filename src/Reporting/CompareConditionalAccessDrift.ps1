#Requires -Version 7.4

function Get-EntraPostureFieldDifference {
    <#
        .SYNOPSIS
        Recursively diffs two canonical values (ordered dictionaries, arrays, or scalars) into a
        flat list of leaf-level field changes -- the generic primitive behind
        Compare-EntraPostureConditionalAccessDrift's own policy field-diff (VNext build order
        item 10, drift detection).

        .DESCRIPTION
        Ordered dictionaries recurse per key, over the union of both sides' keys (a key present
        on only one side is reported as that leaf changing to/from $null, not skipped). Arrays
        are compared as unordered string sets, not positionally -- Microsoft Graph does not
        document array ordering as stable for condition fields like includeUsers/
        includePlatforms/builtInControls, so a same-membership-different-order array would
        otherwise be misreported as changed. Every other value is compared as a scalar string.

        .PARAMETER OldValue
        .PARAMETER NewValue
        .PARAMETER PathPrefix
        Dotted field path accumulated so far (e.g. 'conditions.users.includeGroups'); starts
        empty at the root call.

        .OUTPUTS
        Array of ordered dictionaries: FieldPath, OldValue, NewValue. Empty if the two values are
        equivalent.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter()]
        [AllowNull()]
        [object]$OldValue,

        [Parameter()]
        [AllowNull()]
        [object]$NewValue,

        [Parameter()]
        [string]$PathPrefix = ''
    )

    $diffs = [System.Collections.Generic.List[object]]::new()

    $oldIsDict = $OldValue -is [System.Collections.Specialized.OrderedDictionary]
    $newIsDict = $NewValue -is [System.Collections.Specialized.OrderedDictionary]
    if ($oldIsDict -or $newIsDict) {
        $oldDict = if ($oldIsDict) { $OldValue } else { [ordered]@{} }
        $newDict = if ($newIsDict) { $NewValue } else { [ordered]@{} }
        $allKeys = @(@($oldDict.Keys) + @($newDict.Keys) | Select-Object -Unique)
        foreach ($k in $allKeys) {
            $childPath = if ($PathPrefix) { "$PathPrefix.$k" } else { [string]$k }
            $ov = if ($oldDict.Contains($k)) { $oldDict[$k] } else { $null }
            $nv = if ($newDict.Contains($k)) { $newDict[$k] } else { $null }
            $childDiffs = Get-EntraPostureFieldDifference -OldValue $ov -NewValue $nv -PathPrefix $childPath
            foreach ($d in $childDiffs) { $diffs.Add($d) }
        }
        return ,@($diffs.ToArray())
    }

    $oldIsArray = $OldValue -is [array]
    $newIsArray = $NewValue -is [array]
    if ($oldIsArray -or $newIsArray) {
        $oldSorted = @(@($OldValue) | ForEach-Object { [string]$_ } | Sort-Object)
        $newSorted = @(@($NewValue) | ForEach-Object { [string]$_ } | Sort-Object)
        $same = $oldSorted.Count -eq $newSorted.Count
        if ($same) {
            for ($i = 0; $i -lt $oldSorted.Count; $i++) {
                if ($oldSorted[$i] -ne $newSorted[$i]) { $same = $false; break }
            }
        }
        if (-not $same) {
            $diffs.Add([ordered]@{ FieldPath = $PathPrefix; OldValue = $oldSorted; NewValue = $newSorted })
        }
        return ,@($diffs.ToArray())
    }

    $oldStr = if ($null -eq $OldValue) { $null } else { [string]$OldValue }
    $newStr = if ($null -eq $NewValue) { $null } else { [string]$NewValue }
    if ($oldStr -ne $newStr) {
        $diffs.Add([ordered]@{ FieldPath = $PathPrefix; OldValue = $OldValue; NewValue = $NewValue })
    }
    return ,@($diffs.ToArray())
}

function Get-EntraPostureConditionalAccessCombinatorialScopeKey {
    <#
        .SYNOPSIS
        Reconstructs the exact Scope string CA-002's own evaluator produces for a given (role,
        generated scenario) pair -- used to diff the SET of scope keys CA-002 would evaluate
        between two snapshots ("expected case changed", VNext build order item 10).

        .DESCRIPTION
        Deliberately duplicated from Test-EntraPostureConditionalAccessCombinatorialCoverageControl's
        own scope-string construction rather than calling into it -- that function returns full
        evaluated Pass/Fail results, not the bare scope-key set this drift comparison needs, and
        evaluators are not meant to be called for their side-effects on formatting alone.

        .PARAMETER RoleEntityId
        .PARAMETER Scenario
        A scenario from Get-EntraPostureConditionalAccessCombinatorialScenario.

        .OUTPUTS
        String.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$RoleEntityId,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Scenario
    )

    $locationLabel = if ($Scenario.IsTrustedLocation) { 'trusted' } else { 'untrusted' }
    return "$RoleEntityId::$($Scenario.Platform)::$($Scenario.ClientAppType)::$locationLabel::$($Scenario.SignInRiskLevel)::$($Scenario.UserRiskLevel)"
}

function Find-EntraPostureRelatedResultTransition {
    <#
        .SYNOPSIS
        Finds every ResultTransition whose EvidenceReferences name a given entity, or whose own
        Scope matches one of a given set of scope keys -- the correlation step behind
        Compare-EntraPostureConditionalAccessDrift's own RelatedResultTransitions field.

        .DESCRIPTION
        A standalone top-level function, not nested inside
        Compare-EntraPostureConditionalAccessDrift -- this project's build sweeps nested
        function definitions in any src/ file regardless of subdirectory, a rule this session
        already caught and fixed twice before (the device-filter parser, item 5) and is applying
        proactively here rather than a third time.

        .PARAMETER ResultTransitions
        The full ResultTransitions array to search.

        .PARAMETER EntityId
        Match a transition whose EvidenceReferences contains this entityId. $null/empty skips
        this half of the match.

        .PARAMETER ScopeKeys
        Match a transition whose own Scope is one of these values. Empty skips this half.

        .OUTPUTS
        Array of ordered dictionaries: ControlId, Scope, OldStatus, NewStatus.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$ResultTransitions,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EntityId,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$ScopeKeys = @()
    )

    $matchingTransitions = @($ResultTransitions | Where-Object {
        $refs = @($_.EvidenceReferences)
        $matchesEvidence = -not [string]::IsNullOrEmpty($EntityId) -and (@($refs | Where-Object { $_.entityId -eq $EntityId }).Count -gt 0)
        $matchesScope = @($ScopeKeys).Count -gt 0 -and ($ScopeKeys -contains [string]$_.Scope)
        $matchesEvidence -or $matchesScope
    } | ForEach-Object {
        [ordered]@{ ControlId = $_.ControlId; Scope = $_.Scope; OldStatus = $_.OldStatus; NewStatus = $_.NewStatus }
    })
    return ,@($matchingTransitions)
}

function Compare-EntraPostureConditionalAccessDrift {
    <#
        .SYNOPSIS
        Diffs Conditional Access policy evidence between two snapshots into a list of drift
        events -- VNext build order item 10 (drift detection, deliberately built last per the
        project owner's own explicit instruction this session).

        .DESCRIPTION
        Implements the review plan's own drift categories (WS4 task 12: "policy added/removed/
        changed, effective coverage changed, expected case changed, object scope changed") and its
        own drift definition ("a snapshot change identifies the fact, affected control/case, and
        old/new result"):
          - PolicyAdded / PolicyRemoved / PolicyModified: a structural diff of ConditionalAccessPolicy
            evidence, correlated by entityId (immutable across snapshots, per this project's
            established comparison principle -- Compare-EntraPostureAssessmentDocument's own
            DESCRIPTION). PolicyModified events carry every changed field (via
            Get-EntraPostureFieldDifference) and an IsScopeChange flag -- true when any changed
            field path starts with 'conditions.users.', called out separately (not a distinct
            top-level category) since the review plan names "object scope changed" as its own
            drift dimension, but this project treats it as a sub-classification of a policy
            change rather than reinventing a parallel category with its own add/remove/modify
            semantics.
          - ExpectedCaseAdded / ExpectedCaseRemoved: CA-002's own policy-induced scenario set
            (Get-EntraPostureConditionalAccessCombinatorialScenario) is regenerated against
            each snapshot's own evidence and diffed as a set of scope keys -- a scenario that's
            newly evaluated (e.g. a policy started referencing a platform value nobody named
            before) or no longer evaluated (e.g. a curated Tier-0 role was deactivated) between
            snapshots, independent of whether any specific verdict changed. CA-001's own scenario
            set is a fixed constant grid (4 platforms x 4 client app types, Global Administrator
            only) and never drifts, so this category is CA-002-specific. If case generation
            throws on either side (its own -MaxScenarios bound exceeded), this half of the
            comparison is skipped, not silently ignored -- reported via ExpectedCaseAnalysisSkipped/
            ExpectedCaseAnalysisSkipReason, the same "never hide sampling/skipped analysis"
            discipline this project applies everywhere else.
          - "Effective coverage changed" is not re-implemented here -- it's exactly what
            Compare-EntraPostureAssessmentDocument's own ResultTransitions already computes for
            CA-001/CA-002 (or any control). This function instead correlates each policy-level
            drift event against the caller-supplied ResultTransitions (matched via each
            transition's own EvidenceReferences, now carried through by
            Compare-EntraPostureAssessmentDocument -- VNext build order item 10's own extension
            to that pre-existing function) so a drift event's RelatedResultTransitions answers the
            review plan's own "affected control/case, and old/new result" requirement directly,
            not just "some CA policy changed, go look."

        .PARAMETER OldEvidenceProvider
        .PARAMETER NewEvidenceProvider
        Handles from New-EntraPostureEvidenceProvider, for the two snapshots being compared.

        .PARAMETER OldSnapshotId
        .PARAMETER NewSnapshotId

        .PARAMETER ResultTransitions
        Optional. The ResultTransitions array from Compare-EntraPostureAssessmentDocument
        (already computed by the caller) -- used purely for correlation via EvidenceReferences,
        not recomputed here. Omitting it still produces every drift event, just without
        RelatedResultTransitions populated.

        .PARAMETER MaxScenarios
        Passed straight through to both sides' Get-EntraPostureConditionalAccessCombinatorialScenario
        call (default 5000, matching that function's own default). Exposed here rather than
        hardcoded so a caller facing a tenant with unusually high policy complexity can raise it
        deliberately, and so this function's own "skip, don't crash" behavior is directly testable.

        .OUTPUTS
        Ordered dictionary: DriftEvents (array, see schemas/drift-event.schema.json),
        ExpectedCaseAnalysisSkipped (bool), ExpectedCaseAnalysisSkipReason (string or $null),
        Summary.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$OldEvidenceProvider,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$NewEvidenceProvider,

        [Parameter(Mandatory)]
        [string]$OldSnapshotId,

        [Parameter(Mandatory)]
        [string]$NewSnapshotId,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$ResultTransitions = @(),

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxScenarios = 5000
    )

    $detectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $driftEvents = [System.Collections.Generic.List[object]]::new()

    # -- Policy-level structural drift --
    $oldPolicies = Get-EntraPostureEntity -Provider $OldEvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $newPolicies = Get-EntraPostureEntity -Provider $NewEvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $oldPoliciesById = @{}
    foreach ($p in $oldPolicies) { $oldPoliciesById[$p.entityId] = $p }
    $newPoliciesById = @{}
    foreach ($p in $newPolicies) { $newPoliciesById[$p.entityId] = $p }
    $allPolicyIds = @(@($oldPoliciesById.Keys) + @($newPoliciesById.Keys) | Select-Object -Unique)

    foreach ($policyId in $allPolicyIds) {
        $hasOld = $oldPoliciesById.ContainsKey($policyId)
        $hasNew = $newPoliciesById.ContainsKey($policyId)

        if ($hasOld -and -not $hasNew) {
            $old = $oldPoliciesById[$policyId]
            $driftEvents.Add([ordered]@{
                driftEventId       = "PolicyRemoved::$policyId"
                category            = 'PolicyRemoved'
                entityType          = 'ConditionalAccessPolicy'
                entityId            = $policyId
                oldSnapshotId       = $OldSnapshotId
                newSnapshotId       = $NewSnapshotId
                detectedAtUtc       = $detectedAtUtc
                isScopeChange       = $null
                fieldChanges        = @()
                affectedControlIds  = @('CA-001', 'CA-002')
                relatedResultTransitions = (Find-EntraPostureRelatedResultTransition -ResultTransitions $ResultTransitions -EntityId $policyId -ScopeKeys @())
                summary             = "Conditional Access policy '$($old.displayName)' ($policyId) was removed."
            })
            continue
        }
        if (-not $hasOld -and $hasNew) {
            $new = $newPoliciesById[$policyId]
            $driftEvents.Add([ordered]@{
                driftEventId       = "PolicyAdded::$policyId"
                category            = 'PolicyAdded'
                entityType          = 'ConditionalAccessPolicy'
                entityId            = $policyId
                oldSnapshotId       = $OldSnapshotId
                newSnapshotId       = $NewSnapshotId
                detectedAtUtc       = $detectedAtUtc
                isScopeChange       = $null
                fieldChanges        = @()
                affectedControlIds  = @('CA-001', 'CA-002')
                relatedResultTransitions = (Find-EntraPostureRelatedResultTransition -ResultTransitions $ResultTransitions -EntityId $policyId -ScopeKeys @())
                summary             = "Conditional Access policy '$($new.displayName)' ($policyId) was added."
            })
            continue
        }

        $old = $oldPoliciesById[$policyId]
        $new = $newPoliciesById[$policyId]
        $fieldChanges = Get-EntraPostureFieldDifference -OldValue $old.properties -NewValue $new.properties
        if (@($fieldChanges).Count -eq 0) { continue }

        $isScopeChange = @($fieldChanges | Where-Object { $_.FieldPath -like 'conditions.users.*' }).Count -gt 0
        $driftEvents.Add([ordered]@{
            driftEventId       = "PolicyModified::$policyId"
            category            = 'PolicyModified'
            entityType          = 'ConditionalAccessPolicy'
            entityId            = $policyId
            oldSnapshotId       = $OldSnapshotId
            newSnapshotId       = $NewSnapshotId
            detectedAtUtc       = $detectedAtUtc
            isScopeChange       = $isScopeChange
            fieldChanges        = @($fieldChanges)
            affectedControlIds  = @('CA-001', 'CA-002')
            relatedResultTransitions = (Find-EntraPostureRelatedResultTransition -ResultTransitions $ResultTransitions -EntityId $policyId -ScopeKeys @())
            summary             = "Conditional Access policy '$($new.displayName)' ($policyId) changed ($(@($fieldChanges).Count) field(s)$(if ($isScopeChange) { ', including its user/group/role scope' }))."
        })
    }

    # -- Expected-case drift (CA-002's own generated scenario set, policy-induced) --
    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')
    # Two-step capture, not a direct pipe off the function call -- Get-EntraPostureEntity
    # already comma-protects its return as a single pipeline object, so piping it straight into
    # Where-Object binds $_ to the WHOLE array on one single invocation rather than enumerating
    # it element by element (confirmed directly: the "roles" produced this way had
    # System.Object[] elements, not DirectoryRole ordered dictionaries, and later failed to bind
    # to a typed parameter). Plain assignment first correctly unwraps it into a real array
    # variable, which -then- pipes into Where-Object safely, per element -- the same distinction
    # every other control evaluator in this project's registry already gets right (e.g. AR-001's
    # own `$definitions = Get-EntraPostureEntity ...` followed by a *separate*
    # `$definitions | Where-Object` line), now understood precisely rather than just imitated.
    $oldRoleEntities = Get-EntraPostureEntity -Provider $OldEvidenceProvider -EntityType 'DirectoryRole'
    $oldRoles = @($oldRoleEntities | Where-Object { $tierZeroRoleNames -contains $_.displayName })
    $newRoleEntities = Get-EntraPostureEntity -Provider $NewEvidenceProvider -EntityType 'DirectoryRole'
    $newRoles = @($newRoleEntities | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    $expectedCaseSkipped = $false
    $expectedCaseSkipReason = $null
    $oldScopeKeys = @()
    $newScopeKeys = @()
    try {
        $oldCases = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies $oldPolicies -RoleEntities $oldRoles -MaxScenarios $MaxScenarios
        $oldScopeKeys = @($oldCases | ForEach-Object { Get-EntraPostureConditionalAccessCombinatorialScopeKey -RoleEntityId $_.RoleEntity.entityId -Scenario $_.Scenario })
        $newCases = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies $newPolicies -RoleEntities $newRoles -MaxScenarios $MaxScenarios
        $newScopeKeys = @($newCases | ForEach-Object { Get-EntraPostureConditionalAccessCombinatorialScopeKey -RoleEntityId $_.RoleEntity.entityId -Scenario $_.Scenario })
    } catch {
        $expectedCaseSkipped = $true
        $expectedCaseSkipReason = "Case generation exceeded its safety bound on at least one side: $($_.Exception.Message)"
    }

    if (-not $expectedCaseSkipped) {
        $addedScopeKeys = @($newScopeKeys | Where-Object { $oldScopeKeys -notcontains $_ })
        $removedScopeKeys = @($oldScopeKeys | Where-Object { $newScopeKeys -notcontains $_ })

        foreach ($key in $addedScopeKeys) {
            $driftEvents.Add([ordered]@{
                driftEventId       = "ExpectedCaseAdded::$key"
                category            = 'ExpectedCaseAdded'
                entityType          = 'CA-002-Scenario'
                entityId            = $key
                oldSnapshotId       = $OldSnapshotId
                newSnapshotId       = $NewSnapshotId
                detectedAtUtc       = $detectedAtUtc
                isScopeChange       = $null
                fieldChanges        = @()
                affectedControlIds  = @('CA-002')
                relatedResultTransitions = (Find-EntraPostureRelatedResultTransition -ResultTransitions $ResultTransitions -EntityId $null -ScopeKeys @($key))
                summary             = "CA-002 now evaluates a scenario it did not evaluate before ('$key')."
            })
        }
        foreach ($key in $removedScopeKeys) {
            $driftEvents.Add([ordered]@{
                driftEventId       = "ExpectedCaseRemoved::$key"
                category            = 'ExpectedCaseRemoved'
                entityType          = 'CA-002-Scenario'
                entityId            = $key
                oldSnapshotId       = $OldSnapshotId
                newSnapshotId       = $NewSnapshotId
                detectedAtUtc       = $detectedAtUtc
                isScopeChange       = $null
                fieldChanges        = @()
                affectedControlIds  = @('CA-002')
                relatedResultTransitions = (Find-EntraPostureRelatedResultTransition -ResultTransitions $ResultTransitions -EntityId $null -ScopeKeys @($key))
                summary             = "CA-002 no longer evaluates a scenario it previously evaluated ('$key')."
            })
        }
    }

    $driftEventsArray = @($driftEvents.ToArray())
    return [ordered]@{
        DriftEvents                 = $driftEventsArray
        ExpectedCaseAnalysisSkipped = $expectedCaseSkipped
        ExpectedCaseAnalysisSkipReason = $expectedCaseSkipReason
        Summary                     = [ordered]@{
            TotalDriftEventCount = $driftEventsArray.Count
            PolicyAddedCount     = @($driftEventsArray | Where-Object { $_.category -eq 'PolicyAdded' }).Count
            PolicyRemovedCount   = @($driftEventsArray | Where-Object { $_.category -eq 'PolicyRemoved' }).Count
            PolicyModifiedCount  = @($driftEventsArray | Where-Object { $_.category -eq 'PolicyModified' }).Count
            ScopeChangeCount     = @($driftEventsArray | Where-Object { $_.isScopeChange -eq $true }).Count
            ExpectedCaseAddedCount   = @($driftEventsArray | Where-Object { $_.category -eq 'ExpectedCaseAdded' }).Count
            ExpectedCaseRemovedCount = @($driftEventsArray | Where-Object { $_.category -eq 'ExpectedCaseRemoved' }).Count
        }
    }
}
