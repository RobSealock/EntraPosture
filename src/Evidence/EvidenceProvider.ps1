#Requires -Version 7.4

function New-EntraPostureEvidenceProvider {
    <#
        .SYNOPSIS
        Creates a read-only handle evaluators use to read entities/relationships from a sealed
        snapshot, by type.

        .DESCRIPTION
        Engineering plan section 12: "Give evaluators a read-only evidence-provider interface
        rather than raw paths or whole arrays." Phase 6 widens Phase 5's naive per-type
        full-file-load version with real indexing (Get-EntraPostureEvidenceIndex) and
        deterministic ordering -- nothing about this function's own shape changed for
        evaluators when that happened, only the internal implementation, exactly as Phase 5's
        version predicted it would.

        Deliberately takes an already-validated -SnapshotPath, not a raw path this function
        would validate itself -- the caller (Invoke-EntraPostureEvaluation) must have already
        called Get-EntraPostureTrustedSnapshot on it first (Phase 3's exit criterion:
        "invalid/unsealed data cannot reach evaluators"). This function has no code path that
        performs that trust check itself, on purpose, so there is exactly one place in the
        codebase responsible for it.

        .PARAMETER SnapshotPath
        Root directory of an already-trust-verified sealed snapshot bundle.

        .OUTPUTS
        Ordered dictionary handle: SnapshotPath, Cache (internal, runtime-only).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Allocates an in-process-memory-only handle with no disk/network/system side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$SnapshotPath
    )

    return [ordered]@{
        SnapshotPath = $SnapshotPath
        # Plain Hashtable is deliberate here, same rationale as TokenCache.ps1's Store: a
        # runtime-only read cache, never serialized/hashed/compared, so it does not need to go
        # through this project's canonical-ordered-dictionary discipline. Each value is itself a
        # small Hashtable: { Records; ByTargetEntityId; BySourceEntityId } -- see
        # Get-EntraPostureEvidenceIndex.
        Cache        = @{}
    }
}

function Get-EntraPostureEvidenceIndex {
    <#
        .SYNOPSIS
        Internal: loads, deterministically orders, and indexes every record of one registered
        type from a snapshot's evidence directory, on first access; returns the cached
        index thereafter.

        .DESCRIPTION
        Not exported. Section 12: "indexes" and "deterministic streaming behavior" -- this is
        both. Records are sorted once, at load time, by their own stable ID field (entityId for
        entities, relationshipId for relationships) using ordinal string comparison via
        [System.StringComparer]::Ordinal -- never Sort-Object's default culture-sensitive
        comparison, and never Sort-Object '-CultureInvariant' either, which Phase 3 already
        established does not exist as a real parameter (see
        src/Integrity/AggregateHash.ps1's file-sorting logic, which established the
        [Array]::Sort-with-an-explicit-ordinal-comparer pattern this function reuses). This
        means every read of the same snapshot, regardless of the order records were originally
        collected or written in, returns them in one fixed order -- collection concurrency
        (bounded, real, deliberately deferred work per 00-open-questions.md's Phase 6 section)
        can therefore be introduced later without changing evaluation output ordering at all.

        Relationships are additionally indexed by targetEntityId and sourceEntityId at the same
        load pass, turning Get-EntraPostureRelationship's filtered lookups from an O(n) scan
        over every relationship of a type into an O(1) dictionary access -- the exact
        "evidence-provider indexes" section 12 names, and the concrete fix for what would
        otherwise be a linear rescan per role/object in a large-tenant evaluation. Per section
        12's "build only indexes required by enabled controls," these indexes are built lazily,
        the same way the underlying record load always has been -- a type nothing ever queries
        is never read from disk or indexed at all.

        .PARAMETER Provider
        .PARAMETER TypeName
        entityType or relationshipType value, must be registered in
        Get-EntraPostureEvidenceFileRegistry.

        .OUTPUTS
        Hashtable: Records (array), ByTargetEntityId (Hashtable of arrays), BySourceEntityId
        (Hashtable of arrays). The latter two are empty Hashtables (not errors) for a type whose
        records have no such fields (entities).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Provider,

        [Parameter(Mandatory)]
        [string]$TypeName
    )

    # A single Hashtable is a scalar-shaped return value, not an array -- no leading-comma
    # protection needed here (see Get-EntraPostureEntity's own comment for why that
    # protection is specifically for arrays flowing across a return boundary, not every return
    # value in this file).
    if ($Provider.Cache.ContainsKey($TypeName)) {
        return $Provider.Cache[$TypeName]
    }

    # Assigned to a variable before piping, deliberately -- Get-EntraPostureEvidenceFileRegistry
    # returns its array via the leading-comma pattern (`,@(...)`, see that function's own
    # comment), and piping a comma-protected return value *directly* into Where-Object delivers
    # the whole array as a single $_ rather than iterating its elements (confirmed directly: the
    # filter silently matched everything, because '$wholeArray.TypeName -eq $TypeName' triggers
    # PowerShell's array member-enumeration plus array-vs-scalar -eq semantics, which returns a
    # truthy non-empty array for any partial match instead of a per-element boolean). Piping an
    # already-materialized *variable* holding that same array does enumerate correctly -- only
    # piping directly from the command invocation is affected.
    $registry = Get-EntraPostureEvidenceFileRegistry
    $registryEntry = $registry | Where-Object { $_.TypeName -eq $TypeName } | Select-Object -First 1
    if (-not $registryEntry) {
        throw "Get-EntraPostureEvidenceIndex: '$TypeName' is not a registered evidence type (see Get-EntraPostureEvidenceFileRegistry) -- this is a caller programming error, not a missing-evidence condition."
    }

    $fullPath = Join-Path $Provider.SnapshotPath $registryEntry.RelativePath
    $records = @()

    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        $lines = @(Get-Content -LiteralPath $fullPath | Where-Object { $_.Trim().Length -gt 0 })
        $records = @(foreach ($line in $lines) { ConvertFrom-EntraPostureJson -Json $line })
    }

    if ($records.Count -gt 1) {
        $sortKey = if ($records[0].Contains('entityId')) { 'entityId' } elseif ($records[0].Contains('relationshipId')) { 'relationshipId' } else { $null }
        if ($sortKey) {
            $sortKeys = [string[]]@($records | ForEach-Object { [string]$_[$sortKey] })
            $sortedRecords = [object[]]$records
            # Explicit [Array]/[IComparer] casts are required, not decorative -- confirmed
            # directly that without them, PowerShell's method-overload resolution silently binds
            # this call to Array.Sort's *generic* <TKey,TValue> overload instead of the intended
            # non-generic Sort(Array, Array, IComparer) one (both are 3-argument overloads with
            # array-shaped first two parameters), and the generic overload sorted $sortKeys
            # correctly while leaving $sortedRecords completely unreordered -- a real,
            # non-obvious PowerShell/.NET overload-binding gotcha, not a hypothetical concern.
            [System.Array]::Sort([Array]$sortKeys, [Array]$sortedRecords, [System.Collections.IComparer][System.StringComparer]::Ordinal)
            $records = $sortedRecords
        }
    }

    $byTargetEntityId = @{}
    $bySourceEntityId = @{}
    foreach ($record in $records) {
        if ($record.Contains('targetEntityId')) {
            $key = [string]$record['targetEntityId']
            if (-not $byTargetEntityId.ContainsKey($key)) { $byTargetEntityId[$key] = [System.Collections.Generic.List[object]]::new() }
            $byTargetEntityId[$key].Add($record)
        }
        if ($record.Contains('sourceEntityId')) {
            $key = [string]$record['sourceEntityId']
            if (-not $bySourceEntityId.ContainsKey($key)) { $bySourceEntityId[$key] = [System.Collections.Generic.List[object]]::new() }
            $bySourceEntityId[$key].Add($record)
        }
    }

    $indexEntry = @{
        Records          = $records
        ByTargetEntityId = $byTargetEntityId
        BySourceEntityId = $bySourceEntityId
    }
    $Provider.Cache[$TypeName] = $indexEntry
    return $indexEntry
}

function Get-EntraPostureEntity {
    <#
        .SYNOPSIS
        Returns every collected entity of one type from a snapshot, via an evidence provider,
        in deterministic entityId order.

        .PARAMETER Provider
        A handle from New-EntraPostureEvidenceProvider.

        .PARAMETER EntityType
        .OUTPUTS
        Array of ordered dictionaries matching entity.schema.json (possibly empty).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Provider,

        [Parameter(Mandatory)]
        [string]$EntityType
    )

    $index = Get-EntraPostureEvidenceIndex -Provider $Provider -TypeName $EntityType
    return ,@($index.Records)
}

function Get-EntraPostureRelationship {
    <#
        .SYNOPSIS
        Returns collected relationships of one type from a snapshot, optionally filtered by
        source/target entity ID, via an evidence provider, in deterministic relationshipId
        order.

        .DESCRIPTION
        -TargetEntityId and -SourceEntityId are answered from Get-EntraPostureEvidenceIndex's
        pre-built per-type indexes (O(1) dictionary access) rather than scanning every
        relationship of the type on every call -- the concrete performance difference this
        matters for is a large-tenant evaluation asking "who holds this specific role" once per
        role rather than paying an O(n) scan each time.

        .PARAMETER Provider
        A handle from New-EntraPostureEvidenceProvider.

        .PARAMETER RelationshipType
        .PARAMETER TargetEntityId
        Optional filter -- most evaluators want "relationships pointing at this specific
        object" (e.g. a specific role), not the full unfiltered set.

        .PARAMETER SourceEntityId
        Optional filter.

        .OUTPUTS
        Array of ordered dictionaries matching relationship.schema.json (possibly empty).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Provider,

        [Parameter(Mandatory)]
        [string]$RelationshipType,

        [Parameter()]
        [string]$TargetEntityId,

        [Parameter()]
        [string]$SourceEntityId
    )

    $index = Get-EntraPostureEvidenceIndex -Provider $Provider -TypeName $RelationshipType

    # @() around the whole (nested) if/else -- see CollectAndSeal.ps1's $armGrantedForCoverage
    # for why an inner branch's own @() does not survive the outer if/else-as-expression
    # assignment boundary when the taken branch yields 0 or 1 elements.
    $records = @(if ($TargetEntityId) {
        if ($index.ByTargetEntityId.ContainsKey($TargetEntityId)) { @($index.ByTargetEntityId[$TargetEntityId]) } else { @() }
    } else {
        @($index.Records)
    })

    if ($SourceEntityId) {
        $records = @($records | Where-Object { $_.sourceEntityId -eq $SourceEntityId })
    }

    return ,@($records)
}
