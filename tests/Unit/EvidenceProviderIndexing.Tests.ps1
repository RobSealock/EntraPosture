#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 6: "Implement evidence-provider indexes and deterministic streaming behavior."
    Formalizes the ad hoc validation performed while building
    src/Evidence/EvidenceProvider.ps1's indexed rewrite -- including the real
    [Array]::Sort generic-vs-non-generic overload-resolution bug found and fixed during that
    work (see the file's own inline comment for the full writeup).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Evidence/EvidenceFileRegistry.ps1')
    . (Join-Path $script:RepoRoot 'src/Evidence/EvidenceProvider.ps1')

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "evidence-index-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:New-TestRoleLine {
        param([string]$EntityId, [string]$DisplayName)
        return "{`"entityId`":`"$EntityId`",`"entityType`":`"DirectoryRole`",`"tenantScope`":`"t1`",`"displayName`":`"$DisplayName`",`"collectedAt`":`"2026-01-01T00:00:00Z`",`"collectorVersion`":`"0.1.0`",`"sourceEndpoint`":`"x`",`"properties`":{},`"redacted`":false}"
    }

    function script:New-TestRelationshipLine {
        param([string]$Source, [string]$Target)
        return "{`"relationshipId`":`"$Source::$Target`",`"sourceEntityId`":`"$Source`",`"targetEntityId`":`"$Target`",`"relationshipType`":`"DirectoryRoleAssignment`",`"assignmentState`":`"Active`",`"scope`":`"directory`",`"provenance`":{`"collectorVersion`":`"0.1.0`",`"sourceEndpoint`":`"x`",`"collectedAt`":`"2026-01-01T00:00:00Z`"},`"validity`":{`"startDateTime`":null,`"endDateTime`":null,`"isTransitive`":false}}"
    }
}

Describe 'Get-EntraPostureEntity deterministic ordering' {
    It 'returns entities in ordinal entityId order regardless of on-disk write order' {
        $dir = New-TestSnapshotDir
        $lines = @(
            (New-TestRoleLine -EntityId 'zzz-role' -DisplayName 'Z'),
            (New-TestRoleLine -EntityId 'mmm-role' -DisplayName 'M'),
            (New-TestRoleLine -EntityId 'aaa-role' -DisplayName 'A')
        )
        Set-Content -LiteralPath (Join-Path $dir 'evidence/entra-roles.jsonl') -Value ($lines -join "`n")

        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $roles = Get-EntraPostureEntity -Provider $provider -EntityType 'DirectoryRole'

        @($roles.entityId) | Should -Be @('aaa-role', 'mmm-role', 'zzz-role')
    }

    It 'returns a proper 1-element array (not a collapsed scalar) for a single-record type' {
        $dir = New-TestSnapshotDir
        Set-Content -LiteralPath (Join-Path $dir 'evidence/entra-roles.jsonl') -Value (New-TestRoleLine -EntityId 'only-role' -DisplayName 'Only')

        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $roles = Get-EntraPostureEntity -Provider $provider -EntityType 'DirectoryRole'

        ($roles -is [object[]]) | Should -BeTrue
        $roles.Count | Should -Be 1
        $roles[0].entityId | Should -Be 'only-role'
    }

    It 'returns a proper empty array for a type with no evidence file at all' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $roles = Get-EntraPostureEntity -Provider $provider -EntityType 'DirectoryRole'

        ($roles -is [object[]]) | Should -BeTrue
        $roles.Count | Should -Be 0
    }
}

Describe 'Get-EntraPostureRelationship indexed lookups' {
    BeforeAll {
        $script:RelDir = New-TestSnapshotDir
        $lines = @(
            (New-TestRelationshipLine -Source 'user-z' -Target 'role-a'),
            (New-TestRelationshipLine -Source 'user-a' -Target 'role-a'),
            (New-TestRelationshipLine -Source 'user-m' -Target 'role-b')
        )
        Set-Content -LiteralPath (Join-Path $script:RelDir 'evidence/entra-role-assignments.jsonl') -Value ($lines -join "`n")
    }

    It 'filters by TargetEntityId via the index, in deterministic relationshipId order' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId 'role-a'
        @($rels.sourceEntityId) | Should -Be @('user-a', 'user-z')
    }

    It 'returns a proper 1-element array for a TargetEntityId with exactly one match' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId 'role-b'
        ($rels -is [object[]]) | Should -BeTrue
        $rels.Count | Should -Be 1
        $rels[0].sourceEntityId | Should -Be 'user-m'
    }

    It 'returns a proper empty array for a TargetEntityId with no matches' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId 'role-nonexistent'
        ($rels -is [object[]]) | Should -BeTrue
        $rels.Count | Should -Be 0
    }

    It 'combines TargetEntityId and SourceEntityId filters' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId 'role-a' -SourceEntityId 'user-a'
        $rels.Count | Should -Be 1
        $rels[0].sourceEntityId | Should -Be 'user-a'
    }

    It 'filters by SourceEntityId alone' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId 'user-m'
        $rels.Count | Should -Be 1
        $rels[0].targetEntityId | Should -Be 'role-b'
    }

    It 'returns every relationship of the type, sorted, when no filter is supplied' {
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $script:RelDir
        $rels = Get-EntraPostureRelationship -Provider $provider -RelationshipType 'DirectoryRoleAssignment'
        $rels.Count | Should -Be 3
    }
}

Describe 'Evidence index caching' {
    It 'loads a type from disk only once -- a second call reuses the cached index' {
        $dir = New-TestSnapshotDir
        $path = Join-Path $dir 'evidence/entra-roles.jsonl'
        Set-Content -LiteralPath $path -Value (New-TestRoleLine -EntityId 'role-1' -DisplayName 'One')

        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $first = Get-EntraPostureEntity -Provider $provider -EntityType 'DirectoryRole'
        $first.Count | Should -Be 1

        # Mutate the file after the first load -- if the second call re-read from disk instead
        # of using the cache, it would see two records instead of one.
        Add-Content -LiteralPath $path -Value (New-TestRoleLine -EntityId 'role-2' -DisplayName 'Two')

        $second = Get-EntraPostureEntity -Provider $provider -EntityType 'DirectoryRole'
        $second.Count | Should -Be 1
    }
}
