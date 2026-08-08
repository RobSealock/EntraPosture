#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 9 (AR-002): ConvertTo-EntraPostureAccessReviewInstanceEntity. The
    critical property under test is redaction-by-construction -- the matrix's own AR-002 design
    explicitly forbids storing individual reviewer identities or per-principal decision outcomes,
    so these tests assert the returned record's properties never contain anything from RawDecisions
    beyond the four aggregate counts, not just that the counts themselves are correct.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAccessReviewInstance.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }

    function script:ConvertTo-TestOrderedDictionaryArray {
        param([Parameter(Mandatory)][string]$Json)
        return @((ConvertFrom-EntraPostureJson -Json $Json))
    }
}

Describe 'ConvertTo-EntraPostureAccessReviewInstanceEntity: field mapping' {
    It 'maps id/startDateTime/endDateTime/status and the supplied DefinitionId' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "id": "inst-1", "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2026-01-15T00:00:00Z", "status": "Completed" }
'@
        $entity = ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $raw -DefinitionId 'def-1' -RawDecisions @() `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'inst-1'
        $entity.entityType | Should -Be 'AccessReviewInstance'
        $entity.displayName | Should -BeNullOrEmpty
        $entity.properties.definitionId | Should -Be 'def-1'
        $entity.properties.startDateTime | Should -Be '2026-01-01T00:00:00Z'
        $entity.properties.endDateTime | Should -Be '2026-01-15T00:00:00Z'
        $entity.properties.status | Should -Be 'Completed'
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "status": "Completed" }'
        { ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $raw -DefinitionId 'def-1' -RawDecisions @() `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}

Describe 'ConvertTo-EntraPostureAccessReviewInstanceEntity: decision aggregation and redaction' {
    It 'aggregates reviewed/not-reviewed/applied counts and never persists any raw decision field' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "inst-2", "status": "Completed" }'
        $decisions = ConvertTo-TestOrderedDictionaryArray -Json @'
[
  { "id": "d1", "decision": "Approve", "applyResult": "AppliedSuccessfully", "principal": { "id": "user-1" }, "reviewedBy": { "id": "reviewer-1" }, "justification": "still needed" },
  { "id": "d2", "decision": "Deny", "applyResult": "New", "principal": { "id": "user-2" } },
  { "id": "d3", "decision": "NotReviewed", "applyResult": "New", "principal": { "id": "user-3" } },
  { "id": "d4", "decision": "DontKnow", "applyResult": "AppliedWithUnknownFailure", "principal": { "id": "user-4" } }
]
'@
        $entity = ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $raw -DefinitionId 'def-2' -RawDecisions $decisions `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.properties.decisionsTotalCount | Should -Be 4
        $entity.properties.decisionsReviewedCount | Should -Be 3
        $entity.properties.decisionsNotReviewedCount | Should -Be 1
        $entity.properties.decisionsAppliedCount | Should -Be 2

        # Redaction-by-construction: the property bag's own keys are the complete allowlist --
        # assert no principal/reviewedBy/justification/id-of-decision field leaked through.
        $propertyKeys = @($entity.properties.Keys)
        $propertyKeys | Should -Not -Contain 'principal'
        $propertyKeys | Should -Not -Contain 'reviewedBy'
        $propertyKeys | Should -Not -Contain 'justification'
        $propertyKeys | Should -Not -Contain 'decisions'
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $entity
        $json | Should -Not -Match 'user-1'
        $json | Should -Not -Match 'reviewer-1'
        $json | Should -Not -Match 'still needed'
    }

    It 'treats a missing decision value the same as NotReviewed' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "inst-3", "status": "InProgress" }'
        $decisions = ConvertTo-TestOrderedDictionaryArray -Json '[ { "id": "d1" } ]'
        $entity = ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $raw -DefinitionId 'def-3' -RawDecisions $decisions `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.properties.decisionsTotalCount | Should -Be 1
        $entity.properties.decisionsReviewedCount | Should -Be 0
        $entity.properties.decisionsNotReviewedCount | Should -Be 1
        $entity.properties.decisionsAppliedCount | Should -Be 0
    }

    It 'defaults to zero counts when no decisions are supplied' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "inst-4", "status": "NotStarted" }'
        $entity = ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $raw -DefinitionId 'def-4' -RawDecisions @() `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.properties.decisionsTotalCount | Should -Be 0
        $entity.properties.decisionsReviewedCount | Should -Be 0
        $entity.properties.decisionsNotReviewedCount | Should -Be 0
        $entity.properties.decisionsAppliedCount | Should -Be 0
    }
}
