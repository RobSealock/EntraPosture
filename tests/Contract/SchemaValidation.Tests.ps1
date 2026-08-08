#Requires -Version 7.4
#Requires -Modules Pester

<#
    Contract tests (engineering plan section 14 item 2): every registered schema validates a
    realistic conforming fixture, and rejects representative violations of required fields,
    enums, additionalProperties:false, and (for snapshot-manifest) the Partial/Sealed
    conditional rule.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/TestSchema.ps1')

    function Copy-EntraPostureTestFixture {
        # System.Collections.Specialized.OrderedDictionary does not expose .Clone() via
        # PowerShell's default dot-notation member resolution (confirmed empirically --
        # ICloneable.Clone() is an explicit interface implementation, not a public instance
        # method PowerShell picks up), so test fixtures use this shallow-copy helper instead.
        param ([Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Source)
        $copy = [ordered]@{}
        foreach ($key in $Source.Keys) { $copy[$key] = $Source[$key] }
        return $copy
    }

    $now = (Get-Date).ToUniversalTime().ToString('o')

    $script:ValidFixtures = @{
        'entity' = [ordered]@{
            entityId = 'g1'; entityType = 'Group'; tenantScope = 'contoso'; displayName = 'Test Group'
            collectedAt = $now; collectorVersion = '0.1.0'; sourceEndpoint = '/v1.0/groups'
            properties = [ordered]@{ mailEnabled = $false }; redacted = $false
        }
        'relationship' = [ordered]@{
            relationshipId = 'r1'; sourceEntityId = 'u1'; targetEntityId = 'g1'; relationshipType = 'MemberOf'
            assignmentState = 'Active'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = '/v1.0/groups/g1/members'; collectedAt = $now }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
        'snapshot-manifest' = [ordered]@{
            snapshotId = 'snap-1'; toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '0.1.0'
            powerShellVersion = '7.4'; tenantScope = 'contoso'; cloud = 'Public'; authMode = 'CertificateAppOnly'
            collectionStartUtc = $now; collectionEndUtc = $now; status = 'Sealed'; partialReason = $null; sealedAt = $now
        }
        'resolved-profile' = [ordered]@{
            profileSchemaVersion = '1.0.0'
            precedenceTrace = @([ordered]@{ settingPath = 'auth.mode'; effectiveSource = 'NamedCliParameter'; value = 'CertificateAppOnly' })
            settings = [ordered]@{ auth = [ordered]@{ mode = 'CertificateAppOnly' } }
        }
        'coverage' = [ordered]@{
            collectors = @([ordered]@{
                collectorName = 'Groups'; accessRequested = @('Group.Read.All'); rightsPresentInToken = @('Group.Read.All')
                rightsExpected = @('Group.Read.All'); accessVerified = $true; evidenceStatus = 'Collected'
                affectedControlIds = @('XTA-001'); affectedReportSections = @('Groups')
            })
        }
        'control-definition' = [ordered]@{
            controlId = 'XTA-001'; version = '1.0.0'; title = 'Default Cross-Tenant Trust Settings Enabled Without Justification'
            description = 'desc'; rationale = 'rationale'; severity = 3; category = 'Cross-Tenant Access'; ownership = 'Security Ops'
            requiredEvidenceDomains = @('CrossTenantAccessPolicy')
            requiredPermissions = @([ordered]@{ scope = 'Policy.Read.All'; confirmed = $true })
            applicability = 'Always'
            reasonCodes = @([ordered]@{ code = 'XTA001-DEFAULT-PERMISSIVE'; resultStatus = 'Fail'; description = 'desc' })
            expectedResultSemantics = 'semantics'; evaluatorFunctionName = 'Test-Xta001'
            evidenceRedactionPolicy = 'Identifiers'; remediation = 'remediation'; references = @('https://learn.microsoft.com/')
            provenance = [ordered]@{ disposition = 'Reimplement'; sourceProject = $null; notes = 'clean-room' }
            externalMappings = @([ordered]@{ framework = 'CIS'; identifier = '1.1' })
            baselineDependency = [ordered]@{ documentationUrl = 'https://learn.microsoft.com/'; asOfDate = '2026-03-28'; citationStrength = 'DirectQuote' }
        }
        'control-result' = [ordered]@{
            controlId = 'XTA-001'; controlVersion = '1.0.0'; evaluatorVersion = '0.1.0'; scope = 'tenant'
            status = 'Fail'; reasonCode = 'XTA001-DEFAULT-PERMISSIVE'; rationale = 'rationale'
            evidenceReferences = @(); collectionCoverage = 'Complete'; evaluatedAt = $now
            remediation = 'remediation'; correlationId = [guid]::NewGuid().ToString(); deviation = $null
        }
        'deviation' = [ordered]@{
            deviationId = 'dev-1'; controlId = 'XTA-001'; objectScope = 'tenant'; approver = 'CISO'; justification = 'justification'
            owner = 'Security Ops'; startDate = '2026-08-06'; expiryDate = '2026-12-31'; compensatingControl = $null; evidence = @()
        }
        'comparison' = [ordered]@{
            comparisonId = 'cmp-1'; leftId = 'snap-1'; rightId = 'snap-2'; compatibility = 'Compatible'; comparedAt = $now
            evidenceChanges = @(); resultTransitions = @(); coverageChanges = @(); deviationChanges = @(); whatIfChanges = @(); evaluatorVersionChanges = @()
        }
        'integrity' = [ordered]@{
            files = @([ordered]@{ relativePath = 'manifest.json'; byteSize = 100; fileHash = ('a' * 64) })
            aggregateHash = ('b' * 64); recordCount = 1; signatureStatus = 'Unsigned'; signature = $null
        }
        'error-record' = [ordered]@{
            ErrorId = 'TEST-ERROR'; Stage = 'Collection'; Source = $null; Retryable = $false; EndpointClass = $null
            CorrelationId = [guid]::NewGuid().ToString(); Message = 'safe message'; TimestampUtc = $now
        }
        'whatif-scenario' = [ordered]@{
            scenarioId = 'sc-1'
            subject = [ordered]@{ principalType = 'User'; principalId = 'u1' }
            resource = [ordered]@{ applicationId = 'app1'; userAction = $null }
            client = 'Browser'; platform = $null
            deviceState = [ordered]@{ isCompliant = $null; isHybridAzureAdJoined = $null }
            location = $null
            risk = [ordered]@{ userRiskLevel = $null; signInRiskLevel = $null }
            authenticationContext = $null
        }
        'whatif-result' = [ordered]@{
            scenarioId = 'sc-1'; microsoftResult = $null; localModeledResult = $null; disagreement = 'NotComparable'
            missingInputs = @('No lab tenant available'); graphApiVersion = 'v1.0'; evaluatedAt = $now
        }
    }
}

Describe 'Schema validation -- <_>' -ForEach @(
    'entity', 'relationship', 'snapshot-manifest', 'resolved-profile', 'coverage',
    'control-definition', 'control-result', 'deviation', 'comparison', 'integrity',
    'error-record', 'whatif-scenario', 'whatif-result'
) {
    BeforeAll {
        $script:ContractName = $_
    }

    It 'accepts a realistic conforming fixture' {
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $ValidFixtures[$ContractName]
        $result = Test-EntraPostureSchema -Json $json -ContractName $ContractName
        $result.IsValid | Should -BeTrue -Because ($result.Errors -join '; ')
    }

    It 'rejects an unexpected additional property' {
        $fixture = Copy-EntraPostureTestFixture -Source $ValidFixtures[$ContractName]
        $fixture['zzzUnexpectedField'] = 'sneaky'
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $fixture
        (Test-EntraPostureSchema -Json $json -ContractName $ContractName).IsValid | Should -BeFalse
    }
}

Describe 'Schema validation -- targeted negative cases' {
    It 'entity: rejects an invalid entityType enum value' {
        $bad = Copy-EntraPostureTestFixture -Source $ValidFixtures['entity']
        $bad['entityType'] = 'NotARealType'
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $bad) -ContractName 'entity').IsValid | Should -BeFalse
    }

    It 'deviation: rejects a document missing required fields' {
        $bad = [ordered]@{ deviationId = 'd'; controlId = 'XTA-001' }
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $bad) -ContractName 'deviation').IsValid | Should -BeFalse
    }

    It 'integrity: rejects a fileHash that is not 64 lowercase hex characters' {
        $bad = [ordered]@{
            files = @([ordered]@{ relativePath = 'a'; byteSize = 1; fileHash = 'NOTAHASH' })
            aggregateHash = ('a' * 64); recordCount = 1; signatureStatus = 'Unsigned'; signature = $null
        }
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $bad) -ContractName 'integrity').IsValid | Should -BeFalse
    }

    It 'snapshot-manifest: rejects status=Partial with a null partialReason (conditional rule)' {
        $bad = Copy-EntraPostureTestFixture -Source $ValidFixtures['snapshot-manifest']
        $bad['status'] = 'Partial'
        $bad['partialReason'] = $null
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $bad) -ContractName 'snapshot-manifest').IsValid | Should -BeFalse
    }

    It 'snapshot-manifest: accepts status=Partial when partialReason is a non-empty string' {
        $ok = Copy-EntraPostureTestFixture -Source $ValidFixtures['snapshot-manifest']
        $ok['status'] = 'Partial'
        $ok['partialReason'] = 'PIM collector denied'
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $ok) -ContractName 'snapshot-manifest').IsValid | Should -BeTrue
    }

    It 'snapshot-manifest: rejects status=Sealed with a non-null partialReason (conditional rule, inverse direction)' {
        $bad = Copy-EntraPostureTestFixture -Source $ValidFixtures['snapshot-manifest']
        $bad['partialReason'] = 'should not be set'
        (Test-EntraPostureSchema -Json (ConvertTo-EntraPostureCanonicalJson $bad) -ContractName 'snapshot-manifest').IsValid | Should -BeFalse
    }
}

Describe 'Schema cross-consistency' {
    It 'control-definition reasonCodes.resultStatus enum matches control-result status enum exactly' {
        # These two enums are deliberately duplicated rather than $ref'd across schema files
        # (see control-definition.schema.json's comment on why) -- this test is the mechanism
        # that keeps them from silently drifting apart instead.
        $controlDefSchema = Get-Content -Raw (Join-Path $RepoRoot 'schemas/control-definition.schema.json') | ConvertFrom-Json
        $controlResultSchema = Get-Content -Raw (Join-Path $RepoRoot 'schemas/control-result.schema.json') | ConvertFrom-Json

        $defEnum = @($controlDefSchema.properties.reasonCodes.items.properties.resultStatus.enum | Sort-Object)
        $resultEnum = @($controlResultSchema.properties.status.enum | Sort-Object)

        $defEnum | Should -Be $resultEnum
    }
}
