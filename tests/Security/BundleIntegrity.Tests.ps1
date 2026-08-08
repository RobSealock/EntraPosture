#Requires -Version 7.4
#Requires -Modules Pester

<#
    Security/adversarial tests for the staging -> seal -> integrity-verification pipeline.
    This is the concrete proof of engineering plan Phase 3's exit criterion: "invalid/unsealed
    data cannot reach evaluators." No evaluator exists yet (Phase 7); these tests instead prove
    that Get-EntraPostureTrustedSnapshot -- the mandatory gate every future evaluator entry
    point must call -- correctly refuses every tampering/forgery scenario tried against it, and
    correctly accepts an untampered bundle in both signed and unsigned form.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/TestSchema.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/FileHash.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/AggregateHash.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/DetachedSignature.ps1')
    . (Join-Path $script:RepoRoot 'src/Snapshots/NewStagingDirectory.ps1')
    . (Join-Path $script:RepoRoot 'src/Snapshots/SealSnapshot.ps1')
    . (Join-Path $script:RepoRoot 'src/Integrity/TestBundleIntegrity.ps1')

    function New-EntraPostureTestCertificate {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=EntraPostureTestCert', $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
    }

    function New-EntraPostureTestEntity {
        param([string]$Id, [string]$Name)
        return [ordered]@{
            entityId = $Id; entityType = 'Group'; tenantScope = 'contoso'; displayName = $Name
            collectedAt = (Get-Date).ToUniversalTime().ToString('o'); collectorVersion = '0.1.0'
            sourceEndpoint = '/v1.0/groups'; properties = [ordered]@{}; redacted = $false
        }
    }

    $script:ManifestMeta = [ordered]@{
        toolVersion = '0.1.0'; schemaVersion = '1.0.0'; controlRegistryVersion = '0.1.0'; powerShellVersion = '7.4'
        tenantScope = 'contoso'; cloud = 'Public'; authMode = 'CertificateAppOnly'
        collectionStartUtc = (Get-Date).ToUniversalTime().ToString('o'); collectionEndUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

Describe 'Protect-EntraPostureSnapshot' {
    # Pester 6 requires Each-scoped setup/teardown to live inside a container (Describe/Context),
    # not at the script root -- confirmed empirically ("Each test setup is not supported in root").
    # Duplicated identically into each of this file's three Describe blocks rather than factored
    # into one wrapping container, to keep this as a minimal, low-risk structural fix.
    BeforeEach {
        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "eatest-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }


    It 'seals a single-record JSONL evidence file successfully' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-1'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM

        $manifest = Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-1'

        $manifest.status | Should -Be 'Sealed'
        Test-Path (Join-Path $staging 'manifest.json') | Should -BeTrue
        Test-Path (Join-Path $staging 'integrity.json') | Should -BeTrue
    }

    It 'seals a multi-record JSONL evidence file successfully' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-multi'
        $lines = @(
            (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One'))
            (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g2' 'Two'))
        ) -join "`n"
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value $lines -Encoding utf8NoBOM

        $manifest = Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-multi'
        $manifest.status | Should -Be 'Sealed'
    }

    It 'refuses to seal and writes nothing when evidence fails schema validation' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-bad'
        $bad = New-EntraPostureTestEntity 'x' 'Bad'
        $bad['entityType'] = 'NotARealType'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson $bad) -Encoding utf8NoBOM

        { Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-bad' } | Should -Throw

        Test-Path (Join-Path $staging 'manifest.json') | Should -BeFalse
        Test-Path (Join-Path $staging 'integrity.json') | Should -BeFalse
    }

    It 'refuses to seal and writes nothing when evidence has a duplicate JSON key' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-dup'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value '{"entityId":"g1","entityId":"g2","entityType":"Group","tenantScope":"contoso","displayName":"x","collectedAt":"2026-01-01T00:00:00Z","collectorVersion":"1","sourceEndpoint":"/x","properties":{},"redacted":false}' -Encoding utf8NoBOM

        { Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-dup' } | Should -Throw '*duplicate*'
        Test-Path (Join-Path $staging 'manifest.json') | Should -BeFalse
    }

    It 'requires -PartialReason when -IsPartial is set' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-partial-bad'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        { Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-partial-bad' -IsPartial $true } | Should -Throw '*PartialReason*'
    }

    It 'writes status=Partial with the given reason when -IsPartial is set correctly' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-partial-ok'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        $manifest = Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-partial-ok' -IsPartial $true -PartialReason 'PIM collector denied'
        $manifest.status | Should -Be 'Partial'
        $manifest.partialReason | Should -Be 'PIM collector denied'
    }

    It 'refuses to reseal an already-sealed staging directory in place' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-resealattempt'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-resealattempt' | Out-Null

        { Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-resealattempt' } | Should -Throw '*already contains*'
    }
}

Describe 'Test-EntraPostureBundleIntegrity and Get-EntraPostureTrustedSnapshot' {

    BeforeEach {
        $script:TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "eatest-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $script:TestRoot -Force | Out-Null
        $script:Cert = New-EntraPostureTestCertificate
    }

    AfterEach {
        Remove-Item -LiteralPath $script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'reports NotSealed for a directory with no manifest.json/integrity.json' {
        $dir = Join-Path $TestRoot 'unsealed'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        (Test-EntraPostureBundleIntegrity -BundlePath $dir).Status | Should -Be 'NotSealed'
    }

    It 'reports Signed and IsTrusted=true for an untampered, signed bundle' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-signed'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-signed' -SigningCertificate $Cert | Out-Null

        $trust = Test-EntraPostureBundleIntegrity -BundlePath $staging
        $trust.Status | Should -Be 'Signed'
        $trust.IsTrusted | Should -BeTrue
    }

    It 'reports Unsigned and IsTrusted=true for an untampered, unsigned bundle' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-unsigned'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-unsigned' | Out-Null

        $trust = Test-EntraPostureBundleIntegrity -BundlePath $staging
        $trust.Status | Should -Be 'Unsigned'
        $trust.IsTrusted | Should -BeTrue
    }

    It 'detects an evidence file modified after sealing (HashMismatch)' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-tamper'
        $evidencePath = Join-Path $staging 'evidence/entra-groups.jsonl'
        Set-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-tamper' -SigningCertificate $Cert | Out-Null

        Add-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'INJECTED' 'Injected'))

        $trust = Test-EntraPostureBundleIntegrity -BundlePath $staging
        $trust.Status | Should -Be 'HashMismatch'
        $trust.IsTrusted | Should -BeFalse
    }

    It 'detects a forged integrity.json that was rewritten to match tampered evidence but reuses the stale signature (InvalidSignature)' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-forge'
        $evidencePath = Join-Path $staging 'evidence/entra-groups.jsonl'
        Set-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-forge' -SigningCertificate $Cert | Out-Null

        # Attacker adds a record, then recomputes and rewrites integrity.json to match --
        # but cannot forge a new signature without the private key, so the old .p7s is reused.
        Add-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g2' 'Two'))
        $forgedInventory = Get-EntraPostureBundleFileInventory -BundleRoot $staging
        $forgedAgg = $forgedInventory | Get-EntraPostureAggregateHash
        $forgedIntegrity = [ordered]@{
            files = $forgedInventory; aggregateHash = $forgedAgg.aggregateHash; recordCount = $forgedAgg.recordCount
            signatureStatus = 'Signed'; signature = [ordered]@{ detachedSignatureFile = 'integrity.p7s'; certificateThumbprint = $Cert.Thumbprint }
        }
        Set-Content -LiteralPath (Join-Path $staging 'integrity.json') -Value (ConvertTo-EntraPostureCanonicalJson $forgedIntegrity) -Encoding utf8NoBOM -NoNewline

        $trust = Test-EntraPostureBundleIntegrity -BundlePath $staging
        $trust.Status | Should -Be 'InvalidSignature'
        $trust.IsTrusted | Should -BeFalse
    }

    It 'Get-EntraPostureTrustedSnapshot returns the manifest for a trustworthy bundle' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-trusted-read'
        Set-Content -LiteralPath (Join-Path $staging 'evidence/entra-groups.jsonl') -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-trusted-read' | Out-Null

        (Get-EntraPostureTrustedSnapshot -BundlePath $staging).snapshotId | Should -Be 'snap-trusted-read'
    }

    It 'Get-EntraPostureTrustedSnapshot throws rather than returning data for a tampered bundle -- the concrete Phase 3 exit-criterion check' {
        $staging = New-EntraPostureStagingDirectory -RunRoot $TestRoot -SnapshotId 'snap-trusted-read-tampered'
        $evidencePath = Join-Path $staging 'evidence/entra-groups.jsonl'
        Set-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'g1' 'One')) -Encoding utf8NoBOM
        Protect-EntraPostureSnapshot -StagingPath $staging -EvidenceSchemaMap @{ 'evidence/entra-groups.jsonl' = 'entity' } -ManifestMetadata $ManifestMeta -SnapshotId 'snap-trusted-read-tampered' | Out-Null
        Add-Content -LiteralPath $evidencePath -Value (ConvertTo-EntraPostureCanonicalJson (New-EntraPostureTestEntity 'INJECTED' 'Injected'))

        { Get-EntraPostureTrustedSnapshot -BundlePath $staging } | Should -Throw '*refusing to treat*'
    }

    It 'Get-EntraPostureTrustedSnapshot throws for an unsealed directory' {
        $dir = Join-Path $TestRoot 'unsealed2'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        { Get-EntraPostureTrustedSnapshot -BundlePath $dir } | Should -Throw
    }
}

Describe 'New-EntraPostureDetachedSignature / Test-EntraPostureDetachedSignature' {
    BeforeEach {
        $script:Cert = New-EntraPostureTestCertificate
    }

    It 'a signature produced for one payload does not validate against a different payload' {
        $bytesA = [System.Text.Encoding]::UTF8.GetBytes('payload A')
        $bytesB = [System.Text.Encoding]::UTF8.GetBytes('payload B')
        $signature = New-EntraPostureDetachedSignature -Content $bytesA -Certificate $Cert
        Test-EntraPostureDetachedSignature -Content $bytesB -SignatureBytes $signature | Should -BeFalse
    }

    It 'a signature produced for a payload validates against that exact payload' {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes('payload A')
        $signature = New-EntraPostureDetachedSignature -Content $bytes -Certificate $Cert
        Test-EntraPostureDetachedSignature -Content $bytes -SignatureBytes $signature | Should -BeTrue
    }

    It 'rejects a certificate with no private key' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=NoKey', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $fullCert = $req.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(1))
        $publicOnlyCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($fullCert.Export('Cert'))

        { New-EntraPostureDetachedSignature -Content ([System.Text.Encoding]::UTF8.GetBytes('x')) -Certificate $publicOnlyCert } | Should -Throw '*private key*'
    }
}
