#Requires -Version 7.4

function Get-EntraPostureIntegrityAttestationPayload {
    <#
        .SYNOPSIS
        Builds the exact ordered-dictionary subset of an integrity record that gets signed.

        .DESCRIPTION
        Deliberately excludes signatureStatus/signature from the signed payload -- a signature
        cannot cover the field that describes its own presence without becoming circular (the
        payload would have to be finalized before we know whether signing is happening, but
        signing requires the payload's bytes first). Both
        New-EntraPostureDetachedSignature (at seal time) and
        Test-EntraPostureBundleIntegrity (at verify time) call this same function so the
        signed and re-verified payloads are always constructed identically.

        .PARAMETER Files
        Array of ordered dictionaries with relativePath/byteSize/fileHash.

        .PARAMETER AggregateHash
        Lowercase hex SHA-256 aggregate hash.

        .PARAMETER RecordCount
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [array]$Files,

        [Parameter(Mandatory)]
        [string]$AggregateHash,

        [Parameter(Mandatory)]
        [int]$RecordCount
    )

    return [ordered]@{
        files         = $Files
        aggregateHash = $AggregateHash
        recordCount   = $RecordCount
    }
}

function Get-EntraPostureBundleFileInventory {
    <#
        .SYNOPSIS
        Computes relativePath/byteSize/fileHash for every file under a bundle root, excluding
        the integrity record and its detached signature.

        .DESCRIPTION
        Engineering plan section 8.4: "SHA-256 separately covers every file in the sealed
        snapshot... except its own integrity record and detached signature." Shared by both
        Protect-EntraPostureSnapshot (computing what to record) and
        Test-EntraPostureBundleIntegrity (recomputing what to compare against) so both sides
        of the trust check use one identical definition of "every file."

        .PARAMETER BundleRoot

        .PARAMETER ExcludeDirectoryName
        Optional top-level subdirectory name (relative to -BundleRoot) to exclude entirely, in
        addition to integrity.json/integrity.p7s. Added for assessment bundles' reports/
        subdirectory (Invoke-EntraPostureEvaluationPipeline/Invoke-EntraPostureReportPipeline):
        rendered reports are regenerable derived output written *after* the assessment's
        results/deviations/manifest are sealed, not part of the immutable core those hashes
        protect -- including them would make every subsequent New-EntraPostureReport call
        (even re-rendering the same bundle with a different -RedactionMode) look like tampering
        (confirmed directly: a second report-generation call on an already-reported-on bundle
        failed integrity verification with a HashMismatch before this parameter existed).
        Snapshot bundles never pass this -- their evidence/whatif/logs/ contents are exactly the
        protected core, unchanged from Phase 3.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [string]$BundleRoot,

        [Parameter()]
        [string]$ExcludeDirectoryName
    )

    $excludedNames = @('integrity.json', 'integrity.p7s')
    $resolvedRoot = (Resolve-Path -LiteralPath $BundleRoot).Path
    $excludedDirPrefix = if ($ExcludeDirectoryName) { (Join-Path $resolvedRoot $ExcludeDirectoryName) + [System.IO.Path]::DirectorySeparatorChar } else { $null }

    $files = Get-ChildItem -LiteralPath $BundleRoot -Recurse -File |
        Where-Object { $_.Name -notin $excludedNames } |
        Where-Object { -not $excludedDirPrefix -or -not $_.FullName.StartsWith($excludedDirPrefix, [StringComparison]::Ordinal) } |
        Sort-Object FullName

    # @() around the whole foreach, and the leading comma at return -- both required. See
    # src/Evidence/EvidenceProvider.ps1 for the full empirical writeup: a bundle reduced to
    # exactly one hashed file (a real, reachable case once -ExcludeDirectoryName removes
    # everything else) would otherwise collapse this to a bare scalar record instead of a
    # 1-element array.
    $inventory = @(foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($resolvedRoot.Length + 1) -replace '\\', '/'
        [ordered]@{
            relativePath = $relativePath
            byteSize     = [long]$file.Length
            fileHash     = Get-EntraPostureFileHash -Path $file.FullName
        }
    })

    return ,@($inventory)
}

function Protect-EntraPostureSnapshot {
    <#
        .SYNOPSIS
        Validates every declared evidence file against its schema, computes bundle integrity,
        and writes manifest.json/coverage.json/integrity.json -- the only way a staging
        directory becomes a trusted, sealed snapshot.

        .DESCRIPTION
        Engineering plan section 8.3: "Validation must complete before a snapshot manifest and
        integrity record seal the snapshot." If any evidence file fails strict JSON parsing or
        schema validation, this function throws with the full list of failures and writes
        nothing -- the staging directory is left exactly as it was, still lacking
        manifest.json/integrity.json, and therefore still correctly unsealed (never a partially
        written, ambiguously-trustworthy bundle).

        .PARAMETER StagingPath
        A directory created by New-EntraPostureStagingDirectory, already populated with
        evidence.

        .PARAMETER EvidenceSchemaMap
        Hashtable mapping a relative path (under StagingPath) to a registered contract name
        (Get-EntraPostureSchemaPath's ValidateSet). Files ending '.jsonl' are validated one
        JSON record per non-empty line; files ending '.json' are validated as a single document.

        .PARAMETER ManifestMetadata
        Ordered dictionary supplying every snapshot-manifest field except snapshotId/status/
        partialReason/sealedAt, which this function fills in itself.

        .PARAMETER SnapshotId
        .PARAMETER IsPartial
        .PARAMETER PartialReason
        Required (and validated) when IsPartial is set.

        .PARAMETER Coverage
        Optional ordered dictionary matching coverage.schema.json.

        .PARAMETER SigningCertificate
        Optional X509Certificate2 with a private key. When supplied, integrity.p7s is written
        and integrity.json records signatureStatus 'Signed'; when omitted, signatureStatus is
        explicitly 'Unsigned' (never silently ambiguous, per section 8.4).

        .OUTPUTS
        The sealed bundle's manifest as an ordered dictionary.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$StagingPath,

        [Parameter(Mandatory)]
        [hashtable]$EvidenceSchemaMap,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$ManifestMetadata,

        [Parameter(Mandatory)]
        [string]$SnapshotId,

        [Parameter()]
        [bool]$IsPartial = $false,

        [Parameter()]
        [string]$PartialReason,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$Coverage,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate
    )

    if (-not (Test-Path -LiteralPath $StagingPath -PathType Container)) {
        throw "Protect-EntraPostureSnapshot: staging path '$StagingPath' does not exist."
    }

    $existingManifest = Join-Path $StagingPath 'manifest.json'
    $existingIntegrity = Join-Path $StagingPath 'integrity.json'
    if ((Test-Path -LiteralPath $existingManifest) -or (Test-Path -LiteralPath $existingIntegrity)) {
        throw "Protect-EntraPostureSnapshot: '$StagingPath' already contains manifest.json or integrity.json -- refusing to reseal an already-sealed bundle in place. Sealing is a one-way operation; start a new staging directory instead."
    }

    if ($IsPartial -and [string]::IsNullOrWhiteSpace($PartialReason)) {
        throw "Protect-EntraPostureSnapshot: -IsPartial requires a non-empty -PartialReason."
    }
    if (-not $IsPartial -and -not [string]::IsNullOrWhiteSpace($PartialReason)) {
        throw "Protect-EntraPostureSnapshot: -PartialReason was supplied but -IsPartial was not set -- ambiguous. A Sealed (non-partial) manifest must have a null partialReason."
    }

    # ---------------------------------------------------------------------
    # 1. Validate every declared evidence file BEFORE writing anything.
    # ---------------------------------------------------------------------
    $validationFailures = [System.Collections.Generic.List[string]]::new()

    foreach ($relativePath in $EvidenceSchemaMap.Keys) {
        $contractName = $EvidenceSchemaMap[$relativePath]
        $fullPath = Join-Path $StagingPath $relativePath

        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $validationFailures.Add("Declared evidence file '$relativePath' (contract '$contractName') does not exist under staging.")
            continue
        }

        $isJsonl = $relativePath.EndsWith('.jsonl')
        $rawContent = Get-Content -LiteralPath $fullPath -Raw
        # The whole if/else must be wrapped in the outer @() -- an @() around only the inner
        # branch is not sufficient. PowerShell control-flow statements used as expressions
        # perform their own output enumeration when assigned to a variable, which silently
        # collapses a single-element array back down to its scalar element (confirmed directly:
        # `$x = if ($true) { @(Get-Content $singleLineFile) }` yields a bare [string], not a
        # 1-element [object[]], even though the inner @() alone produces an array in isolation).
        # That collapsed scalar then makes $records[0] do *character* indexing instead of
        # *array-element* indexing, which is exactly the failure this comment prevents someone
        # from reintroducing.
        $records = @(if ($isJsonl) {
            (Get-Content -LiteralPath $fullPath) | Where-Object { $_.Trim().Length -gt 0 }
        } else {
            $rawContent
        })

        for ($i = 0; $i -lt $records.Count; $i++) {
            $lineDescriptor = if ($isJsonl) { "line $($i + 1)" } else { "document" }
            try {
                # Strict parse first (rejects duplicate keys / malformed JSON), independent of
                # schema validation, so a duplicate-key error is reported distinctly from a
                # schema-shape error rather than being masked by whichever ConvertFrom-Json
                # last-wins interpretation Test-Json would have validated instead.
                ConvertFrom-EntraPostureJson -Json $records[$i] | Out-Null
            } catch {
                $validationFailures.Add("'$relativePath' $lineDescriptor -- strict parse failed: $($_.Exception.Message)")
                continue
            }

            $result = Test-EntraPostureSchema -Json $records[$i] -ContractName $contractName
            if (-not $result.IsValid) {
                $validationFailures.Add("'$relativePath' $lineDescriptor -- schema '$contractName' violated: $($result.Errors -join '; ')")
            }
        }
    }

    if ($Coverage) {
        $coverageJson = ConvertTo-EntraPostureCanonicalJson -InputObject $Coverage
        $coverageResult = Test-EntraPostureSchema -Json $coverageJson -ContractName 'coverage'
        if (-not $coverageResult.IsValid) {
            $validationFailures.Add("Supplied -Coverage failed schema validation: $($coverageResult.Errors -join '; ')")
        }
    }

    if ($validationFailures.Count -gt 0) {
        $summary = $validationFailures -join "`n  "
        throw "Protect-EntraPostureSnapshot: sealing refused -- $($validationFailures.Count) validation failure(s) in staging path '$StagingPath':`n  $summary`nNo manifest.json or integrity.json was written; the staging directory remains unsealed."
    }

    # ---------------------------------------------------------------------
    # 2. Write manifest.json and (optionally) coverage.json.
    # ---------------------------------------------------------------------
    $sealedAt = (Get-Date).ToUniversalTime().ToString('o')

    $manifest = [ordered]@{}
    foreach ($key in $ManifestMetadata.Keys) { $manifest[$key] = $ManifestMetadata[$key] }
    $manifest['snapshotId'] = $SnapshotId
    $manifest['status'] = if ($IsPartial) { 'Partial' } else { 'Sealed' }
    $manifest['partialReason'] = if ($IsPartial) { $PartialReason } else { $null }
    $manifest['sealedAt'] = $sealedAt

    $manifestJson = ConvertTo-EntraPostureCanonicalJson -InputObject $manifest
    $manifestResult = Test-EntraPostureSchema -Json $manifestJson -ContractName 'snapshot-manifest'
    if (-not $manifestResult.IsValid) {
        throw "Protect-EntraPostureSnapshot: internal error -- constructed manifest failed its own schema: $($manifestResult.Errors -join '; ')"
    }
    [System.IO.File]::WriteAllText((Join-Path $StagingPath 'manifest.json'), $manifestJson, [System.Text.UTF8Encoding]::new($false))

    if ($Coverage) {
        [System.IO.File]::WriteAllText((Join-Path $StagingPath 'coverage.json'), (ConvertTo-EntraPostureCanonicalJson -InputObject $Coverage), [System.Text.UTF8Encoding]::new($false))
    }

    # ---------------------------------------------------------------------
    # 3. Hash every file now present (including manifest.json/coverage.json
    #    just written), compute the aggregate hash, optionally sign, write
    #    integrity.json last.
    # ---------------------------------------------------------------------
    $fileInventory = Get-EntraPostureBundleFileInventory -BundleRoot $StagingPath
    $aggregate = $fileInventory | Get-EntraPostureAggregateHash

    $attestationPayload = Get-EntraPostureIntegrityAttestationPayload -Files $fileInventory -AggregateHash $aggregate.aggregateHash -RecordCount $aggregate.recordCount
    $attestationJson = ConvertTo-EntraPostureCanonicalJson -InputObject $attestationPayload
    $attestationBytes = [System.Text.Encoding]::UTF8.GetBytes($attestationJson)

    $signatureStatus = 'Unsigned'
    $signatureRecord = $null

    if ($SigningCertificate) {
        $signatureBytes = New-EntraPostureDetachedSignature -Content $attestationBytes -Certificate $SigningCertificate
        [System.IO.File]::WriteAllBytes((Join-Path $StagingPath 'integrity.p7s'), $signatureBytes)
        $signatureStatus = 'Signed'
        $signatureRecord = [ordered]@{
            detachedSignatureFile = 'integrity.p7s'
            certificateThumbprint = $SigningCertificate.Thumbprint
        }
    }

    $integrityRecord = [ordered]@{
        files           = $fileInventory
        aggregateHash   = $aggregate.aggregateHash
        recordCount     = $aggregate.recordCount
        signatureStatus = $signatureStatus
        signature       = $signatureRecord
    }

    $integrityJson = ConvertTo-EntraPostureCanonicalJson -InputObject $integrityRecord
    $integrityResult = Test-EntraPostureSchema -Json $integrityJson -ContractName 'integrity'
    if (-not $integrityResult.IsValid) {
        throw "Protect-EntraPostureSnapshot: internal error -- constructed integrity record failed its own schema: $($integrityResult.Errors -join '; ')"
    }
    [System.IO.File]::WriteAllText((Join-Path $StagingPath 'integrity.json'), $integrityJson, [System.Text.UTF8Encoding]::new($false))

    return $manifest
}
