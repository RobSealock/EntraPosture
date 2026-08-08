#Requires -Version 7.4

function Test-EntraPostureBundleIntegrity {
    <#
        .SYNOPSIS
        Determines a sealed bundle's trust status: NotSealed, Signed, Unsigned,
        InvalidSignature, or HashMismatch.

        .DESCRIPTION
        Engineering plan section 8.4: "Invalid signatures or hashes are rejected before
        evaluation." This function is that rejection gate. It never trusts the per-file hashes
        recorded in integrity.json at face value -- it independently recomputes every file's
        hash from what is actually on disk right now (via the same
        Get-EntraPostureBundleFileInventory used at seal time) and compares against the
        recorded aggregate hash. If a detached signature is present, it is verified against the
        exact recorded {files, aggregateHash, recordCount} attestation payload (not the recomputed
        one) -- this distinguishes "the manifest itself was altered after signing"
        (InvalidSignature) from "the manifest is internally consistent and validly signed, but
        files on disk no longer match it" (HashMismatch), which are different failure modes a
        caller may want to react to differently.

        .PARAMETER BundlePath
        Path to a (supposedly) sealed bundle directory.

        .OUTPUTS
        Ordered dictionary: IsTrusted (bool -- true only for Signed/Unsigned), Status, Details,
        Manifest (parsed manifest.json content, or $null if not even readable).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$BundlePath
    )

    $manifestPath = Join-Path $BundlePath 'manifest.json'
    $integrityPath = Join-Path $BundlePath 'integrity.json'

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $integrityPath -PathType Leaf)) {
        return [ordered]@{
            IsTrusted = $false
            Status    = 'NotSealed'
            Details   = "manifest.json and/or integrity.json missing under '$BundlePath' -- this is not a sealed bundle."
            Manifest  = $null
        }
    }

    try {
        $manifestJson = Get-Content -LiteralPath $manifestPath -Raw
        $manifest = ConvertFrom-EntraPostureJson -Json $manifestJson
        $manifestSchemaResult = Test-EntraPostureSchema -Json $manifestJson -ContractName 'snapshot-manifest'
        if (-not $manifestSchemaResult.IsValid) {
            return [ordered]@{
                IsTrusted = $false
                Status    = 'HashMismatch'
                Details   = "manifest.json does not conform to its schema (treated as corrupt): $($manifestSchemaResult.Errors -join '; ')"
                Manifest  = $null
            }
        }
    } catch {
        return [ordered]@{
            IsTrusted = $false
            Status    = 'HashMismatch'
            Details   = "manifest.json could not be parsed (treated as corrupt): $($_.Exception.Message)"
            Manifest  = $null
        }
    }

    try {
        $integrityJson = Get-Content -LiteralPath $integrityPath -Raw
        $recordedIntegrity = ConvertFrom-EntraPostureJson -Json $integrityJson
        $integritySchemaResult = Test-EntraPostureSchema -Json $integrityJson -ContractName 'integrity'
        if (-not $integritySchemaResult.IsValid) {
            return [ordered]@{
                IsTrusted = $false
                Status    = 'HashMismatch'
                Details   = "integrity.json does not conform to its schema (treated as corrupt): $($integritySchemaResult.Errors -join '; ')"
                Manifest  = $manifest
            }
        }
    } catch {
        return [ordered]@{
            IsTrusted = $false
            Status    = 'HashMismatch'
            Details   = "integrity.json could not be parsed (treated as corrupt): $($_.Exception.Message)"
            Manifest  = $manifest
        }
    }

    # Recompute from actual disk content -- the recorded values are never trusted at face value.
    $actualInventory = Get-EntraPostureBundleFileInventory -BundleRoot $BundlePath
    $actualAggregate = $actualInventory | Get-EntraPostureAggregateHash

    $recordedPayload = Get-EntraPostureIntegrityAttestationPayload -Files $recordedIntegrity.files -AggregateHash $recordedIntegrity.aggregateHash -RecordCount $recordedIntegrity.recordCount
    $recordedPayloadJson = ConvertTo-EntraPostureCanonicalJson -InputObject $recordedPayload
    $recordedPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($recordedPayloadJson)

    if ($recordedIntegrity.signatureStatus -eq 'Signed') {
        $p7sPath = Join-Path $BundlePath ($recordedIntegrity.signature.detachedSignatureFile)
        if (-not (Test-Path -LiteralPath $p7sPath -PathType Leaf)) {
            return [ordered]@{
                IsTrusted = $false
                Status    = 'InvalidSignature'
                Details   = "integrity.json declares signatureStatus 'Signed' but the referenced signature file '$($recordedIntegrity.signature.detachedSignatureFile)' is missing."
                Manifest  = $manifest
            }
        }

        $signatureBytes = [System.IO.File]::ReadAllBytes($p7sPath)
        $signatureValid = Test-EntraPostureDetachedSignature -Content $recordedPayloadBytes -SignatureBytes $signatureBytes

        if (-not $signatureValid) {
            return [ordered]@{
                IsTrusted = $false
                Status    = 'InvalidSignature'
                Details   = 'The detached signature does not validate against the recorded integrity attestation payload -- integrity.json was altered after signing, the wrong signature file is present, or the signature is corrupt.'
                Manifest  = $manifest
            }
        }
    }

    if ($actualAggregate.aggregateHash -ne $recordedIntegrity.aggregateHash) {
        return [ordered]@{
            IsTrusted = $false
            Status    = 'HashMismatch'
            Details   = "Recomputed aggregate hash ($($actualAggregate.aggregateHash)) does not match the recorded aggregate hash ($($recordedIntegrity.aggregateHash)) -- one or more files changed after sealing."
            Manifest  = $manifest
        }
    }

    $finalStatus = if ($recordedIntegrity.signatureStatus -eq 'Signed') { 'Signed' } else { 'Unsigned' }

    return [ordered]@{
        IsTrusted = $true
        Status    = $finalStatus
        Details   = 'Bundle hashes match recorded integrity record' + $(if ($finalStatus -eq 'Signed') { ' and the detached signature is valid.' } else { '.' })
        Manifest  = $manifest
    }
}

function Get-EntraPostureTrustedSnapshot {
    <#
        .SYNOPSIS
        The mandatory trust gate: returns a sealed snapshot's manifest only if
        Test-EntraPostureBundleIntegrity confirms it is trustworthy; throws otherwise.

        .DESCRIPTION
        This is the concrete enforcement point for engineering plan Phase 3's exit criterion
        "invalid/unsealed data cannot reach evaluators." No evaluator exists yet (Phase 7), but
        this function is what every future evaluation entry point (Invoke-EntraPostureEvaluation,
        Phase 7) must call before touching bundle content -- there is deliberately no other
        supported way in this codebase to read a bundle as trusted.

        .PARAMETER BundlePath
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$BundlePath
    )

    $trust = Test-EntraPostureBundleIntegrity -BundlePath $BundlePath

    if (-not $trust.IsTrusted) {
        throw "Get-EntraPostureTrustedSnapshot: refusing to treat '$BundlePath' as trusted evidence (status: $($trust.Status)). $($trust.Details)"
    }

    return $trust.Manifest
}
