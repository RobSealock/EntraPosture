#Requires -Version 7.4

function New-EntraPostureAssessmentDocument {
    <#
        .SYNOPSIS
        Assembles the authoritative, complete, machine-readable assessment document (engineering
        plan section 10.1: "assessment.json is the authoritative complete machine-readable
        assessment").

        .DESCRIPTION
        A straightforward aggregation of already-individually-schema-governed pieces (each
        element of -Results already validates against control-result.schema.json; each element
        of -Deviations against deviation.schema.json; -SnapshotManifest against
        snapshot-manifest.schema.json) -- this document's own top-level shape does not yet have
        a dedicated schema of its own. That is a deliberate Phase 5 scope boundary, not an
        oversight: engineering plan Phase 9 ("Reporting, comparison, and hardening") is where
        reporting output gets formally hardened, and a wrapper schema belongs there once the
        shape has had a chance to prove itself against real usage first.

        .PARAMETER SnapshotManifest
        The trusted snapshot's manifest (from Get-EntraPostureTrustedSnapshot).

        .PARAMETER EvaluationId
        .PARAMETER Coverage
        Ordered dictionary matching coverage.schema.json.

        .PARAMETER Results
        Array of ordered dictionaries matching control-result.schema.json (post-deviation
        application).

        .PARAMETER Deviations
        Array of ordered dictionaries matching deviation.schema.json.

        .PARAMETER EvaluatedAtUtc
        ISO 8601 UTC timestamp string.

        .OUTPUTS
        Ordered dictionary: the full assessment document.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory data aggregation -- no external side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$SnapshotManifest,

        [Parameter(Mandatory)]
        [string]$EvaluationId,

        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Coverage,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Results,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Deviations,

        [Parameter(Mandatory)]
        [string]$EvaluatedAtUtc
    )

    $versionInfo = Get-EntraPostureToolVersionInfo

    $statusCounts = [ordered]@{
        Pass          = @($Results | Where-Object { $_.status -eq 'Pass' }).Count
        Fail          = @($Results | Where-Object { $_.status -eq 'Fail' }).Count
        NotApplicable = @($Results | Where-Object { $_.status -eq 'NotApplicable' }).Count
        NotEvaluated  = @($Results | Where-Object { $_.status -eq 'NotEvaluated' }).Count
        Error         = @($Results | Where-Object { $_.status -eq 'Error' }).Count
    }

    $unapprovedFailCount = @($Results | Where-Object { $_.status -eq 'Fail' -and -not $_.deviation }).Count

    return [ordered]@{
        assessmentId           = $EvaluationId
        snapshotId              = $SnapshotManifest.snapshotId
        toolVersion             = $versionInfo.ToolVersion
        schemaVersion           = $versionInfo.SchemaVersion
        controlRegistryVersion  = $versionInfo.ControlRegistryVersion
        tenantScope             = $SnapshotManifest.tenantScope
        cloud                   = $SnapshotManifest.cloud
        authMode                = $SnapshotManifest.authMode
        collectionStartUtc      = $SnapshotManifest.collectionStartUtc
        collectionEndUtc        = $SnapshotManifest.collectionEndUtc
        snapshotStatus          = $SnapshotManifest.status
        evaluatedAtUtc          = $EvaluatedAtUtc
        coverage                = $Coverage
        results                 = @($Results)
        deviations              = @($Deviations)
        summary                 = [ordered]@{
            controlResultCount    = @($Results).Count
            statusCounts          = $statusCounts
            unapprovedFailCount   = $unapprovedFailCount
            deviationCount        = @($Deviations).Count
        }
    }
}
