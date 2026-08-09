#Requires -Version 7.4

function Test-EntraPostureKnownAbusedAppControl {
    <#
        .SYNOPSIS
        ENT-013's evaluator: for each service principal (enterprise application) in the tenant,
        checks whether its own appId matches an entry in the locally vendored known-abused-app
        list.

        .DESCRIPTION
        CollectServicePrincipals.ps1 alone declares 'ENT-013' in its own AffectedControlIds --
        the actual mechanism Invoke-EntraPostureSnapshotEvaluation gates Complete/Partial on is
        which COLLECTOR declares a controlId, not a control's own requiredEvidenceDomains list
        (a real, hard-learned distinction -- see ENT-013.psd1's own applicability field). So this
        control always runs off ServicePrincipal's own coverage alone (never NotEvaluated just
        because the optional known-abused-app list was never configured), specifically to avoid
        the "any NotEvaluated result forces the whole run's exit code to Partial" rule
        (Get-EntraPostureRunExitCode's own priority table) turning every ordinary assessment
        Partial just because this one optional control exists. This evaluator therefore handles
        "no reference data available" itself, explicitly, as a single tenant-scoped
        NotApplicable -- deliberately NOT letting every service principal fall through to a
        vacuous Pass when there was nothing to check against, since "checked, found nothing" and
        "nothing was checked" are different claims a report reader needs to be able to tell
        apart. A local list that WAS configured but failed to parse is different: Invoke-
        EntraPostureCollectAndSeal's own KnownAbusedAppList coverage record (Malformed in that
        case) also names 'ENT-013', so that genuine failure does correctly make this control
        NotEvaluated too.

        Every Fail's own Rationale repeats the disclaimer this project makes at every layer that
        touches this dataset (the cmdlet, the README, this control's own .psd1 rationale): a
        match here means the application was observed being abused in real compromises, not that
        it is confirmed malicious in this tenant specifically -- manual review is required before
        acting on it. The Rationale also names the exact local file and its own recorded
        freshness (from KnownAbusedAppListMetadata, sourced from the refresh cmdlet's own
        sidecar if one exists) so a report reader knows exactly where to go check for a newer
        version, per the project owner's own explicit requirement for this control. Never
        produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        ENT-013.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'

    if (@($servicePrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-013-NO-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $knownAbusedApps = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'KnownAbusedApp'

    if (@($knownAbusedApps).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-013-NO-REFERENCE-DATA'
                Rationale = 'No known-abused-app reference data was available for this snapshot -- Update-EntraPostureKnownAbusedAppList was never run, or -KnownAbusedAppListPath was never configured. Nothing was actually checked.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $knownAbusedAppById = @{}
    foreach ($app in $knownAbusedApps) { $knownAbusedAppById[$app.entityId] = $app }

    $metadataRecords = @(Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'KnownAbusedAppListMetadata')
    $metadata = if ($metadataRecords.Count -gt 0) { $metadataRecords[0] } else { $null }
    $filePath = if ($metadata) { $metadata.properties.filePath } else { 'unknown' }
    $freshnessText = if ($metadata -and $metadata.properties.commitDateUtc) {
        "source last updated $($metadata.properties.commitDateUtc)"
    } elseif ($metadata -and $metadata.properties.fetchedAtUtc) {
        "fetched $($metadata.properties.fetchedAtUtc), source update date unknown"
    } else {
        'freshness unknown (no refresh metadata found next to this file)'
    }
    $disclaimer = "Match against a community-maintained list of applications observed in adversarial contexts -- presence does not confirm malicious intent; review manually before acting. Local list: '$filePath' ($freshnessText). Run Update-EntraPostureKnownAbusedAppList to check for a newer version."

    $evaluationResults = @(foreach ($sp in $servicePrincipals) {
        $appId = [string]$sp.properties.appId
        $evidenceRef = @([ordered]@{ entityId = $sp.entityId; entityType = 'ServicePrincipal' })

        if (-not [string]::IsNullOrWhiteSpace($appId) -and $knownAbusedAppById.ContainsKey($appId)) {
            $matchedApp = $knownAbusedAppById[$appId]
            $evidenceRef += [ordered]@{ entityId = $matchedApp.entityId; entityType = 'KnownAbusedApp' }
            [ordered]@{
                Scope = $sp.entityId; Status = 'Fail'; ReasonCode = 'ENT-013-KNOWN-ABUSED-APP-MATCH'
                Rationale = "Enterprise application '$($sp.displayName)' (appId $appId) matches known-abused-app entry '$($matchedApp.displayName)': $($matchedApp.properties.description) $disclaimer"
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $sp.entityId; Status = 'Pass'; ReasonCode = 'ENT-013-NO-KNOWN-ABUSED-APP-MATCH'
                Rationale = "Enterprise application '$($sp.displayName)' does not match any entry in the local known-abused-app list."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
