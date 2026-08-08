#Requires -Version 7.4

function Test-EntraPosturePreflight {
    <#
        .SYNOPSIS
        Projects a set of declared collector requirements against an acquired token's actual
        granted permissions (and, when available, real endpoint-verification results) into the
        coverage.schema.json-shaped record.

        .DESCRIPTION
        Engineering plan section 7.2's six-item coverage-accounting list, applied per collector:
          1. Access requested   -- this run's RequiredPermissions declaration
          2. Rights present     -- GrantedPermissions (from Get-EntraPostureTokenGrantedPermission)
          3. Rights expected    -- same declaration (the collector's own documented minimum)
          4. Access verified    -- from -EndpointVerificationResults; **never assumed true**
             when not supplied, per "a Global Reader label never implies complete coverage"
          5. Evidence status    -- derived, not asserted by the caller
          6. Affected controls/report sections -- passed through from the declaration

        EvidenceStatus derivation, most-to-least severe:
          - 'Denied' if none of the required permissions are present in the granted set at all
          - 'Incomplete' if some but not all required permissions are present
          - 'Collected' only if every required permission is present AND -EndpointVerificationResults
            explicitly confirms the endpoint call actually succeeded
          - 'Unavailable' if every required permission is present but no verification result was
            supplied -- this is the deliberately conservative default: token claims alone are
            "should work," not "did work," and this function refuses to call that Collected.

        .PARAMETER CollectorRequirements
        Array from New-EntraPostureCollectorRequirement.

        .PARAMETER GrantedPermissions
        String array from Get-EntraPostureTokenGrantedPermission's .Permissions field.

        .PARAMETER EndpointVerificationResults
        Optional hashtable: CollectorName -> $true/$false, populated by whatever actually
        exercised each collector's endpoint(s) (e.g. a real Send-EntraPostureRequest probe
        call during Phase 6). Absent entries are treated as not-yet-verified, not as failed.

        .OUTPUTS
        Ordered dictionary matching coverage.schema.json: { collectors: [...] }.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary[]]$CollectorRequirements,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$GrantedPermissions,

        [Parameter()]
        [hashtable]$EndpointVerificationResults = @{}
    )

    $collectorRecords = foreach ($requirement in $CollectorRequirements) {
        $required = @($requirement.RequiredPermissions)
        $present = @($required | Where-Object { $_ -in $GrantedPermissions })
        $accessVerified = $false
        if ($EndpointVerificationResults.ContainsKey($requirement.CollectorName)) {
            $accessVerified = [bool]$EndpointVerificationResults[$requirement.CollectorName]
        }

        $evidenceStatus =
            if ($present.Count -eq 0) { 'Denied' }
            elseif ($present.Count -lt $required.Count) { 'Incomplete' }
            elseif ($accessVerified) { 'Collected' }
            else { 'Unavailable' }

        [ordered]@{
            collectorName           = $requirement.CollectorName
            accessRequested         = $required
            rightsPresentInToken    = $present
            rightsExpected          = $required
            accessVerified          = $accessVerified
            evidenceStatus          = $evidenceStatus
            affectedControlIds      = @($requirement.AffectedControlIds)
            affectedReportSections  = @($requirement.AffectedReportSections)
        }
    }

    return [ordered]@{
        collectors = @($collectorRecords)
    }
}

function Get-EntraPostureUnaffectedControlId {
    <#
        .SYNOPSIS
        Convenience helper: returns the set of control IDs that are safe to evaluate (every
        collector they depend on has evidenceStatus 'Collected') from a coverage record.

        .DESCRIPTION
        The inverse -- control IDs depending on any collector NOT at 'Collected' -- is exactly
        the set that must become NotEvaluated per ADR-015. This function returns the *safe* set
        so a future evaluator gate (Phase 7) can default-deny anything not explicitly returned
        here, matching the project's consistent "no accidental pass" posture.

        .PARAMETER Coverage
        Output of Test-EntraPosturePreflight.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Coverage
    )

    $blockedControlIds = [System.Collections.Generic.HashSet[string]]::new()
    $allControlIds = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($collector in $Coverage.collectors) {
        foreach ($controlId in @($collector.affectedControlIds)) {
            [void]$allControlIds.Add($controlId)
            if ($collector.evidenceStatus -ne 'Collected') {
                [void]$blockedControlIds.Add($controlId)
            }
        }
    }

    return @($allControlIds | Where-Object { $_ -notin $blockedControlIds } | Sort-Object)
}
