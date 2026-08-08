#Requires -Version 7.4

function Set-EntraPostureControlResultDeviation {
    <#
        .SYNOPSIS
        Attaches the matching approved, in-scope, unexpired Deviation's ID to each ControlResult
        that has one -- never modifies the result's underlying technical status.

        .DESCRIPTION
        Engineering plan section 9.3: "Deviations are separate immutable annotations... They
        never modify the underlying status... Expired or scope-mismatched approvals have no
        effect." A deviation matches a result when controlId and objectScope/scope are exactly
        equal (never fuzzy/prefix matching -- "a deviation approved for one object never
        silently covers another") and -AsOfDate falls within [startDate, expiryDate] inclusive.
        Date comparison uses ordinal string comparison on the zero-padded 'yyyy-MM-dd' form
        (never [datetime] parsing/culture-sensitive comparison, per section 8.2), which is
        correct for ISO 8601 calendar dates because lexical and chronological order coincide
        for that fixed-width, zero-padded format.

        Attaches a matching deviation regardless of the result's own status (Pass/Fail/
        NotApplicable/NotEvaluated/Error all keep whatever deviation field value matches) --
        deciding that only a 'Fail' result's deviation is meaningful enough to change how it is
        *displayed* ("Fail -- Approved Deviation") is a reporting/presentation choice, made by
        the reporting layer at render time, not by this matching function.

        Throws if more than one deviation matches the same (controlId, scope) pair for the same
        -AsOfDate -- an ambiguous match is a deviation-registry integrity problem to surface
        loudly, not something to resolve by silently picking one.

        .PARAMETER Results
        Array of ordered dictionaries matching control-result.schema.json.

        .PARAMETER Deviations
        Array of ordered dictionaries matching deviation.schema.json.

        .PARAMETER AsOfDate
        Defaults to today (UTC). Exists as a parameter (not hardcoded to "now") so evaluation
        logic and its tests are reproducible against a fixed date rather than depending on
        wall-clock time at test-run time.

        .OUTPUTS
        A new array of ordered dictionaries -- copies of -Results with the 'deviation' field
        updated. Input records are never mutated in place.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory data transformation -- returns new records, never mutates input or touches disk/network.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary[]]$Results,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Deviations,

        [Parameter()]
        [datetime]$AsOfDate = (Get-Date).ToUniversalTime().Date
    )

    $asOfString = $AsOfDate.ToString('yyyy-MM-dd')

    $updatedResults = @(foreach ($result in $Results) {
        $matchingEntries = @($Deviations | Where-Object {
            $_.controlId -eq $result.controlId -and
            $_.objectScope -eq $result.scope -and
            ([string]::CompareOrdinal($_.startDate, $asOfString) -le 0) -and
            ([string]::CompareOrdinal($asOfString, $_.expiryDate) -le 0)
        })

        if ($matchingEntries.Count -gt 1) {
            throw "Set-EntraPostureControlResultDeviation: $($matchingEntries.Count) deviations match controlId '$($result.controlId)' scope '$($result.scope)' as of $asOfString -- ambiguous, refusing to pick one. Deviation IDs: $(($matchingEntries | ForEach-Object { $_.deviationId }) -join ', ')."
        }

        $updated = [ordered]@{}
        foreach ($key in $result.Keys) { $updated[$key] = $result[$key] }
        $updated['deviation'] = if ($matchingEntries.Count -eq 1) { $matchingEntries[0].deviationId } else { $null }
        $updated
    })

    return ,@($updatedResults)
}
