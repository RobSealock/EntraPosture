#Requires -Version 7.4

function Get-EntraPostureRunExitCode {
    <#
        .SYNOPSIS
        Applies engineering plan section 11's priority table to decide one run's exit code.

        .DESCRIPTION
        Priority order, highest first (matches section 11: "operational/integrity/partial
        failures take precedence over compliance outcome"):
          1. -OperationalFailureReason, if supplied at all (any of UnexpectedInternalError,
             InvalidInput, AuthPreflightFailure, IntegrityFailure, CollectionFailure,
             EvaluationOrReportFailure) -- an operational failure always wins outright, before
             any compliance result is even considered.
          2. Partial assessment: -IsPartial, or any -Results entry with status 'NotEvaluated'.
          3. Compliance outcome: exit code 2 if any -Results entry is an *unapproved* Fail
             (status 'Fail' and deviation is null) -- or, under -Strict, if any -Results entry
             is Fail at all, deviation or not (section 11: "-Strict makes all technical failures
             return code 2").
          4. Otherwise 0 (Success).

        .PARAMETER OperationalFailureReason
        Optional. One of Get-EntraPostureExitCode's non-Success/non-compliance reason names.
        When supplied, every other parameter is ignored -- this always wins.

        .PARAMETER IsPartial
        .PARAMETER Results
        Array of ordered dictionaries matching control-result.schema.json.

        .PARAMETER Strict
        .OUTPUTS
        Integer exit code.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter()]
        [ValidateSet('UnexpectedInternalError', 'InvalidInput', 'AuthPreflightFailure', 'IntegrityFailure', 'CollectionFailure', 'EvaluationOrReportFailure')]
        [string]$OperationalFailureReason,

        [Parameter()]
        [bool]$IsPartial = $false,

        [Parameter()]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$Results = @(),

        [Parameter()]
        [switch]$Strict
    )

    if ($OperationalFailureReason) {
        return Get-EntraPostureExitCode -Reason $OperationalFailureReason
    }

    $hasNotEvaluated = @($Results | Where-Object { $_.status -eq 'NotEvaluated' }).Count -gt 0
    if ($IsPartial -or $hasNotEvaluated) {
        return Get-EntraPostureExitCode -Reason 'PartialAssessment'
    }

    $hasUnapprovedFail = if ($Strict) {
        @($Results | Where-Object { $_.status -eq 'Fail' }).Count -gt 0
    } else {
        @($Results | Where-Object { $_.status -eq 'Fail' -and -not $_.deviation }).Count -gt 0
    }
    if ($hasUnapprovedFail) {
        return Get-EntraPostureExitCode -Reason 'UnapprovedControlFailure'
    }

    return Get-EntraPostureExitCode -Reason 'Success'
}
