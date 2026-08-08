#Requires -Version 7.4

<#
    Exit code contract. Engineering plan section 11.
    Values are frozen once shipped: a released exit code's meaning cannot change without a
    new major module version, since automation pipelines key off these numbers.
#>

$script:EntraPostureExitCodes = [ordered]@{
    Success                  = 0  # Completed with no unapproved control failures
    UnexpectedInternalError  = 1
    UnapprovedControlFailure = 2  # Completed with one or more unapproved control failures ('-Strict' also lands here)
    PartialAssessment        = 3  # Partial assessment or required evidence NotEvaluated
    InvalidInput             = 4  # Invalid configuration, schema, or command input
    AuthPreflightFailure     = 5  # Fatal authentication or permission-preflight failure
    IntegrityFailure         = 6  # Snapshot hash or signature failure
    CollectionFailure        = 7  # Fatal collection/API failure
    EvaluationOrReportFailure = 8 # Evaluation or report-generation failure
}

function Get-EntraPostureExitCode {
    <#
        .SYNOPSIS
        Resolves a named exit-code reason to its stable integer exit code.

        .DESCRIPTION
        Public commands must never hardcode a bare integer for `exit`/`return` — always resolve
        through this function so the contract in engineering plan section 11 stays the single
        source of truth for what each code means.

        .PARAMETER Reason
        One of the named keys in the frozen exit-code table.

        .EXAMPLE
        Get-EntraPostureExitCode -Reason InvalidInput
        # 4
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet(
            'Success',
            'UnexpectedInternalError',
            'UnapprovedControlFailure',
            'PartialAssessment',
            'InvalidInput',
            'AuthPreflightFailure',
            'IntegrityFailure',
            'CollectionFailure',
            'EvaluationOrReportFailure'
        )]
        [string]$Reason
    )

    return $script:EntraPostureExitCodes[$Reason]
}
