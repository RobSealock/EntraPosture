#Requires -Version 7.4

function Assert-EntraPostureNotImplemented {
    <#
        .SYNOPSIS
        Throws a consistent, structured "not yet implemented" error for public-command stubs.

        .DESCRIPTION
        Phase 2 (module skeleton and build chain) exports the full public command surface so
        the build/export/signing pipeline can be validated end-to-end, but the commands'
        real logic lands in later phases. Every stub calls this immediately so an accidental
        invocation fails loudly and traceably (exit code 1, per Get-EntraPostureExitCode
        'UnexpectedInternalError' — there is no successful-completion path for a command that
        does not exist yet) rather than silently returning an empty/misleading result. This is
        the same "no accidental pass" principle the control-result contract (ADR-016) applies
        to findings, applied here to command surface instead.

        .PARAMETER CommandName
        The public command name reporting as not yet implemented.

        .PARAMETER TargetPhase
        The engineering-plan phase expected to implement this command.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [string]$TargetPhase
    )

    $errorRecord = New-EntraPostureErrorRecord `
        -ErrorId 'COMMAND-NOT-IMPLEMENTED' `
        -Stage 'Orchestration' `
        -Source $CommandName `
        -Retryable $false `
        -Message "$CommandName is exported as part of the Phase 2 module skeleton but its logic is not yet implemented (expected in $TargetPhase)."

    throw "[$($errorRecord.ErrorId)] $($errorRecord.Message) (correlationId=$($errorRecord.CorrelationId))"
}
