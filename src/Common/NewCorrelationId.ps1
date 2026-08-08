#Requires -Version 7.4

function New-EntraPostureCorrelationId {
    <#
        .SYNOPSIS
        Generates a stable correlation ID for tying together log records, error records, and
        network requests that belong to the same logical operation.

        .DESCRIPTION
        A lowercase GUID string. Not a secret, not tenant-identifying on its own, safe to log
        and include in support requests.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure in-memory value generation with no external side effect; the New- verb reflects what the value represents, not a state change to guard with -WhatIf/-Confirm.')]
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    return [guid]::NewGuid().ToString()
}
