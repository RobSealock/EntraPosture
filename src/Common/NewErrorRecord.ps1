#Requires -Version 7.4

function Test-EntraPostureSafeDiagnosticText {
    <#
        .SYNOPSIS
        Rejects diagnostic text that looks like it contains a bearer token, authorization
        header, or token-bearing URL query string.

        .DESCRIPTION
        A defensive, best-effort pattern check, not a guarantee of safety — engineering plan
        section 13 requires "no secrets or tokens in config, logs, errors, snapshots, reports,
        or test artifacts" as a mandatory security property. This function is the single place
        that rule is enforced for error/log text, so every call site inherits the same check
        rather than re-implementing it. It is intentionally conservative: it flags common token
        shapes (JWT-looking strings, 'Bearer ' prefixes, 'access_token=' query fragments) and
        callers must not work around a rejection by pre-truncating text to dodge the pattern.

        .PARAMETER Text
        The candidate diagnostic string.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $true
    }

    $unsafePatterns = @(
        'Bearer\s+[A-Za-z0-9\-_\.]+',
        'access_token=',
        'refresh_token=',
        'client_secret=',
        'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' # JWT shape (header.payload.signature)
    )

    foreach ($pattern in $unsafePatterns) {
        if ($Text -match $pattern) {
            return $false
        }
    }

    return $true
}

function New-EntraPostureErrorRecord {
    <#
        .SYNOPSIS
        Builds a structured, sanitized error record matching the engineering plan section 11
        contract: stable error ID, stage, collector/control source, retryability, endpoint
        class, correlation ID, and safe diagnostic detail.

        .DESCRIPTION
        This is the only supported way to construct an error record in this module. Callers
        never build their own ad hoc error shape, so every log/error sink downstream can rely
        on one stable structure. Throws if the diagnostic message fails the safe-text check
        (Test-EntraPostureSafeDiagnosticText) rather than silently emitting unsafe text —
        a caller that trips this must fix the message at the source, not bypass the check.

        .PARAMETER ErrorId
        A stable, human-meaningful identifier for this error class (e.g.
        'TRANSPORT-RETRY-EXHAUSTED'), not a GUID — used for grouping/searching across runs.

        .PARAMETER Stage
        The pipeline stage that raised the error.

        .PARAMETER Message
        Safe diagnostic detail. Must not contain tokens, secrets, or authorization headers.

        .PARAMETER Source
        Optional collector or control name.

        .PARAMETER Retryable
        Whether the operation that failed is safe to retry.

        .PARAMETER EndpointClass
        Optional transport endpoint classification (e.g. 'Graph.v1.0', 'Graph.beta', 'ARM').

        .PARAMETER CorrelationId
        Correlation ID tying this error to related log/request records. Generated if omitted.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure in-memory record construction with no external side effect; the New- verb reflects what the value represents, not a state change to guard with -WhatIf/-Confirm.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z0-9][A-Z0-9\-]{2,63}$')]
        [string]$ErrorId,

        [Parameter(Mandatory)]
        [ValidateSet('Preflight', 'Collection', 'Validation', 'Evaluation', 'Reporting', 'Comparison', 'Build', 'Orchestration')]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [string]$Source,

        [Parameter()]
        [bool]$Retryable = $false,

        [Parameter()]
        [string]$EndpointClass,

        [Parameter()]
        [string]$CorrelationId
    )

    if (-not (Test-EntraPostureSafeDiagnosticText -Text $Message)) {
        throw "Refusing to construct an error record: -Message for error '$ErrorId' matched an unsafe-content pattern (possible token/secret leak). Fix the message at its source; do not bypass this check."
    }

    if (-not $CorrelationId) {
        $CorrelationId = New-EntraPostureCorrelationId
    }

    return [ordered]@{
        ErrorId        = $ErrorId
        Stage          = $Stage
        Source         = $Source
        Retryable      = $Retryable
        EndpointClass  = $EndpointClass
        CorrelationId  = $CorrelationId
        Message        = $Message
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString('o')
    }
}
