#Requires -Version 7.4

function Write-EntraPostureLog {
    <#
        .SYNOPSIS
        Emits a single structured, sanitized log record.

        .DESCRIPTION
        Every log record shares the same shape as an error record's diagnostic fields
        (correlation ID, stage, safe message) plus a severity level, per engineering plan
        section 11's "sanitized structured JSONL records" requirement. This function never
        writes to any network destination — engineering plan ADR-030 forbids external telemetry
        outright, and this function has no code path that could send one.

        Console output (Level -eq 'Info' or higher, written via Write-Host) is a concise
        operational cue only, per section 10.1 ("Console output is a concise operational
        summary, not the authoritative record") — the returned/written structured record is
        the authoritative one, not the console line.

        .PARAMETER Level
        Severity: Trace, Debug, Verbose, Info, Warning, or Error.

        .PARAMETER Stage
        Pipeline stage emitting this record.

        .PARAMETER Message
        Safe diagnostic text. Validated by Test-EntraPostureSafeDiagnosticText; throws
        rather than emitting unsafe content.

        .PARAMETER Source
        Optional collector/control/component name.

        .PARAMETER CorrelationId
        Correlation ID tying related records together. Generated if omitted.

        .PARAMETER Path
        Optional JSONL file to append the record to. When omitted, the record is only
        returned to the caller (and, for Info/Warning/Error, echoed as a concise console line) —
        it is the caller's responsibility to route it to a durable sink if one is needed.

        .OUTPUTS
        The structured ordered-dictionary log record.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Trace', 'Debug', 'Verbose', 'Info', 'Warning', 'Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [ValidateSet('Preflight', 'Collection', 'Validation', 'Evaluation', 'Reporting', 'Comparison', 'Build', 'Orchestration')]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [string]$Source,

        [Parameter()]
        [string]$CorrelationId,

        [Parameter()]
        [string]$Path
    )

    if (-not (Test-EntraPostureSafeDiagnosticText -Text $Message)) {
        throw "Refusing to write a log record: -Message matched an unsafe-content pattern (possible token/secret leak). Fix the message at its source; do not bypass this check."
    }

    if (-not $CorrelationId) {
        $CorrelationId = New-EntraPostureCorrelationId
    }

    $record = [ordered]@{
        Level          = $Level
        Stage          = $Stage
        Source         = $Source
        Message        = $Message
        CorrelationId  = $CorrelationId
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString('o')
    }

    if ($Path) {
        # Deterministic, single-property-order JSON per record; caller supplies an
        # already-created/writable path. No retry/locking logic here by design — durable
        # streaming semantics (bounded concurrency, ordering) belong to the Evidence layer
        # (ADR-031), not this general-purpose logging primitive.
        ($record | ConvertTo-Json -Depth 5 -Compress) | Add-Content -LiteralPath $Path -Encoding utf8NoBOM
    }

    if ($Level -in @('Info', 'Warning', 'Error')) {
        $prefix = switch ($Level) {
            'Warning' { '[!]' }
            'Error'   { '[x]' }
            default   { '[*]' }
        }
        Write-Host "$prefix $Message"
    }

    return $record
}
