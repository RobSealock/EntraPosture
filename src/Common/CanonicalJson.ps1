#Requires -Version 7.4

function ConvertTo-EntraPostureCanonicalJson {
    <#
        .SYNOPSIS
        Serializes a canonical record to a deterministic JSON string for hashing and
        byte-equivalence comparison.

        .DESCRIPTION
        Engineering plan section 8.2: "Canonical hashing uses a dedicated deterministic
        serializer with defined property order, escaping, invariant numbers, UTF-8 encoding,
        and LF line endings. Ordinary ConvertTo-Json output is not a hash contract." This
        function is that dedicated serializer -- it is never appropriate to hash the output of
        the built-in ConvertTo-Json for integrity purposes.

        Design choices, stated explicitly so a future reader doesn't have to reverse-engineer
        them from behavior:
          - Output is always fully compact (no insignificant whitespace). This removes an
            entire class of "same data, different bytes" ambiguity rather than trying to pin
            down one specific pretty-printing style as canonical.
          - Property order is the input ordered dictionary's enumeration order, not
            alphabetical. Determinism therefore depends on callers constructing records
            deterministically (ADR-014 already requires ordered dictionaries as canonical
            records for exactly this reason) -- this function enforces that requirement at the
            type level rather than trusting callers: only
            [System.Collections.Specialized.OrderedDictionary], arrays, strings, booleans,
            integers, doubles, decimals, and $null are accepted. A plain (unordered)
            [hashtable] is rejected, because enumeration order is not guaranteed -- and
            PSCustomObject is rejected because section 8.2 reserves it for presentation only,
            never for canonical/hashed records.
          - Non-finite doubles (NaN, +/-Infinity) are rejected outright, per section 8.2's
            "non-finite numbers... are rejected."
          - Serialization uses System.Text.Json.Utf8JsonWriter directly (not
            ConvertTo-Json) so escaping and number formatting come from a single well-tested
            .NET primitive rather than a hand-rolled string builder.

        .PARAMETER InputObject
        The ordered-dictionary-rooted structure to serialize. Pipeline-capable.

        .OUTPUTS
        A single-line, UTF-8, LF-normalized JSON string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    begin {
        function Write-EntraPostureCanonicalValue {
            param (
                [Parameter(Mandatory)]
                [System.Text.Json.Utf8JsonWriter]$Writer,

                [AllowNull()]
                $Value
            )

            if ($null -eq $Value) {
                $Writer.WriteNullValue()
                return
            }

            if ($Value -is [System.Collections.Specialized.OrderedDictionary]) {
                $Writer.WriteStartObject()
                foreach ($key in $Value.Keys) {
                    if ($key -isnot [string]) {
                        throw "Canonical JSON error: dictionary key '$key' (type $($key.GetType().FullName)) is not a string."
                    }
                    $Writer.WritePropertyName([string]$key)
                    Write-EntraPostureCanonicalValue -Writer $Writer -Value $Value[$key]
                }
                $Writer.WriteEndObject()
                return
            }

            if ($Value -is [hashtable]) {
                throw "Canonical JSON error: plain [hashtable] is not accepted (enumeration order is not guaranteed). Use [ordered]@{} instead."
            }

            if ($Value -is [System.Management.Automation.PSCustomObject]) {
                throw "Canonical JSON error: PSCustomObject is reserved for presentation (engineering plan section 8.2) and is never a canonical/hashed record. Use an ordered dictionary."
            }

            if ($Value -is [string]) {
                $Writer.WriteStringValue([string]$Value)
                return
            }

            if ($Value -is [bool]) {
                $Writer.WriteBooleanValue([bool]$Value)
                return
            }

            if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
                $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
                $Writer.WriteNumberValue([long]$Value)
                return
            }

            if ($Value -is [decimal]) {
                $Writer.WriteNumberValue([decimal]$Value)
                return
            }

            if ($Value -is [double] -or $Value -is [single]) {
                $doubleValue = [double]$Value
                if ([double]::IsNaN($doubleValue) -or [double]::IsInfinity($doubleValue)) {
                    throw "Canonical JSON error: non-finite number (NaN/Infinity) cannot be serialized."
                }
                $Writer.WriteNumberValue($doubleValue)
                return
            }

            if ($Value -is [System.Collections.IEnumerable]) {
                $Writer.WriteStartArray()
                foreach ($item in $Value) {
                    Write-EntraPostureCanonicalValue -Writer $Writer -Value $item
                }
                $Writer.WriteEndArray()
                return
            }

            throw "Canonical JSON error: unsupported .NET type '$($Value.GetType().FullName)'. Only ordered dictionaries, arrays, strings, booleans, integers, doubles, decimals, and `$null are supported."
        }
    }

    process {
        $stream = [System.IO.MemoryStream]::new()
        $writerOptions = [System.Text.Json.JsonWriterOptions]::new()
        $writerOptions.Indented = $false
        $writer = [System.Text.Json.Utf8JsonWriter]::new($stream, $writerOptions)

        try {
            Write-EntraPostureCanonicalValue -Writer $writer -Value $InputObject
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }

        $bytes = $stream.ToArray()
        $stream.Dispose()

        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        # Defensive normalization: compact JSON should not contain a raw, unescaped newline
        # outside string content, but normalize CRLF -> LF in case a future .NET runtime
        # ever behaves differently, per the LF requirement in section 8.2.
        return ($text -replace "`r`n", "`n")
    }
}
