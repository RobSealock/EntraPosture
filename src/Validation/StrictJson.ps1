#Requires -Version 7.4

function Test-EntraPostureJsonElementForDuplicateKey {
    <#
        .SYNOPSIS
        Internal recursive helper: walks a parsed JsonElement and throws on the first
        duplicate property name found within any single object.

        .DESCRIPTION
        Not exported; only called by Test-EntraPostureJsonKeyUniqueness. Separated into
        its own function (rather than a nested function) because PowerShell's ref-struct
        restriction pushed this implementation toward System.Text.Json.JsonDocument -- see the
        caller's DESCRIPTION for why Utf8JsonReader could not be used here at all.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Element
    )

    switch ($Element.ValueKind) {
        'Object' {
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $seen.Add($property.Name)) {
                    throw "Test-EntraPostureJsonKeyUniqueness: duplicate JSON key '$($property.Name)' found within the same object."
                }
                Test-EntraPostureJsonElementForDuplicateKey -Element $property.Value
            }
        }
        'Array' {
            foreach ($item in $Element.EnumerateArray()) {
                Test-EntraPostureJsonElementForDuplicateKey -Element $item
            }
        }
        default {
            # Scalars (String/Number/True/False/Null/Undefined) have nothing to recurse into.
        }
    }
}

function Test-EntraPostureJsonKeyUniqueness {
    <#
        .SYNOPSIS
        Scans raw JSON text and throws if any object contains a duplicate property name at the
        same nesting level.

        .DESCRIPTION
        PowerShell's built-in ConvertFrom-Json (with or without -AsHashtable) silently applies
        last-value-wins on duplicate keys rather than rejecting them -- engineering plan section
        8.2 requires "strict JSON parsing," and a document that redefines the same key twice is
        exactly the kind of ambiguous input that must not silently resolve to one interpretation.

        Implementation note: the obvious low-level tool for this is
        System.Text.Json.Utf8JsonReader, but it is a `ref struct` and .NET ref structs cannot be
        instantiated or held as a value inside PowerShell script code at all (confirmed
        empirically: "Cannot create an instance of the ByRef-like type... ByRef-like types are
        not supported in PowerShell"). This function instead parses with
        System.Text.Json.JsonDocument (an ordinary managed type, not a ref struct) and walks the
        resulting JsonElement tree recursively -- JsonDocument.Parse/EnumerateObject is confirmed
        (verified directly against this runtime, not assumed from documentation alone) to expose
        every duplicate property rather than silently collapsing them the way a
        deserialize-to-object path would, which is exactly the property this function needs.

        .PARAMETER Json
        Raw JSON text to scan.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Json
    )

    $docOptions = [System.Text.Json.JsonDocumentOptions]::new()
    $docOptions.CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow
    $docOptions.AllowTrailingCommas = $false
    $docOptions.MaxDepth = 64

    try {
        $document = [System.Text.Json.JsonDocument]::Parse($Json, $docOptions)
    } catch [System.Text.Json.JsonException] {
        throw "Test-EntraPostureJsonKeyUniqueness: input is not well-formed JSON: $($_.Exception.Message)"
    }

    try {
        Test-EntraPostureJsonElementForDuplicateKey -Element $document.RootElement
    } finally {
        $document.Dispose()
    }
}

function ConvertTo-EntraPostureOrderedDictionary {
    <#
        .SYNOPSIS
        Recursively converts a parsed PowerShell OrderedHashtable/array structure into the
        project's single canonical ordered-collection type
        (System.Collections.Specialized.OrderedDictionary).

        .DESCRIPTION
        `ConvertFrom-Json -AsHashtable` returns System.Management.Automation.OrderedHashtable
        (a Hashtable subtype) for objects, which is genuinely insertion-order-preserving in
        practice but is not the same .NET type as [ordered]@{} produces
        (System.Collections.Specialized.OrderedDictionary) and is not accepted by
        ConvertTo-EntraPostureCanonicalJson's strict type check. Rather than widen that
        check to accept two different "ordered-ish" types forever, this function normalizes at
        the JSON-parsing boundary so every part of the codebase downstream of parsing only ever
        sees one ordered-collection type.

        .PARAMETER InputObject
        The structure to normalize (typically -AsHashtable output).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $result = [ordered]@{}
            foreach ($key in $InputObject.Keys) {
                $result[[string]$key] = ConvertTo-EntraPostureOrderedDictionary -InputObject $InputObject[$key]
            }
            return $result
        }

        if ($InputObject -is [string]) {
            return $InputObject
        }

        if ($InputObject -is [System.Collections.IEnumerable]) {
            # Both wrappings are required, not decorative. `@()` around the whole foreach
            # (not just around the finished $items) is required because assigning a bare
            # foreach-as-expression's output collapses a single-iteration result to its scalar
            # value and turns a zero-iteration result into $null entirely -- confirmed directly:
            # a 1-element input array produced a bare converted scalar instead of a 1-element
            # array, and a 0-element input array produced $null instead of an empty array (this
            # is exactly the class of bug documented at length in src/Snapshots/SealSnapshot.ps1
            # for if/else-as-expression, but it turned out to apply here too, undiscovered since
            # Phase 3 because nothing had previously round-tripped a genuinely 1- or 0-element
            # JSON/psd1 array field through this function and closely inspected the result). The
            # leading comma on `return` is the separate, additional fix for the return-boundary
            # collapse (see src/Evidence/EvidenceProvider.ps1's Get-EntraPostureEvidenceRecord
            # for that mechanism's full empirical writeup) -- both bugs are real and distinct,
            # and both had to be fixed for this function to correctly round-trip every array size.
            $items = @(foreach ($item in $InputObject) {
                ConvertTo-EntraPostureOrderedDictionary -InputObject $item
            })
            return ,@($items)
        }

        return $InputObject
    }
}

function ConvertFrom-EntraPostureJson {
    <#
        .SYNOPSIS
        Strictly parses JSON text: rejects duplicate object keys, comments, and trailing
        commas, and returns the project's canonical ordered-dictionary shape.

        .DESCRIPTION
        The single supported way to parse JSON that will be treated as trusted structured data
        anywhere in this project (evidence files, manifests, control definitions read back from
        disk). Never use the bare ConvertFrom-Json cmdlet directly on data that feeds evidence,
        integrity, or control logic -- it silently accepts duplicate keys, and (confirmed
        directly, not merely suspected) also silently auto-converts any ISO-8601-shaped JSON
        *string* value into a live [System.DateTime] object rather than leaving it as a string,
        even under -AsHashtable. That directly violates section 8.2's "dates are UTC ISO 8601
        strings; culture-sensitive conversion is forbidden" -- and since
        ConvertTo-EntraPostureCanonicalJson correctly rejects [DateTime] as an unsupported
        .NET type, the practical effect was every round-trip of a record containing a
        date-shaped field (collectedAt, provenance timestamps, an entity's own
        createdDateTime/modifiedDateTime properties -- found via a normalizer round-trip test,
        not by inspection) throwing "unsupported .NET type 'System.DateTime'" downstream,
        arbitrarily far from the actual cause. -DateKind String is the documented fix: it keeps
        every JSON string a PowerShell string, unconditionally, regardless of its shape.

        .PARAMETER Json
        Raw JSON text.

        .PARAMETER MaxDepth
        Maximum nesting depth to accept, passed to the underlying parser. Defaults to 64, matching
        the duplicate-key scanner's reader options so both passes reject the same malformed-depth
        inputs consistently.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Json,

        [Parameter()]
        [int]$MaxDepth = 64
    )

    process {
        Test-EntraPostureJsonKeyUniqueness -Json $Json

        $parsed = $Json | ConvertFrom-Json -AsHashtable -Depth $MaxDepth -DateKind String -ErrorAction Stop
        return (ConvertTo-EntraPostureOrderedDictionary -InputObject $parsed)
    }
}
