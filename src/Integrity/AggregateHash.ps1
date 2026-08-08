#Requires -Version 7.4

function Get-EntraPostureAggregateHash {
    <#
        .SYNOPSIS
        Computes the aggregate SHA-256 hash covering every file in a sealed bundle, exactly per
        engineering plan section 8.4.

        .DESCRIPTION
        "The aggregate hash is SHA-256 over the UTF-8/LF serialization of sorted records in the
        exact form `normalized-relative-path NUL byte-size NUL file-hash`. Paths use `/`,
        comparison is ordinal, and duplicates or case-collisions are rejected before sealing."

        This function implements that literally:
          1. Every entry's relativePath is normalized to use '/' (never '\').
          2. Entries are sorted by relativePath using ordinal string comparison (not
             culture-aware -- ordinal is the only comparison that produces the same order on
             every machine regardless of locale).
          3. Exact-duplicate paths and case-only collisions (e.g. 'Foo.json' and 'foo.json',
             which would collide on a case-insensitive filesystem) are both rejected before any
             hash is computed -- a build/seal must fail here, not silently pick one.
          4. Each record is serialized as "<path>\0<byteSize>\0<fileHash>" and joined with LF.
          5. The UTF-8 bytes of that joined text are SHA-256'd; the result is the aggregate hash.

        Field names are lowerCamelCase (relativePath/byteSize/fileHash, and the output's
        aggregateHash/recordCount) to match every JSON-facing schema in this project -- this
        function's output is embedded directly into an integrity record and must not require a
        casing conversion step at that boundary (an earlier PascalCase version of this function
        was caught failing schema validation for exactly that reason during Phase 3 end-to-end
        testing).

        .PARAMETER Entry
        One or more ordered dictionaries with keys relativePath (string), byteSize (integer),
        and fileHash (lowercase hex SHA-256 string, e.g. from Get-EntraPostureFileHash).
        Accepts pipeline input so a caller can stream file entries in.

        .OUTPUTS
        A single ordered dictionary: aggregateHash (lowercase hex) and recordCount.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Collections.Specialized.OrderedDictionary[]]$Entry
    )

    begin {
        $allEntries = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($e in $Entry) {
            foreach ($requiredKey in @('relativePath', 'byteSize', 'fileHash')) {
                if (-not $e.Contains($requiredKey)) {
                    throw "Get-EntraPostureAggregateHash: entry is missing required key '$requiredKey'."
                }
            }
            $allEntries.Add($e)
        }
    }

    end {
        if ($allEntries.Count -eq 0) {
            throw "Get-EntraPostureAggregateHash: at least one entry is required -- an empty bundle has nothing to seal."
        }

        # Normalize path separators before anything else touches the path.
        $normalized = foreach ($e in $allEntries) {
            [pscustomobject]@{
                relativePath = [string]$e.relativePath -replace '\\', '/'
                byteSize     = [long]$e.byteSize
                fileHash     = [string]$e.fileHash
            }
        }

        # Reject exact duplicates and case-only collisions before sorting/hashing anything.
        $byLowerPath = $normalized | Group-Object { $_.relativePath.ToLowerInvariant() }
        foreach ($group in $byLowerPath) {
            if ($group.Count -gt 1) {
                # -CaseSensitive is required here: Sort-Object -Unique is case-insensitive by
                # default and would collapse 'X.json'/'x.json' into one value, misclassifying a
                # case-only collision as an exact duplicate below.
                $distinctActualPaths = @($group.Group.relativePath | Sort-Object -Unique -CaseSensitive)
                if ($distinctActualPaths.Count -eq 1) {
                    throw "Get-EntraPostureAggregateHash: duplicate path in bundle entries: '$($distinctActualPaths[0])'."
                } else {
                    throw "Get-EntraPostureAggregateHash: case-only path collision in bundle entries: $($distinctActualPaths -join ', ')."
                }
            }
        }

        # Ordinal sort -- never culture-aware, so hash output is machine/locale independent.
        # Sort-Object's -Property/-Culture parameters do not guarantee true ordinal comparison
        # (culture-invariant is not the same thing as ordinal -- e.g. combining characters can
        # still compare differently), so this uses [string]::CompareOrdinal explicitly via
        # [Array]::Sort rather than relying on Sort-Object for a hash-affecting order.
        $sortedArray = @($normalized)
        [Array]::Sort($sortedArray, [Comparison[object]] {
            param($left, $right)
            return [string]::CompareOrdinal($left.relativePath, $right.relativePath)
        })
        $sorted = $sortedArray

        $records = foreach ($item in $sorted) {
            "{0}`0{1}`0{2}" -f $item.relativePath, $item.byteSize, $item.fileHash
        }
        $joined = ($records -join "`n")

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($bytes)
        } finally {
            $sha256.Dispose()
        }
        $hex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

        return [ordered]@{
            aggregateHash = $hex
            recordCount   = $sorted.Count
        }
    }
}
