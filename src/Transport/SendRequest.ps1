#Requires -Version 7.4

function Get-EntraPostureRetryDelay {
    <#
        .SYNOPSIS
        Computes a bounded exponential backoff delay with full jitter for a given retry attempt.

        .DESCRIPTION
        ADR-019 requires "bounded exponential backoff with jitter." Phase 1's regression specs
        found that neither EntraFalcon's nor Conditional Access Validator's transport
        implements jitter at all (pure 2^n backoff) -- this function exists specifically not to
        repeat that gap. Uses "full jitter" (a random delay uniformly chosen between 0 and the
        computed exponential ceiling, per the widely-cited AWS architecture blog formulation)
        rather than "equal jitter," because full jitter provides the strongest protection
        against synchronized retry storms across multiple concurrent collector instances, which
        is the exact failure mode ADR-031's "bounded concurrency" already anticipates elsewhere.

        .PARAMETER RetryAttempt
        1-based retry attempt number.

        .PARAMETER RetryAfterSeconds
        If the server supplied a Retry-After header, honor it exactly (no jitter applied) --
        the server is telling this client precisely how long to wait, which takes precedence
        over a locally-computed guess.

        .PARAMETER MaxDelaySeconds
        Ceiling on the computed exponential delay before jitter is applied. Default 60.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param (
        [Parameter(Mandatory)]
        [int]$RetryAttempt,

        [Parameter()]
        [Nullable[int]]$RetryAfterSeconds,

        [Parameter()]
        [int]$MaxDelaySeconds = 60
    )

    if ($null -ne $RetryAfterSeconds) {
        return [double]$RetryAfterSeconds
    }

    $ceiling = [Math]::Min($MaxDelaySeconds, [Math]::Pow(2, $RetryAttempt))
    return (Get-Random -Minimum 0.0 -Maximum $ceiling)
}

function Write-EntraPostureAuditRecord {
    <#
        .SYNOPSIS
        Writes one sanitized audit record for a single HTTP attempt.

        .DESCRIPTION
        Never receives or logs the Authorization header value or a query string -- only the
        host and the *matched allowlist path template* (not the literal request path with real
        object IDs in it), which is enough to prove "every request is traceable to an allowlist
        entry" (Phase 4 exit criterion) without putting tenant object identifiers in a log file.

        .PARAMETER CorrelationId
        .PARAMETER PathTemplate
        .PARAMETER Method
        .PARAMETER StatusCode
        .PARAMETER AttemptNumber
        .PARAMETER DurationMs
        .PARAMETER AuditLogPath
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CorrelationId,

        [Parameter(Mandatory)]
        [string]$PathTemplate,

        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [int]$StatusCode,

        [Parameter(Mandatory)]
        [int]$AttemptNumber,

        [Parameter(Mandatory)]
        [double]$DurationMs,

        [Parameter()]
        [string]$AuditLogPath
    )

    Write-EntraPostureLog -Level Debug -Stage Collection `
        -Message "$Method $PathTemplate -> $StatusCode (attempt $AttemptNumber, $([Math]::Round($DurationMs))ms)" `
        -Source $PathTemplate -CorrelationId $CorrelationId -Path $AuditLogPath | Out-Null
}

function Send-EntraPostureRequest {
    <#
        .SYNOPSIS
        The single centralized, allowlist-enforced, paginated, retrying transport client.
        Evaluators never call this function directly (ADR-019) -- only collectors do.

        .DESCRIPTION
        Engineering plan section 7.3 and ADR-019, applied together:
          - Every request is checked against Test-EntraPostureEndpointAllowed *before*
            anything is sent -- an unlisted host/path/method/stability combination never reaches
            Invoke-RestMethod at all, not even to fail; there is no code path that sends a
            request first and validates after.
          - Pagination follows '@odata.nextLink' with loop detection (a HashSet of already-seen
            links; a repeated link aborts pagination with a warning rather than looping forever
            -- the one genuinely strong pattern Phase 1 found in EntraFalcon's transport,
            carried forward deliberately).
          - Retries on 429/500/502/503/504 with Get-EntraPostureRetryDelay's jittered backoff,
            honoring a server Retry-After header exactly when present.
          - Every attempt is logged via Write-EntraPostureAuditRecord using only the matched
            *template*, never the literal path/query (which may contain tenant object IDs) and
            never the Authorization header.
          - Response validation: content-type must be application/json (or absent body for
            204), status code must be 2xx by the time retries are exhausted, and the body must
            parse via the project's strict JSON parser (rejects duplicate keys) before any field
            is read.

        .PARAMETER RequestHost
        .PARAMETER Path
        Literal request path (with real object IDs already substituted in) -- distinct from the
        allowlist's PathTemplate.

        .PARAMETER Method
        .PARAMETER ApiStability
        .PARAMETER AccessToken
        .PARAMETER QueryParameters
        Hashtable, appended to the initial request URL only (not to pagination follow-up
        requests, whose nextLink already carries its own complete query string).

        .PARAMETER Body
        Ordered dictionary, canonically serialized, for POST requests to read-only-classified
        endpoints (e.g. a What If evaluation payload).

        .PARAMETER MaxRetries
        Default 5.

        .PARAMETER MaxPages
        Hard ceiling on pagination pages as a truncation-detection backstop distinct from
        loop detection -- a well-behaved but enormous result set should be bounded by a
        collector-level budget decision, not silently consumed without limit here. Default 1000.

        .PARAMETER CorrelationId
        Generated if not supplied. The same ID covers every page/retry of one logical request.

        .PARAMETER UserAgent
        Defaults to an honest, versioned identifier -- Phase 1 flagged EntraFalcon's transport
        for defaulting to a User-Agent string that impersonates a real browser; this project's
        transport identifies itself accurately instead.

        .PARAMETER AuditLogPath
        Optional JSONL path for Write-EntraPostureAuditRecord; omit to skip durable audit
        logging (record still returned in-memory via -Verbose/-Debug streams either way).

        .PARAMETER AllowlistOverride
        Test-only. Production collector code must never pass this -- see
        Test-EntraPostureEndpointAllowed's -Allowlist parameter for why it exists.

        .PARAMETER SchemeOverride
        Test-only, defaults to 'https'. Production collector code must never pass 'http' -- see
        the inline comment at this function's URI-construction line for why it exists.

        .OUTPUTS
        Array of result objects (the concatenated 'value' arrays across all pages, or the single
        response body for a non-paginated/POST call).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter(Mandatory)]
        [string]$RequestHost,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [ValidateSet('Stable', 'Preview')]
        [string]$ApiStability,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter()]
        [hashtable]$QueryParameters,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$Body,

        [Parameter()]
        [int]$MaxRetries = 5,

        [Parameter()]
        [int]$MaxPages = 1000,

        [Parameter()]
        [string]$CorrelationId,

        [Parameter()]
        [string]$UserAgent = 'EntraPosture/0.1.0 (+internal-use)',

        [Parameter()]
        [string]$AuditLogPath,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https'
    )

    $allowCheckParams = @{
        RequestHost  = $RequestHost
        Path         = $Path
        Method       = $Method
        ApiStability = $ApiStability
    }
    if ($AllowlistOverride) {
        $allowCheckParams['Allowlist'] = $AllowlistOverride
    }
    $allowCheck = Test-EntraPostureEndpointAllowed @allowCheckParams
    if (-not $allowCheck.IsAllowed) {
        throw "Send-EntraPostureRequest: refusing to send -- $($allowCheck.Reason)"
    }
    $pathTemplate = $allowCheck.MatchedEntry.PathTemplate

    if (-not $CorrelationId) {
        $CorrelationId = New-EntraPostureCorrelationId
    }

    # ApiStability is not concatenated into the URL -- for Graph it's already encoded in Path
    # (/v1.0/ vs /beta/); it exists as an explicit parameter purely so
    # Test-EntraPostureEndpointAllowed above can distinguish a Stable-only allowlist entry
    # from its Preview counterpart at the same literal path, and so a future non-Graph host
    # whose stability isn't path-encoded has somewhere to declare it.
    #
    # SchemeOverride defaults to 'https' and production collector code must never pass 'http' --
    # it exists only so tests can exercise this function against a local HttpListener mock
    # server, which (confirmed directly: hardcoding https:// here caused every mock-server test
    # request to fail with no response at all, since HttpListener has no practical
    # cross-platform way to serve HTTPS in this dev environment) cannot itself serve TLS.
    $baseUri = "$($SchemeOverride)://$RequestHost$Path"
    if ($QueryParameters -and $QueryParameters.Count -gt 0) {
        $queryString = ($QueryParameters.GetEnumerator() | ForEach-Object { "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString([string]$_.Value))" }) -join '&'
        $baseUri = "$baseUri`?$queryString"
    }

    $headers = @{
        'Authorization'    = "Bearer $AccessToken"
        'User-Agent'       = $UserAgent
        'client-request-id' = $CorrelationId
        'Accept'           = 'application/json'
    }

    $bodyJson = $null
    if ($Body) {
        $bodyJson = ConvertTo-EntraPostureCanonicalJson -InputObject $Body
        $headers['Content-Type'] = 'application/json'
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $seenNextLinks = [System.Collections.Generic.HashSet[string]]::new()
    # The starting URI is seeded into the seen-set up front, not just nextLinks encountered
    # along the way -- otherwise a nextLink cycle that points straight back to the first page
    # isn't caught until it repeats a *second* time (one extra full round-trip through the
    # cycle), since the first page's own URL would never have been recorded as "seen" from its
    # initial fetch. Confirmed directly with a 2-page back-to-start cycle: without this seed,
    # loop detection took 3 fetches to trigger instead of 2.
    [void]$seenNextLinks.Add($baseUri)
    $currentUri = $baseUri
    $currentMethod = $Method
    $currentBody = $bodyJson
    $pageCount = 0

    while ($currentUri) {
        $pageCount++
        if ($pageCount -gt $MaxPages) {
            throw "Send-EntraPostureRequest: exceeded MaxPages ($MaxPages) while paginating '$pathTemplate' -- refusing to continue without an explicit higher budget (truncation-detection backstop, ADR-019)."
        }

        $retryAttempt = 0
        $response = $null

        while ($true) {
            $requestParams = @{
                Uri             = $currentUri
                Method          = $currentMethod
                Headers         = $headers
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($currentBody) {
                $requestParams['Body'] = $currentBody
            }

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                # This try/catch's only job is the HTTP call itself and the retry decision --
                # response *validation* (content-type, JSON well-formedness) deliberately happens
                # after this loop, not inside it. Validation failures were originally thrown from
                # inside this try block and caught by the same catch below, which had no HTTP
                # exception/status code to inspect and consequently reported every validation
                # failure as a misleading generic "status: no response" -- confirmed directly by
                # testing a deliberately-wrong-content-type mock response and seeing that exact
                # unhelpful message instead of the specific one this function actually throws.
                $rawResponse = Invoke-WebRequest @requestParams
                $stopwatch.Stop()
                Write-EntraPostureAuditRecord -CorrelationId $CorrelationId -PathTemplate $pathTemplate -Method $currentMethod -StatusCode $rawResponse.StatusCode -AttemptNumber ($retryAttempt + 1) -DurationMs $stopwatch.Elapsed.TotalMilliseconds -AuditLogPath $AuditLogPath
                break
            } catch {
                $stopwatch.Stop()
                $statusCode = $null
                $retryAfterHeader = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    # System.Net.Http.Headers.HttpResponseHeaders does not support bracket
                    # indexing the way a Hashtable does -- confirmed empirically that
                    # $Headers['Retry-After'] silently returns nothing even when the header is
                    # genuinely present (no error, just an empty result, which is the dangerous
                    # kind of wrong). TryGetValues is the correct HttpHeaders API for this.
                    [string[]]$retryAfterValues = $null
                    $hasRetryAfter = $_.Exception.Response.Headers.TryGetValues('Retry-After', [ref]$retryAfterValues)
                    if ($hasRetryAfter -and $retryAfterValues.Count -gt 0) {
                        $parsedRetryAfter = 0
                        if ([int]::TryParse($retryAfterValues[0], [ref]$parsedRetryAfter)) {
                            $retryAfterHeader = $parsedRetryAfter
                        }
                    }
                }

                Write-EntraPostureAuditRecord -CorrelationId $CorrelationId -PathTemplate $pathTemplate -Method $currentMethod -StatusCode ($statusCode ?? 0) -AttemptNumber ($retryAttempt + 1) -DurationMs $stopwatch.Elapsed.TotalMilliseconds -AuditLogPath $AuditLogPath

                $retryableStatusCodes = @(429, 500, 502, 503, 504)
                if ($statusCode -in $retryableStatusCodes -and $retryAttempt -lt $MaxRetries) {
                    $delay = Get-EntraPostureRetryDelay -RetryAttempt ($retryAttempt + 1) -RetryAfterSeconds $retryAfterHeader
                    Write-EntraPostureLog -Level Warning -Stage Collection -Message "Request to $pathTemplate returned $statusCode; retrying in $([Math]::Round($delay,1))s (attempt $($retryAttempt+1)/$MaxRetries)." -CorrelationId $CorrelationId | Out-Null
                    Start-Sleep -Seconds $delay
                    $retryAttempt++
                    continue
                }

                $safeStatus = if ($statusCode) { $statusCode } else { 'no response' }

                # Extract Graph's own {"error":{"code":..., "message":...}} body, the same
                # pattern already established in Invoke-EntraPostureTokenRequest -- confirmed
                # directly (via a real live-tenant PIM collection failure) that discarding this
                # and keeping only the HTTP status code makes an otherwise-precise error
                # (e.g. a licensing gate) indistinguishable from any other 400/403, forcing a slow
                # manual investigation for something Graph already explained in its response body.
                # Routed through the same Test-EntraPostureSafeDiagnosticText gate as every
                # other diagnostic message in this project -- Graph error bodies do not carry
                # tokens/secrets by design, but this is enforced rather than assumed.
                $errorDetail = $null
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    try {
                        $parsedError = ConvertFrom-EntraPostureJson -Json $_.ErrorDetails.Message
                        if ($parsedError -and $parsedError.Contains('error')) {
                            $graphError = $parsedError['error']
                            $code = if ($graphError -and $graphError.Contains('code')) { [string]$graphError['code'] } else { $null }
                            $message = if ($graphError -and $graphError.Contains('message')) { [string]$graphError['message'] } else { $null }
                            $errorDetail = (@($code, $message) | Where-Object { $_ }) -join ': '
                        }
                    } catch {
                        # Non-JSON or unexpected-shape error body is a real, expected case (e.g.
                        # an HTML error page from an intermediary proxy) -- fall through with no
                        # extra detail rather than treating a parse failure here as itself fatal.
                        $errorDetail = $null
                    }
                }

                $safeErrorDetail = $null
                if ($errorDetail) {
                    $sanitizedDetail = $errorDetail -replace '[\r\n]+', ' '
                    $safeErrorDetail = if (Test-EntraPostureSafeDiagnosticText -Text $sanitizedDetail) { $sanitizedDetail } else { 'detail withheld: matched unsafe-content pattern' }
                }

                $detailSuffix = if ($safeErrorDetail) { " Graph error: $safeErrorDetail" } else { '' }
                throw "Send-EntraPostureRequest: request to '$pathTemplate' failed after $($retryAttempt + 1) attempt(s), status: $safeStatus.$detailSuffix"
            }
        }

        # Response validation happens here, outside the HTTP retry try/catch above (see the
        # comment at that try block for why) -- a validation failure is a distinct, immediately
        # fatal error, never retried, never confused with a transport-level failure.
        $contentType = $rawResponse.Headers['Content-Type']
        if ($contentType -and -not (@($contentType) -join ';').Contains('application/json')) {
            throw "Send-EntraPostureRequest: unexpected Content-Type '$contentType' for '$pathTemplate' (expected application/json)."
        }

        if ([string]::IsNullOrWhiteSpace($rawResponse.Content)) {
            $response = $null
        } else {
            $response = ConvertFrom-EntraPostureJson -Json $rawResponse.Content
        }

        if ($null -ne $response -and $response.Contains('value')) {
            foreach ($item in @($response['value'])) {
                $results.Add($item)
            }
        } elseif ($null -ne $response) {
            $results.Add($response)
        }

        $nextLink = $null
        if ($null -ne $response -and $response.Contains('@odata.nextLink')) {
            $nextLink = [string]$response['@odata.nextLink']
        }

        if ([string]::IsNullOrWhiteSpace($nextLink)) {
            $currentUri = $null
        } elseif (-not $seenNextLinks.Add($nextLink)) {
            Write-EntraPostureLog -Level Warning -Stage Collection -Message "Pagination aborted for '$pathTemplate': API returned a repeated @odata.nextLink (loop-detection, ADR-019)." -CorrelationId $CorrelationId | Out-Null
            $currentUri = $null
        } else {
            $currentUri = $nextLink
            $currentMethod = 'GET'
            $currentBody = $null
        }
    }

    # The leading unary comma is required, not decorative: PowerShell unwraps a returned
    # single-element array back into its bare scalar element at the caller's assignment site --
    # confirmed empirically (the same class of bug as Phase 3's if/else-expression array
    # collapse, but triggered here by a plain `return $array`, not an if/else). Without the
    # comma, a result set containing exactly one item silently returns that item's own .Count
    # (e.g. 1, if it happens to be a 1-key dictionary) instead of the array's Count, and integer
    # indexing into it (`$result[0]`) silently returns $null instead of throwing.
    return ,$results.ToArray()
}
