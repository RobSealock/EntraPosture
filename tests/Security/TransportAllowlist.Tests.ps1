#Requires -Version 7.4
#Requires -Modules Pester

<#
    Security tests for src/Transport: the endpoint allowlist registry/matcher and the
    centralized Send-EntraPostureRequest client. This is the concrete proof of Phase 4's
    exit criterion "every request is traceable to an allowlist entry" -- these tests run a real
    local HttpListener mock server (not a mocked function) so the assertions cover the actual
    HTTP call, retry, pagination, and content-type-validation code paths, not just the allowlist
    lookup in isolation.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/NewCorrelationId.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/NewErrorRecord.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Logging/WriteLog.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Authentication/LoopbackListener.ps1')
    . (Join-Path $script:RepoRoot 'src/Transport/EndpointAllowlist.ps1')
    . (Join-Path $script:RepoRoot 'src/Transport/SendRequest.ps1')

    # Background mock HTTP server: a real System.Net.HttpListener run on a background PowerShell
    # runspace (not [System.Threading.Tasks.Task]::Run -- that has no overload accepting this
    # many arguments, confirmed directly). Canned responses are supplied through a thread-safe
    # ConcurrentQueue, which is safe to share by reference across runspaces in the same process
    # (no serialization boundary for in-process runspaces).
    $script:MockServerScript = {
        param($Listener, $ResponseQueue, $RequestLog)
        while ($Listener.IsListening) {
            try {
                $context = $Listener.GetContext()
            } catch {
                break
            }
            $RequestLog.Add($context.Request.RawUrl)
            $resp = $null
            if (-not $ResponseQueue.TryDequeue([ref]$resp)) {
                $resp = @{ StatusCode = 500; Body = '{"error":"no canned response queued"}'; ContentType = 'application/json' }
            }
            $context.Response.StatusCode = $resp.StatusCode
            if ($resp.Headers) {
                foreach ($h in $resp.Headers.GetEnumerator()) {
                    $context.Response.Headers.Add($h.Key, $h.Value)
                }
            }
            $context.Response.ContentType = $resp.ContentType
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$resp.Body)
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.OutputStream.Close()
        }
    }

    function script:Start-EntraPostureMockServer {
        $port = Get-EntraPostureAvailableLoopbackPort
        $prefix = "http://127.0.0.1:$port/"
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add($prefix)
        $listener.Start()

        $responseQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
        $requestLog = [System.Collections.Concurrent.ConcurrentBag[string]]::new()

        $ps = [powershell]::Create()
        $ps.AddScript($script:MockServerScript).AddArgument($listener).AddArgument($responseQueue).AddArgument($requestLog) | Out-Null
        $asyncResult = $ps.BeginInvoke()

        return [ordered]@{
            Listener      = $listener
            PowerShell    = $ps
            AsyncResult   = $asyncResult
            ResponseQueue = $responseQueue
            RequestLog    = $requestLog
            Port          = $port
            HostHeader    = "127.0.0.1:$port"
        }
    }

    function script:Stop-EntraPostureMockServer {
        param($Server)
        if ($Server.Listener.IsListening) {
            $Server.Listener.Stop()
        }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Add-EntraPostureMockResponse {
        param($Server, [int]$StatusCode, [string]$Body, [string]$ContentType = 'application/json', [hashtable]$Headers)
        $Server.ResponseQueue.Enqueue(@{ StatusCode = $StatusCode; Body = $Body; ContentType = $ContentType; Headers = $Headers })
    }
}

Describe 'Get-EntraPostureEndpointAllowlist' {
    It 'returns every entry with a Host, PathTemplate, ApiStability, and Method' {
        $entries = Get-EntraPostureEndpointAllowlist
        $entries.Count | Should -BeGreaterThan 0
        foreach ($entry in $entries) {
            $entry.Host | Should -Not -BeNullOrEmpty
            $entry.PathTemplate | Should -Not -BeNullOrEmpty
            $entry.ApiStability | Should -BeIn @('Stable', 'Preview')
            $entry.Method | Should -BeIn @('GET', 'POST')
        }
    }

    It 'requires every POST entry to declare a non-null ReadOnlyClassification' {
        $entries = Get-EntraPostureEndpointAllowlist
        $postEntries = @($entries | Where-Object { $_.Method -eq 'POST' })
        $postEntries.Count | Should -BeGreaterThan 0
        foreach ($entry in $postEntries) {
            $entry.ReadOnlyClassification | Should -Not -BeNullOrEmpty
        }
    }

    It 'every registry entry self-consistently matches its own path template regex with placeholders substituted' {
        $entries = Get-EntraPostureEndpointAllowlist
        foreach ($entry in $entries) {
            $samplePath = $entry.PathTemplate -replace '\{scope\}', 'subscriptions/00000000-0000-0000-0000-000000000000' -replace '\{[^}]+\}', '11111111-1111-1111-1111-111111111111'
            $pattern = ConvertTo-EntraPosturePathTemplateRegex -PathTemplate $entry.PathTemplate
            $samplePath | Should -Match $pattern -Because "PathTemplate '$($entry.PathTemplate)' should match its own instantiated sample path"
        }
    }
}

Describe 'ConvertTo-EntraPosturePathTemplateRegex' {
    It 'matches a single-segment {id}-style placeholder to exactly one path segment' {
        $pattern = ConvertTo-EntraPosturePathTemplateRegex -PathTemplate '/v1.0/groups/{groupId}'
        '/v1.0/groups/abc-123' | Should -Match $pattern
        '/v1.0/groups/abc-123/owners' | Should -Not -Match $pattern
    }

    It 'matches the special {scope} placeholder across multiple path segments' {
        $pattern = ConvertTo-EntraPosturePathTemplateRegex -PathTemplate '/{scope}/providers/Microsoft.Authorization/roleAssignments'
        '/subscriptions/abc-123/providers/Microsoft.Authorization/roleAssignments' | Should -Match $pattern
        '/subscriptions/abc-123/resourceGroups/rg1/providers/Microsoft.Authorization/roleAssignments' | Should -Match $pattern
        '/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/roleAssignments' | Should -Match $pattern
    }

    It 'does not match a path missing a required literal segment' {
        $pattern = ConvertTo-EntraPosturePathTemplateRegex -PathTemplate '/v1.0/groups/{groupId}/owners'
        '/v1.0/groups/abc-123' | Should -Not -Match $pattern
    }
}

Describe 'Test-EntraPostureEndpointAllowed' {
    It 'allows an exact-match GET entry' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'graph.microsoft.com' -Path '/v1.0/users' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
        $result.MatchedEntry.PathTemplate | Should -Be '/v1.0/users'
    }

    It 'allows a templated GET entry with a real object ID substituted' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'graph.microsoft.com' -Path '/v1.0/groups/abc-123' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
        $result.MatchedEntry.PathTemplate | Should -Be '/v1.0/groups/{groupId}'
    }

    It 'denies a POST to a path whose only registry entry is GET' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'graph.microsoft.com' -Path '/v1.0/users' -Method POST -ApiStability Stable
        $result.IsAllowed | Should -BeFalse
    }

    It 'allows a POST entry explicitly classified read-only' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'graph.microsoft.com' -Path '/v1.0/identity/conditionalAccess/evaluate' -Method POST -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
        $result.MatchedEntry.ReadOnlyClassification | Should -Be 'WhatIfEvaluation'
    }

    It 'denies when ApiStability does not match the registered entry' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'graph.microsoft.com' -Path '/v1.0/users' -Method GET -ApiStability Preview
        $result.IsAllowed | Should -BeFalse
    }

    It 'denies an unlisted host entirely' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'evil.example.com' -Path '/v1.0/users' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeFalse
        $result.Reason | Should -Not -BeNullOrEmpty
    }

    It 'matches Azure ARM {scope} at subscription depth' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'management.azure.com' -Path '/subscriptions/abc-123/providers/Microsoft.Authorization/roleAssignments' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
    }

    It 'matches Azure ARM {scope} at resource-group depth' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'management.azure.com' -Path '/subscriptions/abc-123/resourceGroups/rg1/providers/Microsoft.Authorization/roleAssignments' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
    }

    It 'matches Azure ARM {scope} at management-group depth' {
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'management.azure.com' -Path '/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/roleAssignments' -Method GET -ApiStability Stable
        $result.IsAllowed | Should -BeTrue
    }

    It 'accepts a test-only -Allowlist override in place of the production registry' {
        $customAllowlist = @([ordered]@{ Host = 'mock.local'; PathTemplate = '/thing'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' })
        $result = Test-EntraPostureEndpointAllowed -RequestHost 'mock.local' -Path '/thing' -Method GET -ApiStability Stable -Allowlist $customAllowlist
        $result.IsAllowed | Should -BeTrue
    }
}

Describe 'Get-EntraPostureRetryDelay' {
    It 'returns the exact Retry-After value when supplied, with no jitter' {
        Get-EntraPostureRetryDelay -RetryAttempt 3 -RetryAfterSeconds 7 | Should -Be 7.0
    }

    It 'returns a jittered value between 0 and the exponential ceiling when no Retry-After is supplied' {
        1..20 | ForEach-Object {
            $delay = Get-EntraPostureRetryDelay -RetryAttempt 2 -MaxDelaySeconds 60
            $delay | Should -BeGreaterOrEqual 0
            $delay | Should -BeLessOrEqual 4.0
        }
    }

    It 'caps the exponential ceiling at MaxDelaySeconds for a large retry attempt' {
        1..10 | ForEach-Object {
            $delay = Get-EntraPostureRetryDelay -RetryAttempt 20 -MaxDelaySeconds 5
            $delay | Should -BeLessOrEqual 5.0
        }
    }
}

Describe 'Send-EntraPostureRequest' {
    BeforeEach {
        $script:Server = Start-EntraPostureMockServer
        $script:TestAllowlist = @(
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/items'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/page1'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/page2'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/single'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/throttled'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/badcontenttype'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/loop1'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/loop2'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/graph-error'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/mock/malformed-error'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        )
    }

    AfterEach {
        Stop-EntraPostureMockServer -Server $script:Server
    }

    It 'returns items from a single-page response' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[{"id":"1"},{"id":"2"},{"id":"3"}]}'
        $result = Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/items' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http'
        @($result).Count | Should -Be 3
        @($result.id) | Should -Be @('1', '2', '3')
    }

    It 'does not unwrap a single-item result into a bare scalar' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[{"id":"only"}]}'
        $result = Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/single' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http'
        # Deliberately not `$result | Should -BeOfType ...` -- piping a 1-element array re-enumerates
        # it and hands Should the bare element, silently passing even if the SUT's own unwrap-guard
        # regressed. ($result -is [object[]]) inspects the variable directly, with no pipe involved.
        ($result -is [object[]]) | Should -BeTrue
        @($result).Count | Should -Be 1
        $result[0].id | Should -Be 'only'
    }

    It 'follows @odata.nextLink pagination across multiple pages in order' {
        $page2Uri = "http://$($script:Server.HostHeader)/mock/page2"
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body "{`"value`":[{`"id`":`"p1a`"},{`"id`":`"p1b`"}],`"@odata.nextLink`":`"$page2Uri`"}"
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[{"id":"p2a"}]}'

        $result = Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/page1' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http'
        @($result.id) | Should -Be @('p1a', 'p1b', 'p2a')
        $script:Server.RequestLog.Count | Should -Be 2
    }

    It 'retries on 429 honoring the exact Retry-After header, then succeeds' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 429 -Body '{"error":"throttled"}' -Headers @{ 'Retry-After' = '1' }
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[{"id":"after-retry"}]}'

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/throttled' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http'
        $sw.Stop()

        @($result).Count | Should -Be 1
        $result[0].id | Should -Be 'after-retry'
        $sw.Elapsed.TotalSeconds | Should -BeGreaterOrEqual 0.9
        $script:Server.RequestLog.Count | Should -Be 2
    }

    It 'bounds pagination via loop detection when a nextLink repeats' {
        $loop1Uri = "http://$($script:Server.HostHeader)/mock/loop1"
        $loop2Uri = "http://$($script:Server.HostHeader)/mock/loop2"
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body "{`"value`":[{`"id`":`"l1`"}],`"@odata.nextLink`":`"$loop2Uri`"}"
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body "{`"value`":[{`"id`":`"l2`"}],`"@odata.nextLink`":`"$loop1Uri`"}"

        $result = Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/loop1' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http'
        @($result.id) | Should -Be @('l1', 'l2')
        $script:Server.RequestLog.Count | Should -Be 2
    }

    It 'throws a specific error (not a generic "no response") on an unexpected Content-Type' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '<html>not json</html>' -ContentType 'text/html'
        { Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/badcontenttype' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http' } |
            Should -Throw '*unexpected Content-Type*text/html*'
    }

    It 'includes Graph''s own error code and message in the thrown exception for a non-retryable status' {
        # Added after a real live-tenant PIM collection failure surfaced only as "status: 400"
        # with no further detail -- Graph's actual response body (a licensing-gate error, in that
        # case) was silently discarded. This confirms the fix: the code/message pair from a
        # standard {"error":{"code":...,"message":...}} Graph error body now survives into the
        # thrown message, the same extraction pattern already used by
        # Invoke-EntraPostureTokenRequest for OAuth error bodies.
        $errorBody = '{"error":{"code":"MissingLicense","message":"This tenant does not have a license for this feature."}}'
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 400 -Body $errorBody -ContentType 'application/json'
        { Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/graph-error' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http' } |
            Should -Throw '*status: 400*MissingLicense: This tenant does not have a license for this feature.*'
    }

    It 'falls back to just the status code, without throwing a second error, when the error body is not valid JSON' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 400 -Body '<html>upstream proxy error</html>' -ContentType 'text/html'
        { Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/malformed-error' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http' } |
            Should -Throw '*status: 400.'
    }

    It 'rejects a non-allowlisted path before sending any request' {
        { Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/not-registered' -Method GET -ApiStability Stable -AccessToken 'fake-token' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http' } |
            Should -Throw '*refusing to send*'
        $script:Server.RequestLog.Count | Should -Be 0
    }

    It 'enforces the real production allowlist by default when no override is supplied' {
        { Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/items' -Method GET -ApiStability Stable -AccessToken 'fake-token' -SchemeOverride 'http' } |
            Should -Throw '*refusing to send*'
        $script:Server.RequestLog.Count | Should -Be 0
    }

    It 'audits every request against the matched allowlist template, never the literal path or Authorization header' {
        # The concrete mechanism behind the Phase 4 exit criterion "every request is traceable
        # to an allowlist entry": the durable audit record must name the registry's PathTemplate
        # (e.g. '/mock/items'), not a literal request path that could carry a real tenant object
        # ID, and must never contain the bearer token.
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[{"id":"1"}]}'
        $auditLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "entraposture-audit-test-$([guid]::NewGuid()).jsonl"
        try {
            Send-EntraPostureRequest -RequestHost $script:Server.HostHeader -Path '/mock/items' -Method GET -ApiStability Stable `
                -AccessToken 'super-secret-bearer-value' -AllowlistOverride $script:TestAllowlist -SchemeOverride 'http' -AuditLogPath $auditLogPath | Out-Null

            # @() forces array semantics -- Get-Content returns a bare string (not a 1-element
            # array) for a file with exactly one line, and indexing a string with [0] silently
            # returns its first character instead of the line (the same class of PowerShell
            # scalar-unwrap gotcha found repeatedly elsewhere in this project, here at the
            # Get-Content layer rather than a function return).
            $auditLines = @(Get-Content -LiteralPath $auditLogPath)
            $auditLines.Count | Should -BeGreaterOrEqual 1
            $auditRecord = $auditLines[0] | ConvertFrom-Json
            $auditRecord.Message | Should -Match ([regex]::Escape('/mock/items'))
            $auditRecord.Source | Should -Be '/mock/items'
            ($auditLines -join "`n") | Should -Not -Match 'super-secret-bearer-value'
        } finally {
            Remove-Item -LiteralPath $auditLogPath -ErrorAction SilentlyContinue
        }
    }
}
