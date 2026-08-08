#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 6: Invoke-EntraPostureGroupCollector's N+1 transitiveMembers fetch,
    specifically named in VNext.md's own text ("including Groups' real N+1 fetch pattern"), now
    dispatched through Invoke-EntraPostureBoundedParallel instead of a sequential foreach.
    Exercised against a real local HttpListener mock server (path-keyed response map, same
    pattern as tests/Integration/VerticalSlice.Tests.ps1), not a mocked function -- this is the
    one collector this project doesn't already have dedicated coverage for outside the full
    VerticalSlice pipeline, and the pipeline's own fixtures never populate real groups.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1', 'src/Common/CanonicalJson.ps1',
        'src/Common/ToolVersionInfo.ps1', 'src/Logging/WriteLog.ps1', 'src/Validation/StrictJson.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/Normalization/NormalizeGroup.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1',
        'src/Collectors/CollectGroups.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    $script:MockServerScript = {
        param($Listener, $ResponseMap)
        while ($Listener.IsListening) {
            try { $context = $Listener.GetContext() } catch { break }
            $path = $context.Request.Url.AbsolutePath
            $status = 200
            $body = if ($ResponseMap.ContainsKey($path)) { $ResponseMap[$path] } else { $status = 404; '{"error":"not found: ' + $path + '"}' }
            $context.Response.StatusCode = $status
            $context.Response.ContentType = 'application/json'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$body)
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.OutputStream.Close()
        }
    }

    function script:Start-GroupsMockServer {
        param([hashtable]$ResponseMap)
        $port = Get-EntraPostureAvailableLoopbackPort
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()
        $syncMap = [System.Collections.Hashtable]::Synchronized($ResponseMap)
        $ps = [powershell]::Create()
        $ps.AddScript($script:MockServerScript).AddArgument($listener).AddArgument($syncMap) | Out-Null
        $asyncResult = $ps.BeginInvoke()
        return [ordered]@{ Listener = $listener; PowerShell = $ps; AsyncResult = $asyncResult; HostHeader = "127.0.0.1:$port" }
    }

    function script:Stop-GroupsMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-GroupsAllowlist {
        param([string]$HostHeader)
        return @(
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/groups'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/groups/{groupId}/transitiveMembers'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        )
    }
}

Describe 'Invoke-EntraPostureGroupCollector: bounded-concurrent transitiveMembers fetch' {
    It 'correctly collects transitiveMembers for every group, concurrency notwithstanding' {
        $responseMap = @{
            '/v1.0/groups' = '{"value":[{"id":"g1","displayName":"Group 1"},{"id":"g2","displayName":"Group 2"},{"id":"g3","displayName":"Group 3"}]}'
            '/v1.0/groups/g1/transitiveMembers' = '{"value":[{"@odata.type":"#microsoft.graph.user","id":"u1"}]}'
            '/v1.0/groups/g2/transitiveMembers' = '{"value":[{"@odata.type":"#microsoft.graph.user","id":"u2"},{"@odata.type":"#microsoft.graph.user","id":"u3"}]}'
            '/v1.0/groups/g3/transitiveMembers' = '{"value":[]}'
        }
        $server = Start-GroupsMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-GroupsAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureGroupCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Entities.Count | Should -Be 3
            $result.Relationships.Count | Should -Be 3

            $g1Members = @($result.Relationships | Where-Object { $_.targetEntityId -eq 'g1' })
            $g2Members = @($result.Relationships | Where-Object { $_.targetEntityId -eq 'g2' })
            $g3Members = @($result.Relationships | Where-Object { $_.targetEntityId -eq 'g3' })
            $g1Members.Count | Should -Be 1
            $g2Members.Count | Should -Be 2
            $g3Members.Count | Should -Be 0
        } finally {
            Stop-GroupsMockServer -Server $server
        }
    }

    It 'throws (failing the whole collector) when one group''s transitiveMembers fetch fails -- matches the prior sequential-loop behavior' {
        $responseMap = @{
            '/v1.0/groups' = '{"value":[{"id":"g1","displayName":"Group 1"},{"id":"g-missing","displayName":"Broken Group"}]}'
            '/v1.0/groups/g1/transitiveMembers' = '{"value":[]}'
            # '/v1.0/groups/g-missing/transitiveMembers' deliberately absent -- mock server 404s it.
        }
        $server = Start-GroupsMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-GroupsAllowlist -HostHeader $server.HostHeader
            { Invoke-EntraPostureGroupCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader } |
                Should -Throw '*g-missing*'
        } finally {
            Stop-GroupsMockServer -Server $server
        }
    }
}
