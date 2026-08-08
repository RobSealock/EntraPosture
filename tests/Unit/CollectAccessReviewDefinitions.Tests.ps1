#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 9 (AR-002): Invoke-EntraPostureAccessReviewDefinitionCollector's
    new two-level N+1 (definitions -> most-recent instance -> that instance's decisions),
    dispatched through Invoke-EntraPostureBoundedParallel -- same pattern and same rationale
    as tests/Unit/CollectGroups.Tests.ps1 (the pipeline's own vertical-slice fixtures never
    populate real definitions, so this is the one place this N+1 logic gets exercised against a
    real HTTP round trip).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1', 'src/Common/CanonicalJson.ps1',
        'src/Common/ToolVersionInfo.ps1', 'src/Logging/WriteLog.ps1', 'src/Validation/StrictJson.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/Normalization/NormalizeAccessReviewDefinition.ps1', 'src/Normalization/NormalizeAccessReviewInstance.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1',
        'src/Collectors/CollectAccessReviewDefinitions.ps1'
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

    function script:Start-ArMockServer {
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

    function script:Stop-ArMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-ArAllowlist {
        param([string]$HostHeader)
        return @(
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances/{instanceId}/decisions'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        )
    }
}

Describe 'Invoke-EntraPostureAccessReviewDefinitionCollector: bounded-concurrent instance/decisions fetch' {
    It 'picks the most recent instance per definition and aggregates its decisions, concurrency notwithstanding' {
        $responseMap = @{
            '/v1.0/identityGovernance/accessReviews/definitions' = '{"value":[{"id":"def-1","displayName":"Def 1"},{"id":"def-2","displayName":"Def 2"}]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-1/instances' = '{"value":[
                {"id":"def-1-inst-old","startDateTime":"2025-01-01T00:00:00Z","endDateTime":"2025-01-15T00:00:00Z","status":"Completed"},
                {"id":"def-1-inst-new","startDateTime":"2026-01-01T00:00:00Z","endDateTime":"2026-01-15T00:00:00Z","status":"Completed"}
            ]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-1/instances/def-1-inst-new/decisions' = '{"value":[
                {"id":"d1","decision":"Approve","applyResult":"AppliedSuccessfully"},
                {"id":"d2","decision":"NotReviewed","applyResult":"New"}
            ]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-2/instances' = '{"value":[
                {"id":"def-2-inst-1","startDateTime":"2026-02-01T00:00:00Z","endDateTime":"2026-02-15T00:00:00Z","status":"InProgress"}
            ]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-2/instances/def-2-inst-1/decisions' = '{"value":[]}'
        }
        $server = Start-ArMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-ArAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAccessReviewDefinitionCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $definitionEntities = @($result.Entities | Where-Object { $_.entityType -eq 'AccessReviewDefinition' })
            $instanceEntities = @($result.Entities | Where-Object { $_.entityType -eq 'AccessReviewInstance' })
            $definitionEntities.Count | Should -Be 2
            $instanceEntities.Count | Should -Be 2

            $def1Instance = $instanceEntities | Where-Object { $_.properties.definitionId -eq 'def-1' }
            $def1Instance.entityId | Should -Be 'def-1-inst-new'
            $def1Instance.properties.decisionsTotalCount | Should -Be 2
            $def1Instance.properties.decisionsReviewedCount | Should -Be 1
            $def1Instance.properties.decisionsAppliedCount | Should -Be 1

            $def2Instance = $instanceEntities | Where-Object { $_.properties.definitionId -eq 'def-2' }
            $def2Instance.entityId | Should -Be 'def-2-inst-1'
            $def2Instance.properties.decisionsTotalCount | Should -Be 0
        } finally {
            Stop-ArMockServer -Server $server
        }
    }

    It 'produces no instance entity for a definition with zero instances yet' {
        $responseMap = @{
            '/v1.0/identityGovernance/accessReviews/definitions' = '{"value":[{"id":"def-draft","displayName":"Draft review"}]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-draft/instances' = '{"value":[]}'
        }
        $server = Start-ArMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-ArAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAccessReviewDefinitionCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            @($result.Entities | Where-Object { $_.entityType -eq 'AccessReviewDefinition' }).Count | Should -Be 1
            @($result.Entities | Where-Object { $_.entityType -eq 'AccessReviewInstance' }).Count | Should -Be 0
        } finally {
            Stop-ArMockServer -Server $server
        }
    }

    It 'throws (failing the whole collector) when one definition''s instances fetch fails' {
        $responseMap = @{
            '/v1.0/identityGovernance/accessReviews/definitions' = '{"value":[{"id":"def-ok","displayName":"OK"},{"id":"def-missing","displayName":"Broken"}]}'
            '/v1.0/identityGovernance/accessReviews/definitions/def-ok/instances' = '{"value":[]}'
            # def-missing's instances path deliberately absent -- mock server 404s it.
        }
        $server = Start-ArMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-ArAllowlist -HostHeader $server.HostHeader
            { Invoke-EntraPostureAccessReviewDefinitionCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader } |
                Should -Throw '*def-missing*'
        } finally {
            Stop-ArMockServer -Server $server
        }
    }
}
