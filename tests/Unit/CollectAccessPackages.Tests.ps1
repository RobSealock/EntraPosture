#Requires -Version 7.4
#Requires -Modules Pester

<#
    v.next build order item 11 (EM-001/EM-002): Invoke-EntraPostureAccessPackageCollector's
    per-package detail N+1 (list -> bounded-concurrent per-package $expand=resourceRoleScopes,
    assignmentPolicies) plus a separate tenant-wide assignments fetch, exercised against a real
    HTTP mock server -- same rationale as CollectGroups.Tests.ps1/
    CollectAccessReviewDefinitions.Tests.ps1 (no shared-fixture integration test exercises this
    collector's real data with non-empty results).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1', 'src/Common/CanonicalJson.ps1',
        'src/Common/ToolVersionInfo.ps1', 'src/Logging/WriteLog.ps1', 'src/Validation/StrictJson.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/Normalization/NormalizeAccessPackage.ps1', 'src/Normalization/NormalizeAccessPackageAssignmentPolicy.ps1',
        'src/Normalization/NormalizeAccessPackageAssignment.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1',
        'src/Collectors/CollectAccessPackages.ps1'
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

    function script:Start-EmMockServer {
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

    function script:Stop-EmMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-EmAllowlist {
        param([string]$HostHeader)
        return @(
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/accessPackages/{accessPackageId}'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
            [ordered]@{ Host = $HostHeader; PathTemplate = '/v1.0/identityGovernance/entitlementManagement/assignments'; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        )
    }
}

Describe 'Invoke-EntraPostureAccessPackageCollector: bounded-concurrent per-package detail fetch plus tenant-wide assignments' {
    It 'collects every package''s resource roles and policies, and every tenant-wide assignment' {
        $responseMap = @{
            '/v1.0/identityGovernance/entitlementManagement/accessPackages' = '{"value":[
                {"id":"pkg-1","displayName":"Privileged Package"},
                {"id":"pkg-2","displayName":"Ordinary Package"}
            ]}'
            '/v1.0/identityGovernance/entitlementManagement/accessPackages/pkg-1' = '{
                "id":"pkg-1","displayName":"Privileged Package","description":"desc","isHidden":false,
                "resourceRoleScopes":[
                    {"id":"rrs-1","role":{"id":"r1","displayName":"Member","originSystem":"AadGroup","originId":"group-priv"},"scope":{"id":"s1","displayName":"Root"}}
                ],
                "assignmentPolicies":[
                    {"id":"pol-auto","displayName":"Auto policy","allowedTargetScope":"allDirectoryUsers","automaticRequestSettings":{}},
                    {"id":"pol-narrow","displayName":"Narrow policy","allowedTargetScope":"specificDirectoryUsers","requestApprovalSettings":{"isApprovalRequiredForAdd":true},"expiration":{"type":"afterDuration","duration":"P90D"}}
                ]
            }'
            '/v1.0/identityGovernance/entitlementManagement/accessPackages/pkg-2' = '{
                "id":"pkg-2","displayName":"Ordinary Package","isHidden":false,
                "resourceRoleScopes":[
                    {"id":"rrs-2","role":{"id":"r2","displayName":"Reader","originSystem":"SharePointOnline","originId":"site-1"},"scope":{"id":"s2","displayName":"Root"}}
                ],
                "assignmentPolicies":[]
            }'
            '/v1.0/identityGovernance/entitlementManagement/assignments' = '{"value":[
                {"id":"asg-1","state":"expired","status":"ExpiredNotificationTriggered","expiredDateTime":"2026-01-01T00:00:00Z","accessPackage":{"id":"pkg-1"}},
                {"id":"asg-2","state":"delivered","status":"Delivered","accessPackage":{"id":"pkg-1"}}
            ]}'
        }
        $server = Start-EmMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-EmAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAccessPackageCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $packageEntities = @($result.Entities | Where-Object { $_.entityType -eq 'AccessPackage' })
            $policyEntities = @($result.Entities | Where-Object { $_.entityType -eq 'AccessPackageAssignmentPolicy' })
            $assignmentEntities = @($result.Entities | Where-Object { $_.entityType -eq 'AccessPackageAssignment' })

            $packageEntities.Count | Should -Be 2
            $policyEntities.Count | Should -Be 2
            $assignmentEntities.Count | Should -Be 2

            $pkg1 = $packageEntities | Where-Object { $_.entityId -eq 'pkg-1' }
            $pkg1.properties.resourceRoles.Count | Should -Be 1
            $pkg1.properties.resourceRoles[0].originSystem | Should -Be 'AadGroup'
            $pkg1.properties.resourceRoles[0].originId | Should -Be 'group-priv'

            $autoPolicy = $policyEntities | Where-Object { $_.entityId -eq 'pol-auto' }
            $autoPolicy.properties.isAutoAssignment | Should -BeTrue
            $autoPolicy.properties.accessPackageId | Should -Be 'pkg-1'

            $narrowPolicy = $policyEntities | Where-Object { $_.entityId -eq 'pol-narrow' }
            $narrowPolicy.properties.isAutoAssignment | Should -BeFalse
            $narrowPolicy.properties.isApprovalRequiredForAdd | Should -BeTrue
            $narrowPolicy.properties.expirationType | Should -Be 'afterDuration'

            $expiredAssignment = $assignmentEntities | Where-Object { $_.entityId -eq 'asg-1' }
            $expiredAssignment.properties.state | Should -Be 'expired'
            $expiredAssignment.properties.accessPackageId | Should -Be 'pkg-1'
        } finally {
            Stop-EmMockServer -Server $server
        }
    }

    It 'throws (failing the whole collector) when one package''s detail fetch fails' {
        $responseMap = @{
            '/v1.0/identityGovernance/entitlementManagement/accessPackages' = '{"value":[{"id":"pkg-ok","displayName":"OK"},{"id":"pkg-missing","displayName":"Broken"}]}'
            '/v1.0/identityGovernance/entitlementManagement/accessPackages/pkg-ok' = '{"id":"pkg-ok","displayName":"OK","isHidden":false,"resourceRoleScopes":[],"assignmentPolicies":[]}'
            # pkg-missing's detail path deliberately absent -- mock server 404s it.
        }
        $server = Start-EmMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-EmAllowlist -HostHeader $server.HostHeader
            { Invoke-EntraPostureAccessPackageCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader } |
                Should -Throw '*pkg-missing*'
        } finally {
            Stop-EmMockServer -Server $server
        }
    }
}
