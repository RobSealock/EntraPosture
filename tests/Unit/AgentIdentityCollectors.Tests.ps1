#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 13 (agent identity / PIM-for-Groups): the five new collectors'
    real N+1 fetch patterns, exercised against a real HTTP mock server -- same rationale as
    CollectAccessPackages.Tests.ps1/CollectAccessReviewDefinitions.Tests.ps1 (no shared-fixture
    integration test exercises these collectors' real data with non-empty results).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1', 'src/Common/CanonicalJson.ps1',
        'src/Common/ToolVersionInfo.ps1', 'src/Logging/WriteLog.ps1', 'src/Validation/StrictJson.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/Normalization/NormalizeOwnerOf.ps1', 'src/Normalization/NormalizeAgentIdentityBlueprint.ps1',
        'src/Normalization/NormalizeAgentIdentityBlueprintPrincipal.ps1', 'src/Normalization/NormalizeAgentIdentity.ps1',
        'src/Normalization/NormalizeAgentUser.ps1', 'src/Normalization/NormalizePimForGroups.ps1',
        'src/Orchestration/BoundedParallelExecution.ps1',
        'src/Collectors/CollectAgentIdentityBlueprints.ps1', 'src/Collectors/CollectAgentIdentityBlueprintPrincipals.ps1',
        'src/Collectors/CollectAgentIdentities.ps1', 'src/Collectors/CollectAgentUsers.ps1',
        'src/Collectors/CollectPimForGroups.ps1'
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

    function script:Start-AgtMockServer {
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

    function script:Stop-AgtMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Get-AgtAllowlist {
        param([string]$HostHeader)
        $paths = @(
            '/v1.0/applications/microsoft.graph.agentIdentityBlueprint', '/v1.0/applications/{applicationId}/owners',
            '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal', '/v1.0/servicePrincipals/microsoft.graph.agentIdentity',
            '/v1.0/users/microsoft.graph.agentUser', '/v1.0/users/{userId}/ownedObjects',
            '/v1.0/groups',
            '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances',
            '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'
        )
        return @($paths | ForEach-Object {
            [ordered]@{ Host = $HostHeader; PathTemplate = $_; ApiStability = 'Stable'; Method = 'GET'; ReadOnlyClassification = $null; Description = 'test' }
        })
    }
}

Describe 'Invoke-EntraPostureAgentIdentityBlueprintCollector: list plus per-blueprint owners N+1' {
    It 'collects every blueprint and its owners' {
        $responseMap = @{
            '/v1.0/applications/microsoft.graph.agentIdentityBlueprint' = '{"value":[
                {"id":"bp-1","appId":"app-1","displayName":"Blueprint One","passwordCredentials":[{"keyId":"k1"}]},
                {"id":"bp-2","appId":"app-2","displayName":"Blueprint Two","passwordCredentials":[]}
            ]}'
            '/v1.0/applications/bp-1/owners' = '{"value":[{"id":"owner-1"}]}'
            '/v1.0/applications/bp-2/owners' = '{"value":[]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAgentIdentityBlueprintCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Entities.Count | Should -Be 2
            $bp1 = $result.Entities | Where-Object { $_.entityId -eq 'bp-1' }
            $bp1.properties.passwordCredentialCount | Should -Be 1
            $bp2 = $result.Entities | Where-Object { $_.entityId -eq 'bp-2' }
            $bp2.properties.passwordCredentialCount | Should -Be 0

            $result.Relationships.Count | Should -Be 1
            $result.Relationships[0].sourceEntityId | Should -Be 'owner-1'
            $result.Relationships[0].targetEntityId | Should -Be 'bp-1'
            $result.Relationships[0].relationshipType | Should -Be 'OwnerOf'
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }
}

Describe 'Invoke-EntraPostureAgentIdentityBlueprintPrincipalCollector' {
    It 'collects blueprint principals with appOwnerOrganizationId' {
        $responseMap = @{
            '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' = '{"value":[
                {"id":"bpp-1","appId":"app-1","appDisplayName":"Blueprint One","appOwnerOrganizationId":"foreign-tenant","accountEnabled":true}
            ]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAgentIdentityBlueprintPrincipalCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Entities.Count | Should -Be 1
            $result.Entities[0].entityType | Should -Be 'AgentIdentityBlueprintPrincipal'
            $result.Entities[0].properties.appId | Should -Be 'app-1'
            $result.Entities[0].properties.appOwnerOrganizationId | Should -Be 'foreign-tenant'
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }
}

Describe 'Invoke-EntraPostureAgentIdentityCollector' {
    It 'collects agent identities with their blueprint appId reference' {
        $responseMap = @{
            '/v1.0/servicePrincipals/microsoft.graph.agentIdentity' = '{"value":[
                {"id":"agt-1","displayName":"Agent One","agentIdentityBlueprintId":"app-1","accountEnabled":true}
            ]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAgentIdentityCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Entities.Count | Should -Be 1
            $result.Entities[0].entityType | Should -Be 'AgentIdentity'
            $result.Entities[0].properties.agentIdentityBlueprintId | Should -Be 'app-1'
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }
}

Describe 'Invoke-EntraPostureAgentUserCollector: list plus per-user ownedObjects N+1 (group-typed only)' {
    It 'collects agent users and only their group-typed owned objects' {
        $responseMap = @{
            '/v1.0/users/microsoft.graph.agentUser' = '{"value":[
                {"id":"au-1","displayName":"Agent User One","identityParentId":"agt-1","accountEnabled":true}
            ]}'
            '/v1.0/users/au-1/ownedObjects' = '{"value":[
                {"@odata.type":"#microsoft.graph.group","id":"group-1"},
                {"@odata.type":"#microsoft.graph.application","id":"app-owned-1"}
            ]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPostureAgentUserCollector -AccessToken 'tok' -TenantScope 't1' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Entities.Count | Should -Be 1
            $result.Entities[0].properties.identityParentId | Should -Be 'agt-1'

            $result.Relationships.Count | Should -Be 1
            $result.Relationships[0].sourceEntityId | Should -Be 'au-1'
            $result.Relationships[0].targetEntityId | Should -Be 'group-1'
            $result.Relationships[0].relationshipType | Should -Be 'OwnerOf'
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }
}

Describe 'Invoke-EntraPosturePimForGroupsCollector: role-assignable-group-scoped N+1' {
    It 'only queries PIM-for-Groups schedules for role-assignable groups, and collects both eligibility and active relationships' {
        $responseMap = @{
            '/v1.0/groups' = '{"value":[
                {"id":"grp-role-assignable","isAssignableToRole":true},
                {"id":"grp-ordinary","isAssignableToRole":false}
            ]}'
            '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances' = '{"value":[
                {"id":"e1","principalId":"user-1","groupId":"grp-role-assignable","accessId":"member","startDateTime":"2026-01-01T00:00:00Z","endDateTime":null}
            ]}'
            '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances' = '{"value":[
                {"id":"a1","principalId":"user-2","groupId":"grp-role-assignable","accessId":"member","assignmentType":"Assigned","startDateTime":"2026-01-01T00:00:00Z","endDateTime":null}
            ]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPosturePimForGroupsCollector -AccessToken 'tok' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $eligible = @($result.Relationships | Where-Object { $_.relationshipType -eq 'PimEligible' })
            $active = @($result.Relationships | Where-Object { $_.relationshipType -eq 'PimActive' })
            $eligible.Count | Should -Be 1
            $eligible[0].sourceEntityId | Should -Be 'user-1'
            $eligible[0].targetEntityId | Should -Be 'grp-role-assignable'
            $active.Count | Should -Be 1
            $active[0].sourceEntityId | Should -Be 'user-2'
            $active[0].validity.endDateTime | Should -BeNullOrEmpty
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }

    It 'produces zero relationships when no group is role-assignable, without calling the schedule endpoints' {
        $responseMap = @{
            '/v1.0/groups' = '{"value":[{"id":"grp-ordinary","isAssignableToRole":false}]}'
        }
        $server = Start-AgtMockServer -ResponseMap $responseMap
        try {
            $allowlist = Get-AgtAllowlist -HostHeader $server.HostHeader
            $result = Invoke-EntraPosturePimForGroupsCollector -AccessToken 'tok' `
                -AllowlistOverride $allowlist -SchemeOverride 'http' -RequestHostOverride $server.HostHeader

            $result.Relationships.Count | Should -Be 0
        } finally {
            Stop-AgtMockServer -Server $server
        }
    }
}
