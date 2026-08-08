#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 8 WS4 task 10: live What-If comparison utility. Invoke-EntraPostureWhatIfEvaluation
    is tested here against a real local mock server (same discipline as
    tests/Security/TransportAllowlist.Tests.ps1 -- a real HTTP round trip, not a mocked function),
    confirming the request body shape and response parsing; Compare-EntraPostureWhatIfResult's
    comparison logic is tested separately with fixture data, no network needed.

    The actual live comparison against the real tenant is deliberately not run by this suite --
    that is Phase 8's own explicit, opt-in, user-initiated next step (00-open-questions.md), not
    something the automated test suite does unattended against a real tenant.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/NewCorrelationId.ps1', 'src/Common/NewErrorRecord.ps1', 'src/Common/CanonicalJson.ps1',
        'src/Logging/WriteLog.ps1', 'src/Validation/StrictJson.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Transport/EndpointAllowlist.ps1', 'src/Transport/SendRequest.ps1',
        'src/ConditionalAccess/ScenarioModel.ps1', 'src/ConditionalAccess/MatchPolicy.ps1',
        'src/ConditionalAccess/EvaluateScenario.ps1', 'src/ConditionalAccess/WhatIfComparison.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    $script:MockServerScript = {
        param($Listener, $ResponseQueue, $RequestLog, $BodyLog)
        while ($Listener.IsListening) {
            try {
                $context = $Listener.GetContext()
            } catch {
                break
            }
            $RequestLog.Add($context.Request.RawUrl)
            if ($context.Request.HasEntityBody) {
                $reader = [System.IO.StreamReader]::new($context.Request.InputStream, $context.Request.ContentEncoding)
                $BodyLog.Add($reader.ReadToEnd())
                $reader.Dispose()
            }
            $resp = $null
            if (-not $ResponseQueue.TryDequeue([ref]$resp)) {
                $resp = @{ StatusCode = 500; Body = '{"error":"no canned response queued"}'; ContentType = 'application/json' }
            }
            $context.Response.StatusCode = $resp.StatusCode
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
        $bodyLog = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
        $ps = [powershell]::Create()
        $ps.AddScript($script:MockServerScript).AddArgument($listener).AddArgument($responseQueue).AddArgument($requestLog).AddArgument($bodyLog) | Out-Null
        $asyncResult = $ps.BeginInvoke()
        return [ordered]@{ Listener = $listener; PowerShell = $ps; AsyncResult = $asyncResult; ResponseQueue = $responseQueue; RequestLog = $requestLog; BodyLog = $bodyLog; Port = $port; HostHeader = "127.0.0.1:$port" }
    }

    function script:Stop-EntraPostureMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:Add-EntraPostureMockResponse {
        param($Server, [int]$StatusCode, [string]$Body, [string]$ContentType = 'application/json')
        $Server.ResponseQueue.Enqueue(@{ StatusCode = $StatusCode; Body = $Body; ContentType = $ContentType })
    }
}

Describe 'Invoke-EntraPostureWhatIfEvaluation' {
    BeforeEach {
        $script:Server = Start-EntraPostureMockServer
        $script:TestAllowlist = @([ordered]@{ Host = $script:Server.HostHeader; PathTemplate = '/v1.0/identity/conditionalAccess/evaluate'; ApiStability = 'Stable'; Method = 'POST'; ReadOnlyClassification = 'WhatIfEvaluation'; Description = 'test' })
    }

    AfterEach {
        Stop-EntraPostureMockServer -Server $script:Server
    }

    It 'sends the documented signInIdentity/signInContext/signInConditions request shape' {
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body '{"value":[]}'
        Invoke-EntraPostureWhatIfEvaluation -AccessToken 'fake-token' -UserId 'user-1' -ApplicationId 'app-1' `
            -ClientAppType 'browser' -Platform 'windows' -SignInRiskLevel 'high' -UserRiskLevel 'none' -IsCompliantDevice $true `
            -AllowlistOverride $script:TestAllowlist -RequestHostOverride $script:Server.HostHeader -SchemeOverride 'http' | Out-Null

        $script:Server.BodyLog.Count | Should -Be 1
        $sentBody = ConvertFrom-EntraPostureJson -Json $script:Server.BodyLog[0]
        $sentBody['signInIdentity']['userId'] | Should -Be 'user-1'
        $sentBody['signInIdentity']['@odata.type'] | Should -Be '#microsoft.graph.userSignIn'
        $sentBody['signInContext']['includeApplications'] | Should -Be @('app-1')
        $sentBody['signInConditions']['devicePlatform'] | Should -Be 'windows'
        $sentBody['signInConditions']['clientAppType'] | Should -Be 'browser'
        $sentBody['signInConditions']['signInRiskLevel'] | Should -Be 'high'
        $sentBody['signInConditions']['deviceInfo']['isCompliant'] | Should -Be $true
        $sentBody['appliedPoliciesOnly'] | Should -Be $false
    }

    It 'parses a realistic whatIfAnalysisResult collection, including policyApplies and analysisReasons' {
        $mockResponse = '{"value":[
            {"id":"policy-1","displayName":"Require MFA","state":"enabled","policyApplies":true,"analysisReasons":"notSet"},
            {"id":"policy-2","displayName":"Block legacy auth","state":"enabled","policyApplies":false,"analysisReasons":"clientApps"}
        ]}'
        Add-EntraPostureMockResponse -Server $script:Server -StatusCode 200 -Body $mockResponse
        $results = Invoke-EntraPostureWhatIfEvaluation -AccessToken 'fake-token' -UserId 'user-1' -ApplicationId 'app-1' `
            -AllowlistOverride $script:TestAllowlist -RequestHostOverride $script:Server.HostHeader -SchemeOverride 'http'

        $results.Count | Should -Be 2
        ($results | Where-Object { $_.id -eq 'policy-1' }).policyApplies | Should -Be $true
        ($results | Where-Object { $_.id -eq 'policy-2' }).analysisReasons | Should -Be 'clientApps'
    }

    It 'rejects a call to this endpoint on a host not carrying the allowlist entry' {
        { Invoke-EntraPostureWhatIfEvaluation -AccessToken 'fake-token' -UserId 'user-1' -ApplicationId 'app-1' `
            -RequestHostOverride $script:Server.HostHeader -SchemeOverride 'http' } |
            Should -Throw '*refusing to send*'
        $script:Server.RequestLog.Count | Should -Be 0
    }
}

Describe 'Compare-EntraPostureWhatIfResult' {
    BeforeAll {
        function script:New-LocalResult {
            param([string[]]$ApplicableIds = @(), [string[]]$NotApplicableIds = @())
            return [ordered]@{
                Result = 'NotBlocked'
                ApplicablePolicies = @($ApplicableIds | ForEach-Object { [ordered]@{ PolicyId = $_ } })
                NotApplicablePolicies = @($NotApplicableIds | ForEach-Object { [ordered]@{ PolicyId = $_ } })
                RequiredControlGroups = @()
            }
        }
        function script:New-LiveResult {
            param([string]$Id, [bool]$Applies, [string]$Reason = 'notSet')
            return [ordered]@{ id = $Id; policyApplies = $Applies; analysisReasons = $Reason }
        }
    }

    It 'reports full agreement when local and live both say a policy applies' {
        $local = New-LocalResult -ApplicableIds @('policy-1')
        $live = @((New-LiveResult -Id 'policy-1' -Applies $true))
        $comparison = Compare-EntraPostureWhatIfResult -LocalScenarioResult $local -LiveWhatIfResults $live
        $comparison.AgreementCount | Should -Be 1
        $comparison.DisagreementCount | Should -Be 0
        $comparison.Comparisons[0].Agrees | Should -BeTrue
    }

    It 'reports a disagreement when local says applies but live says it does not' {
        $local = New-LocalResult -ApplicableIds @('policy-1')
        $live = @((New-LiveResult -Id 'policy-1' -Applies $false -Reason 'devicePlatform'))
        $comparison = Compare-EntraPostureWhatIfResult -LocalScenarioResult $local -LiveWhatIfResults $live
        $comparison.DisagreementCount | Should -Be 1
        $comparison.Comparisons[0].Agrees | Should -BeFalse
        $comparison.Comparisons[0].LiveAnalysisReason | Should -Be 'devicePlatform'
    }

    It 'reports agreement when both local and live say a policy does not apply' {
        $local = New-LocalResult -NotApplicableIds @('policy-1')
        $live = @((New-LiveResult -Id 'policy-1' -Applies $false))
        $comparison = Compare-EntraPostureWhatIfResult -LocalScenarioResult $local -LiveWhatIfResults $live
        $comparison.AgreementCount | Should -Be 1
    }

    It 'flags a policy present only on the live side as a disagreement, not silently skipped' {
        $local = New-LocalResult
        $live = @((New-LiveResult -Id 'policy-new' -Applies $true))
        $comparison = Compare-EntraPostureWhatIfResult -LocalScenarioResult $local -LiveWhatIfResults $live
        $comparison.Comparisons.Count | Should -Be 1
        $comparison.Comparisons[0].Agrees | Should -BeFalse
        $comparison.Comparisons[0].LocalApplies | Should -Be $null
    }

    It 'handles an empty live result set (e.g. tenant currently has zero CA policies) without error' {
        $local = New-LocalResult
        $comparison = Compare-EntraPostureWhatIfResult -LocalScenarioResult $local -LiveWhatIfResults @()
        $comparison.AgreementCount | Should -Be 0
        $comparison.DisagreementCount | Should -Be 0
        $comparison.Comparisons.Count | Should -Be 0
    }
}
