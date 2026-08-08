#Requires -Version 7.4

function Invoke-EntraPostureWhatIfEvaluation {
    <#
        .SYNOPSIS
        Calls Microsoft's real Conditional Access What If evaluation API
        (POST /v1.0/identity/conditionalAccess/evaluate) for a scenario, and returns the raw
        per-policy whatIfAnalysisResult collection.

        .DESCRIPTION
        Engineering plan WS4 task 10: "Use Microsoft's own What If tool and evaluation API as the
        authoritative ground truth." This is the one function in the Conditional Access subsystem
        that DOES call a live endpoint (ADR-019's "evaluators never call live APIs" applies to
        control evaluators reading sealed snapshots, not to this explicit, opt-in live-comparison
        utility, which is never invoked as part of offline evaluation).

        Requests every policy's applicability (-AppliedPoliciesOnly:$false, the default), not
        only the applicable subset, specifically so Compare-EntraPostureWhatIfResult can do a
        precise per-policy agreement/disagreement comparison against this project's own
        simulation engine, rather than only comparing the aggregate outcome.

        -ApplicationId must be a real application ID from the tenant (or a well-known first-party
        app ID) -- unlike the offline simulation engine, which accepts the literal 'All' as a
        wildcard scenario input, the live API's signInContext.includeApplications requires actual
        application ID(s) to evaluate against.

        .PARAMETER AccessToken
        A Graph-audience access token. Requires Policy.Read.ConditionalAccess (or a higher-
        privileged equivalent already granted, e.g. Policy.Read.All) -- confirmed directly
        against Microsoft Graph's own documented permission table for this endpoint.

        .PARAMETER UserId
        .PARAMETER ApplicationId
        A real Graph application (client) ID, not the offline engine's 'All' placeholder.

        .PARAMETER ClientAppType
        .PARAMETER Platform
        .PARAMETER SignInRiskLevel
        .PARAMETER UserRiskLevel
        .PARAMETER IsCompliantDevice
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only passthrough to Send-EntraPostureRequest.

        .OUTPUTS
        Array of raw whatIfAnalysisResult ordered dictionaries (id, displayName, state,
        policyApplies, analysisReasons, conditions, grantControls, sessionControls), one per
        Conditional Access policy in the tenant.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter()]
        [ValidateSet('all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')]
        [string]$ClientAppType = 'browser',

        [Parameter()]
        [ValidateSet('android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'all')]
        [string]$Platform = 'windows',

        [Parameter()]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$SignInRiskLevel = 'none',

        [Parameter()]
        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$UserRiskLevel = 'none',

        [Parameter()]
        [bool]$IsCompliantDevice = $false,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'graph.microsoft.com'
    )

    $requestBody = [ordered]@{
        signInIdentity  = [ordered]@{
            '@odata.type' = '#microsoft.graph.userSignIn'
            userId        = $UserId
        }
        signInContext   = [ordered]@{
            '@odata.type'       = '#microsoft.graph.applicationContext'
            includeApplications = @($ApplicationId)
        }
        signInConditions = [ordered]@{
            devicePlatform  = $Platform
            clientAppType   = $ClientAppType
            signInRiskLevel = $SignInRiskLevel
            userRiskLevel   = $UserRiskLevel
            deviceInfo      = [ordered]@{ isCompliant = $IsCompliantDevice }
        }
        appliedPoliciesOnly = $false
    }

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
        Body         = $requestBody
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $rawResults = Send-EntraPostureRequest @sendParams -Path '/v1.0/identity/conditionalAccess/evaluate' -Method POST

    return ,@($rawResults)
}

function Compare-EntraPostureWhatIfResult {
    <#
        .SYNOPSIS
        Compares this project's offline CA simulation engine result against Microsoft's live
        What If result for the same scenario, per policy -- WS4 task 10's "record agreement/
        disagreement" deliverable.

        .DESCRIPTION
        Correlates by policy ID (whatIfAnalysisResult.id matches the same ConditionalAccessPolicy
        entityId the offline engine already used). A policy present in one result set but not the
        other (e.g. collected in the sealed snapshot but deleted/created between collection and
        this live call) is reported as its own disagreement category, not silently skipped or
        forced into a false match.

        Never throws on a disagreement -- disagreement is the expected, useful output of this
        function, not an error condition. Per 16-ca-evaluation-semantics.md §10 and the
        engineering plan's own framing, Microsoft's What If is authoritative *within a fully
        specified supported scenario*; a disagreement here is a finding to record and
        investigate, not proof this project's engine is wrong, and not silently auto-resolved
        either way.

        .PARAMETER LocalScenarioResult
        Output of Invoke-EntraPostureConditionalAccessScenario for the exact same scenario.

        .PARAMETER LiveWhatIfResults
        Output of Invoke-EntraPostureWhatIfEvaluation for the exact same scenario.

        .OUTPUTS
        Ordered dictionary: AgreementCount, DisagreementCount, Comparisons (array, one per policy
        ID seen in either result set: PolicyId, LocalApplies, LiveApplies, LiveAnalysisReason,
        Agrees).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$LocalScenarioResult,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$LiveWhatIfResults
    )

    $localAppliesById = @{}
    foreach ($entry in $LocalScenarioResult.ApplicablePolicies) { $localAppliesById[$entry.PolicyId] = $true }
    foreach ($entry in $LocalScenarioResult.NotApplicablePolicies) {
        # A 'state' exclusion (disabled) is a distinct local concept from Graph's own
        # policyApplies -- What If itself still reports policyApplies for disabled policies
        # (it echoes state separately), so this project's own 'not evaluated because disabled'
        # bucket is treated as 'does not apply' for this comparison's purposes, not excluded from
        # it, since the practical question ("would this policy have contributed to the enforced
        # outcome") answer is the same either way.
        $localAppliesById[$entry.PolicyId] = $false
    }

    $liveById = @{}
    foreach ($liveEntry in $LiveWhatIfResults) { $liveById[[string]$liveEntry['id']] = $liveEntry }

    $allPolicyIds = @(@($localAppliesById.Keys) + @($liveById.Keys) | Select-Object -Unique)

    $comparisons = @(foreach ($policyId in $allPolicyIds) {
        $hasLocal = $localAppliesById.ContainsKey($policyId)
        $hasLive = $liveById.ContainsKey($policyId)

        if (-not $hasLocal -or -not $hasLive) {
            [ordered]@{
                PolicyId          = $policyId
                LocalApplies      = if ($hasLocal) { $localAppliesById[$policyId] } else { $null }
                LiveApplies       = if ($hasLive) { [bool]$liveById[$policyId]['policyApplies'] } else { $null }
                LiveAnalysisReason = if ($hasLive) { $liveById[$policyId]['analysisReasons'] } else { $null }
                Agrees            = $false
            }
            continue
        }

        $localApplies = $localAppliesById[$policyId]
        $liveApplies = [bool]$liveById[$policyId]['policyApplies']

        [ordered]@{
            PolicyId           = $policyId
            LocalApplies       = $localApplies
            LiveApplies        = $liveApplies
            LiveAnalysisReason = $liveById[$policyId]['analysisReasons']
            Agrees             = ($localApplies -eq $liveApplies)
        }
    })

    $agreementCount = @($comparisons | Where-Object { $_.Agrees }).Count
    $disagreementCount = @($comparisons | Where-Object { -not $_.Agrees }).Count

    return [ordered]@{
        AgreementCount    = $agreementCount
        DisagreementCount = $disagreementCount
        Comparisons       = $comparisons
    }
}
