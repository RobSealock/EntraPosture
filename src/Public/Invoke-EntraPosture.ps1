#Requires -Version 7.4

function Invoke-EntraPosture {
    <#
        .SYNOPSIS
        Runs preflight, collection, sealing, evaluation, and reporting end to end.

        .DESCRIPTION
        The single end-to-end orchestration command (engineering plan section 6.2). ADR-027's
        fixed pipeline order: Preflight (implicit, inside collection) -> Collect to staging ->
        Validate -> Seal -> Evaluate offline -> Report. Sets $global:LASTEXITCODE to the result
        of Get-EntraPostureRunExitCode (engineering plan section 11's priority table) and
        also returns it in the result object -- this function never calls `exit` itself (that
        would terminate the caller's whole PowerShell session, not just this command); the
        caller decides whether/how to act on the exit code.

        An operational failure (authentication, collection, or evaluation/report throwing)
        short-circuits the remaining pipeline stages and is reflected via
        -OperationalFailureReason to Get-EntraPostureRunExitCode, which always takes
        precedence over any compliance outcome (section 11).

        .PARAMETER TenantId
        .PARAMETER ClientId
        .PARAMETER AuthMode
        .PARAMETER Certificate
        Required when -AuthMode is 'Certificate'.

        .PARAMETER Browser
        .PARAMETER PrivateBrowsing
        Optional, only meaningful when -AuthMode is 'Delegated'. See
        Connect-EntraPostureDelegated's parameters of the same names.

        .PARAMETER RunRoot
        .PARAMETER ArmScope
        Optional -- Azure RBAC collection is skipped entirely when omitted.

        .PARAMETER DeviationsPath
        .PARAMETER RedactionMode
        .PARAMETER SigningCertificate
        .PARAMETER Strict
        Makes every technical Fail return exit code 2, deviation or not (engineering plan
        section 11).

        .PARAMETER AccessTokenOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER GraphRequestHostOverride
        .PARAMETER ArmRequestHostOverride
        Test-only, forwarded to New-EntraPostureSnapshot. See that command's parameters of
        the same names.

        .PARAMETER KnownAbusedAppListPath
        Optional -- forwarded to New-EntraPostureSnapshot. Omitted here means omitted there too,
        which resolves to that command's own default vendored-data location; see its parameter
        docs for the full resolution story (ENT-013).

        .OUTPUTS
        Ordered dictionary: ExitCode, SnapshotPath, AssessmentPath, Results, Coverage,
        HtmlReportPath, CsvReportPath, ConsoleReportPath, AssessmentJsonPath.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [ValidateSet('Delegated', 'Certificate')]
        [string]$AuthMode,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [switch]$PrivateBrowsing,

        [Parameter(Mandatory)]
        [string]$RunRoot,

        [Parameter()]
        [string]$ArmScope,

        [Parameter()]
        [string]$DeviationsPath,

        [Parameter()]
        [ValidateSet('None', 'Identifiers', 'Strict')]
        [string]$RedactionMode = 'None',

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter()]
        [switch]$Strict,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary]$AccessTokenOverride,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$GraphRequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [string]$ArmRequestHostOverride = 'management.azure.com',

        [Parameter()]
        [AllowNull()]
        [string]$KnownAbusedAppListPath
    )

    $snapshotResult = $null
    try {
        $snapshotParams = @{
            TenantId                 = $TenantId
            ClientId                 = $ClientId
            AuthMode                 = $AuthMode
            RunRoot                  = $RunRoot
            SchemeOverride           = $SchemeOverride
            GraphRequestHostOverride = $GraphRequestHostOverride
            ArmRequestHostOverride   = $ArmRequestHostOverride
        }
        if ($Certificate) { $snapshotParams['Certificate'] = $Certificate }
        if ($Browser) { $snapshotParams['Browser'] = $Browser }
        if ($PrivateBrowsing) { $snapshotParams['PrivateBrowsing'] = $PrivateBrowsing }
        if ($ArmScope) { $snapshotParams['ArmScope'] = $ArmScope }
        if ($SigningCertificate) { $snapshotParams['SigningCertificate'] = $SigningCertificate }
        if ($AccessTokenOverride) { $snapshotParams['AccessTokenOverride'] = $AccessTokenOverride }
        if ($AllowlistOverride) { $snapshotParams['AllowlistOverride'] = $AllowlistOverride }
        if ($KnownAbusedAppListPath) { $snapshotParams['KnownAbusedAppListPath'] = $KnownAbusedAppListPath }

        $snapshotResult = New-EntraPostureSnapshot @snapshotParams
    } catch {
        $exitCode = Get-EntraPostureRunExitCode -OperationalFailureReason CollectionFailure
        $global:LASTEXITCODE = $exitCode
        return [ordered]@{ ExitCode = $exitCode; SnapshotPath = $null; AssessmentPath = $null; Results = @(); Coverage = $null; Error = $_.Exception.Message }
    }

    $evaluationResult = $null
    try {
        $evalParams = @{ SnapshotPath = $snapshotResult.SnapshotPath; RunRoot = $RunRoot }
        if ($DeviationsPath) { $evalParams['DeviationsPath'] = $DeviationsPath }
        if ($SigningCertificate) { $evalParams['SigningCertificate'] = $SigningCertificate }

        $evaluationResult = Invoke-EntraPostureEvaluation @evalParams
    } catch {
        $exitCode = Get-EntraPostureRunExitCode -OperationalFailureReason EvaluationOrReportFailure
        $global:LASTEXITCODE = $exitCode
        return [ordered]@{ ExitCode = $exitCode; SnapshotPath = $snapshotResult.SnapshotPath; AssessmentPath = $null; Results = @(); Coverage = $snapshotResult.Coverage; Error = $_.Exception.Message }
    }

    $reportResult = $null
    try {
        $reportResult = New-EntraPostureReport -AssessmentPath $evaluationResult.AssessmentPath -SnapshotPath $snapshotResult.SnapshotPath -RedactionMode $RedactionMode
    } catch {
        $exitCode = Get-EntraPostureRunExitCode -OperationalFailureReason EvaluationOrReportFailure
        $global:LASTEXITCODE = $exitCode
        return [ordered]@{ ExitCode = $exitCode; SnapshotPath = $snapshotResult.SnapshotPath; AssessmentPath = $evaluationResult.AssessmentPath; Results = $evaluationResult.Results; Coverage = $snapshotResult.Coverage; Error = $_.Exception.Message }
    }

    $isPartial = $snapshotResult.Manifest.status -eq 'Partial'
    $exitCode = Get-EntraPostureRunExitCode -IsPartial $isPartial -Results $evaluationResult.Results -Strict:$Strict
    $global:LASTEXITCODE = $exitCode

    return [ordered]@{
        ExitCode           = $exitCode
        SnapshotPath       = $snapshotResult.SnapshotPath
        AssessmentPath     = $evaluationResult.AssessmentPath
        Results            = $evaluationResult.Results
        Coverage           = $snapshotResult.Coverage
        HtmlReportPath     = $reportResult.HtmlReportPath
        CsvReportPath      = $reportResult.CsvReportPath
        ConsoleReportPath  = $reportResult.ConsoleReportPath
        AssessmentJsonPath = $reportResult.AssessmentJsonPath
    }
}
