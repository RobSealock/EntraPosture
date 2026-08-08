#Requires -Version 7.4

function Test-EntraPostureAppInstancePropertyLockControl {
    <#
        .SYNOPSIS
        APP-002's evaluator: checks each Application entity for whether App Instance Property
        Lock (servicePrincipalLockConfiguration.isEnabled) is enabled.

        .DESCRIPTION
        App Instance Property Lock, when enabled, prevents a customer tenant's own admins from
        modifying sensitive properties (credentials, token encryption key) of the service
        principal created when they consent to a multitenant application -- confirmed directly
        against the live application Graph reference page and the servicePrincipalLockConfiguration
        resource's own field documentation, re-fetched 2026-08-08. Without it, a compromised
        customer-tenant admin (or a customer tenant admin acting maliciously) could add their own
        credential to the service principal and impersonate the multitenant app -- the specific
        attack this feature exists to close, per Microsoft's own published guidance ("Protect your
        multitenant application from being hijacked").

        Scoped to multitenant applications only (signInAudience not equal to the single-tenant
        default 'AzureADMyOrg') -- Microsoft's own documentation frames this feature specifically
        as protecting "the multitenant app," and a single-tenant application has no other
        customer tenant able to consent to and locally modify its service principal, so the
        finding does not meaningfully apply. A single-tenant Application produces no result, the
        same "zero results, not Pass/Fail" shape this project applies whenever a check's own
        population doesn't include an item, not a silent Pass. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per APP-002.psd1's
        expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $applications = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Application'
    $multitenantApplications = @($applications | Where-Object { [string]$_.properties.signInAudience -ne 'AzureADMyOrg' -and -not [string]::IsNullOrWhiteSpace([string]$_.properties.signInAudience) })

    if (@($multitenantApplications).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'APP-002-NO-MULTITENANT-APPLICATIONS'
                Rationale = 'No multitenant Application entity (signInAudience other than AzureADMyOrg) was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($application in $multitenantApplications) {
        $isLocked = [bool]$application.properties.appInstancePropertyLockEnabled
        $evidenceRef = @([ordered]@{ entityId = $application.entityId; entityType = 'Application' })

        if ($isLocked) {
            [ordered]@{
                Scope = $application.entityId; Status = 'Pass'; ReasonCode = 'APP-002-INSTANCE-LOCK-ENABLED'
                Rationale = "App registration '$($application.displayName)' has App Instance Property Lock enabled."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $application.entityId; Status = 'Fail'; ReasonCode = 'APP-002-INSTANCE-LOCK-MISSING'
                Rationale = "App registration '$($application.displayName)' does not have App Instance Property Lock enabled."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
