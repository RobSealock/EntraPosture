#Requires -Version 7.4

function Test-EntraPostureEnterpriseAppClientCredentialsControl {
    <#
        .SYNOPSIS
        ENT-001's evaluator: checks each ServicePrincipal entity for the presence of any key or
        password credential added directly to the service principal itself.

        .DESCRIPTION
        Same direct field-check shape as APP-001's evaluator, reading ServicePrincipal.
        properties.keyCredentialCount/passwordCredentialCount -- a service principal's own
        credentials, independently settable via the Add key/Add password service principal APIs,
        distinct from its associated Application registration's own passwordCredentials (which
        APP-001 already checks on the Application entity). Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per ENT-001.psd1's
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

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'

    if (@($servicePrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-001-NO-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $servicePrincipals) {
        $hasCredential = ([int]$principal.properties.keyCredentialCount -gt 0) -or ([int]$principal.properties.passwordCredentialCount -gt 0)
        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })

        if ($hasCredential) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-001-HAS-CLIENT-CREDENTIAL'
                Rationale = "Enterprise application '$($principal.displayName)' has at least one key or password credential configured directly on the service principal."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-001-NO-CLIENT-CREDENTIAL'
                Rationale = "Enterprise application '$($principal.displayName)' has no key or password credential configured directly on the service principal."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
