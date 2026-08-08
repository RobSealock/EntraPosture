#Requires -Version 7.4

function Test-EntraPostureAppRegistrationSecretsControl {
    <#
        .SYNOPSIS
        APP-001's evaluator: checks each Application entity for the presence of any password
        credential (client secret).

        .DESCRIPTION
        Same direct field-check shape as AGT-001's evaluator (Test-
        EntraPostureAgentBlueprintClientSecretControl), reading Application.properties.
        passwordCredentialCount instead of AgentIdentityBlueprint's own field of the same name.
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        APP-001.psd1's expectedResultSemantics.

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

    if (@($applications).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'APP-001-NO-APPLICATIONS'
                Rationale = 'No Application entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($application in $applications) {
        $hasSecret = [int]$application.properties.passwordCredentialCount -gt 0
        $evidenceRef = @([ordered]@{ entityId = $application.entityId; entityType = 'Application' })

        if ($hasSecret) {
            [ordered]@{
                Scope = $application.entityId; Status = 'Fail'; ReasonCode = 'APP-001-HAS-PASSWORD-CREDENTIAL'
                Rationale = "App registration '$($application.displayName)' has at least one password credential (client secret) configured."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $application.entityId; Status = 'Pass'; ReasonCode = 'APP-001-NO-PASSWORD-CREDENTIAL'
                Rationale = "App registration '$($application.displayName)' has no password credential configured."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
