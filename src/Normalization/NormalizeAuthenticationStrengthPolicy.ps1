#Requires -Version 7.4

function ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph authenticationStrengthPolicy object
        (GET /v1.0/policies/authenticationStrengthPolicies) into a canonical Entity record.

        .DESCRIPTION
        Field shape confirmed directly against Microsoft Graph's authenticationStrengthPolicy
        resource documentation (re-fetched 2026-08-07, updated_at 2026-02-13). Field allowlist per
        section 8.4: policyType, requirementsSatisfied, allowedCombinations -- deliberately not
        combinationConfigurations (per-combination authentication-method-instance requirements,
        e.g. "must be a specific FIDO2 key AAGUID"), which this project has no evaluation need for
        and which the List endpoint doesn't even expand by default.

        .PARAMETER RawPolicy
        One element of the Graph response's 'value' array.

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawPolicy,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawPolicy.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawPolicy['id'])) {
        throw 'ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity: raw authenticationStrengthPolicy record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawPolicy['id']
        entityType       = 'AuthenticationStrengthPolicy'
        tenantScope      = $TenantScope
        displayName      = if ($RawPolicy.Contains('displayName')) { $RawPolicy['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            policyType             = if ($RawPolicy.Contains('policyType')) { $RawPolicy['policyType'] } else { $null }
            requirementsSatisfied  = if ($RawPolicy.Contains('requirementsSatisfied')) { $RawPolicy['requirementsSatisfied'] } else { $null }
            allowedCombinations    = @(if ($RawPolicy.Contains('allowedCombinations')) { $RawPolicy['allowedCombinations'] } else { @() })
        }
        redacted         = $false
    }
}
