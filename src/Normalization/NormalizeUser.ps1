#Requires -Version 7.4

function ConvertTo-EntraPostureUserEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph user object (GET /v1.0/users) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, userPrincipalName, accountEnabled,
        userType only -- deliberately not the much larger set of PII-adjacent user profile
        fields (jobTitle, department, phone numbers, addresses, etc.) that this project has no
        current security-evaluation need for. accountEnabled and userType (Member/Guest) are
        the two fields load-bearing for identity-posture and guest-access findings; expanding
        this allowlist should be a deliberate, control-driven decision in a later phase, not a
        default "collect everything available" choice (section 8.4: "collectors use field
        allowlists and do not persist full API responses by default").

        .PARAMETER RawUser
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
        [System.Collections.Specialized.OrderedDictionary]$RawUser,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawUser.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawUser['id'])) {
        throw 'ConvertTo-EntraPostureUserEntity: raw user record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawUser['id']
        entityType       = 'User'
        tenantScope      = $TenantScope
        displayName      = if ($RawUser.Contains('displayName')) { $RawUser['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            userPrincipalName = if ($RawUser.Contains('userPrincipalName')) { $RawUser['userPrincipalName'] } else { $null }
            accountEnabled    = if ($RawUser.Contains('accountEnabled')) { $RawUser['accountEnabled'] } else { $null }
            userType          = if ($RawUser.Contains('userType')) { $RawUser['userType'] } else { $null }
        }
        redacted         = $false
    }
}
