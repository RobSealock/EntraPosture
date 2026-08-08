#Requires -Version 7.4

function ConvertTo-EntraPostureUserSignInActivityEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph user object's signInActivity sub-object (from GET /v1.0/users?
        $select=id,signInActivity) into a canonical Entity record.

        .DESCRIPTION
        A deliberately separate entity type from User, not a bonus property merged onto it --
        entity.schema.json's one-canonical-source-per-entityId-per-type model doesn't support two
        different collectors both writing 'User' records, and more importantly, signInActivity is
        gated behind a real, distinct external dependency User itself is not: a Microsoft Entra ID
        P1 or P2 license, plus the AuditLog.Read.All permission (confirmed directly against the
        live "List users" Graph reference page, re-fetched 2026-08-08 -- "Details for the
        signInActivity property require a Microsoft Entra ID P1 or P2 license and the
        AuditLog.Read.All permission"). Keeping it a wholly separate collector/entity/coverage
        domain means an unlicensed tenant only loses USR-005 (NotEvaluated via
        AffectedControlIds, per the orchestration layer's standard coverage-gating), not the
        entire Users evidence set USR-007/008 and every future User-reading control also depend
        on -- baking signInActivity into CollectUsers.ps1's own $select would have put the whole
        Users collector at risk of a licensing 403 on any tenant without P1/P2.

        Field allowlist per section 8.4: id and the three signInActivity date fields
        (lastSignInDateTime, lastNonInteractiveSignInDateTime, lastSuccessfulSignInDateTime) --
        not the two accompanying *RequestId fields, which this project has no evaluation need
        for. lastSuccessfulSignInDateTime is USR-005's own primary field (Microsoft's own resource
        reference page: "Use this property if you need to determine when the account was truly
        accessed... This field can be used to build reports, such as inactive users").

        .PARAMETER RawUser
        One element of GET /v1.0/users' 'value' array (id + signInActivity only, per this
        collector's own $select).

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
        throw 'ConvertTo-EntraPostureUserSignInActivityEntity: raw user record has no id.'
    }

    $signInActivity = if ($RawUser.Contains('signInActivity')) { $RawUser['signInActivity'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawUser['id']
        entityType       = 'UserSignInActivity'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            lastSignInDateTime              = if ($signInActivity -and $signInActivity.Contains('lastSignInDateTime')) { $signInActivity['lastSignInDateTime'] } else { $null }
            lastNonInteractiveSignInDateTime = if ($signInActivity -and $signInActivity.Contains('lastNonInteractiveSignInDateTime')) { $signInActivity['lastNonInteractiveSignInDateTime'] } else { $null }
            lastSuccessfulSignInDateTime    = if ($signInActivity -and $signInActivity.Contains('lastSuccessfulSignInDateTime')) { $signInActivity['lastSuccessfulSignInDateTime'] } else { $null }
        }
        redacted         = $false
    }
}
