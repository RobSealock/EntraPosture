#Requires -Version 7.4

function ConvertTo-EntraPostureUserRegistrationDetailsEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph userRegistrationDetails object (from GET /v1.0/reports/
        authenticationMethods/userRegistrationDetails) into a canonical Entity record.

        .DESCRIPTION
        A deliberately different evidence source from the naive "call
        /users/{id}/authentication/methods per user" approach USR-010/011/012 were originally
        deferred over (00-open-questions.md §36) -- Microsoft's own "List methods" reference page
        explicitly states: "We don't recommend using the authentication methods APIs for
        scenarios where you need to iterate over your entire user population for auditing or
        security check purposes... we recommend using the authentication method registration and
        usage reporting APIs" instead, naming this exact report. Re-scoped 2026-08-08 on that
        basis: this is a single bulk paginated call, not an N+1 fetch, and its `methodsRegistered`
        property is a flat string collection (`mobilePhone`, `email`, `passKeyDeviceBound`, etc.),
        not the polymorphic complex-typed collection `/authentication/methods` itself returns --
        both confirmed directly against the live "List userRegistrationDetails" and
        "userRegistrationDetails resource type" Graph reference pages, re-fetched 2026-08-08.

        Field allowlist per section 8.4: id (the user's own Entra ID object ID, confirmed on the
        resource's own reference page -- a direct 1:1 correlation key with the already-collected
        User entity, no join table needed), isAdmin, isMfaRegistered, isMfaCapable,
        isPasswordlessCapable, isSsprRegistered, isSsprEnabled, isSsprCapable, methodsRegistered,
        userType. isAdmin is Microsoft's own report-level "has an admin role" flag -- not used in
        place of this project's own curated Tier-0 role correlation (USR-006's own established
        pattern), only persisted alongside it since it's part of the same record.

        Requires AuditLog.Read.All (the same permission this project's UserSignInActivity
        collector already requests for USR-005) and, per the live "Authentication Methods
        Activity" guidance page (re-fetched 2026-08-08), a Microsoft Entra ID P1 or P2 license --
        the same collector-level licensing dependency USR-005 already established, surfacing as a
        real API failure (NotEvaluated via the orchestration layer's partial-evidence handling)
        on an unlicensed tenant, not detected by this project itself. The report also excludes
        disabled and recently soft-deleted users entirely (confirmed on the same guidance page),
        so this collector's own population is already implicitly enabled-users-only -- no
        separate accountEnabled filter is needed downstream.

        .PARAMETER RawUserRegistrationDetail
        One element of GET /v1.0/reports/authenticationMethods/userRegistrationDetails' 'value'
        array.

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
        [System.Collections.Specialized.OrderedDictionary]$RawUserRegistrationDetail,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawUserRegistrationDetail.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawUserRegistrationDetail['id'])) {
        throw 'ConvertTo-EntraPostureUserRegistrationDetailsEntity: raw record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawUserRegistrationDetail['id']
        entityType       = 'UserRegistrationDetails'
        tenantScope      = $TenantScope
        displayName      = if ($RawUserRegistrationDetail.Contains('userDisplayName')) { $RawUserRegistrationDetail['userDisplayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            isAdmin               = if ($RawUserRegistrationDetail.Contains('isAdmin')) { $RawUserRegistrationDetail['isAdmin'] } else { $null }
            isMfaRegistered       = if ($RawUserRegistrationDetail.Contains('isMfaRegistered')) { $RawUserRegistrationDetail['isMfaRegistered'] } else { $null }
            isMfaCapable          = if ($RawUserRegistrationDetail.Contains('isMfaCapable')) { $RawUserRegistrationDetail['isMfaCapable'] } else { $null }
            isPasswordlessCapable = if ($RawUserRegistrationDetail.Contains('isPasswordlessCapable')) { $RawUserRegistrationDetail['isPasswordlessCapable'] } else { $null }
            isSsprRegistered      = if ($RawUserRegistrationDetail.Contains('isSsprRegistered')) { $RawUserRegistrationDetail['isSsprRegistered'] } else { $null }
            isSsprEnabled         = if ($RawUserRegistrationDetail.Contains('isSsprEnabled')) { $RawUserRegistrationDetail['isSsprEnabled'] } else { $null }
            isSsprCapable         = if ($RawUserRegistrationDetail.Contains('isSsprCapable')) { $RawUserRegistrationDetail['isSsprCapable'] } else { $null }
            methodsRegistered     = @(if ($RawUserRegistrationDetail.Contains('methodsRegistered')) { $RawUserRegistrationDetail['methodsRegistered'] } else { @() })
            userType              = if ($RawUserRegistrationDetail.Contains('userType')) { $RawUserRegistrationDetail['userType'] } else { $null }
        }
        redacted         = $false
    }
}
