#Requires -Version 7.4

function New-EntraPostureTokenCache {
    <#
        .SYNOPSIS
        Creates a new, empty, in-process-memory-only token cache.

        .DESCRIPTION
        Engineering plan section 7.1: "Tokens retained in process memory only" and section 13:
        "no secrets or tokens in config, logs, errors, snapshots, reports, or test artifacts."
        This cache has no disk-backed persistence path at all -- not "persistence disabled by a
        setting," but no code path capable of writing a token to disk in the first place, so
        there is no configuration mistake that could turn it on. Entries live only as long as
        the PowerShell session that created them; nothing survives process exit by design.

        Keyed by (resourceAudience, tenantId) so the same session can concurrently hold Graph
        and Azure ARM tokens, or tokens for the same resource across a tenant switch, without
        collision.

        .OUTPUTS
        A cache handle (ordered dictionary wrapping a private hashtable) to pass to
        Get-EntraPostureCachedToken / Set-EntraPostureCachedToken /
        Remove-EntraPostureCachedToken / Clear-EntraPostureTokenCache.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Allocates an in-process-memory-only object with no disk/network/system side effect.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return [ordered]@{
        # A generic Hashtable here is an internal implementation detail of the cache, never
        # serialized/hashed/compared -- it deliberately does not go through this project's
        # canonical-ordered-dictionary discipline, which exists for on-disk/hashed records, not
        # runtime-only in-memory state.
        Store = [hashtable]::Synchronized(@{})
    }
}

function Get-EntraPostureTokenCacheKey {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$Audience,

        [Parameter(Mandatory)]
        [string]$TenantId
    )
    return "$Audience|$TenantId"
}

function Set-EntraPostureCachedToken {
    <#
        .SYNOPSIS
        Stores an access token in the memory-only cache, keyed by audience and tenant.

        .PARAMETER Cache
        A handle from New-EntraPostureTokenCache.

        .PARAMETER Audience
        .PARAMETER TenantId

        .PARAMETER AccessToken

        .PARAMETER ExpiresAtUtc
        Absolute UTC expiry, used by Get-EntraPostureCachedToken to decide whether a cached
        entry is still usable without needing to re-decode the token's own 'exp' claim every time.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Mutates an in-process-memory-only cache, not disk/network/system state.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Cache,

        [Parameter(Mandatory)]
        [string]$Audience,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [datetime]$ExpiresAtUtc
    )

    $key = Get-EntraPostureTokenCacheKey -Audience $Audience -TenantId $TenantId
    $Cache.Store[$key] = [ordered]@{
        AccessToken  = $AccessToken
        ExpiresAtUtc = $ExpiresAtUtc.ToUniversalTime()
    }
}

function Get-EntraPostureCachedToken {
    <#
        .SYNOPSIS
        Returns a cached access token if one exists and has not expired (with a small
        expiry-skew buffer), or $null otherwise.

        .DESCRIPTION
        Never returns a token within 60 seconds of its recorded expiry -- callers should treat a
        $null result as "acquire a fresh token," not retry against the cache. This is a small,
        deliberate buffer against a token expiring mid-request.

        .PARAMETER Cache
        .PARAMETER Audience
        .PARAMETER TenantId
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Cache,

        [Parameter(Mandatory)]
        [string]$Audience,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $key = Get-EntraPostureTokenCacheKey -Audience $Audience -TenantId $TenantId
    if (-not $Cache.Store.ContainsKey($key)) {
        return $null
    }

    $entry = $Cache.Store[$key]
    $skewBuffer = [TimeSpan]::FromSeconds(60)
    if ((Get-Date).ToUniversalTime() -ge ($entry.ExpiresAtUtc - $skewBuffer)) {
        # Expired (or expiring imminently) -- remove it so a stale entry never lingers to
        # confuse a later cache inspection, and return null to force reacquisition.
        $Cache.Store.Remove($key)
        return $null
    }

    return $entry.AccessToken
}

function Remove-EntraPostureCachedToken {
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Mutates an in-process-memory-only cache, not disk/network/system state.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Cache,

        [Parameter(Mandatory)]
        [string]$Audience,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $key = Get-EntraPostureTokenCacheKey -Audience $Audience -TenantId $TenantId
    $Cache.Store.Remove($key)
}

function Clear-EntraPostureTokenCache {
    <#
        .SYNOPSIS
        Removes every cached token. Called at the end of a run (mirrors the Phase 2
        Start-CleanUp-style discipline of not letting session state outlive its need) and
        available for a caller to invoke early if a run must abandon its tokens immediately
        (e.g. after a detected tenant-binding failure).

        .PARAMETER Cache
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Cache
    )

    $Cache.Store.Clear()
}
