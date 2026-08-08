#Requires -Version 7.4

function Get-EntraPostureAvailableLoopbackPort {
    <#
        .SYNOPSIS
        Finds an available TCP port on the loopback interface for the redirect listener.

        .DESCRIPTION
        HttpListener has no "bind to port 0 and tell me what you picked" API, so this uses the
        conventional workaround: bind a throwaway TcpListener to port 0 (which the OS resolves
        to a free ephemeral port), read the assigned port back, then release it immediately
        before HttpListener binds the same port. There's an unavoidable, industry-standard small
        race window between the two binds; this is the same approach used by other native-app
        OAuth implementations for the same reason -- neither .NET nor the OS exposes a stronger
        primitive for this specific handoff.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param ()

    $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $tcpListener.Start()
        return $tcpListener.LocalEndpoint.Port
    } finally {
        $tcpListener.Stop()
    }
}

function Start-EntraPostureLoopbackListener {
    <#
        .SYNOPSIS
        Starts an HttpListener bound only to the loopback interface, for capturing the
        authorization-code redirect in the delegated interactive flow (RFC 8252).

        .DESCRIPTION
        Binds exclusively to http://localhost:<port>/ -- never 0.0.0.0 or a routable hostname --
        so the redirect endpoint is never reachable from outside the local machine (HttpListener
        resolves a "localhost" prefix to the loopback interface only, the same as an explicit
        127.0.0.1 bind). This is the "documented public-client flow" engineering plan section 7.1
        requires, and matches RFC 8252's recommendation over an embedded webview or a custom URI
        scheme.

        Deliberately uses the 'localhost' hostname rather than the 127.0.0.1 literal, even though
        Microsoft's own general redirect-URI guidance recommends preferring 127.0.0.1 "to prevent
        your app from breaking due to misconfigured firewalls or renamed network interfaces" --
        that guidance trades away a property this specific flow depends on. Confirmed directly
        against Microsoft Learn's redirect-URI documentation
        (https://learn.microsoft.com/en-us/entra/identity-platform/reply-url, "Localhost
        exceptions"): the port component of a redirect URI is matched-ignoring-port only for the
        literal 'localhost' hostname ("Due to ephemeral port ranges often required by native
        applications, the port component... is ignored for the purposes of matching a *localhost*
        redirect URI... This is *only* true for localhost redirect URIs. In all other cases, the
        port component is *not* ignored.") -- an app registration's single pre-registered redirect
        URI can therefore match this listener's randomly-chosen ephemeral port every run only when
        registered as http://localhost/ (or http://localhost:<any-port>/), never as
        http://127.0.0.1/. The original 127.0.0.1-based implementation would have failed
        AADSTS50011 (redirect URI mismatch) on every real run once a fixed app-registration
        redirect URI was registered against a genuinely random per-run port -- found and fixed
        while answering a live-tenant connection question, not by a failing test (no test
        exercised registration against a *pre-fixed* redirect URI, only same-run self-consistency).

        .OUTPUTS
        Ordered dictionary: Listener (started System.Net.HttpListener, caller must call
        Stop-EntraPostureLoopbackListener when done) and RedirectUri.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    $port = Get-EntraPostureAvailableLoopbackPort
    $redirectUri = "http://localhost:$port/"

    if (-not $PSCmdlet.ShouldProcess($redirectUri, 'Start loopback HTTP listener')) {
        return $null
    }

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($redirectUri)
    $listener.Start()

    return [ordered]@{
        Listener    = $listener
        RedirectUri = $redirectUri
    }
}

function Stop-EntraPostureLoopbackListener {
    <#
        .SYNOPSIS
        Stops and disposes a loopback listener started by Start-EntraPostureLoopbackListener.

        .PARAMETER Listener
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Idempotent cleanup/dispose step, always called from a finally block -- must always run to release the OS-level listener resource, the same way Dispose() is never itself gated behind -WhatIf.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Net.HttpListener]$Listener
    )

    if ($Listener.IsListening) {
        $Listener.Stop()
    }
    $Listener.Close()
}

function Receive-EntraPostureLoopbackRedirect {
    <#
        .SYNOPSIS
        Waits for exactly one redirect request on the loopback listener, validates the returned
        'state', and returns the authorization code (or throws on an OAuth error / state
        mismatch / timeout).

        .DESCRIPTION
        Responds to the browser with a minimal, static, self-contained HTML page (no external
        assets, no tenant data, no token echoed back into the page) so the user sees a clear
        "you can close this tab" result regardless of outcome. The state check is not optional
        and cannot be bypassed by a caller -- an authorization code is never returned without it
        matching exactly, which is what makes 'state' meaningful CSRF protection here rather
        than a value nobody checks.

        .PARAMETER Listener
        A started listener from Start-EntraPostureLoopbackListener.

        .PARAMETER ExpectedState
        The exact state value this run generated (New-EntraPostureOAuthState).

        .PARAMETER TimeoutSeconds
        How long to wait for the redirect before giving up. Default 300 (5 minutes), matching a
        realistic upper bound for a user to complete an interactive sign-in.

        .OUTPUTS
        The authorization code string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [System.Net.HttpListener]$Listener,

        [Parameter(Mandatory)]
        [string]$ExpectedState,

        [Parameter()]
        [int]$TimeoutSeconds = 300
    )

    $contextTask = $Listener.GetContextAsync()
    $completed = $contextTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))

    if (-not $completed) {
        throw "Receive-EntraPostureLoopbackRedirect: timed out after $TimeoutSeconds second(s) waiting for the sign-in redirect."
    }

    $context = $contextTask.Result
    $query = $context.Request.QueryString

    $responseHtml = $null
    $result = $null
    $errorMessage = $null

    $returnedState = $query['state']
    $authorizationCode = $query['code']
    $oauthError = $query['error']
    $oauthErrorDescription = $query['error_description']

    if ($oauthError) {
        $errorMessage = "Receive-EntraPostureLoopbackRedirect: identity provider returned an error: $oauthError - $oauthErrorDescription"
        $responseHtml = '<html><body><p>Sign-in failed. You can close this tab and return to the terminal.</p></body></html>'
    } elseif ($returnedState -ne $ExpectedState) {
        $errorMessage = 'Receive-EntraPostureLoopbackRedirect: state mismatch on redirect -- refusing to trust this authorization code. This could indicate a CSRF attempt or a stale/reused redirect.'
        $responseHtml = '<html><body><p>Sign-in could not be verified. You can close this tab and return to the terminal.</p></body></html>'
    } elseif ([string]::IsNullOrWhiteSpace($authorizationCode)) {
        $errorMessage = 'Receive-EntraPostureLoopbackRedirect: redirect contained no authorization code and no error.'
        $responseHtml = '<html><body><p>Sign-in failed. You can close this tab and return to the terminal.</p></body></html>'
    } else {
        $result = $authorizationCode
        $responseHtml = '<html><body><p>Sign-in complete. You can close this tab and return to the terminal.</p></body></html>'
    }

    $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
    $context.Response.ContentType = 'text/html; charset=utf-8'
    $context.Response.ContentLength64 = $buffer.Length
    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $context.Response.OutputStream.Close()

    if ($errorMessage) {
        throw $errorMessage
    }

    return $result
}
