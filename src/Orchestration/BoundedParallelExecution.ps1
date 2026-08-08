#Requires -Version 7.4

function Invoke-EntraPostureBoundedParallel {
    <#
        .SYNOPSIS
        Runs one named function once per supplied parameter set, bounded to at most
        -ThrottleLimit concurrent invocations (engineering plan section 12: "Use bounded
        collection concurrency, default four, with central throttling"), returning results in the
        same order as -ParameterSets regardless of actual completion order.

        .DESCRIPTION
        Engineering plan section 12 also requires "Make all result ordering deterministic
        independently of collection concurrency" -- this function is the one place that
        requirement is actually enforced: work is dispatched concurrently (BeginInvoke on a
        bounded RunspacePool), but results are collected back by calling EndInvoke() on each
        [powershell] instance strictly in -ParameterSets' own input order, not completion order.
        Callers therefore never need their own thread-safe collections or their own re-sorting --
        merging the returned array sequentially, in order, is already deterministic.

        PowerShell's -Parallel/Start-ThreadJob/runspace primitives all start each unit of work in
        a genuinely fresh runspace: functions dot-sourced or imported in the calling scope are NOT
        automatically visible inside it (confirmed directly, not assumed -- a dot-sourced function
        call from inside a bare `ForEach-Object -Parallel` block throws "term ... is not
        recognized", and even a function from an Import-Module'd module isn't visible either
        unless the module is explicitly re-imported inside the parallel block itself). Rather than
        re-importing anything (which would need different logic for this project's dev-tree
        dot-sourcing vs. its built-module Import-Module contexts, and would reload the whole
        module once per concurrent worker), this function instead builds one InitialSessionState
        and injects every function already loaded in the CALLING scope whose name matches
        -FunctionNamePattern as a real SessionStateFunctionEntry, confirmed directly to correctly
        preserve CmdletBinding/typed parameters/OutputType and to correctly round-trip complex
        return types (e.g. ordered dictionaries) with no serialization step needed, since
        RunspacePool runspaces are same-process, just separate threads. This also sidesteps
        needing to manually enumerate -CommandName's own transitive function dependencies (e.g.
        Send-EntraPostureRequest calling Get-EntraPostureRetryDelay,
        Write-EntraPostureAuditRecord, etc.) -- every matching function loaded in the calling
        scope is injected wholesale, regardless of how deep the call chain goes.

        A per-work-item failure (the target function throwing) is caught individually and
        reported in that item's own result entry (Success=$false, ErrorMessage set) -- it does not
        abort or affect any other work item, matching the existing sequential
        try { collector } catch { $collectionErrors.Add(...) } pattern every caller of this
        function already used before switching to it.

        .PARAMETER CommandName
        Name of an already-loaded function (in the calling scope) to invoke once per parameter
        set. Must itself be side-effect-free with respect to shared mutable state -- this function
        provides concurrency, not synchronization, so CommandName must not read/write anything
        outside the arguments it's given and the value it returns.

        .PARAMETER ParameterSets
        One hashtable of named parameters per invocation. Determines both the number of
        invocations and the order results are returned in.

        .PARAMETER ThrottleLimit
        Maximum concurrent invocations. Defaults to 4 (engineering plan section 12's own stated
        default).

        .PARAMETER FunctionNamePattern
        Wildcard pattern selecting which currently-loaded functions to inject into each worker
        runspace. Defaults to this project's own naming convention, '*-EntraPosture*' -- every
        collector, normalizer, and transport function this project defines matches it, so the
        default is correct for every real caller; overridable only for tests that define
        differently-named helper functions.

        .OUTPUTS
        Array of ordered dictionaries, one per -ParameterSets entry, same order: Success (bool),
        Result (the function's return value, or $null if it threw), ErrorMessage (string or $null).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [string]$CommandName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [hashtable[]]$ParameterSets,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ThrottleLimit = 4,

        [Parameter()]
        [string]$FunctionNamePattern = '*-EntraPosture*'
    )

    if (@($ParameterSets).Count -eq 0) {
        return ,@()
    }

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($function in (Get-Command -Name $FunctionNamePattern -CommandType Function)) {
        $initialSessionState.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($function.Name, $function.Definition)) | Out-Null
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $initialSessionState, $Host)
    $pool.Open()

    try {
        # Every [powershell] instance is created (and BeginInvoke'd) up front -- the pool itself
        # enforces the ThrottleLimit bound on how many actually run concurrently, queuing the
        # rest; this loop does not need its own queuing logic.
        $pending = @(foreach ($parameterSet in $ParameterSets) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            $ps.AddCommand($CommandName).AddParameters($parameterSet) | Out-Null
            [ordered]@{
                PowerShell   = $ps
                AsyncResult  = $ps.BeginInvoke()
            }
        })

        # Collected strictly in -ParameterSets' own order (see this function's own DESCRIPTION
        # for why this is the actual determinism guarantee, not an incidental side effect).
        $results = @(foreach ($item in $pending) {
            try {
                $output = $item.PowerShell.EndInvoke($item.AsyncResult)
                [ordered]@{
                    Success      = $true
                    Result       = if (@($output).Count -eq 1) { $output[0] } else { $output }
                    ErrorMessage = $null
                }
            } catch {
                [ordered]@{
                    Success      = $false
                    Result       = $null
                    ErrorMessage = $_.Exception.Message
                }
            } finally {
                $item.PowerShell.Dispose()
            }
        })

        return ,@($results)
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
}
