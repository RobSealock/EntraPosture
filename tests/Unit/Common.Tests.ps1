#Requires -Version 7.4
#Requires -Modules Pester

<#
    Unit tests for src/Common and src/Logging, dot-sourced directly (not through the built
    module) so private helpers are directly testable per engineering plan section 14 item 1.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/ExitCode.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/NewCorrelationId.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/NewErrorRecord.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/AssertNotImplemented.ps1')
    . (Join-Path $script:RepoRoot 'src/Logging/WriteLog.ps1')
}

Describe 'Get-EntraPostureExitCode' {
    It 'resolves every documented exit-code reason to its frozen integer (engineering plan section 11)' {
        @{
            Success                   = 0
            UnexpectedInternalError   = 1
            UnapprovedControlFailure  = 2
            PartialAssessment         = 3
            InvalidInput              = 4
            AuthPreflightFailure      = 5
            IntegrityFailure          = 6
            CollectionFailure         = 7
            EvaluationOrReportFailure = 8
        }.GetEnumerator() | ForEach-Object {
            Get-EntraPostureExitCode -Reason $_.Key | Should -Be $_.Value
        }
    }

    It 'rejects an unrecognized reason rather than returning a default code' {
        { Get-EntraPostureExitCode -Reason 'NotARealReason' } | Should -Throw
    }
}

Describe 'New-EntraPostureCorrelationId' {
    It 'returns a parseable GUID string' {
        $id = New-EntraPostureCorrelationId
        { [guid]::Parse($id) } | Should -Not -Throw
    }

    It 'returns a different value on each call' {
        (New-EntraPostureCorrelationId) | Should -Not -Be (New-EntraPostureCorrelationId)
    }
}

Describe 'Test-EntraPostureSafeDiagnosticText' {
    It 'accepts ordinary diagnostic text' {
        Test-EntraPostureSafeDiagnosticText -Text 'Collection failed: HTTP 503 from Graph after 3 retries.' | Should -BeTrue
    }

    It 'accepts an empty string' {
        Test-EntraPostureSafeDiagnosticText -Text '' | Should -BeTrue
    }

    It 'rejects text containing a Bearer token' {
        Test-EntraPostureSafeDiagnosticText -Text 'Request failed with header Authorization: Bearer abc123.def456-ghi' | Should -BeFalse
    }

    It 'rejects text containing an access_token query fragment' {
        Test-EntraPostureSafeDiagnosticText -Text 'Redirected to https://login/callback?access_token=eyabc123' | Should -BeFalse
    }

    It 'rejects text containing a JWT-shaped string' {
        $fakeJwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFmbmwm-EAY'
        Test-EntraPostureSafeDiagnosticText -Text "Token was: $fakeJwt" | Should -BeFalse
    }
}

Describe 'New-EntraPostureErrorRecord' {
    It 'builds a record with all required fields' {
        $record = New-EntraPostureErrorRecord -ErrorId 'TEST-ERROR-CASE' -Stage 'Collection' -Message 'safe message' -Source 'UnitTest' -Retryable $true -EndpointClass 'Graph.v1.0'

        $record.ErrorId | Should -Be 'TEST-ERROR-CASE'
        $record.Stage | Should -Be 'Collection'
        $record.Message | Should -Be 'safe message'
        $record.Source | Should -Be 'UnitTest'
        $record.Retryable | Should -BeTrue
        $record.EndpointClass | Should -Be 'Graph.v1.0'
        $record.CorrelationId | Should -Not -BeNullOrEmpty
        { [guid]::Parse($record.CorrelationId) } | Should -Not -Throw
        { [datetime]::Parse($record.TimestampUtc) } | Should -Not -Throw
    }

    It 'rejects an ErrorId that does not match the required pattern' {
        { New-EntraPostureErrorRecord -ErrorId 'not valid!' -Stage 'Collection' -Message 'x' } | Should -Throw
    }

    It 'throws rather than constructing a record when the message contains a token' {
        { New-EntraPostureErrorRecord -ErrorId 'TEST-CASE' -Stage 'Collection' -Message 'Authorization: Bearer abc123.def456-ghi' } | Should -Throw
    }

    It 'reuses a supplied correlation ID instead of generating a new one' {
        $suppliedId = [guid]::NewGuid().ToString()
        $record = New-EntraPostureErrorRecord -ErrorId 'TEST-CASE' -Stage 'Collection' -Message 'x' -CorrelationId $suppliedId
        $record.CorrelationId | Should -Be $suppliedId
    }
}

Describe 'Write-EntraPostureLog' {
    It 'returns a structured record with the requested level and stage' {
        $record = Write-EntraPostureLog -Level 'Debug' -Stage 'Build' -Message 'unit test message' -InformationAction SilentlyContinue 6>$null
        $record.Level | Should -Be 'Debug'
        $record.Stage | Should -Be 'Build'
        $record.Message | Should -Be 'unit test message'
    }

    It 'throws rather than logging a message that contains a token' {
        { Write-EntraPostureLog -Level 'Error' -Stage 'Collection' -Message 'leaked refresh_token=abc123' } | Should -Throw
    }

    It 'appends a JSONL line to -Path when supplied' {
        $tmpFile = Join-Path ([System.IO.Path]::GetTempPath()) "entraposture-log-test-$([guid]::NewGuid()).jsonl"
        try {
            Write-EntraPostureLog -Level 'Info' -Stage 'Build' -Message 'line one' -Path $tmpFile | Out-Null
            Write-EntraPostureLog -Level 'Info' -Stage 'Build' -Message 'line two' -Path $tmpFile | Out-Null

            $lines = Get-Content -LiteralPath $tmpFile
            $lines.Count | Should -Be 2
            { $lines[0] | ConvertFrom-Json } | Should -Not -Throw
            (($lines[0] | ConvertFrom-Json).Message) | Should -Be 'line one'
        } finally {
            Remove-Item -LiteralPath $tmpFile -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Assert-EntraPostureNotImplemented' {
    It 'throws an error identifying the command name and target phase' {
        { Assert-EntraPostureNotImplemented -CommandName 'Test-Command' -TargetPhase 'Phase 99' } |
            Should -Throw -ExpectedMessage '*Test-Command*Phase 99*'
    }
}
