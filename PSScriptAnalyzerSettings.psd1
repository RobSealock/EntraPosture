@{
    <#
        Style/lint gate (engineering plan Phase 2: "Add Pester and PSScriptAnalyzer gates").
        Severity is set to fail CI on Warning and above; rules are the default rule set plus a
        few explicit additions relevant to this project's security posture (ADR-006/ADR-007/
        section 13: no plaintext secrets, no unapproved network primitives outside the
        transport layer once that layer exists).
    #>
    Severity     = @('Error', 'Warning')
    IncludeRules = @('*')
    ExcludeRules = @(
        # PSAvoidUsingWriteHost is intentionally allowed: engineering plan section 10.1 treats
        # console output as a deliberate, distinct concise-summary channel, not an oversight to
        # silence. Write-EntraPostureLog is the single sanctioned call site for it.
        'PSAvoidUsingWriteHost'

        # engineering plan section 18 mandates "UTF-8 without BOM and LF for canonical machine
        # files" as a deliberate project decision -- this rule's default recommendation
        # (add a BOM) directly conflicts with that decision and is excluded project-wide rather
        # than suppressed file-by-file.
        'PSUseBOMForUnicodeEncodedFile'
    )
    Rules        = @{
        PSAvoidUsingPlainTextForPassword = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $true
            BlockComment = $true
            Placement = 'begin'
        }
    }
}
