#Requires -Version 7.4

function Test-EntraPosturePrivilegedRoleAssignmentControl {
    <#
        .SYNOPSIS
        PRIV-001's evaluator: counts Active DirectoryRoleAssignment relationships targeting the
        Global Administrator role and checks the count against Microsoft's recommended range.

        .DESCRIPTION
        One aggregate result per tenant (scope = the Global Administrator DirectoryRole's own
        entityId), not one result per individual assignment -- the applicable unit for this
        control is "the role's current membership," not each holder independently. Never
        produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        PRIV-001.psd1's expectedResultSemantics.

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

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $globalAdminRole = $roles | Where-Object { $_.displayName -eq 'Global Administrator' } | Select-Object -First 1

    if (-not $globalAdminRole) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PRIV-001-NO-GA-ROLE-ACTIVATED'
                Rationale          = 'No Global Administrator DirectoryRole entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $globalAdminRole.entityId
    $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' })
    $count = $activeAssignments.Count

    $evidenceRef = @([ordered]@{ entityId = $globalAdminRole.entityId; entityType = 'DirectoryRole' })
    foreach ($assignment in $activeAssignments) {
        $evidenceRef += [ordered]@{ entityId = $assignment.sourceEntityId; entityType = 'User' }
    }

    $result =
        if ($count -lt 2) {
            [ordered]@{
                Scope              = $globalAdminRole.entityId
                Status             = 'Fail'
                ReasonCode         = 'PRIV-001-TOO-FEW-GLOBAL-ADMINS'
                Rationale          = "Only $count Active Global Administrator assignment(s) found; Microsoft recommends at least 2 to avoid a single point of failure for tenant recovery."
                EvidenceReferences = $evidenceRef
            }
        } elseif ($count -gt 4) {
            [ordered]@{
                Scope              = $globalAdminRole.entityId
                Status             = 'Fail'
                ReasonCode         = 'PRIV-001-TOO-MANY-GLOBAL-ADMINS'
                Rationale          = "$count Active Global Administrator assignments found; Microsoft recommends keeping the count to 4 or fewer to limit blast radius."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $globalAdminRole.entityId
                Status             = 'Pass'
                ReasonCode         = 'PRIV-001-GLOBAL-ADMIN-COUNT-WITHIN-RANGE'
                Rationale          = "$count Active Global Administrator assignment(s) found, within Microsoft's recommended range of 2-4."
                EvidenceReferences = $evidenceRef
            }
        }

    # $result is a single ordered dictionary (one aggregate result per tenant), not an array --
    # ,@($result) wraps it into the proper 1-element array this function's OutputType promises,
    # using the same leading-comma pattern as every other array-returning function in this
    # project (see src/Evidence/EvidenceProvider.ps1 for the full empirical rationale for why
    # @() alone is not sufficient at a return boundary).
    return ,@($result)
}
