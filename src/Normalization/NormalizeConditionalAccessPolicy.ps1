#Requires -Version 7.4

function ConvertTo-EntraPostureConditionalAccessPolicyEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph conditionalAccessPolicy object
        (GET /v1.0/identity/conditionalAccess/policies) into a canonical Entity record, with the
        full condition/grant-control/session-control object graph -- Phase 8's expansion of
        Phase 5's minimal (state/displayName/dates-only) stub.

        .DESCRIPTION
        Field shape confirmed directly against the current Microsoft Graph v1.0 resource
        documentation, not inherited from any reviewed source-tool repository (per the
        engineering plan's explicit warning that Conditional Access Validator/caOptics predate
        some current CA surface): conditionalAccessPolicy (updated_at 2026-06-20),
        conditionalAccessConditionSet (2025-12-03), conditionalAccessUsers (2024-11-21),
        conditionalAccessGrantControls (2026-04-28), conditionalAccessSessionControls
        (2024-11-27). The simpler sub-objects (applications, platforms, locations, devices,
        clientApplications, guestsOrExternalUsers, the individual session-control types) use
        well-documented Microsoft Graph field names not independently re-fetched this pass --
        same standing verification caveat already tracked for other controls/normalizers in
        00-open-questions.md.

        Unlike every other normalizer in this project (which flatten a small number of fields
        with prefixed keys, e.g. inboundTrustIsMfaAccepted), this one nests sub-objects directly
        under properties.conditions / properties.grantControls / properties.sessionControls --
        a deliberate deviation justified by depth: CA's condition model alone has ~10 sub-objects,
        and prefix-flattening that many fields would be harder to read and to consume from
        Phase 8's simulation engine than the nesting Graph itself already uses. properties remains
        a generic object per entity.schema.json (section 8.4: structure varies per entityType,
        validated by the owning collector's field allowlist, not the generic envelope).

        Deliberately NOT captured (each a documented v1 scope boundary, not an oversight):
        - conditions.devices.deviceRule -- the raw device-filter rule-language string is stored,
          but this project's Phase 8 simulation engine does not parse/evaluate device-filter rule
          syntax against a synthetic device in v1 (Test-EntraPostureConditionalAccessScenario's
          own DESCRIPTION documents this same boundary from the evaluator side).
        - grantControls.authenticationStrength -- only the policy ID reference is stored, not the
          resolved allowed-authentication-method-combinations set (a separate Graph resource,
          authenticationStrengthPolicy, not fetched by this collector).
        - conditions.users.includeGuestsOrExternalUsers/excludeGuestsOrExternalUsers -- the raw
          guestOrExternalUserTypes flags and external-tenant scope are stored, but the six-way
          B2B-collaboration-guest/B2B-collaboration-member/B2B-direct-connect/local-guest/
          service-provider/other-external distinction is not modeled as separate matchable
          categories in v1's simulation engine, only as a single "is this a guest" signal.

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
        throw 'ConvertTo-EntraPostureConditionalAccessPolicyEntity: raw policy record has no id.'
    }

    $rawConditions = if ($RawPolicy.Contains('conditions')) { $RawPolicy['conditions'] } else { $null }
    $rawUsers = if ($rawConditions -and $rawConditions.Contains('users')) { $rawConditions['users'] } else { $null }
    $rawApplications = if ($rawConditions -and $rawConditions.Contains('applications')) { $rawConditions['applications'] } else { $null }
    $rawPlatforms = if ($rawConditions -and $rawConditions.Contains('platforms')) { $rawConditions['platforms'] } else { $null }
    $rawLocations = if ($rawConditions -and $rawConditions.Contains('locations')) { $rawConditions['locations'] } else { $null }
    $rawDevices = if ($rawConditions -and $rawConditions.Contains('devices')) { $rawConditions['devices'] } else { $null }
    $rawDeviceFilter = if ($rawDevices -and $rawDevices.Contains('deviceFilter')) { $rawDevices['deviceFilter'] } else { $null }
    $rawClientApplications = if ($rawConditions -and $rawConditions.Contains('clientApplications')) { $rawConditions['clientApplications'] } else { $null }
    $rawAuthFlows = if ($rawConditions -and $rawConditions.Contains('authenticationFlows')) { $rawConditions['authenticationFlows'] } else { $null }
    $rawIncludeGuests = if ($rawUsers -and $rawUsers.Contains('includeGuestsOrExternalUsers')) { $rawUsers['includeGuestsOrExternalUsers'] } else { $null }
    $rawExcludeGuests = if ($rawUsers -and $rawUsers.Contains('excludeGuestsOrExternalUsers')) { $rawUsers['excludeGuestsOrExternalUsers'] } else { $null }

    $rawGrantControls = if ($RawPolicy.Contains('grantControls')) { $RawPolicy['grantControls'] } else { $null }
    $rawAuthStrength = if ($rawGrantControls -and $rawGrantControls.Contains('authenticationStrength')) { $rawGrantControls['authenticationStrength'] } else { $null }

    $rawSessionControls = if ($RawPolicy.Contains('sessionControls')) { $RawPolicy['sessionControls'] } else { $null }
    $rawSignInFrequency = if ($rawSessionControls -and $rawSessionControls.Contains('signInFrequency')) { $rawSessionControls['signInFrequency'] } else { $null }
    $rawPersistentBrowser = if ($rawSessionControls -and $rawSessionControls.Contains('persistentBrowser')) { $rawSessionControls['persistentBrowser'] } else { $null }
    $rawAppEnforced = if ($rawSessionControls -and $rawSessionControls.Contains('applicationEnforcedRestrictions')) { $rawSessionControls['applicationEnforcedRestrictions'] } else { $null }
    $rawCloudAppSecurity = if ($rawSessionControls -and $rawSessionControls.Contains('cloudAppSecurity')) { $rawSessionControls['cloudAppSecurity'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawPolicy['id']
        entityType       = 'ConditionalAccessPolicy'
        tenantScope      = $TenantScope
        displayName      = if ($RawPolicy.Contains('displayName')) { $RawPolicy['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            state            = if ($RawPolicy.Contains('state')) { $RawPolicy['state'] } else { $null }
            createdDateTime  = if ($RawPolicy.Contains('createdDateTime')) { $RawPolicy['createdDateTime'] } else { $null }
            modifiedDateTime = if ($RawPolicy.Contains('modifiedDateTime')) { $RawPolicy['modifiedDateTime'] } else { $null }

            conditions = [ordered]@{
                clientAppTypes             = @(if ($rawConditions -and $rawConditions.Contains('clientAppTypes')) { $rawConditions['clientAppTypes'] } else { @() })
                signInRiskLevels           = @(if ($rawConditions -and $rawConditions.Contains('signInRiskLevels')) { $rawConditions['signInRiskLevels'] } else { @() })
                userRiskLevels             = @(if ($rawConditions -and $rawConditions.Contains('userRiskLevels')) { $rawConditions['userRiskLevels'] } else { @() })
                servicePrincipalRiskLevels = @(if ($rawConditions -and $rawConditions.Contains('servicePrincipalRiskLevels')) { $rawConditions['servicePrincipalRiskLevels'] } else { @() })
                insiderRiskLevels          = if ($rawConditions -and $rawConditions.Contains('insiderRiskLevels')) { $rawConditions['insiderRiskLevels'] } else { $null }

                users = [ordered]@{
                    includeUsers                 = @(if ($rawUsers -and $rawUsers.Contains('includeUsers')) { $rawUsers['includeUsers'] } else { @() })
                    excludeUsers                 = @(if ($rawUsers -and $rawUsers.Contains('excludeUsers')) { $rawUsers['excludeUsers'] } else { @() })
                    includeGroups                = @(if ($rawUsers -and $rawUsers.Contains('includeGroups')) { $rawUsers['includeGroups'] } else { @() })
                    excludeGroups                = @(if ($rawUsers -and $rawUsers.Contains('excludeGroups')) { $rawUsers['excludeGroups'] } else { @() })
                    includeRoles                 = @(if ($rawUsers -and $rawUsers.Contains('includeRoles')) { $rawUsers['includeRoles'] } else { @() })
                    excludeRoles                 = @(if ($rawUsers -and $rawUsers.Contains('excludeRoles')) { $rawUsers['excludeRoles'] } else { @() })
                    includeGuestOrExternalUserTypes = @(if ($rawIncludeGuests -and $rawIncludeGuests.Contains('guestOrExternalUserTypes')) { ([string]$rawIncludeGuests['guestOrExternalUserTypes']).Split(',') } else { @() })
                    excludeGuestOrExternalUserTypes = @(if ($rawExcludeGuests -and $rawExcludeGuests.Contains('guestOrExternalUserTypes')) { ([string]$rawExcludeGuests['guestOrExternalUserTypes']).Split(',') } else { @() })
                }

                applications = [ordered]@{
                    includeApplications                          = @(if ($rawApplications -and $rawApplications.Contains('includeApplications')) { $rawApplications['includeApplications'] } else { @() })
                    excludeApplications                          = @(if ($rawApplications -and $rawApplications.Contains('excludeApplications')) { $rawApplications['excludeApplications'] } else { @() })
                    includeUserActions                           = @(if ($rawApplications -and $rawApplications.Contains('includeUserActions')) { $rawApplications['includeUserActions'] } else { @() })
                    includeAuthenticationContextClassReferences  = @(if ($rawApplications -and $rawApplications.Contains('includeAuthenticationContextClassReferences')) { $rawApplications['includeAuthenticationContextClassReferences'] } else { @() })
                }

                platforms = [ordered]@{
                    includePlatforms = @(if ($rawPlatforms -and $rawPlatforms.Contains('includePlatforms')) { $rawPlatforms['includePlatforms'] } else { @() })
                    excludePlatforms = @(if ($rawPlatforms -and $rawPlatforms.Contains('excludePlatforms')) { $rawPlatforms['excludePlatforms'] } else { @() })
                }

                locations = [ordered]@{
                    includeLocations = @(if ($rawLocations -and $rawLocations.Contains('includeLocations')) { $rawLocations['includeLocations'] } else { @() })
                    excludeLocations = @(if ($rawLocations -and $rawLocations.Contains('excludeLocations')) { $rawLocations['excludeLocations'] } else { @() })
                }

                devices = [ordered]@{
                    deviceFilterMode = if ($rawDeviceFilter -and $rawDeviceFilter.Contains('mode')) { $rawDeviceFilter['mode'] } else { $null }
                    deviceFilterRule = if ($rawDeviceFilter -and $rawDeviceFilter.Contains('rule')) { $rawDeviceFilter['rule'] } else { $null }
                }

                clientApplications = [ordered]@{
                    includeServicePrincipals = @(if ($rawClientApplications -and $rawClientApplications.Contains('includeServicePrincipals')) { $rawClientApplications['includeServicePrincipals'] } else { @() })
                    excludeServicePrincipals = @(if ($rawClientApplications -and $rawClientApplications.Contains('excludeServicePrincipals')) { $rawClientApplications['excludeServicePrincipals'] } else { @() })
                }

                authenticationFlowTransferMethods = if ($rawAuthFlows -and $rawAuthFlows.Contains('transferMethods')) { $rawAuthFlows['transferMethods'] } else { $null }
            }

            grantControls = [ordered]@{
                operator                    = if ($rawGrantControls -and $rawGrantControls.Contains('operator')) { $rawGrantControls['operator'] } else { $null }
                builtInControls             = @(if ($rawGrantControls -and $rawGrantControls.Contains('builtInControls')) { $rawGrantControls['builtInControls'] } else { @() })
                customAuthenticationFactors  = @(if ($rawGrantControls -and $rawGrantControls.Contains('customAuthenticationFactors')) { $rawGrantControls['customAuthenticationFactors'] } else { @() })
                termsOfUse                   = @(if ($rawGrantControls -and $rawGrantControls.Contains('termsOfUse')) { $rawGrantControls['termsOfUse'] } else { @() })
                authenticationStrengthId    = if ($rawAuthStrength -and $rawAuthStrength.Contains('id')) { $rawAuthStrength['id'] } else { $null }
            }

            sessionControls = [ordered]@{
                signInFrequencyIsEnabled       = if ($rawSignInFrequency -and $rawSignInFrequency.Contains('isEnabled')) { $rawSignInFrequency['isEnabled'] } else { $null }
                signInFrequencyValue           = if ($rawSignInFrequency -and $rawSignInFrequency.Contains('value')) { $rawSignInFrequency['value'] } else { $null }
                signInFrequencyType            = if ($rawSignInFrequency -and $rawSignInFrequency.Contains('type')) { $rawSignInFrequency['type'] } else { $null }
                signInFrequencyAuthenticationType = if ($rawSignInFrequency -and $rawSignInFrequency.Contains('frequencyInterval')) { $rawSignInFrequency['frequencyInterval'] } else { $null }
                persistentBrowserIsEnabled     = if ($rawPersistentBrowser -and $rawPersistentBrowser.Contains('isEnabled')) { $rawPersistentBrowser['isEnabled'] } else { $null }
                persistentBrowserMode          = if ($rawPersistentBrowser -and $rawPersistentBrowser.Contains('mode')) { $rawPersistentBrowser['mode'] } else { $null }
                applicationEnforcedRestrictionsIsEnabled = if ($rawAppEnforced -and $rawAppEnforced.Contains('isEnabled')) { $rawAppEnforced['isEnabled'] } else { $null }
                cloudAppSecurityIsEnabled      = if ($rawCloudAppSecurity -and $rawCloudAppSecurity.Contains('isEnabled')) { $rawCloudAppSecurity['isEnabled'] } else { $null }
                cloudAppSecurityType           = if ($rawCloudAppSecurity -and $rawCloudAppSecurity.Contains('cloudAppSecurityType')) { $rawCloudAppSecurity['cloudAppSecurityType'] } else { $null }
                disableResilienceDefaults      = if ($rawSessionControls -and $rawSessionControls.Contains('disableResilienceDefaults')) { $rawSessionControls['disableResilienceDefaults'] } else { $null }
            }
        }
        redacted         = $false
    }
}
