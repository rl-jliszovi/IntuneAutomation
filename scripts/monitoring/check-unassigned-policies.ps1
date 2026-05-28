<#
.TITLE
    Unassigned Policies Monitor

.SYNOPSIS
    Identify and report on all unassigned policies in Microsoft Intune.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves all device configuration policies
    configured in Intune, then checks which policies have no assignments to users, groups,
    or devices. Unassigned policies represent potential configuration drift, unused resources,
    or incomplete policy deployment. The script generates detailed reports in CSV format,
    highlighting unassigned policies with creation dates, policy types, and recommendations.
    This helps administrators maintain clean policy governance and identify policies that
    may need assignment or removal.

.TAGS
    Monitoring

.MINROLE
    Intune Administrator

.PERMISSIONS
    DeviceManagementConfiguration.Read.All

.AUTHOR
    Ugur Koc

.VERSION
    1.0

.CHANGELOG
    1.0 - Initial release

.LASTUPDATE
    2025-05-29

.EXAMPLE
    .\check-unassigned-policies.ps1
    Generates a report of all unassigned policies

.EXAMPLE
    .\check-unassigned-policies.ps1 -OutputPath "C:\Reports" -IncludeDetails
    Generates a detailed report and saves to specified directory

.EXAMPLE
    .\check-unassigned-policies.ps1 -CreatedWithinDays 7
    Generates report for policies created in the last 7 days

.NOTES
    - Requires Microsoft.Graph.Authentication module: Install-Module Microsoft.Graph.Authentication
    - Requires appropriate permissions in Azure AD
    - Checks all policy types: Device Configuration, Settings Catalog, Administrative Templates
    - Unassigned policies may indicate incomplete deployment or unused configurations
    - Regular monitoring helps maintain policy governance and compliance
    - Consider removing or assigning policies that have been unassigned for extended periods
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Directory path to save reports")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include detailed policy information")]
    [switch]$IncludeDetails,
    
    [Parameter(Mandatory = $false, HelpMessage = "Show only policies created in the last N days")]
    [ValidateRange(1, 365)]
    [int]$CreatedWithinDays = 0,
    
    [Parameter(Mandatory = $false, HelpMessage = "Force module installation without prompting")]
    [switch]$ForceModuleInstall
)

# ============================================================================
# ENVIRONMENT DETECTION AND SETUP
# ============================================================================

function Initialize-RequiredModule {
    <#
    .SYNOPSIS
    Ensures required modules are available and loaded
    #>
    param(
        [string[]]$ModuleNames,
        [bool]$IsAutomationEnvironment,
        [bool]$ForceInstall = $false
    )
    
    foreach ($ModuleName in $ModuleNames) {
        Write-Verbose "Checking module: $ModuleName"
        
        # Check if module is available
        $module = Get-Module -ListAvailable -Name $ModuleName | Select-Object -First 1
        
        if (-not $module) {
            if ($IsAutomationEnvironment) {
                $errorMessage = @"
Module '$ModuleName' is not available in this Azure Automation Account.

To resolve this issue:
1. Go to Azure Portal
2. Navigate to your Automation Account
3. Go to 'Modules' > 'Browse Gallery'
4. Search for '$ModuleName'
5. Click 'Import' and wait for installation to complete

Alternative: Use PowerShell to import the module:
Import-Module Az.Automation
Import-AzAutomationModule -AutomationAccountName "YourAccount" -ResourceGroupName "YourRG" -Name "$ModuleName"
"@
                throw $errorMessage
            }
            else {
                # Local environment - attempt to install
                Write-Information "Module '$ModuleName' not found. Attempting to install..." -InformationAction Continue
                
                if (-not $ForceInstall) {
                    $response = Read-Host "Install module '$ModuleName'? (Y/N)"
                    if ($response -notmatch '^[Yy]') {
                        throw "Module '$ModuleName' is required but installation was declined."
                    }
                }
                
                try {
                    # Check if running as administrator for AllUsers scope
                    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
                    $scope = if ($isAdmin) { "AllUsers" } else { "CurrentUser" }
                    
                    Write-Information "Installing '$ModuleName' in scope '$scope'..." -InformationAction Continue
                    Install-Module -Name $ModuleName -Scope $scope -Force -AllowClobber -Repository PSGallery
                    Write-Information "✓ Successfully installed '$ModuleName'" -InformationAction Continue
                }
                catch {
                    throw "Failed to install module '$ModuleName': $($_.Exception.Message)"
                }
            }
        }
        
        # Import the module
        try {
            Write-Verbose "Importing module: $ModuleName"
            Import-Module -Name $ModuleName -Force -ErrorAction Stop
            Write-Verbose "✓ Successfully imported '$ModuleName'"
        }
        catch {
            throw "Failed to import module '$ModuleName': $($_.Exception.Message)"
        }
    }
}

# Detect execution environment
if ($PSPrivateMetadata.JobId.Guid) {
    Write-Output "Running inside Azure Automation Runbook"
    $IsAzureAutomation = $true
}
else {
    Write-Information "Running locally in IDE or terminal" -InformationAction Continue
    $IsAzureAutomation = $false
}

# Initialize required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication"
)

try {
    Initialize-RequiredModule -ModuleNames $RequiredModules -IsAutomationEnvironment $IsAzureAutomation -ForceInstall $ForceModuleInstall
    Write-Verbose "✓ All required modules are available"
}
catch {
    Write-Error "Module initialization failed: $_"
    exit 1
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

try {
    if ($IsAzureAutomation) {
        # Azure Automation - Use Managed Identity
        Write-Output "Connecting to Microsoft Graph using Managed Identity..."
        Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
        Write-Output "✓ Successfully connected to Microsoft Graph using Managed Identity"
    }
    else {
        # Local execution - Use interactive authentication
        Write-Information "Connecting to Microsoft Graph with interactive authentication..." -InformationAction Continue
        $Scopes = @(
            "DeviceManagementConfiguration.Read.All"
        )
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
        Write-Information "✓ Successfully connected to Microsoft Graph" -InformationAction Continue
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Function to get all pages of results from Graph API
function Get-MgGraphAllPage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [int]$DelayMs = 100
    )
    
    $AllResults = @()
    $NextLink = $Uri
    $RequestCount = 0
    
    do {
        try {
            # Add delay to respect rate limits
            if ($RequestCount -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
            
            $Response = Invoke-MgGraphRequest -Uri $NextLink -Method GET
            $RequestCount++
            
            if ($Response.value) {
                $AllResults += $Response.value
            }
            else {
                $AllResults += $Response
            }
            
            $NextLink = $Response.'@odata.nextLink'
        }
        catch {
            if ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*throttled*") {
                Write-Information "`nRate limit hit, waiting 60 seconds..." -InformationAction Continue
                Start-Sleep -Seconds 60
                continue
            }
            Write-Warning "Error fetching data from $NextLink : $($_.Exception.Message)"
            break
        }
    } while ($NextLink)
    
    return $AllResults
}

# Function to get policy assignments
function Get-PolicyAssignment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        [Parameter(Mandatory = $true)]
        [string]$PolicyType
    )
    
    try {
        switch ($PolicyType) {
            "DeviceConfiguration" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId/assignments"
            }
            "ConfigurationPolicy" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$PolicyId/assignments"
            }
            "GroupPolicyConfiguration" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$PolicyId/assignments"
            }
            "DeviceCompliancePolicy" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$PolicyId/assignments"
            }
            "CompliancePolicy" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies/$PolicyId/assignments"
            }
            "PowerShellScript" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$PolicyId/assignments"
            }
            "ShellScript" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$PolicyId/assignments"
            }
            "AutopilotDeploymentProfile" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles/$PolicyId/assignments"
            }
            "CloudPCProvisioningPolicy" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies/$PolicyId/assignments"
            }
            "CloudPCUserSetting" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings/$PolicyId/assignments"
            }
            "EndpointSecurityIntent" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/intents/$PolicyId/assignments"
            }
            "MobileApp" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$PolicyId/assignments"
            }
            "iOSAppProtection" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$PolicyId/assignments"
            }
            "AndroidAppProtection" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections/$PolicyId/assignments"
            }
            "WindowsAppProtection" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections/$PolicyId/assignments"
            }
            "WindowsInformationProtectionMDM" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies/$PolicyId/assignments"
            }
            "WindowsInformationProtectionMAM" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies/$PolicyId/assignments"
            }
            "ManagedDeviceAppConfig" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$PolicyId/assignments"
            }
            "ManagedAppConfig" {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations/$PolicyId/assignments"
            }
            default {
                $AssignmentsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$PolicyId/assignments"
            }
        }
        
        $Assignments = Get-MgGraphAllPage -Uri $AssignmentsUri
        return $Assignments
    }
    catch {
        Write-Warning "Failed to get assignments for policy $PolicyId : $($_.Exception.Message)"
        return @()
    }
}

# Function to determine policy risk level
function Get-PolicyRiskLevel {
    param(
        [string]$PolicyName,
        [datetime]$CreatedDateTime,
        [string]$PolicyType
    )
    
    $DaysOld = (Get-Date) - $CreatedDateTime
    
    # High risk: Security-related policies that are unassigned
    if ($PolicyName -match "(Security|Firewall|BitLocker|Defender|Encryption|Password|PIN)") {
        return "High"
    }
    
    # High risk: Compliance policies that are unassigned
    if ($PolicyType -match "(Compliance|DeviceCompliance)") {
        return "High"
    }
    
    # High risk: Endpoint security intents and app protection / WIP policies
    if ($PolicyType -match "(EndpointSecurityIntent|iOSAppProtection|AndroidAppProtection|WindowsAppProtection|WindowsInformationProtection)") {
        return "High"
    }
    
    # Medium risk: App configuration policies and mobile apps
    if ($PolicyType -match "(ManagedDeviceAppConfig|ManagedAppConfig|MobileApp)") {
        return "Medium"
    }
    
    # Medium risk: Policies older than 30 days
    if ($DaysOld.Days -gt 30) {
        return "Medium"
    }
    
    # Low risk: Recently created policies
    return "Low"
}

# Function to format policy details
function Format-PolicyDetail {
    param(
        [object]$Policy,
        [string]$PolicyType
    )
    
    $Details = @()
    
    if ($PolicyType -eq "ConfigurationPolicy" -and $Policy.templateReference) {
        $Details += "Template: $($Policy.templateReference.templateDisplayName)"
        $Details += "Template Version: $($Policy.templateReference.templateDisplayVersion)"
    }
    
    if ($Policy.platforms) {
        $Details += "Platforms: $($Policy.platforms -join ', ')"
    }
    
    if ($Policy.technologies) {
        $Details += "Technologies: $($Policy.technologies -join ', ')"
    }
    
    if ($Policy.settingCount) {
        $Details += "Settings Count: $($Policy.settingCount)"
    }
    
    return $Details -join "; "
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

try {
    Write-Information "Starting unassigned policies analysis..." -InformationAction Continue
    
    # Calculate filter date if specified
    $FilterDate = $null
    if ($CreatedWithinDays -gt 0) {
        $FilterDate = (Get-Date).AddDays(-$CreatedWithinDays)
        Write-Information "Filtering policies created after: $($FilterDate.ToString('yyyy-MM-dd'))" -InformationAction Continue
    }
    
    # ========================================================================
    # GET ALL DEVICE CONFIGURATION POLICIES
    # ========================================================================
    
    Write-Information "Retrieving device configuration policies..." -InformationAction Continue
    
    $AllUnassignedPolicies = @()
    
    try {
        # Get traditional device configuration policies (with assignments expanded inline)
        $DeviceConfigUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$expand=assignments"
        $DeviceConfigurations = Get-MgGraphAllPage -Uri $DeviceConfigUri
        Write-Information "Retrieved $($DeviceConfigurations.Count) device configuration policies" -InformationAction Continue
        
        # Get Settings Catalog policies (Configuration Policies) (with assignments expanded inline)
        $ConfigPoliciesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$expand=assignments"
        $ConfigurationPolicies = Get-MgGraphAllPage -Uri $ConfigPoliciesUri
        Write-Information "Retrieved $($ConfigurationPolicies.Count) settings catalog policies" -InformationAction Continue
        
        # Get Administrative Templates (Group Policy Configurations) (with assignments expanded inline)
        $GroupPolicyUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$expand=assignments"
        $GroupPolicyConfigurations = Get-MgGraphAllPage -Uri $GroupPolicyUri
        Write-Information "Retrieved $($GroupPolicyConfigurations.Count) administrative template policies" -InformationAction Continue
        
        # Get Legacy Compliance Policies (with assignments expanded inline)
        $LegacyComplianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$expand=assignments"
        $LegacyCompliancePolicies = Get-MgGraphAllPage -Uri $LegacyComplianceUri
        Write-Information "Retrieved $($LegacyCompliancePolicies.Count) legacy compliance policies" -InformationAction Continue
        
        # Get New Compliance Policies (with assignments expanded inline)
        $CompliancePoliciesUri = "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies?`$expand=assignments"
        $CompliancePolicies = Get-MgGraphAllPage -Uri $CompliancePoliciesUri
        Write-Information "Retrieved $($CompliancePolicies.Count) new compliance policies" -InformationAction Continue
        
        # Get Windows PowerShell Scripts (with assignments expanded inline)
        $PowerShellScriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$expand=assignments"
        $PowerShellScripts = Get-MgGraphAllPage -Uri $PowerShellScriptsUri
        Write-Information "Retrieved $($PowerShellScripts.Count) PowerShell scripts" -InformationAction Continue
        
        # Get macOS Shell Scripts (with assignments expanded inline)
        $ShellScriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?`$expand=assignments"
        $ShellScripts = Get-MgGraphAllPage -Uri $ShellScriptsUri
        Write-Information "Retrieved $($ShellScripts.Count) shell scripts" -InformationAction Continue
        
        # Get Windows Autopilot Deployment Profiles (with assignments expanded inline)
        $AutopilotProfilesUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments"
        $AutopilotProfiles = Get-MgGraphAllPage -Uri $AutopilotProfilesUri
        Write-Information "Retrieved $($AutopilotProfiles.Count) Autopilot deployment profiles" -InformationAction Continue
        
        # Get Cloud PC Provisioning Policies (assignments only returned via $expand)
        $CloudPCProvisioningUri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$expand=assignments"
        $CloudPCProvisioningPolicies = Get-MgGraphAllPage -Uri $CloudPCProvisioningUri
        Write-Information "Retrieved $($CloudPCProvisioningPolicies.Count) Cloud PC provisioning policies" -InformationAction Continue
        
        # Get Cloud PC User Settings (with assignments expanded inline)
        $CloudPCUserSettingsUri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings?`$expand=assignments"
        $CloudPCUserSettings = Get-MgGraphAllPage -Uri $CloudPCUserSettingsUri
        Write-Information "Retrieved $($CloudPCUserSettings.Count) Cloud PC user settings" -InformationAction Continue
        
        # Get Endpoint Security Policies / Security Baselines (legacy intents; no extra permission beyond DeviceManagementConfiguration.Read.All)
        $EndpointSecurityIntentsUri = "https://graph.microsoft.com/beta/deviceManagement/intents?`$expand=assignments"
        $EndpointSecurityIntents = Get-MgGraphAllPage -Uri $EndpointSecurityIntentsUri
        Write-Information "Retrieved $($EndpointSecurityIntents.Count) endpoint security intents" -InformationAction Continue
        
        # Get Mobile App Assignments (with assignments expanded inline)
        $MobileAppsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$expand=assignments"
        $MobileApps = Get-MgGraphAllPage -Uri $MobileAppsUri
        Write-Information "Retrieved $($MobileApps.Count) mobile apps" -InformationAction Continue
        
        # Get iOS App Protection Policies (with assignments expanded inline)
        $iOSAppProtectionsUri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections?`$expand=assignments"
        $iOSAppProtections = Get-MgGraphAllPage -Uri $iOSAppProtectionsUri
        Write-Information "Retrieved $($iOSAppProtections.Count) iOS app protection policies" -InformationAction Continue
        
        # Get Android App Protection Policies (with assignments expanded inline)
        $AndroidAppProtectionsUri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?`$expand=assignments"
        $AndroidAppProtections = Get-MgGraphAllPage -Uri $AndroidAppProtectionsUri
        Write-Information "Retrieved $($AndroidAppProtections.Count) Android app protection policies" -InformationAction Continue
        
        # Get Windows App Protection Policies / MAM (beta endpoint, with assignments expanded inline)
        $WindowsAppProtectionsUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections?`$expand=assignments"
        $WindowsAppProtections = Get-MgGraphAllPage -Uri $WindowsAppProtectionsUri
        Write-Information "Retrieved $($WindowsAppProtections.Count) Windows app protection policies" -InformationAction Continue
        
        # Get Windows Information Protection Policies (MDM enrolled devices)
        $WIPMDMUri = "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies?`$expand=assignments"
        $WIPMDMPolicies = Get-MgGraphAllPage -Uri $WIPMDMUri
        Write-Information "Retrieved $($WIPMDMPolicies.Count) Windows Information Protection (MDM) policies" -InformationAction Continue
        
        # Get Windows Information Protection Policies (without enrollment / MAM)
        $WIPMAMUri = "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies?`$expand=assignments"
        $WIPMAMPolicies = Get-MgGraphAllPage -Uri $WIPMAMUri
        Write-Information "Retrieved $($WIPMAMPolicies.Count) Windows Information Protection (MAM) policies" -InformationAction Continue
        
        # Get App Configuration Policies for Managed Devices (with assignments expanded inline)
        $ManagedDeviceAppConfigsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
        $ManagedDeviceAppConfigs = Get-MgGraphAllPage -Uri $ManagedDeviceAppConfigsUri
        Write-Information "Retrieved $($ManagedDeviceAppConfigs.Count) managed device app configuration policies" -InformationAction Continue
        
        # Get App Configuration Policies for Managed Apps / MAM (targeted, with assignments expanded inline)
        $ManagedAppConfigsUri = "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations?`$expand=assignments"
        $ManagedAppConfigs = Get-MgGraphAllPage -Uri $ManagedAppConfigsUri
        Write-Information "Retrieved $($ManagedAppConfigs.Count) managed app configuration policies" -InformationAction Continue
    }
    catch {
        Write-Error "Failed to retrieve policies: $($_.Exception.Message)"
        exit 1
    }
    
    # ========================================================================
    # CHECK ASSIGNMENTS FOR EACH POLICY TYPE
    # ========================================================================
    
    Write-Information "Checking policy assignments..." -InformationAction Continue
    
    # Check Device Configuration Policies
    Write-Information "Analyzing device configuration policies..." -InformationAction Continue
    foreach ($Policy in $DeviceConfigurations) {
        try {
            # Apply date filter if specified
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) {
                    continue
                }
            }
            
            # Use assignments already expanded inline; fall back to individual call if not present
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "DeviceConfiguration" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime ([datetime]$Policy.createdDateTime) -PolicyType "DeviceConfiguration"
                $Details = Format-PolicyDetail -Policy $Policy -PolicyType "DeviceConfiguration"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Device Configuration"
                    PolicySubType   = $Policy.'@odata.type' -replace '#microsoft.graph.', ''
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = $Details
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing device configuration policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Settings Catalog Policies
    Write-Information "Analyzing settings catalog policies..." -InformationAction Continue
    foreach ($Policy in $ConfigurationPolicies) {
        try {
            # Apply date filter if specified
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) {
                    continue
                }
            }
            
            # Use assignments already expanded inline; fall back to individual call if not present
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "ConfigurationPolicy" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.name -CreatedDateTime ([datetime]$Policy.createdDateTime) -PolicyType "ConfigurationPolicy"
                $Details = Format-PolicyDetail -Policy $Policy -PolicyType "ConfigurationPolicy"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.name
                    PolicyType      = "Settings Catalog"
                    PolicySubType   = if ($Policy.templateReference) { $Policy.templateReference.templateDisplayName } else { "Custom" }
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = $Details
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing settings catalog policy '$($Policy.name)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Administrative Template Policies
    Write-Information "Analyzing administrative template policies..." -InformationAction Continue
    foreach ($Policy in $GroupPolicyConfigurations) {
        try {
            # Apply date filter if specified
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) {
                    continue
                }
            }
            
            # Use assignments already expanded inline; fall back to individual call if not present
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "GroupPolicyConfiguration" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime ([datetime]$Policy.createdDateTime) -PolicyType "GroupPolicyConfiguration"
                $Details = Format-PolicyDetail -Policy $Policy -PolicyType "GroupPolicyConfiguration"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Administrative Template"
                    PolicySubType   = "Group Policy"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = $Details
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing administrative template policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Legacy Compliance Policies
    Write-Information "Analyzing legacy compliance policies..." -InformationAction Continue
    foreach ($Policy in $LegacyCompliancePolicies) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "DeviceCompliancePolicy" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime ([datetime]$Policy.createdDateTime) -PolicyType "DeviceCompliancePolicy"
                $Details = Format-PolicyDetail -Policy $Policy -PolicyType "DeviceCompliancePolicy"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Compliance Policy (Legacy)"
                    PolicySubType   = $Policy.'@odata.type' -replace '#microsoft.graph.', ''
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = $Details
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing legacy compliance policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check New Compliance Policies
    Write-Information "Analyzing new compliance policies..." -InformationAction Continue
    foreach ($Policy in $CompliancePolicies) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "CompliancePolicy" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.name -CreatedDateTime ([datetime]$Policy.createdDateTime) -PolicyType "CompliancePolicy"
                $Details = Format-PolicyDetail -Policy $Policy -PolicyType "CompliancePolicy"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.name
                    PolicyType      = "Compliance Policy"
                    PolicySubType   = if ($Policy.templateReference) { $Policy.templateReference.templateDisplayName } else { "Custom" }
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = $Details
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing compliance policy '$($Policy.name)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Windows PowerShell Scripts
    Write-Information "Analyzing PowerShell scripts..." -InformationAction Continue
    foreach ($Script in $PowerShellScripts) {
        try {
            if ($FilterDate -and $Script.createdDateTime) {
                $CreatedDate = [datetime]$Script.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Script.assignments) { $Script.assignments } else { Get-PolicyAssignment -PolicyId $Script.id -PolicyType "PowerShellScript" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Script.displayName -CreatedDateTime ([datetime]$Script.createdDateTime) -PolicyType "PowerShellScript"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Script.displayName
                    PolicyType      = "PowerShell Script"
                    PolicySubType   = "Windows"
                    CreatedDateTime = $Script.createdDateTime
                    LastModified    = $Script.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Script.description
                    Details         = "FileName: $($Script.fileName)"
                    PolicyId        = $Script.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing PowerShell script '$($Script.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check macOS Shell Scripts
    Write-Information "Analyzing shell scripts..." -InformationAction Continue
    foreach ($Script in $ShellScripts) {
        try {
            if ($FilterDate -and $Script.createdDateTime) {
                $CreatedDate = [datetime]$Script.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Script.assignments) { $Script.assignments } else { Get-PolicyAssignment -PolicyId $Script.id -PolicyType "ShellScript" }
            
            if ($Assignments.Count -eq 0) {
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Script.displayName -CreatedDateTime ([datetime]$Script.createdDateTime) -PolicyType "ShellScript"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Script.displayName
                    PolicyType      = "Shell Script"
                    PolicySubType   = "macOS"
                    CreatedDateTime = $Script.createdDateTime
                    LastModified    = $Script.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Script.description
                    Details         = "FileName: $($Script.fileName)"
                    PolicyId        = $Script.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing shell script '$($Script.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Windows Autopilot Deployment Profiles
    Write-Information "Analyzing Autopilot deployment profiles..." -InformationAction Continue
    foreach ($Profile in $AutopilotProfiles) {
        try {
            if ($FilterDate -and $Profile.createdDateTime) {
                $CreatedDate = [datetime]$Profile.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Profile.assignments) { $Profile.assignments } else { Get-PolicyAssignment -PolicyId $Profile.id -PolicyType "AutopilotDeploymentProfile" }
            
            if ($Assignments.Count -eq 0) {
                $ProfileCreated = if ($Profile.createdDateTime) { [datetime]$Profile.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Profile.displayName -CreatedDateTime $ProfileCreated -PolicyType "AutopilotDeploymentProfile"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Profile.displayName
                    PolicyType      = "Autopilot Deployment Profile"
                    PolicySubType   = $Profile.'@odata.type' -replace '#microsoft.graph.', ''
                    CreatedDateTime = $Profile.createdDateTime
                    LastModified    = $Profile.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Profile.description
                    Details         = "DeploymentMode: $($Profile.outOfBoxExperienceSettings.deviceUsageType)"
                    PolicyId        = $Profile.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing Autopilot profile '$($Profile.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Cloud PC Provisioning Policies
    Write-Information "Analyzing Cloud PC provisioning policies..." -InformationAction Continue
    foreach ($Policy in $CloudPCProvisioningPolicies) {
        try {
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "CloudPCProvisioningPolicy" }
            
            if ($Assignments.Count -eq 0) {
                # CloudPC provisioning policies do not expose createdDateTime; use current date as safe fallback
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "CloudPCProvisioningPolicy"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Cloud PC Provisioning Policy"
                    PolicySubType   = if ($Policy.provisioningType) { $Policy.provisioningType } else { "Unknown" }
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "ProvisioningType: $($Policy.provisioningType); ImageType: $($Policy.imageType)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing Cloud PC provisioning policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Cloud PC User Settings
    Write-Information "Analyzing Cloud PC user settings..." -InformationAction Continue
    foreach ($Setting in $CloudPCUserSettings) {
        try {
            $Assignments = if ($null -ne $Setting.assignments) { $Setting.assignments } else { Get-PolicyAssignment -PolicyId $Setting.id -PolicyType "CloudPCUserSetting" }
            
            if ($Assignments.Count -eq 0) {
                # CloudPC user settings do not expose createdDateTime; use current date as safe fallback
                $SettingCreated = if ($Setting.createdDateTime) { [datetime]$Setting.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Setting.displayName -CreatedDateTime $SettingCreated -PolicyType "CloudPCUserSetting"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Setting.displayName
                    PolicyType      = "Cloud PC User Setting"
                    PolicySubType   = "Windows 365"
                    CreatedDateTime = $Setting.createdDateTime
                    LastModified    = $Setting.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = ""
                    Details         = "LocalAdminEnabled: $($Setting.localAdminEnabled); RestorePointEnabled: $($Setting.restorePointSetting.frequencyType)"
                    PolicyId        = $Setting.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing Cloud PC user setting '$($Setting.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Endpoint Security Policies / Security Baselines (legacy intents)
    Write-Information "Analyzing endpoint security intents..." -InformationAction Continue
    foreach ($Intent in $EndpointSecurityIntents) {
        try {
            if ($FilterDate -and $Intent.createdDateTime) {
                $CreatedDate = [datetime]$Intent.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Intent.assignments) { $Intent.assignments } else { Get-PolicyAssignment -PolicyId $Intent.id -PolicyType "EndpointSecurityIntent" }
            
            if ($Assignments.Count -eq 0) {
                $IntentCreated = if ($Intent.createdDateTime) { [datetime]$Intent.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Intent.displayName -CreatedDateTime $IntentCreated -PolicyType "EndpointSecurityIntent"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Intent.displayName
                    PolicyType      = "Endpoint Security Intent"
                    PolicySubType   = if ($Intent.templateId) { $Intent.templateId } else { "Unknown" }
                    CreatedDateTime = $Intent.createdDateTime
                    LastModified    = $Intent.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Intent.description
                    Details         = "TemplateId: $($Intent.templateId)"
                    PolicyId        = $Intent.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing endpoint security intent '$($Intent.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Mobile App Assignments
    Write-Information "Analyzing mobile app assignments..." -InformationAction Continue
    foreach ($App in $MobileApps) {
        try {
            if ($FilterDate -and $App.createdDateTime) {
                $CreatedDate = [datetime]$App.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $App.assignments) { $App.assignments } else { Get-PolicyAssignment -PolicyId $App.id -PolicyType "MobileApp" }
            
            if ($Assignments.Count -eq 0) {
                $AppCreated = if ($App.createdDateTime) { [datetime]$App.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $App.displayName -CreatedDateTime $AppCreated -PolicyType "MobileApp"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $App.displayName
                    PolicyType      = "Mobile App"
                    PolicySubType   = $App.'@odata.type' -replace '#microsoft.graph.', ''
                    CreatedDateTime = $App.createdDateTime
                    LastModified    = $App.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $App.description
                    Details         = "Publisher: $($App.publisher); PublishingState: $($App.publishingState)"
                    PolicyId        = $App.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing mobile app '$($App.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check iOS App Protection Policies
    Write-Information "Analyzing iOS app protection policies..." -InformationAction Continue
    foreach ($Policy in $iOSAppProtections) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "iOSAppProtection" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "iOSAppProtection"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "App Protection Policy"
                    PolicySubType   = "iOS"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "DeployedAppCount: $($Policy.deployedAppCount)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing iOS app protection policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Android App Protection Policies
    Write-Information "Analyzing Android app protection policies..." -InformationAction Continue
    foreach ($Policy in $AndroidAppProtections) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "AndroidAppProtection" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "AndroidAppProtection"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "App Protection Policy"
                    PolicySubType   = "Android"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "DeployedAppCount: $($Policy.deployedAppCount)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing Android app protection policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Windows App Protection Policies (MAM)
    Write-Information "Analyzing Windows app protection policies..." -InformationAction Continue
    foreach ($Policy in $WindowsAppProtections) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "WindowsAppProtection" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "WindowsAppProtection"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "App Protection Policy"
                    PolicySubType   = "Windows (MAM)"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "DeployedAppCount: $($Policy.deployedAppCount)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing Windows app protection policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Windows Information Protection Policies (MDM enrolled)
    Write-Information "Analyzing Windows Information Protection MDM policies..." -InformationAction Continue
    foreach ($Policy in $WIPMDMPolicies) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "WindowsInformationProtectionMDM" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "WindowsInformationProtectionMDM"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Windows Information Protection"
                    PolicySubType   = "MDM Enrolled"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "EnforcementLevel: $($Policy.enforcementLevel)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing WIP MDM policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check Windows Information Protection Policies (without enrollment / MAM)
    Write-Information "Analyzing Windows Information Protection MAM policies..." -InformationAction Continue
    foreach ($Policy in $WIPMAMPolicies) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "WindowsInformationProtectionMAM" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "WindowsInformationProtectionMAM"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "Windows Information Protection"
                    PolicySubType   = "Without Enrollment (MAM)"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "EnforcementLevel: $($Policy.enforcementLevel)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing WIP MAM policy '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check App Configuration Policies for Managed Devices
    Write-Information "Analyzing managed device app configuration policies..." -InformationAction Continue
    foreach ($Policy in $ManagedDeviceAppConfigs) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "ManagedDeviceAppConfig" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "ManagedDeviceAppConfig"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "App Configuration Policy"
                    PolicySubType   = "Managed Device"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "Platform: $($Policy.'@odata.type' -replace '#microsoft.graph.', '')"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing managed device app configuration '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # Check App Configuration Policies for Managed Apps (MAM / Targeted)
    Write-Information "Analyzing managed app configuration policies..." -InformationAction Continue
    foreach ($Policy in $ManagedAppConfigs) {
        try {
            if ($FilterDate -and $Policy.createdDateTime) {
                $CreatedDate = [datetime]$Policy.createdDateTime
                if ($CreatedDate -lt $FilterDate) { continue }
            }
            
            $Assignments = if ($null -ne $Policy.assignments) { $Policy.assignments } else { Get-PolicyAssignment -PolicyId $Policy.id -PolicyType "ManagedAppConfig" }
            
            if ($Assignments.Count -eq 0) {
                $PolicyCreated = if ($Policy.createdDateTime) { [datetime]$Policy.createdDateTime } else { Get-Date }
                $RiskLevel = Get-PolicyRiskLevel -PolicyName $Policy.displayName -CreatedDateTime $PolicyCreated -PolicyType "ManagedAppConfig"
                
                $UnassignedPolicy = [PSCustomObject]@{
                    PolicyName      = $Policy.displayName
                    PolicyType      = "App Configuration Policy"
                    PolicySubType   = "Managed App (MAM)"
                    CreatedDateTime = $Policy.createdDateTime
                    LastModified    = $Policy.lastModifiedDateTime
                    RiskLevel       = $RiskLevel
                    Description     = $Policy.description
                    Details         = "DeployedAppCount: $($Policy.deployedAppCount)"
                    PolicyId        = $Policy.id
                }
                $AllUnassignedPolicies += $UnassignedPolicy
            }
        }
        catch {
            Write-Warning "Error processing managed app configuration '$($Policy.displayName)': $($_.Exception.Message)"
            continue
        }
    }
    
    # ========================================================================
    # ENRICH RESULTS: ADD COMPUTED CSV COLUMNS
    # ========================================================================

    $AllUnassignedPolicies = $AllUnassignedPolicies | ForEach-Object {
        $CreatedDate = if ($_.CreatedDateTime) { [datetime]$_.CreatedDateTime } else { Get-Date }
        $DaysOld     = [int]((Get-Date) - $CreatedDate).TotalDays

        $Category = switch ($_.PolicyType) {
            { $_ -in @("Device Configuration", "Settings Catalog", "Administrative Template") } { "Device Configuration" }
            { $_ -in @("Compliance Policy (Legacy)", "Compliance Policy") }                      { "Compliance" }
            { $_ -in @("PowerShell Script", "Shell Script") }                                    { "Scripts" }
            "Autopilot Deployment Profile"                                                        { "Autopilot" }
            { $_ -in @("Cloud PC Provisioning Policy", "Cloud PC User Setting") }                { "Cloud PC" }
            "Endpoint Security Intent"                                                            { "Endpoint Security" }
            "Mobile App"                                                                          { "Apps" }
            { $_ -in @("App Protection Policy", "Windows Information Protection") }              { "App Protection" }
            "App Configuration Policy"                                                            { "App Configuration" }
            default                                                                               { "Other" }
        }

        $Recommendation = switch ($_.RiskLevel) {
            "High" {
                if ($DaysOld -gt 30) {
                    "Immediate review required - high-risk $($_.PolicyType) has been unassigned for $DaysOld days. Assign to appropriate groups or remove."
                }
                else {
                    "Assign promptly - high-risk $($_.PolicyType) is not yet deployed to any group or device."
                }
            }
            "Medium" {
                if ($DaysOld -gt 30) {
                    "Review recommended - $($_.PolicyType) has been unassigned for $DaysOld days. Assign or decommission if no longer needed."
                }
                else {
                    "Schedule assignment within 30 days or document reason for deferral."
                }
            }
            default { "Monitor - assign when ready or remove if unused." }
        }

        # Derive target platform from PolicyType, PolicySubType (@odata.type), and Details (Settings Catalog exposes platforms property there)
        $Platform = switch ($_.PolicyType) {
            # Unambiguously single-platform types
            "PowerShell Script"              { "Windows" }
            "Shell Script"                   { "macOS" }
            "Autopilot Deployment Profile"   { "Windows" }
            "Cloud PC Provisioning Policy"   { "Windows" }
            "Cloud PC User Setting"          { "Windows" }
            "Endpoint Security Intent"       { "Windows" }
            "Administrative Template"        { "Windows" }
            "Windows Information Protection" { "Windows" }

            # App protection - platform encoded in PolicySubType
            "App Protection Policy" {
                switch ($_.PolicySubType) {
                    "iOS"           { "iOS" }
                    "Android"       { "Android" }
                    "Windows (MAM)" { "Windows" }
                    default         { $_.PolicySubType }
                }
            }

            # @odata.type encoded in PolicySubType - parse keywords
            { $_ -in @("Device Configuration", "Compliance Policy (Legacy)", "Mobile App") } {
                $s = "$($_.PolicySubType)".ToLower()
                if     ($s -match "ios")              { "iOS" }
                elseif ($s -match "android")          { "Android" }
                elseif ($s -match "macos|mac")        { "macOS" }
                elseif ($s -match "linux")            { "Linux" }
                elseif ($s -match "chromeos")         { "ChromeOS" }
                elseif ($s -match "windows|win32|win10|win81|win8") { "Windows" }
                else                                  { "Cross-Platform" }
            }

            # Settings Catalog: Format-PolicyDetail writes "Platforms: <value>" into Details
            "Settings Catalog" {
                if ($_.Details -match "Platforms:\s*([^;]+)") {
                    $raw = $Matches[1].Trim().ToLower()
                    if     ($raw -match "ios")         { "iOS" }
                    elseif ($raw -match "android")     { "Android" }
                    elseif ($raw -match "macos|mac")   { "macOS" }
                    elseif ($raw -match "linux")       { "Linux" }
                    elseif ($raw -match "windows")     { "Windows" }
                    else                               { $Matches[1].Trim() }
                }
                else { "Windows" }
            }

            # New compliance policies: template name often contains platform keyword
            "Compliance Policy" {
                $s = "$($_.PolicySubType)".ToLower()
                if     ($s -match "ios")              { "iOS" }
                elseif ($s -match "android")          { "Android" }
                elseif ($s -match "macos|mac")        { "macOS" }
                elseif ($s -match "linux")            { "Linux" }
                elseif ($s -match "windows")          { "Windows" }
                else                                  { "Cross-Platform" }
            }

            # App config policies target apps across platforms
            "App Configuration Policy" { "Cross-Platform" }

            default { "Unknown" }
        }

        [PSCustomObject]@{
            PolicyName      = $_.PolicyName
            Category        = $Category
            PolicyType      = $_.PolicyType
            PolicySubType   = $_.PolicySubType
            Platform        = $Platform
            RiskLevel       = $_.RiskLevel
            Recommendation  = $Recommendation
            DaysOld         = $DaysOld
            CreatedDateTime = $_.CreatedDateTime
            LastModified    = $_.LastModified
            Description     = $_.Description
            Details         = $_.Details
            PolicyId        = $_.PolicyId
        }
    }

    # ========================================================================
    # DISPLAY RESULTS
    # ========================================================================
    
    Write-Information "`n========================================" -InformationAction Continue
    Write-Information "UNASSIGNED POLICIES ANALYSIS RESULTS" -InformationAction Continue
    Write-Information "========================================" -InformationAction Continue
    
    if ($AllUnassignedPolicies.Count -eq 0) {
        Write-Information "✓ No unassigned policies found!" -InformationAction Continue
        if ($FilterDate) {
            Write-Information "  (Checked policies created after $($FilterDate.ToString('yyyy-MM-dd')))" -InformationAction Continue
        }
    }
    else {
        Write-Information "Found $($AllUnassignedPolicies.Count) unassigned policies:" -InformationAction Continue
        
        # Group by risk level
        $HighRisk = $AllUnassignedPolicies | Where-Object { $_.RiskLevel -eq "High" }
        $MediumRisk = $AllUnassignedPolicies | Where-Object { $_.RiskLevel -eq "Medium" }
        $LowRisk = $AllUnassignedPolicies | Where-Object { $_.RiskLevel -eq "Low" }
        
        Write-Information "`nRisk Level Summary:" -InformationAction Continue
        Write-Information "  High Risk: $($HighRisk.Count) policies" -InformationAction Continue
        Write-Information "  Medium Risk: $($MediumRisk.Count) policies" -InformationAction Continue
        Write-Information "  Low Risk: $($LowRisk.Count) policies" -InformationAction Continue
        
        # Display top 10 unassigned policies
        Write-Information "`nTop 10 Unassigned Policies (by risk level):" -InformationAction Continue
        $TopPolicies = $AllUnassignedPolicies | Sort-Object @{Expression = {
                switch ($_.RiskLevel) {
                    "High" { 1 }
                    "Medium" { 2 }
                    "Low" { 3 }
                }
            }
        }, CreatedDateTime | Select-Object -First 10
        
        $PolicyNumber = 1
        foreach ($Policy in $TopPolicies) {
            Write-Information "`n[$PolicyNumber] $($Policy.PolicyName)" -InformationAction Continue
            Write-Information "  Type: $($Policy.PolicyType) ($($Policy.PolicySubType))" -InformationAction Continue
            Write-Information "  Created: $($Policy.CreatedDateTime)" -InformationAction Continue
            Write-Information "  Risk Level: $($Policy.RiskLevel)" -InformationAction Continue
            if ($Policy.Description) {
                Write-Information "  Description: $($Policy.Description)" -InformationAction Continue
            }
            if ($IncludeDetails -and $Policy.Details) {
                Write-Information "  Details: $($Policy.Details)" -InformationAction Continue
            }
            $PolicyNumber++
        }
    }
    
    # ========================================================================
    # EXPORT TO CSV
    # ========================================================================
    
    if ($AllUnassignedPolicies.Count -gt 0) {
        $OutputFile = Join-Path -Path $OutputPath -ChildPath "UnassignedPolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $AllUnassignedPolicies | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
            Write-Information "✓ Report exported to: $OutputFile" -InformationAction Continue
        }
        catch {
            Write-Warning "Failed to export CSV report: $($_.Exception.Message)"
        }
    }
    
    Write-Information "`n✓ Unassigned policies analysis completed successfully" -InformationAction Continue
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup operations
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Information "Disconnected from Microsoft Graph" -InformationAction Continue
    }
    catch {
        Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
    }
}

# ============================================================================
# SCRIPT SUMMARY
# ============================================================================

Write-Information "
========================================
Script Execution Summary
========================================
Script: Unassigned Policies Monitor
Total Items Checked: $($DeviceConfigurations.Count + $ConfigurationPolicies.Count + $GroupPolicyConfigurations.Count + $LegacyCompliancePolicies.Count + $CompliancePolicies.Count + $PowerShellScripts.Count + $ShellScripts.Count + $AutopilotProfiles.Count + $CloudPCProvisioningPolicies.Count + $CloudPCUserSettings.Count + $EndpointSecurityIntents.Count + $MobileApps.Count + $iOSAppProtections.Count + $AndroidAppProtections.Count + $WindowsAppProtections.Count + $WIPMDMPolicies.Count + $WIPMAMPolicies.Count + $ManagedDeviceAppConfigs.Count + $ManagedAppConfigs.Count)
Unassigned Policies Found: $($AllUnassignedPolicies.Count)
Status: Completed
========================================
" -InformationAction Continue 