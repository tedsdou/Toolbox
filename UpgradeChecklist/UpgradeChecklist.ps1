#requires -Version 5.1 -RunAsAdministrator
<#
.SYNOPSIS
    Gather system inventory for upgrades
.DESCRIPTION
    Gather system inventory for upgrades
.OUTPUTS
    Output will be in the form of HTML located in $ENV:\Temp
.NOTES
    Author: Ted Sdoukos
    Version: 1.0
    
    DISCLAIMER:
    ===========
    This Sample Code is provided for the purpose of illustration only and is
    not intended to be used in a production environment.
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT
    WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
    LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
    FOR A PARTICULAR PURPOSE.

    We grant You a nonexclusive, royalty-free
    right to use and modify the Sample Code and to reproduce and distribute
    the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software
    product in which the Sample Code is embedded; (ii) to include a valid
    copyright notice on Your software product in which the Sample Code is
    embedded; and (iii) to indemnify, hold harmless, and defend Us and
    Our suppliers from and against any claims or lawsuits, including
    attorneys' fees, that arise or result from the use or distribution
    of the Sample Code.
#>
Function Find-ProfileInfo {
    [cmdletbinding()]
    param (
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = $env:computername
    )            
 
    foreach ($Computer in $ComputerName) {
        $pInfo = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $Computer -ErrorAction Ignore
        foreach ($p in $pInfo) {
            try {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier($p.sid)
                $objuser = $objsid.Translate([System.Security.Principal.NTAccount])
                $objusername = $objuser.value
            }
            catch {
                $objusername = $p.sid
            }
            switch ($p.status) {
                1 { $pType = 'Temporary' }
                2 { $pType = 'Roaming' }
                4 { $pType = 'Mandatory' }
                8 { $pType = 'Corrupted' }
                default { $pType = 'LOCAL' }
            }
            $User = $objUser.Value
            [PSCustomObject] @{
                'ComputerName'    = $Computer.ToUpper()
                'UserName'        = $User
                'LastLogon'       = $p.LastUseTime
                'ProfileName'     = $objusername
                'ProfilePath'     = $p.localpath
                'ProfileType'     = $pType
                'IsinUse'         = $p.loaded
                'IsSystemAccount' = $p.special
            }
  
        }
    }

}

Function Get-WUSettings {
    <#
    .SYNOPSIS
        Get Windows Update settings.
 
    .DESCRIPTION
        Use Get-WUSettings to get Windows Update settings.
 
    .PARAMETER WUAAPI
        Use Windows Update Agent API. Works only on local machine.
 
    .PARAMETER Registry
        Use Windows registry. Works only for GPO settings.
 
    .PARAMETER ComputerName
        Specify the name of the computer to the remote connection.
 
    .PARAMETER Debuger
        Debug mode.
 
    .EXAMPLE
        PS C:\> Get-WUSettings -Registry
         
            AcceptTrustedPublisherCerts : 1
            WUServer : https://wsus.contoso.com
            WUStatusServer : https://wsus.contoso.com
            DetectionFrequencyEnabled : 1
            DetectionFrequency : 2
            NoAutoRebootWithLoggedOnUsers : 1
            RebootRelaunchTimeoutEnabled : 1
            RebootRelaunchTimeout : 240
            IncludeRecommendedUpdates : 0
            NoAutoUpdate : 0
            AUOptions : 2 - Notify before download
            ScheduledInstallDay : 0 - Every Day
            ScheduledInstallTime : 4
            UseWUServer : 1
            ComputerName : G1
         
    .NOTES
        Author: Michal Gajda
         
    .LINK
        https://www.powershellgallery.com/packages/PSWindowsUpdate/1.6.0.3/Content/Get-WUSettings.ps1
    #>    

    [CmdletBinding(
        DefaultParameterSetName = 'Registry'
    )]
    Param
    (
        #Mode options
        [Switch]$Debuger,
        [Parameter(ParameterSetName = 'WUAAPI')]
        [Switch]$WUAAPI,
        [Parameter(ParameterSetName = 'Registry')]
        [Switch]$Registry,
        [parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Registry')]
        [String[]]$ComputerName    
    )
    
    Begin {
        If ($PSBoundParameters['Debuger']) {
            $DebugPreference = 'Continue'
        } #End If $PSBoundParameters['Debuger']
        
        $User = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Role = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

        if (!$Role) {
            Write-Warning 'To perform some operations you must run an elevated Windows PowerShell console.'    
        } #End If !$Role
    }
    
    Process {
        Write-Debug 'Check if ComputerName in set'
        If (-not($ComputerName)) {
            Write-Debug 'Set ComputerName to localhost'
            [String[]]$ComputerName = $env:COMPUTERNAME
        } #End If $ComputerName -eq $null

        $NotificationLevels = @{ 0 = '0 - Not configured'; 1 = '1 - Disabled'; 2 = '2 - Notify before download'; 3 = '3 - Notify before installation'; 4 = '4 - Scheduled installation'; 5 = '5 - Users configure' }
        $ScheduledInstallationDays = @{ 0 = '0 - Every Day'; 1 = '1 - Every Sunday'; 2 = '2 - Every Monday'; 3 = '3 - Every Tuesday'; 4 = '4 - Every Wednesday'; 5 = '5 - Every Thursday'; 6 = '6 - Every Friday'; 7 = '7 - EverySaturday' }

        $Results = @()
        Foreach ($Computer in $ComputerName) {        
            If (Test-Connection -ComputerName $Computer -Quiet) {
                Write-Debug "Connect to reg HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate for $Computer"
                $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]'LocalMachine', $Computer) 
                $RegistrySubKey1 = $RegistryKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\') 
                $RegistrySubKey2 = $RegistryKey.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\')                
                
                if ($RegistrySubKey1) { Write-Verbose 'Some settings are managed by your system administrator.' }
                                
                if ($WUAAPI) {
                    $AutoUpdateSettings = (New-Object -ComObject Microsoft.Update.AutoUpdate).Settings

                    $Result = New-Object -TypeName PSObject -Property @{
                        NotificationLevel         = $NotificationLevels[$AutoUpdateSettings.NotificationLevel]
                        ScheduledInstallationDay  = $ScheduledInstallationDays[$AutoUpdateSettings.ScheduledInstallationDay]
                        ScheduledInstallationTime = $AutoUpdateSettings.ScheduledInstallationTime
                        IncludeRecommendedUpdates = $AutoUpdateSettings.IncludeRecommendedUpdates
                        NonAdministratorsElevated = $AutoUpdateSettings.NonAdministratorsElevated
                        FeaturedUpdatesEnabled    = $AutoUpdateSettings.FeaturedUpdatesEnabled
                    }
                }
                elseif ($Registry) {
                    $Result = New-Object -TypeName PSObject
                    Try {
                        Foreach ($RegName in $RegistrySubKey1.GetValueNames()) { 
                            $Value = $RegistrySubKey1.GetValue($RegName) 
                            $Result | Add-Member -MemberType NoteProperty -Name $RegName -Value $Value
                        }
                        Foreach ($RegName in $RegistrySubKey2.GetValueNames()) { 
                            $Value = $RegistrySubKey2.GetValue($RegName) 
                            Switch ($RegName) {
                                'AUOptions' { $Value = $NotificationLevels[$Value] }
                                'ScheduledInstallDay' { $Value = $ScheduledInstallationDays[$Value] }
                            }
                            $Result | Add-Member -MemberType NoteProperty -Name $RegName -Value $Value
                        }
                    }
                    Catch {
                        Write-Error "Can't find registry subkey: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate. Probably you don't use Group Policy for Windows Update settings. Try use -WUAAPI on local machine." -ErrorAction Stop
                    }

                    $Result | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $Computer
                } #End elseif $Registry
                $Results += $Result
            } # End If Test-Connection -ComputerName $Computer -Quiet
        } # End Foreach $Computer in $ComputerName
 
        $Results

    } #End Process             
} 

Function Get-UACSetting {
    $UAC = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'EnableLUA'
    $AdminBehavior = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'ConsentPromptBehaviorAdmin'
    #https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#registry-key-settings

    switch ($AdminBehavior) {
        0 { $AdBeVal = 'Elevate without prompting' ; Break }
        1 { $AdBeVal = 'Prompt for credentials on the secure desktop' ; Break }
        2 { $AdBeVal = 'Prompt for consent on the secure desktop' ; Break }
        3 { $AdBeVal = 'Prompt for credentials' ; Break }
        4 { $AdBeVal = 'Prompt for consent' ; Break }
        5 { $AdBeVal = 'Prompt for consent for non-Windows binaries' ; Break }
    }
    if ($UAC -eq 1) {
        $UACVal = 'Enabled'
    }
    else {
        $UACVal = 'Disabled'
    }
    [PSCustomObject]@{
        'UAC-RunAllAdminApprovaleMode' = $UACVal
        'UAC-PromptForAdministrators'  = $AdBeVal
    }
}

Function Get-DiskInformation {
    Get-Disk | Select-Object -Property FriendlyName, Number, PartitionStyle, ProvisioningType, HealthStatus, OperationalStatus, PhysicalSectorSize, @{
        Name       = 'TotalSizeInBytes'
        Expression = { '{0:N0}' -f $_.Size }
    }, @{
        Name       = 'AllocatedSizeInBytes'
        Expression = { '{0:N0}' -f $_.AllocatedSize }
    }, NumberOfPartitions, IsBoot, IsClustered, IsHighlyAvailable, IsScaleOut, IsSystem 
}

function Get-VolumeInformation {
    Get-Volume | Select-Object -Property DriveLetter, FileSystem, FileSystemLabel, FileSystemType, OperationalStatus, HealthStatus, DriveType, @{
        Name       = 'SizeInBytes'
        Expression = { '{0:N0}' -f $_.Size }
    }, @{
        Name       = 'SizeRemainingInBytes'
        Expression = { '{0:N0}' -f $_.SizeRemaining }
    } 
}
function Get-NetworkInformation {
    $IPConfig = Get-NetIPConfiguration 
    $IPInfoResult = @()
    foreach ($IP in $IPConfig) {
        $NetAdapter = Get-NetAdapter | Where-Object { $_.InterfaceIndex -eq $IP.InterfaceIndex }
        $WMI = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($IP.InterfaceIndex)"
        $IPInfoResult += [PSCustomObject]@{
            'Interface'            = $IP.InterfaceAlias -join ','
            'IPv4Address'          = $IP.Ipv4Address.IPAddress -join ','
            'SunbetMask'           = $WMI.IPSubnet[0]
            'Gateway'              = $IP.IPv4DefaultGateway.NextHop
            'DNSServer'            = ($IP.DNSServer.ServerAddresses) -join ','
            'DNSSuffixSearchOrder' = $WMI.DNSDomainSuffixSearchOrder -join ', '
            'MacAddress'           = $NetAdapter.MacAddress
            'LinkSpeed'            = $NetAdapter.LinkSpeed
            'DriverInformation'    = $NetAdapter.DriverInformation
            'DriverVersion'        = $NetAdapter.DriverVersion
            'DriverDate'           = $NetAdapter.DriverDate
        } 
    }
    $IPInfoResult
}

# Specify the output path.  By default it will store locally on the machine.
$OutputPath = "$env:Temp\$Env:ComputerName-SystemInventory-$(Get-Date).html"
$UpgradeUserName = Read-Host -Prompt 'Please enter desired username for upgrade account.'
$UserPass = Read-Host -Prompt "Please enter password for $UpgradeUserName" -AsSecureString
$Header = @'
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
'@
#User information
Find-ProfileInfo | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>User Profile</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
Get-LocalUser | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Local User</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
Get-LocalGroup -PipelineVariable Group -Name 'Power Users', 'Remote Desktop Users', 'Remote Management Users' | Get-LocalGroupMember -ErrorAction SilentlyContinue | 
    Select-Object -Property @{name = 'GroupName'; expression = { $Group.Name } }, * | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Local Group</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
try {
    New-LocalUser -Name $UpgradeUserName -AccountNeverExpires -UserMayNotChangePassword -Password $UserPass -Description 'OS Upgrade Account' -ErrorAction Stop
    Add-LocalGroupMember -Group 'Administrators' -Member $UpgradeUserName -ErrorAction Stop
}
Catch {
    Write-Warning -Message "Unable to create user 'FCAOSUPGRADE'`n`rERROR:$($_.Exception.Message)"
}
#Get UAC information
Get-UACSetting | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>User Account Control</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append

#Network information
Get-NetworkInformation | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Network IP Configuration</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property Wins* | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Network WINS</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
Get-NetRoute | Select-Object -Property InterfaceIndex, AddressFamily, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, Store | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Network Route</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
Get-NetFirewallRule | Select-Object -Property Name, DisplayName, Enabled, Profile, Direction, Action, EdgeTraversalPolicy, Owner, PrimaryStatus, Status |
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Network Firewall Rule</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 

#Disable Firewall
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled 'False'
Get-ComputerInfo | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Computer Information</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 

#Disk information
Get-DiskInformation | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Disk Information</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
Get-VolumeInformation | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Volume Information</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
Get-SmbShare | Select-Object -Property Name, Path, Scoped, ScopeName, ShareState, AvailabilityType, ShareType, FolderEnumerationMode, CachingMode, LeasingMode, SmbInstance, ConcurrentUserLimit, ContinuouslyAvailable, EncryptData, Special, SecurityDescriptor | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>SMB Shares</font></u></b><br>' -PostContent '<br>' | 
    Out-File -FilePath $OutputPath -Append 
$InstalledFeatures = Get-WindowsFeature | Where-Object { $_.Installed }
$InstalledFeatures | Select-Object -Property Name, DisplayName, InstallState, FeatureType, Path |
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Installed Features</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
if ($InstalledFeatures.Name -match 'DFS') {
    Get-DfsnRoot -ComputerName $env:COMPUTERNAME | Select-Object -Property Path, Type, Properties, TimeToLIve, State, Description, Flags, @{'Name'='GrantAdminAccess';'Expression'={$_.GrantAdminAccess -join ', '}} | 
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>DFS-N</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
    Get-DfsReplicatedFolder | Select-Object -Property FolderName, DomainName, GroupName, DfsnPath, IsDfsnPathPublished, State | 
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>DFS-N Replication</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}
if (($InstalledFeatures.Name -Match 'file') -and (Get-Command -Name 'Get-FileShare' -ErrorAction Ignore)) {
    Get-FileShare | Select-Object -Property Name, HealthStatus, OperationalStatus, FileSharingProtocol, VolumeRelativePath | 
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>File Shares</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}
if ($InstalledFeatures.Name -Match 'print') {
    Get-Printer | Select-Object -Property Name, Description, PortName, DriverName, JobCount, PrinterStatus, Type, DeviceType, Location, Published, Shared, ShareName |
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Printer Shares</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}
if (($InstalledFeatures.Name -Match 'Web') -and (Get-Module -Name 'IISAdministration' -ListAvailable)) {
    Get-IISAppPool | Select-Object -Property Name, Status, ManagedRuntimeVersion, ManagedPipelineMode, StartMode |
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>IIS App Pool</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
    Get-IISSite | Select-Object -Property Name, ID, State, @{
        Name       = 'Bindings'
        Expression = { $_.Bindings | ForEach-Object { "$($_.protocol) $($_.bindingINformation) sslFlags=$($_.sslFlags)" } }
    }, @{
        Name       = 'PhysicalPath'
        Expression = { $_.Applications.VirtualDirectories.PhysicalPath }
    } |
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>IIS Site</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}

$SQL = Get-Service | Where-Object -FilterScript { $_.Name -match 'SQL' -or $_.DisplayName -match 'SQL'}
if ($SQL) {
    Get-CimInstance -ClassName CIM_Service | Where-Object -FilterScript {$_.Name -in $SQL.Name} | 
        Select-Object -Property Name, DisplayName, State, StartMode, StartName, ProcessID, Description |
        ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>SQL Information</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}

#Service information
Get-Service | Sort-Object -Property StartType | Select-Object -Property Name, Status, StartType | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Services</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 

#WSUS Information
If ($WSUS = Get-WUSettings) {
    $WSUS | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>WSUS Information</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 
}
Else {
    Get-WUSettings -WUAAPI | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>WSUS Information</font></u></b><br>' -PostContent '<br>' | 
        Out-File -FilePath $OutputPath -Append 
}
#Find last update
$LastUpdate = (Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn
[PSCustomObject]@{
    'PatchDate' = $LastUpdate
} | ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Last Update Date</font></u></b><br>' -PostContent '<br>' -Property 'PatchDate' | Out-File -FilePath $OutputPath -Append 
#Program information
Get-Package | Where-Object { $_.ProviderName -match 'msi|program' } | Select-Object -Property Name, Version | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Installed Programs</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 

#Get Event information
Get-WinEvent -FilterHashtable @{'LogName' = 'System', 'Application'; 'Level' = @(1, 2) } | Sort-Object -Property LogName, TimeCreated -Descending | 
    Select-Object -Property LogName, ProviderName, TimeCreated, ID, LevelDisplayName, Message, UserID, RecordID, Keywords |
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>System and Application Event Logs</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 

#Find Scheduled Tasks
Get-ScheduledTask | Select-Object -Property State, Author, Description, Principal, Settings, TaskName, TaskPath, URI | 
    ConvertTo-Html -Head $Header -PreContent '<b><u><font size = 4>Scheduled Task</font></u></b><br>' -PostContent '<br>' | Out-File -FilePath $OutputPath -Append 

### Uncomment rest of script to enable compatibility test.###
<# #Region Upgrade Compatibility Test
$SetupPath = 'E:' #Path to where setup.exe is for the OS
$ResultPath = "$env:Temp" #Path to output results

$CommandFile = "$ResultPath\Check.cmd"
Set-Content -Path $CommandFile -Value '@echo off' -Force
Add-Content -Path $CommandFile -Value "$SetupPath\setup.exe /Auto Upgrade /Quiet /NoReboot /DynamicUpdate Disable /Compat Scanonly" -Force
Add-Content -Path $CommandFile -Value "echo %ERRORLEVEL% > $ResultPath\check.txt" -Force

#Call Setup.exe to see if compatible
cmd.exe /c "$ResultPath\Check.cmd"

$result = Get-Content "$ResultPath\check.txt"
switch ($result) {
    '-1047526896 ' { $Message = "No issues found."; $Color = 'Green' ; Break}
    '-1047526904 ' { $Message = "Compatibility issues found (hard block)."; $Color = 'Red' ; Break}
    '-1047526908 ' { $Message = "Migration choice (auto upgrade) not available (probably the wrong SKU or architecture)·"; $Color = 'Yellow' ; Break}
    '-1047526912 ' { $Message = "Does not meet system requirements."; $Color = 'Yellow' ; Break}
    '-1047526898 ' { $Message = "Insufficient free disk space."; $Color = 'Yellow' ; Break }
    Default { $Message = "Unspecified Error ($_)`n`rPlease refer to:`n`r'https://docs.microsoft.com/en-us/windows/deployment/upgrade/resolution-procedures'`n`r'https://docs.microsoft.com/en-us/windows/deployment/upgrade/resolve-windows-10-upgrade-errors'"; $Color = 'Yellow'}
}
$Hex = [System.Convert]::ToString($result,16) -replace '^f+','0X'
Write-Host -Object "*** UPGRADE EVALUATION RESULT ***`n`r$Hex | $Message`n`rPlease review the logs located in 'C:\`$WINDOWS.~BT\Sources\Panther' for further information" -ForegroundColor Black -BackgroundColor $Color
#EndRegion #>
