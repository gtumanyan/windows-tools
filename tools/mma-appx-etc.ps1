
<#PSScriptInfo

.VERSION 2.81+

.GUID 5cc3176c-2e44-40d7-8ead-592e4e2e3665

.AUTHOR Jonathan E. Brickman & Gregory G. Tumanyan

.COMPANYNAME Ponderworthy Music

.COPYRIGHT (c) 2020 Jonathan E. Brickman

.TAGS 

.LICENSEURI https://opensource.org/licenses/BSD-3-Clause

.PROJECTURI https://github.com/jebofponderworthy/windows-tools

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES
mma-appx-etc - performance gains of several kinds new to Windows 8/10/201*
Configures MMAgent (including Superfetch, Memory Compression, etc.) for performance,
removes several consumer-grade appx items, disables preload of Edge Browser,
and disables Game Mode.

#> 













<# 

.DESCRIPTION 
mma-appx-etc - performance gains of several kinds new to Windows 8/10/201*

#> 

Param()


#####################################################################
# MMA, appx, and other 8+/2012+/10/201*/11/202* performance items   #
# v2.81                                                             #
#####################################################################

#
# by Jonathan E. Brickman
#
# Speeds up Windows 8+/2012+, with special attention to 10 and up.  Specifically:
#
# 1. Set MMAgent for performance.  This includes Superfetch, 
# memory compression, and page combining.  Far better to do these things,
# than to just turn Superfetch off.
#
# 2. Removes several AppX packages which Microsoft has preloaded, whose
# contents may pop up without warning, eating resources.  This includes
# the consumer-grade email/calendar/contacts apps, several Xbox gaming items,
# et cetera.
#
# 3. Removes Edge browser.
# 
# 4. Turns off Game Mode.
#
# The latter two changes identified by the extraordinary Joe Busby.
#
# Copyright 2019 Jonathan E. Brickman
# https://notes.ponderworthy.com/
# This script is licensed under the 3-Clause BSD License
# https://opensource.org/licenses/BSD-3-Clause
# and is reprised at the end of this file
#

""
""
"**************************************************************"
"   Disable Fast Startup   "
"**************************************************************"
""
""

powercfg /hibernate off

""
""
"*********************************************************************"
"   MMA, appx, and other 8+/2012+/10/201*/11/202* performance items   "
"*********************************************************************"
""
""

$WinVersionStr = Get-CimInstance -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption

if ($WinVersionStr -Like "*Windows 7*")
{
	"Windows 7.  Exiting."
	""
	exit 0
}

# Using this to suppress much error output:
$ErrorActionPreference= 'silentlycontinue'

"Configuring and enabling aspects of MMAgent..."

Set-Service sysmain -StartupType Automatic | Out-Null
Start-Service sysmain | Out-Null

Set-MMAgent -MaxOperationAPIFiles 8192 | Out-Null

$MMAgentSetup = Get-MMAgent

If (-Not ($WinVersionStr -Like "*Windows Server 201*"))
	{
	If (-Not $MMAgentSetup.ApplicationPrelaunch)
		{ Enable-MMAgent -ApplicationPreLaunch | Out-Null }
	}	
If (-Not $MMAgentSetup.MemoryCompression)
	{ Enable-MMAgent -MemoryCompression | Out-Null }
If (-Not $MMAgentSetup.OperationAPI)
	{ Enable-MMAgent -OperationAPI -ErrorAction SilentlyContinue }
If (-Not $MMAgentSetup.PageCombining)
	{ Enable-MMAgent -PageCombining | Out-Null }
	
"Removing appx's..."

# Will add deprovisioning:  Remove-AppxProvisionedPackage -Online -PackageName MyAppxPkg

function Remove-Package {
	param( [string] $PackageString )
	
	Get-AppxPackage -allusers -PackageTypeFilter Main, Bundle, Resource | 
	Where-Object {$_.Name -EQ $PackageString} | 
	Remove-AppxPackage -Allusers
}

"WindowsFeedbackHub..."
Remove-Package "Microsoft.WindowsFeedbackHub"
"BingChat..."
$BingChat = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name !BCILauncher 
if ($BingChat)
{
	Get-Process -Name BingChatInstaller | Stop-Process -Force
	Get-Process -Name BCILauncher | Stop-Process -Force
	$BingChat | Remove-ItemProperty -Name !BCILauncher -Force 
}
"BingNews..."
Remove-Package "Microsoft.BingNews"
"BingWeather..."
Remove-Package "Microsoft.BingWeather"
"Microsoft.YourPhone..."
Remove-Package "Microsoft.YourPhone"
"Yandex.Music..."
Remove-Package "A025C540.Yandex.Music"
"XboxApp..."
Remove-Package "Microsoft.XboxApp"
"XboxGamingOverlay..."
Remove-Package "Microsoft.XboxGamingOverlay"
"XboxIdentityProvider..."
Remove-Package "Microsoft.XboxIdentityProvider"
"Xbox.TCUI..."
Remove-Package "Microsoft.Xbox.TCUI"
"XboxSpeechToTextOverlay..."
Remove-Package "Microsoft.XboxSpeechToTextOverlay"
"WindowsCommunicationsApps..."
Remove-Package "Microsoft.WindowsCommunicationsApps"
"Advertising.Xaml..."
Remove-Package "Microsoft.Advertising.Xaml"
"Skype..."
Remove-Package "*Microsoft.Skype*"
"Disney..."
Remove-Package "*Disney*"
"People..."
Remove-Package "Microsoft.People"

Write-Information -MessageData "" -InformationAction Continue
"Removing Microsoft Edge..."
iex "&{$(irm https://raw.githubusercontent.com/he3als/EdgeRemover/main/get.ps1)} -UninstallEdge -RemoveEdgeData -NonInteractive"

# AMD External Events Utility (probably want this one)
if (Get-Service -Name "AMD External Events Utility" -ErrorAction SilentlyContinue)
{
	# Probably want this service running
	Stop-Service -Name "AMD External Events Utility"
	Set-Service -Name "AMD External Events Utility" -StartupType Manual
}

"Enabling Inline AutoComplete in File Explorer and Run Dialog..."
if (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete))
			{
				New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Force
			}
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Name "AutoSuggest" -PropertyType String -Value "yes" -Force | Out-Null
			New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Name "Append Completion" -PropertyType String -Value "yes" -Force | Out-Null

"Removing IDMan autorun entry..." # Didn't find any decent portable (
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name IDMan -Force -ErrorAction Ignore

"Showing All Tray Icons..."
if( [System.Environment]::OSVersion.Version.Build -lt 20000 ) {
	# Pre-Windows-11
	Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'EnableAutoTray' -Type 'DWord' -Value 0 -Force
} else {
	# Windows 11
	$RegPathControlPanelNotify = ('HKCU:\Control Panel\NotifyIconSettings')
	Foreach ($Item in Get-ChildItem $RegPathControlPanelNotify){ Set-ItemProperty -Path $Item.PSPath -Name "IsPromoted" -Value "1" -Type DWord }
}

# The rest do not apply to Windows 8 / Server 2012 platforms.
if ( ($WinVersionStr -Like "*Windows Server 2012*") -Or ($WinVersionStr -Like "*Windows 8*") )
	{ exit 0 }
	
"Disabling AutoGameMode..."
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services -Name "xbgm" -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null

"Letting Windows improve Start and search results by tracking app launches (Remember commands typed in Run)..." # 0 - Disable and Disable "Show most used apps"
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Type 'DWord' -Value 1 -Force

"Explorer. Adding 'Devices and Printers' to 'This PC'..."
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8A91A66-3A7D-4424-8D24-04E180695C7A}"

"Disabling Geolocation Service autostart - If disabled, Windows won't be able to determine your location for certain apps..."
Set-Service -Name "lfsvc" -StartupType Manual

"Disable Windows Compatibility Telemetry..."
taskkill /f /im compattelrunner.exe 2>&1 | Out-Null

Stop-Service -Name "DiagTrack" 2>&1 | Out-Null
Set-Service -Name DiagTrack -StartupType Disabled 2>&1 | Out-Null

"Enable verbvose startup/shutdown mode..."
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System verbosestatus -Value 1

"Disable Microsoft Consumer Experiences..."
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType "DWord" -Force -ErrorAction SilentlyContinue | Out-Null

"Device Metadata bug fix..."
If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "DeviceMetadataServiceURL").DeviceMetadataServiceURL -eq "http://go.microsoft.com/fwlink/?LinkID=252669&clcid=0x409")
{
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "DeviceMetadataServiceURL" -Value "http://dmd.metaservices.microsoft.com/dms/metadata.svc" -Force -ErrorAction SilentlyContinue
}