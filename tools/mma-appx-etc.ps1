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
"Disabling Fast Startup..."
powercfg /hibernate off
""
"*********************************************************************"
"   MMA, appx, and other 8+/2012+/10/201*/11/202* performance items   "
"*********************************************************************"
""

$WinVersionStr = Get-CimInstance -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption

if ($WinVersionStr -Like "*Windows 7*") {
	"Windows 7.  Exiting."
	""
	exit 0
}

# Using this to suppress much error output:
$ErrorActionPreference = 'silentlycontinue'

"Configuring and enabling aspects of MMAgent..."
Set-MMAgent -MaxOperationAPIFiles 1024

$MMAgentSetup = Get-MMAgent

If (-Not ($WinVersionStr -Like "*Windows Server 201*")) {
	If (-Not $MMAgentSetup.ApplicationPrelaunch)
	{ Enable-MMAgent -ApplicationPreLaunch }
}
If (-Not $MMAgentSetup.MemoryCompression)
{ Enable-MMAgent -MemoryCompression }
# OperationAPI: May be hard-locked on NVMe systems or missing SysMain
If (-Not $MMAgentSetup.OperationAPI) {
	Try {
		Enable-MMAgent -OperationAPI -ErrorAction Stop
		Write-Host "  [OK] OperationAPI enabled" -ForegroundColor Green
	}
 Catch {
		# Specifically catch the "Error 50" or "Not Supported" scenario
		If ($_.Exception.Message -match "not supported" -or $_.FullyQualifiedErrorId -match "50") {
			Write-Host "  [LOCKED] OperationAPI is hard-locked by the OS (likely NVMe SSD or missing SysMain service). This is expected on fast storage." -ForegroundColor Yellow
		}
		Else {
			Write-Warning "  [FAIL] Could not enable OperationAPI: $($_.Exception.Message)"
		}
	}
}
If (-Not $MMAgentSetup.PageCombining)
{ Enable-MMAgent -PageCombining }

"
Removing appx's..."

# Will add deprovisioning:  Remove-AppxProvisionedPackage -Online -PackageName MyAppxPkg

function Remove-Package {
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline)]
		[string] $Name
	)

	begin {
		try {
			# "-PackageTypeFilter 'All'" also retrieves Provisionned packages
			$AllAppxPackages = Get-AppxPackage -AllUsers -PackageTypeFilter 'All' -Verbose:$false
		}
		catch {
			# PowerShell on Windows 10: Get-AppxPackage not found
			# https://github.com/PowerShell/PowerShell/issues/19031
			Import-Module -Name 'Appx' -UseWindowsPowerShell -Verbose:$false
			$AllAppxPackages = Get-AppxPackage -AllUsers -PackageTypeFilter 'All' -Verbose:$false
		}
	}

	process {
		$AppxPackageNames = ($AllAppxPackages | Where-Object -Property 'Name' -EQ -Value $Name).PackageFullName
		if ($AppxPackageNames) {
			"Removing $Name ..."
			Remove-AppxPackage $AppxPackageNames -ErrorAction SilentlyContinue
			Remove-AppxPackage $AppxPackageNames -Allusers -ErrorAction SilentlyContinue
		}
	}
}

$PreinstalledAppsToRemove = @(
	'A025C540.Yandex.Music'
	'AppUp.IntelArcSoftware'
	'Microsoft.Advertising.Xaml'
	'Microsoft.BingNews'
	'Microsoft.BingWeather'
	'Microsoft.Getstarted'
	'Microsoft.M365Companions'
	'Microsoft.MicrosoftOfficeHub'
	'Microsoft.MicrosoftSolitaireCollection'
	'Microsoft.People' # old
	'Microsoft.StorePurchaseApp'
	'Microsoft.WindowsFeedbackHub'
	'Microsoft.YourPhone'
	'Microsoft.ZuneMusic'
	'MicrosoftWindows.CrossDevice'
	'MSTeams'

	#'Xbox' # might be required for some games
	'Microsoft.GamingApp'
	'Microsoft.XboxApp' # old & Win10
	'Microsoft.Xbox.TCUI'
	'Microsoft.XboxGameOverlay'
	'Microsoft.XboxGamingOverlay'
	'Microsoft.XboxIdentityProvider'
	'Microsoft.XboxSpeechToTextOverlay'

	# Win 10
	'Microsoft.Microsoft3DViewer' # old
	'Microsoft.MixedReality.Portal' # old
	'Microsoft.Office.OneNote'
	'Microsoft.MSPaint' # old
	'Microsoft.SkypeApp' # old
	'Microsoft.Wallet' # old
)
$PreinstalledAppsToRemove | Remove-Package

"Removing Microsoft Edge..."
iex "&{$(irm https://raw.githubusercontent.com/he3als/EdgeRemover/main/get.ps1)} -UninstallEdge -RemoveEdgeData -NonInteractive"
""
# AMD External Events Utility (probably want this one)
"Stopping AMD External Events Utility..."
if (Get-Service -Name "AMD External Events Utility") {
	# Probably want this service running
	Stop-Service -Name "AMD External Events Utility"
	Set-Service -Name "AMD External Events Utility" -StartupType Manual
}

"Enabling Inline AutoComplete in File Explorer and Run Dialog..."
if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete)) {
	New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Force
}
$null = New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Name "AutoSuggest" -PropertyType String -Value "yes" -Force
$null = New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete -Name "Append Completion" -PropertyType String -Value "yes" -Force

"Removing IDMan autorun entry..." # Didn't find any decent portable (
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name IDMan -Force

"Showing All Tray Icons..."
if ( [System.Environment]::OSVersion.Version.Build -lt 20000 ) {
	# Pre-Windows-11
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name "EnableAutoTray" -Type DWord -Value 0 -Force
}
else {
	# Windows 11
	$RegPathControlPanelNotify = ('HKCU:\Control Panel\NotifyIconSettings')
	Foreach ($Item in Get-ChildItem $RegPathControlPanelNotify) { Set-ItemProperty -Path $Item.PSPath -Name "IsPromoted" -Value "1" -Type DWord }
}

# control panel (icons view) > date and time (timedate.cpl) > internet time
$TimeServer = switch ('Cloudflare') {
	'OpenWRT' { '0.openwrt.pool.ntp.org 1.openwrt.pool.ntp.org 2.openwrt.pool.ntp.org 3.openwrt.pool.ntp.org' }
	'Cloudflare' { 'time.cloudflare.com' }
	'Windows' { 'time.windows.com' }
	'NistGov' { 'time.nist.gov' }
	'PoolNtpOrg' { '0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org' }
}
"Setting 'Internet Time Server' to '$TimeServer' ..."
Start-Service -Name 'W32Time'
$MaxRetries = 20
$RetryCount = 0
while ((Get-Service -Name 'W32Time').Status -ne 'Running' -and $RetryCount -lt $MaxRetries) {
	Start-Sleep -Seconds 0.1
	$RetryCount++
}
if ($RetryCount -eq $MaxRetries) {
	Write-Error -Message "    Cannot start W32Time service. Settings not applied."
}
else {
	w32tm.exe /config /syncfromflags:manual /manualpeerlist:"$TimeServer" /update | Out-Null
}

# The rest do not apply to Windows 8 / Server 2012 platforms.
if ( ($WinVersionStr -Like "*Windows Server 2012*") -Or ($WinVersionStr -Like "*Windows 8*") )
{ exit 0 }

"Disabling AutoGameMode..."
$null = Set-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name AutoGameModeEnabled -Value 0 -Force

"Letting Windows improve Start and search results by tracking app launches (Remember commands typed in Run)..." # 0 - Disable and Disable "Show most used apps"
Set-ItemProperty -Path Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name 'Start_TrackProgs' -Type DWord -Value 1 -Force

"Explorer. Adding 'Devices and Printers' to 'This PC'..."
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8A91A66-3A7D-4424-8D24-04E180695C7A}"

"Disable Windows Compatibility Telemetry..."
Stop-Service -Name "DiagTrack" 2>&1
$null = Set-Service -Name DiagTrack -StartupType Disabled

"Enable verbvose startup/shutdown mode..."
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System verbosestatus -Value 1

"Disable Microsoft Consumer Experiences..."
$null = New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType "DWord" -Force -ErrorAction SilentlyContinue

""