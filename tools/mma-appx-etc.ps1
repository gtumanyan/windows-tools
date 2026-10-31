<#
Purpose:       Script to remove many of the pre-loaded Microsoft Metro "modern app" bloatware
               Add any AppX to this list to target them for removal
Requirements:  1. Administrator access
               2. Windows 8 and up
Author:        WindR https://t.me/Snappy_Driver_Installer
Version:       3 ! Edge browser removal and much more
                 ! Remove installed packages for all users (Windows 10 1803 and up) instead of only the user running the script. Falls back to the
					current user if the all-users removal fails
                 + Stop early if not run as Administrator
				 + Never require a sign-in on wake
				 + Synchronize system time to fix SSL/TLS errors in other scripts
				 + Show all tray icons even on Windows 11 (requires relaunch if new icons are hidden)
				 + Remove IDMan startup
				 + Disable apps resume
				 + Removing Realtek HD Panel from autorun
				 + Do not autostart AMD External Events Utility
				 + Enable Inline AutoComplete in File Explorer and Run
				 + Minimize Keyboard Character Repeat Delay
				 + Remember commands typed in Run menu
				 + Add 'Devices and Printers' to 'This PC' (Do we really need it here?)
				 + Startup/Shutdown Verbose Status Messages
				 + Set Windows Terminal to Automatically copy selection to clipboard
#>
# Using this to suppress much error output:
$ErrorActionPreference = "SilentlyContinue"

#################################################################
# MMA, appx, and other 8+/2012+/10/201*/11/2* performance items #
# v3															#
#################################################################
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

# Must be run as Administrator, otherwise provisioned packages can't be removed
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Output "   ERROR: Not running as Administrator. No apps removed."
	exit 1
}

""
"*******************************************************************"
"   MMA, appx, and other 8+/2012+/10/201*/11/2* performance items 	"
"*******************************************************************"
""

# Never require a sign-in on wake (ConsoleLock: 0 = never, 1 = when the PC wakes from sleep).
"Stopping the machine from demanding a password on wake..."
powercfg /setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0
powercfg /setactive SCHEME_CURRENT

$WinVersionStr = Get-CimInstance -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption

if ($WinVersionStr -Like "*Windows 7*") {
	"Windows 7.  Exiting."
	""
	exit 0
}

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
			Write-Verbose "[LOCKED] OperationAPI is hard-locked by the OS (likely NVMe SSD or missing SysMain service). This is expected on fast storage."
		}
		Else {
			Write-Warning "  [FAIL] Could not enable OperationAPI: $($_.Exception.Message)"
		}
	}
}
If (-Not $MMAgentSetup.PageCombining)
{ Enable-MMAgent -PageCombining }

# Synchronize system time to fix SSL/TLS errors caused by incorrect date and time
$TimeServers = '3.openwrt.pool.ntp.org ntp1.vniiftri.ru ntp2.vniiftri.ru time.cloudflare.com ntp4.vniiftri.ru ntp3.vniiftri.ru 0.openwrt.pool.ntp.org'
try {
	Set-Service -Name W32Time -StartupType Manual -Status Running -ErrorAction Stop
}
catch {
	Write-Error -Message "    Cannot start W32Time service. Settings not applied. $($_.Exception.Message)"
	return  # Exit the script/function since we can't sync without the service
}
& w32tm.exe /Config /SyncFromFlags:Manual /ManualPeerList:"$TimeServers" /Update *>$null
if ($LASTEXITCODE -ne 0) {
	Write-Warning "w32tm /config failed with exit code $LASTEXITCODE."
}
$TimeSource = try { & w32tm.exe /Query /Source 2>$null } catch { "Unknown" }
Write-Host "Syncing time to $TimeSource..."
& w32tm.exe /ReSync /Force *>$null
# Trigger a background sync as well
& w32tm.exe /ReSync /NoWait *>$null
if ($LASTEXITCODE -ne 0) {
	Write-Warning "w32tm /resync returned exit code $LASTEXITCODE. System time may not have been synchronized."
}

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
			# "Import-Module -Name 'xxx' -UseWindowsPowerShell" import the 1.0 version ...

			$AllAppxPackages = powershell.exe -NoProfile -Command {
				Get-AppxPackage -AllUsers -PackageTypeFilter 'All' -Verbose:$false
			}
		}
	}
	
	process {
		$AppxPackageNames = ($AllAppxPackages | Where-Object -Property 'Name' -EQ -Value $Name).PackageFullName
		if ($AppxPackageNames) {
			"Removing $Name ..."
			
			# The progress bar of Remove-AppxPackage mess up the terminal rendering.
			# Use a PowerShell child process as workaround.
			powershell.exe -Args $AppxPackageNames -NoProfile -Command {
				$Args | Remove-AppxPackage -ErrorAction 'SilentlyContinue'
				$Args | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue'
			}
		}
	}
}
# Active identifiers
$PreinstalledAppsToRemove = @(
	'A025C540.Yandex.Music'
	'AppUp.IntelArcSoftware'
	"BrowserChoice"                             # "Browser Choice" screen required by the EU antitrust regulation
	"Microsoft.Advertisin*"                     # Advertising framework, catches the base package + named variants
	'Microsoft.ApplicationCompatibilityEnhancements'
	"Microsoft.BingFinance"                     # Money app - Financial news
	"Microsoft.BingFoodAndDrink"                # Food and Drink app
	"Microsoft.BingHealthAndFitness"            # Health and Fitness app
	"Microsoft.BingMaps"
	"Microsoft.BingNews"                        # Generic news app
	'Microsoft.BingSearch'
	"Microsoft.BingSports"                      # Sports app - Sports news
	"Microsoft.BingTranslator"                  # Translator app - Bing Translate
	"Microsoft.BingTravel"                      # Travel app
	"Microsoft.BingWeather"                     # Weather app
	"Microsoft.CommsPhone"                      # Phone app
	"Microsoft.ConnectivityStore"
	'Microsoft.Copilot'
	"Microsoft.DiagnosticDataViewer"
	'Microsoft.Edge.GameAssist'
	"Microsoft.ForzaHorizon3Demo"
	"Microsoft.ForzaMotorsport7Demo"
	"Microsoft.FrenchRiviera"
	"Microsoft.FreshPaint"                      # Canvas app
	"Microsoft.GamingApp"
	'Microsoft.GetHelp'
	"Microsoft.Getstarted"                      # Get Started link
	"Microsoft.HelpAndTips"
	"Microsoft.HoganThreshold"
	"Microsoft.Lucille"                         # "Browser Choice" screen required by the EU antitrust regulation
	"Microsoft.M365Companions"
	"Microsoft.Messaging"                       # Messaging app
	"Microsoft.MicrosoftJackpot"                # Jackpot app
	"Microsoft.MicrosoftJigsaw"                 # Jigsaw app
	'Microsoft.MicrosoftJournal'
	"Microsoft.MicrosoftMahjong"                # Mahjong game
	'Microsoft.WindowsMaps' 					# old
	'Microsoft.MicrosoftOfficeHub'
	"Microsoft.MicrosoftRewards"
	"Microsoft.MicrosoftSudoku"
	"Microsoft.MicrosoftTreasureHunt"
	"Microsoft.MinecraftUWP"
	"Microsoft.MovieMoments"
	'MicrosoftWindows.Client.CoPilot'
	"Microsoft.Office.OneNote"                  # Onenote app
	"Microsoft.Office.Sway"                     # Sway app
	"Microsoft.OneConnect"                      # OneConnect app
	"Microsoft.People"                          # People app
	"Microsoft.SeaofThieves"
	"Microsoft.SkypeApp"                        # Get Skype link
	"Microsoft.SkypeWiFi"
	"Microsoft.Studios.Wordament"               # imported from stage_2_de-bloat.bat
	"Microsoft.SurfaceDiagnostics"              # added 2021-06-02
	'Microsoft.Windows.Ai.Copilot.Provider'
	'Microsoft.Windows.Copilot'
	'Microsoft.Windows.CrossDevice'
	"Microsoft.Windows.DevHome"
	"Microsoft.Windows.FeatureOnDemand.InsiderHub"
	"Microsoft.WindowsFeedbackHub"              # Feedback app
	"Microsoft.WindowsMaps"                    	# Maps app
	"Microsoft.WindowsReadingList"
	"Microsoft.WorldNationalParks"
	'MicrosoftCorporationII.QuickAssist'
	"Windows.ContactSupport"
	'App.Support.QuickAssist' 					# Win10
	"Microsoft.MicrosoftSolitaireCollection"   	# Solitaire collection
	'Microsoft.BingWeather'
	'Microsoft.Whiteboard'
	'MicrosoftWindows.Client.WebExperience'
	'Microsoft.WidgetsPlatformRuntime'
	'Microsoft.StartExperiencesApp'
	#'Xbox' # might be required for some games
	'Microsoft.XboxApp' 						# old & Win10
	'Microsoft.Xbox.TCUI'
	'Microsoft.XboxGameOverlay'
	'Microsoft.XboxGamingOverlay'
	'Microsoft.XboxIdentityProvider'
	'Microsoft.XboxSpeechToTextOverlay'
	'Microsoft.ZuneMusic'
	'MSTeams'
		
	# Windows 10 only
	'Microsoft.Microsoft3DViewer' 				# old
	'Microsoft.MixedReality.Portal' 			# old
	'Microsoft.Office.OneNote'					# Onenote app
	'Microsoft.MSPaint' 						# old
	'Microsoft.SkypeApp' 						# old
	'Microsoft.Wallet' 							# old
)
$PreinstalledAppsToRemove | Remove-Package

"Removing Microsoft Edge..."
iex "&{$(irm https://raw.githubusercontent.com/he3als/EdgeRemover/main/get.ps1)} -UninstallEdge -RemoveEdgeData -NonInteractive"

"Removing IDMan autorun entry..." # Didn't find any decent portable (
Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name IDMan -Force
	
"Diasbling Apps Resume..."
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume -Name "value" -Value "1" -Type DWord
	
"Removing Realtek HD Panel autorun entry..." # Do we need it in the tray?
Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name RTHDVCPL -Force

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

Write-Host -Message "Setting Keyboard Character Repeat Delay to 0..."
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value "0" -Type String

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

# The rest do not apply to Windows 8 / Server 2012 platforms.
if ( ($WinVersionStr -Like "*Windows Server 2012*") -Or ($WinVersionStr -Like "*Windows 8*") )
{ exit 0 }

"Disabling AutoGameMode..."
$null = Set-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name AutoGameModeEnabled -Value 0 -Force

"Letting Windows improve Start and search results by tracking app launches (Remember commands typed in Run)..."
Set-ItemProperty -Path Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name 'Start_TrackProgs' -Type DWord -Value 1 -Force

"Adding 'Devices and Printers' to 'This PC'..."
New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8A91A66-3A7D-4424-8D24-04E180695C7A}

"Disabling Connected User Experiences and Telemetry..."
Stop-Service -Name "DiagTrack" 2>&1
$null = Set-Service -Name DiagTrack -StartupType Disabled

"Setting 'Startup/Shutdown Verbose Status Messages..."
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System verbosestatus -Value 1

# Prevent the unwanted installation of suggested applications
"Turning off Microsoft consumer experiences..."
$null = New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType "DWord" -Force -ErrorAction SilentlyContinue

"Setting Windows Terminal to Automatically copy selection to clipboard..."
$packageNames = @(
	"Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe",
	"Microsoft.WindowsTerminal_8wekyb3d8bbwe"
)
foreach ($pkg in $packageNames) {
	$userSettingsPath = "$env:LOCALAPPDATA\Packages\$pkg\LocalState\settings.json"
	if (Test-Path $userSettingsPath) {
		$content = Get-Content $userSettingsPath -Raw
		$content = $content -replace '("(copyOnSelect|copyFormatting)"\s*:\s*)(false|true|"[^"]*"|\[.*?\])', '$1true'
		$content | Set-Content $userSettingsPath -Force
	}
}

""