
<#PSScriptInfo

.VERSION 2.81

.GUID 5cc3176c-2e44-40d7-8ead-592e4e2e3665

.AUTHOR Jonathan E. Brickman

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
# 3. Turns off preloading of the Edge browser.
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

"1/12..."
Remove-Package "Microsoft.XboxApp" | Out-Null
"2/12..."
Remove-Package "Microsoft.XboxGamingOverlay" | Out-Null
"3/12..."
Remove-Package "Microsoft.XboxIdentityProvider" | Out-Null
"4/12..."
Remove-Package "Microsoft.Xbox.TCUI" | Out-Null
"5/12..."
Remove-Package "Microsoft.XboxSpeechToTextOverlay" | Out-Null
"6/12..."
Remove-Package "Microsoft.WindowsCommunicationsApps" | Out-Null
"7/12..."
Remove-Package "Microsoft.BingNews" | Out-Null
"8/12..."
Remove-Package "Microsoft.BingWeather" | Out-Null
"9/12..."
Remove-Package "Microsoft.Advertising.Xaml" | Out-Null
"10/12..."
Remove-Package "*Microsoft.Skype*" | Out-Null
"11/12..."
Remove-Package "*Disney*" | Out-Null
"12/12..."
Remove-Package "Microsoft.People" | Out-Null
Remove-Package "Microsoft.WindowsFeedbackHub" | Out-Null

# The rest do not apply to Windows 8 / Server 2012 platforms.
if ( ($WinVersionStr -Like "*Windows Server 2012*") -Or ($WinVersionStr -Like "*Windows 8*") )
	{ exit 0 }
	
"Disabling autostart of user applications at logon..."

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

pushd HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon | Out-Null
New-ItemProperty -Path . -Name RestartApps -Value 0 -PropertyType "DWord" -Force | Out-Null

"Disabling prelaunch/preload of Microsoft Edge browser..."

pushd HKCU:\Software\Policies\Microsoft\ | Out-Null

mkdir MicrosoftEdge -Force | Out-Null
mkdir MicrosoftEdge\Main -Force | Out-Null
mkdir MicrosoftEdge\TabPreloader -Force | Out-Null
CD HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main | Out-Null
New-ItemProperty -Path . -Name AllowPrelaunch -Value 0 -PropertyType "DWord" -Force | Out-Null
CD HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader
New-ItemProperty -Path . -Name AllowTabPreloading -Value 0 -PropertyType "DWord" -Force | Out-Null

CD HKLM:\Software\Policies\Microsoft\ | Out-Null

mkdir MicrosoftEdge -Force | Out-Null
mkdir MicrosoftEdge\Main -Force | Out-Null
mkdir MicrosoftEdge\TabPreloader -Force | Out-Null
CD HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main | Out-Null
New-ItemProperty -Path . -Name AllowPrelaunch -Value 0 -PropertyType "DWord" -Force | Out-Null
CD HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader
New-ItemProperty -Path . -Name AllowTabPreloading -Value 0 -PropertyType "DWord" -Force | Out-Null

# AMD External Events Utility (probably want this one)
if (Get-Service -Name "AMD External Events Utility" -ErrorAction SilentlyContinue)
{
	# Probably want this service running
	Stop-Service -Name "AMD External Events Utility"
	Set-Service -Name "AMD External Events Utility" -StartupType Manual
}

"Disabling AutoGameMode..."

CD HKCU:\Software\Microsoft\ | Out-Null

mkdir GameBar -Force  -ErrorAction SilentlyContinue | Out-Null
CD GameBar
New-ItemProperty -Path . -Name AllowAutoGameMode -Value 0 -PropertyType "DWord" -Force  -ErrorAction SilentlyContinue | Out-Null

CD HKLM:\Software\Microsoft\ | Out-Null

mkdir GameBar -Force  -ErrorAction SilentlyContinue | Out-Null
CD GameBar
New-ItemProperty -Path . -Name AllowAutoGameMode -Value 0 -PropertyType "DWord" -Force  -ErrorAction SilentlyContinue | Out-Null

CD HKLM:\SYSTEM\CurrentControlSet\Services | Out-Null
Set-ItemProperty -Path . -Name "xbgm" -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null

"Disabling Geolocation Service autostart - If disabled, Windows won't be able to determine your location for certain apps..."
Set-Service -Name "lfsvc" -StartupType Manual

"Disable Windows Compatibility Telemetry..."

schtasks /Change /Disable /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
taskkill /f /im compattelrunner.exe 2>&1 | Out-Null

Stop-Service -Name "DiagTrack" 2>&1 | Out-Null
Set-Service -Name DiagTrack -StartupType Disabled 2>&1 | Out-Null

"Disable Microsoft Consumer Experiences..."

CD HKLM:\SOFTWARE\Policies\Microsoft\Windows | Out-Null
mkdir CloudContent -Force  -ErrorAction SilentlyContinue | Out-Null
CD CloudContent
New-ItemProperty -Path . -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType "DWord" -Force -ErrorAction SilentlyContinue | Out-Null

"Device Metadata bug fix..."

CD "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" | Out-Null
If ((Get-ItemProperty -Path . -Name "DeviceMetadataServiceURL").DeviceMetadataServiceURL -eq "http://go.microsoft.com/fwlink/?LinkID=252669&clcid=0x409")
{
	Set-ItemProperty -Path . -Name "DeviceMetadataServiceURL" -Value "http://dmd.metaservices.microsoft.com/dms/metadata.svc" -Force -ErrorAction SilentlyContinue | Out-Null
}

popd | Out-Null

""

# The 3-Clause BSD License

# SPDX short identifier: BSD-3-Clause

# Note: This license has also been called
# the AYA>A>??sA??.??oNew BSD LicenseAYA>A>??sA??,A? or AYA>A>??sA??.??oModified BSD LicenseAYA>A>??sA??,A?.
# See also the 2-clause BSD License.

# Copyright 2019 Jonathan E. Brickman

# Redistribution and use in source and binary
# forms, with or without modification, are
# permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the
# above copyright notice, this list of conditions and
# the following disclaimer.

# 2. Redistributions in binary form must reproduce the
# above copyright notice, this list of conditions and
# the following disclaimer in the documentation and/or
# other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the
# names of its contributors may be used to endorse or
# promote products derived from this software without
# specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS AYA>A>??sA??.??oAS ISAYA>A>??sA??,A? AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
# OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


