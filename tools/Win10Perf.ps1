#######################################################################
# Windows 10 Performance                                              #
#######################################################################

#
# by Jonathan E. Brickman
#
# Speeds up Windows 8 and 10.  Specifically:
#
# 1. Removes several AppX packages which Microsoft has preloaded, whose
# contents often pop up without warning, eating resources.
#
# 2. Turns off preloading of the Edge browser.
# 
# 3. Turns off Game Mode.
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
"*******************************"
"    Win 8 and 10 Performance   "
"*******************************"
""
""

$WinVersionStr = Get-CimInstance -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption

if ($WinVersionStr -Like "*Windows 7*")
{
	"Windows 7.  Exiting."
	""
	exit 0
}

# Using this to suppress all output:  *>&1 | Out-Null

"Configuring and enabling many facets of Superfetch..."

Enable-MMAgent -ApplicationLaunchPrefetching *>&1 | Out-Null
Enable-MMAgent -ApplicationPreLaunch *>&1 | Out-Null
Set-MMAgent -MaxOperationAPIFiles 8192 *>&1 | Out-Null
Enable-MMAgent -MemoryCompression *>&1 | Out-Null
Enable-MMAgent -OperationAPI *>&1 | Out-Null
Enable-MMAgent -PageCombining *>&1 | Out-Null
Set-Service sysmain -StartupType Automatic *>&1 | Out-Null
Start-Service sysmain *>&1 | Out-Null

"Removing Appx's of gaming, entertainment, and consumer items..."

Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxIdentityProvider"  | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay"  | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.WindowsCommunicationsApps" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage *>&1 | Out-Null
Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage *>&1 | Out-Null

if ( ($WinVersionStr -Like "*Windows Server 2012*") -Or ($WinVersionStr -Like "*Windows 8*") )
{
	""
	"Windows 8 or 2012.  Exiting."
	""
	exit 0
}

Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxIdentityProvider"  | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay"  | Remove-AppxPackage  -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.WindowsCommunicationsApps" | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage  -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage -allusers *>&1 | Out-Null
Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage -allusers *>&1 | Out-Null

"Disabling prelaunch/preload of Microsoft Edge browser..."

pushd HKCU:\Software\Policies\Microsoft\ *>&1 | Out-Null
mkdir MicrosoftEdge -Force *>&1 | Out-Null
mkdir MicrosoftEdge\Main -Force *>&1 | Out-Null
CD MicrosoftEdge\Main *>&1 | Out-Null
New-ItemProperty . -Name AllowPrelaunch -Value 0 -PropertyType "DWord" -Force *>&1 | Out-Null

CD HKLM:\Software\Policies\Microsoft\ *>&1 | Out-Null
mkdir MicrosoftEdge -Force *>&1 | Out-Null
mkdir MicrosoftEdge\Main -Force *>&1 | Out-Null
CD MicrosoftEdge\Main *>&1 | Out-Null
New-ItemProperty . -Name AllowPrelaunch -Value 0 -PropertyType "DWord" -Force *>&1 | Out-Null

"Disabling AutoGameMode..."

CD HKCU:\Software\Microsoft\ *>&1 | Out-Null
mkdir GameBar -Force *>&1 | Out-Null
New-ItemProperty . -Name AllowAutoGameMode -Value 0 -PropertyType "DWord" -Force *>&1 | Out-Null

CD HKLM:\Software\Microsoft\ *>&1 | Out-Null
mkdir GameBar -Force *>&1 | Out-Null
New-ItemProperty . -Name AllowAutoGameMode -Value 0 -PropertyType "DWord" -Force *>&1 | Out-Null

popd *>&1 | Out-Null

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







