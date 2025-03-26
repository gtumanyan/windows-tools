
<#PSScriptInfo

.VERSION 2.0

.AUTHOR Jonathan E. Brickman & Gregory G. Tumanyan

.COMPANYNAME Ponderworthy Music

.COPYRIGHT (c) 2025 Jonathan E. Brickman

.TAGS

.LICENSEURI https://opensource.org/licenses/BSD-3-Clause

.PROJECTURI https://github.com/jebofponderworthy/windows-tools

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.PRIVATEDATA

#> 

























<#

.DESCRIPTION 
Tweaks memory and TCP parameters, for performance.

#>

Param()


################################################
# TweakMemTCP: Tweak Memory and TCP Parameters #
################################################

#
# by Jonathan E. Brickman & Gregory G. Tumanyan
#
# Tweaks memory and TCP parameters, for performance.
#
# Copyright 2025 Jonathan E. Brickman
# https://notes.ponderworthy.com/
# This script is licensed under the 3-Clause BSD License
# https://opensource.org/licenses/BSD-3-Clause
# and is reprised at the end of this file
#

""
""
"**************************************************"
"   TweakMemTCP: Tweak Memory and TCP Parameters   "
"**************************************************"
""
""

# Self-elevate if not already elevated.
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
    "Running elevated; good."
    ""
    } else {
    "Not running as elevated.  Starting elevated shell."
    Start-Process powershell -WorkingDirectory $PWD.Path -Verb runAs -ArgumentList "-noprofile -noexit -file $PSCommandPath"
    return "Done. This one will now exit."
    ""
    }


""

# Now we make changes.
# http://www.tomsitpro.com/articles/powershell_registry-powershell_command_line,2-152.html

# The settings come from a quite reliable source:
# https://support.storagecraft.com/s/article/Tuning-Guide-for-StorageCraft-Software-on-Servers?language=en_US

$WinVersionStr = Get-CimInstance -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption

function setupDWORD {
    param( [string]$regPath, [string]$nameForDWORD, [long]$valueForDWORD )

    ##############
    # Error out if cannot touch the registry area at all
    If ( !(Test-Path $regPath) ) {
        Try {
            New-Item $regPath -Force -ErrorAction SilentlyContinue
            }
        Catch {
            Write-Error ("Could not visit or create registry path " + $regPath)
            Return
            }
		Finally {
			$oldValue = ""
			}
        }

    #############
    # If an existing registry entry exists, store its value to report later
    Try {
        $oldValueProperty = Get-ItemProperty -Path $regPath -Name $nameForDWORD -ErrorAction SilentlyContinue
        $oldValue = $oldValueProperty.$nameforDWORD
        }
	Catch {}

    #############
    # Report the changes to make
    Write-Output ("DWORD to write: " + $nameForDWORD)
    Write-Output ("at registry path " + $regPath)
    If ($oldValue -ne "") {
        Write-Output ("Original value is " + $oldValue)
        }
    else {
        Write-Output "No original present."
        }
    Write-Output ("New value is " + $valueforDWORD)

    ############
    # Report no changes to make, set new registry entry, or error out
	If ($oldValue -eq $valueforDWORD) {
		Write-Output "No change to make."
		""
		Return
		}
    Try {
        New-ItemProperty -Path $regPath -Name $nameForDWORD -Value $valueForDWORD -PropertyType DWORD -Force -ErrorAction SilentlyContinue > $null
        }
    Catch {
        Write-Error "Failed!"
        ""
        Return
        }

    "Succeeded!"
    ""
    }
	
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "SystemPages" "0"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "PagedPoolSize" "0x0b71b000"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "PoolUsageMaximum" "0x00000050"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "SessionPoolSize" "0x00000030"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "SessionViewSize" "0x00000044"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "Size" "3"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "TcpTimedWaitDelay" "30"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "StrictTimeWaitSeqCheck" "1"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "MaxUserPort" "65534"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DefaultTTL" "64"
	
setupDWORD "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER\explorer.exe" "MaxConnectionsPer1_0Server" "10"
setupDWORD "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER\iexplore.exe" "MaxConnectionsPer1_0Server" "10"
setupDWORD "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER\explorer.exe" "MaxConnectionsPerServer" "10"
setupDWORD "HKLM:\SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER\iexplore.exe" "MaxConnectionsPerServer" "10"	
	
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" LocalPriority "4"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" HostsPriority "5"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" DnsPriority "6"
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" NetbtPriority "7"
	
setupDWORD "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" "NonBestEffortLimit" "50"

setupDWORD "HKLM:\System\CurrentControlSet\Services\Tcpip\QoS" "Do not use NLA" "1"
	
# Disabling Network Throttling increases DPC latency https://github.com/djdallmann/GamingPCSetup/blob/master/CONTENT/RESEARCH/NETWORK/README.md#networkthrottlingindex
# setupDWORD "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" "0xffffffff"

setupDWORD "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" "10"
	
	
setupDWORD "HKLM:\SYSTEM\CurrentControlSet\ServicesTcpip\Parameters" "EnableTCPA" 1
	
"Set-NetTCPSetting items etc..."

# TCP Window Auto-Tuning does NOT cause bufferbloat, DONT disable to increase score
Set-NetTCPSetting -SettingName "*" -AutoTuningLevelLocal normal -ErrorAction SilentlyContinue | Out-Null
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled -ErrorAction SilentlyContinue | Out-Null
Set-NetOffloadGlobalSetting -ReceiveSideScaling enabled -ErrorAction SilentlyContinue | Out-Null
Disable-NetAdapterLso -Name * -ErrorAction SilentlyContinue | Out-Null
Enable-NetAdapterChecksumOffload -Name * -ErrorAction SilentlyContinue | Out-Null
	
Set-NetTCPSetting -SettingName "*" -EcnCapability enabled -ErrorAction SilentlyContinue | Out-Null
Set-NetOffloadGlobalSetting -Chimney disabled -ErrorAction SilentlyContinue | Out-Null
try {Set-NetTCPSetting -SettingName "*" -Timestamps allowed -ErrorAction Stop} catch {Write-Warning "Allowing timestamps failed, skipping..."}
Set-NetTCPSetting -SettingName "*" -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue | Out-Null
Set-NetTCPSetting -SettingName "*" -NonSackRttResiliency disabled -ErrorAction SilentlyContinue | Out-Null
Set-NetTCPSetting -SettingName "*" -InitialRto 1000 -ErrorAction SilentlyContinue | Out-Null
Set-NetTCPSetting -SettingName "*" -MinRto 300 -ErrorAction SilentlyContinue | Out-Null
	
# enable BBR2 Congestion Control Provider
try {Set-NetTCPSetting -SettingName "*" -CongestionProvider "bbr2"} catch {Write-Waning "BBR2 absent, skipping Congestion Control Provider change}

# HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<<<GUIDs>>>
# TcpAckFrequency <delete value>


# For StorageCraft ImageManager, if it exists
# https://support.storagecraft.com/articles/en_US/Informational/Tuning-Guide-for-StorageCraft-Software-on-Servers
If ( (Test-Path "C:\Program Files (x86)\StorageCraft\ImageManager") -Or (Test-Path "C:\Program Files\StorageCraft\ImageManager") )
	{
	Write-Output "StorageCraft ImageManager found."
	Write-Output ""
	setupDWORD "HKLM:\SYSTEM\CurrentControlSet\Services\StorageCraft ImageManager\Parameters" "ReadUnbuffered" 0x1
	}
	
# The 3-Clause BSD License

# SPDX short identifier: BSD-3-Clause

# Note: This license has also been called
# the "New BSD License" or "Modified BSD License".
# See also the 2-clause BSD License.

# Copyright 2017 Jonathan E. Brickman

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
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
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








