
<#PSScriptInfo

.VERSION 1.0

.AUTHOR Jonathan E. Brickman

.COMPANYNAME Ponderworthy Music

.COPYRIGHT (c) 2021 Jonathan E. Brickman

.TAGS

.LICENSEURI https://opensource.org/licenses/BSD-3-Clause

.PROJECTURI https://github.com/jebofponderworthy/windows-tools

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
TweakSMB
Optimizes SMB, client and server, for performance

.PRIVATEDATA

#> 

<#

.DESCRIPTION 
TweakSMB - optimizes SMB, client and server, for performance

#>

Param()


###############################################
# TweakSMB: Optimizes SMB, client and server, #
# for performance                             #
###############################################

#
# by Jonathan E. Brickman
#
# Tweaks SMB, client and server, for performance
#
# Copyright 2021 Jonathan E. Brickman
# https://notes.ponderworthy.com/
# This script is licensed under the 3-Clause BSD License
# https://opensource.org/licenses/BSD-3-Clause
# and is reprised at the end of this file
#

""
""
"***************"
"   TweakSMB    "
"***************"

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
"Client..."
Set-SmbClientConfiguration -EnableBandwidthThrottling $false -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -EnableLargeMtu $true -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -EnableLoadBalanceScaleOut $true -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -EnableMultiChannel $true -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -EnableSecuritySignature $false -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -MaxCmds 16384 -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -MaximumConnectionCountPerServer 32 -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -OplocksDisabled $false -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -RequireSecuritySignature $false -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -UseOpportunisticLocking $true -force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -WindowSizeThreshold 2 -force -ErrorAction SilentlyContinue
""
"Server..."
# Windows 11 blocks guest logons by default,
# and from build 24H2 it also *requires SMB signing* -- which a guest session cannot do, so
# the first switch alone is not enough there. Set-SmbClientConfiguration is the supported
# cmdlet and takes effect live. Never force-restart
# the workstation service on a machine you still need to reach.
# A network drive belongs to a logon session, so Z: exists only for the logged-in user; the
# UNC path is what a non-interactive run must use.
Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -RequireSecuritySignature $false -Force

Set-SmbServerConfiguration -EnableMultiChannel $true -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EnableOplocks $true -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -ServerHidden $true -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -IrpStackSize 20 -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -MaxMpxCount 4096 -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -MaxWorkItems 16384 -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -MaxSessionPerConnection 16384 -force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -TreatHostAsStableStorage $true -force -ErrorAction SilentlyContinue
""
"Done!"
""

# The 3-Clause BSD License

# SPDX short identifier: BSD-3-Clause

# Note: This license has also been called
# the AYA>A>??sA??.??oNew BSD LicenseAYA>A>??sA??,A? or AYA>A>??sA??.??oModified BSD LicenseAYA>A>??sA??,A?.
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





