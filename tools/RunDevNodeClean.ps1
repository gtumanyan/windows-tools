<#
.DESCRIPTION 
RunDeviceCleanup - removes all non-present devices, that haven't been connected to the system in 3 months or longer
#>

####################################
#  Download and Run DeviceCleanup  #
####################################

#
# by Gregory G. Tumanyan
#
# Downloads the Device Cleanup Cmd, chooses the binary
# appropriate to the bit-width of the current OS, and runs it.
# This cleans unused device nodes in the registry,
# improving performance
#
# Copyright 2026 Gregory G. Tumanyan
# https://t.me/Snappy_Driver_Installer
# This script is licensed under the 3-Clause BSD License
# https://opensource.org/licenses/BSD-3-Clause
# and is reprised at the end of this file
#

""
"**********************"
"   RunDeviceCleanup   "
"**********************"
""

# First, set up temporary space and move there.

"Setting up..."

$TempFolderName = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})

$envTEMP = [Environment]::GetEnvironmentVariable("TEMP")
$TempPath = Join-Path $envTEMP $TempFolderName
New-Item $TempPath -Force -ItemType Container | Out-Null

# Pick URL by bitness
if ([System.IntPtr]::Size -eq 4) {
    # 32-bit OS
    $download_url = 'https://www.uwe-sieber.de/files/DeviceCleanup_Win32.zip'
} else {
    # 64-bit OS
    $download_url = 'https://www.uwe-sieber.de/files/DeviceCleanupCmd_x64.zip'
}

$zipFileName = Split-Path $download_url -Leaf
$zipFile = Join-Path $TempPath $zipFileName

"Downloading $download_url ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $download_url -OutFile $zipFile -UseBasicParsing

"Unpacking..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip {
    param([string]$zipfile, [string]$outpath)
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath) | Out-Null
}

Unzip $zipFile $TempPath

# Find what we just unpacked - works for both
# DeviceCleanupCmd_x64.zip -> DeviceCleanupCmd.exe
# DeviceCleanup_Win32.zip -> DeviceCleanup.exe
$exe = Get-ChildItem -Path $TempPath -Recurse -Filter "DeviceCleanup*.exe" | Select-Object -First 1 -ExpandProperty FullName

if (-not $exe) {
    throw "No DeviceCleanup exe found in $TempPath"
}

"Running $exe ..."
& $exe '* -m:3m -s -n -v'

# Clean up.

Write-Host "Cleaning up..." -NoNewline; Remove-Item $TempPath -Recurse -Force; Write-Host " Done!"

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