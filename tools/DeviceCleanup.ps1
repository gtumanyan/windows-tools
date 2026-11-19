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

$TempFolderName = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
# Используем системный API, чтобы избежать проблем с Unicode-путями.
$TempPath = Join-Path ([System.IO.Path]::GetTempPath()) $TempFolderName

# New-Item has no -LiteralPath; use the .NET API to avoid provider/wildcard issues.
[System.IO.Directory]::CreateDirectory($TempPath) | Out-Null

$download_url = if ([System.IntPtr]::Size -eq 4) {
    'https://www.uwe-sieber.de/files/DeviceCleanupCmd.zip'
} else {
    'https://www.uwe-sieber.de/files/DeviceCleanupCmd_x64.zip'
}

$zipFile = Join-Path $TempPath (Split-Path $download_url -Leaf)

"Downloading $download_url ..."
[Net.ServicePointManager]::SecurityProtocol =
[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
Invoke-WebRequest -Uri $download_url -OutFile $zipFile -UseBasicParsing

"Unpacking..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $TempPath)

    # Both zips contain DeviceCleanupCmd.exe
    $exe = Get-ChildItem -LiteralPath $TempPath -Recurse -Filter 'DeviceCleanupCmd*.exe' |
           Select-Object -First 1 -ExpandProperty FullName
    if (-not $exe) { throw "No DeviceCleanupCmd exe found in $TempPath" }

"Running $exe"
& $exe '* -m:3m -s -n -v'

# Clean up.
Write-Host "Cleaning up..." -NoNewline
Remove-Item -LiteralPath $TempPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host " Done!"
