
<#PSScriptInfo

.VERSION 4.0

.GUID 527423ef-dadd-45b1-a547-56d2fdb325d1

.AUTHOR Jonathan E. Brickman

.COMPANYNAME Ponderworthy Music

.COPYRIGHT (c) 2021 Jonathan E. Brickman

.TAGS

.LICENSEURI https://opensource.org/licenses/BSD-3-Clause

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
TweakDrives
Runs Optimize-Volume -ReTrim on all SSD volumes,
tweaks all NTFS volumes on a system for performance and reliability, using FSUTIL;
also defrags NTFS metafiles using Contig.

.PRIVATEDATA

#> 

<#

.DESCRIPTION 
TRIM-Drives-Etc - Does SSD TRIM and other operations for performance and reliability

#>

Param()


#######################################################
# Trim-Drives-Etc: Does SSD TRIM and other operations #
# for performance and reliability                     #
#######################################################

#
# by Jonathan E. Brickman
#
# Copyright 2023 Jonathan E. Brickman
# https://notes.ponderworthy.com/
# This script is licensed under the 3-Clause BSD License
# https://opensource.org/licenses/BSD-3-Clause
# and is reprised at the end of this file
#

""
""
"*********************"
"   TRIM-Drives-Etc   "
"*********************"

# Self-elevate if not already elevated.

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
    "Running elevated; good."
    ""
    }
else {
    "Not running as elevated.  Starting elevated shell."
    Start-Process powershell -WorkingDirectory $PSScriptRoot -Verb runAs -ArgumentList "-noprofile -noexit -file $PSCommandPath"
    return "Done. This one will now exit."
    ""
    }

# Do TRIM if possible for all volumes on SSDs...

"Manually do TRIM and SlabConsolidate if possible for any volumes..."
""

Get-PhysicalDisk | ForEach-Object {
	Get-Partition -DiskNumber $_.DeviceID | ForEach-Object {
		"Initiating TRIM if appropriate for partition number " + $_.PartitionNumber
		Get-Volume -Partition $_ | Optimize-Volume -Retrim -Verbose -ErrorAction SilentlyContinue
		"Initiating SlabConsolidate if appropriate for partition number " + $_.PartitionNumber
		Get-Volume -Partition $_ | Optimize-Volume -SlabConsolidate -Verbose -ErrorAction SilentlyContinue
		}
	}

"Reliability and performance adjustments for all drives..."
""

# Using & instead of Invoke-Expression, this appears to be security-positive, hopefully less apt to be false-positived by security tools

# Disable Last Access Time stamp in directories, for performance. Does not cause ill effects, widely tested.
& fsutil behavior set DisableLastAccess 1 | Out-Null

# This one enables automatic TRIM in Windows even though it's a 0.  
# Does not always work, the above manual TRIMs are therefore sometimes vital.
& fsutil behavior set DisableDeleteNotify 0 | Out-Null

# Sets up Self-Healing
& fsutil behavior set Bugcheckoncorrupt 1 | Out-Null

# Do NTFS reliability and performance settings for all volumes

Get-CimInstance -Query "Select * FROM Win32_LogicalDisk WHERE DriveType=3" | ForEach-Object {
    $DriveID = $_.DeviceID

    If ($DriveID -match "[A-Z]")
        {
        "Tweaking " + $DriveID + " ..."
		""
		
		"fsutil repair (Self-Healing NTFS)..."
		& fsutil repair set $DriveID 1 | Out-Null
		
		$DriveIDslash = ($DriveID + '\')
		
		"fsutil resource setautoreset true ..."
		& fsutil resource setautoreset true $DriveIDslash | Out-Null
		"fsutil resource setconsistent ..."
		& fsutil resource setconsistent $DriveIDslash | Out-Null
		"fsutil resource setlog shrink 10 ..."
		& fsutil resource setlog shrink 10 $DriveIDslash | Out-Null
		""
        }
    }
	
"Done!"