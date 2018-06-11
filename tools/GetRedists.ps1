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

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

$reportStatus = ''
$currentOp = ''
function ShowCATEProgress {
	param( [string]$reportStatus, [string]$currentOp )

    Write-Progress -Activity "Get Microsoft Redists" -Status $reportStatus -PercentComplete -1 -CurrentOperation $currentOp
    }
$wco = (New-Object System.Net.WebClient)
$wco.Encoding = [System.Text.Encoding]::UTF8

ShowCATEProgress("Preparing Powershell environment:","Installing NuGet Package Provider for VcRedist...")
Install-PackageProvider -Name NuGet -Force
ShowCATEProgress("Preparing Powershell environment:","Installing NuGet for VcRedist...")
Install-Module -Name NuGet -SkipPublisherCheck -Force
ShowCATEProgress("Preparing Powershell environment:","Importing NuGet for VcRedist...")
Import-Module -Name NuGet
ShowCATEProgress("Preparing Powershell environment:","Installing VcRedist...")
Install-Module -Name VcRedist -SkipPublisherCheck -Force
ShowCATEProgress("Preparing Powershell environment:","Importing VcRedist...")
Import-Module -Name VcRedist
ShowCATEProgress("Preparing filesystem","")
New-Item C:\VcRedist -ItemType Directory | Out-Null
ShowCATEProgress("Retrieving all redistributables...","")
Get-VcList | Get-VcRedist -Path C:\VcRedist | Out-Null
ShowCATEProgress("Installing all redistributables...","")
Get-VcList | Install-VcRedist -Path C:\VcRedist | Out-Null
ShowCATEProgress("Removing C:\VcRedist ...","")
Remove-Item C:\VcRedist -Recurse -Force | Out-Null
ShowCATEProgress("Done!","")

