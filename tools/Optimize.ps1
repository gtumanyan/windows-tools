# Restart the script with elevation if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Script is not running with elevated privileges. Restarting as Administrator..."
    Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy Bypass", "-File", "`"$PSCommandPath`"" -Verb RunAs
	exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12;

Import-Module BitsTransfer

$ps_script_list = @(
    'mma-appx-etc.ps1',
    'RunDevNodeClean.ps1',
    'wt_removeGhosts.ps1',
	'TweakSMB.ps1',
    'OWTAS.ps1',
    'OVSS.ps1',
    'CATE.ps1',
	'TweakHardware.ps1',
    'TweakMemTCP.ps1',
    'TweakDrives.ps1'
    )

$wco = (New-Object System.Net.WebClient)

ForEach ($ps_script in $ps_script_list) {
	$download_url = "https://github.com/gtumanyan/windows-tools/raw/master/tools/$ps_script"

	""
	"--- Downloading $ps_script... ---"
	Invoke-WebRequest -Uri $download_url -Outfile ".\$ps_script"
	
	$run_script = ".\$ps_script"

	& $run_script
	Remove-Item ".\$ps_script"
	}
	
$wco.Dispose()

exit
