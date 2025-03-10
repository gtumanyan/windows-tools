# Check if the script is running with elevated privileges
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    "Running elevated; good."
    ""
} else {
    "Not running as elevated. Starting elevated shell."
    # Start a new elevated PowerShell process and exit the non-elevated instance
    Start-Process powershell -WorkingDirectory $PWD.Path -Verb runAs -ArgumentList "-noprofile -noexit -file `"$PSCommandPath`""
    exit
}

# Set execution policy for the current process
Set-ExecutionPolicy Bypass -Scope Process -Force

# Set TLS 1.2 for secure connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Import the BitsTransfer module
Import-Module BitsTransfer

# List of scripts to download and run
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

# Create a WebClient object
$wco = (New-Object System.Net.WebClient)

# Download and run each script
ForEach ($ps_script in $ps_script_list) {
    $download_url = "https://github.com/gtumanyan/windows-tools/raw/master/tools/$ps_script"

    ""
    "--- Downloading $ps_script... ---"
    Invoke-WebRequest -Uri $download_url -Outfile ".\$ps_script"
    
    $run_script = ".\$ps_script"

    & $run_script
    Remove-Item ".\$ps_script"
}

# Dispose of the WebClient object
$wco.Dispose()

exit
