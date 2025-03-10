# Check if script is running as admin
$adminCheck = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $adminCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-Not $isAdmin) {
    Write-Host "Not running as elevated. Restarting with admin privileges..."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Read-Host "Press Enter to exit"
    exit
} else {
    Write-Host "Running elevated; good."
}

"Script started at $(Get-Date)" | Out-File C:\temp\optimize_log.txt -Append
Read-Host "Press Enter to exit..."

try {
    Write-Host "Setting execution policy..."
    Set-ExecutionPolicy Bypass -Scope Process -Force

    Write-Host "Setting TLS 1.2 for secure connections..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Host "Importing BitsTransfer module..."
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

    # Download and run each script
    foreach ($ps_script in $ps_script_list) {
        $download_url = "https://github.com/gtumanyan/windows-tools/raw/master/tools/$ps_script"

        Write-Host "--- Downloading $ps_script... ---"
        Invoke-WebRequest -Uri $download_url -OutFile ".\$ps_script"
        
        $run_script = ".\$ps_script"

        Write-Host "Running $ps_script..."
        & $run_script
        Remove-Item ".\$ps_script"
    }

    Write-Host "Script completed successfully."
} catch {
    Write-Host "An error occurred: $_"
}

Write-Host "Press Enter to exit..."
Read-Host