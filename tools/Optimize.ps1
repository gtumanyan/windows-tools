# Check if the script is running with elevated privileges
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Running elevated; good."
    ""
} else {
    Write-Host "Not running as elevated. Starting elevated shell."
    # Start a new elevated PowerShell process
    $newProcess = Start-Process powershell -WorkingDirectory $PWD.Path -Verb runAs -ArgumentList "-noprofile -noexit -file `"$PSCommandPath`"" -PassThru
    if ($newProcess) {
        Write-Host "Elevated process started successfully."
    } else {
        Write-Host "Failed to start elevated process."
    }
    Write-Host "Press Enter to exit..."
    Read-Host
    exit
}

try {
    Write-Host "Setting execution policy..."
    Set-ExecutionPolicy Bypass -Scope Process -Force

    Write-Host "Setting TLS 1.2 for secure connections..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

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
    ForEach ($ps_script in $ps_script_list) {
        $download_url = "https://github.com/gtumanyan/windows-tools/raw/master/tools/$ps_script"

        Write-Host "--- Downloading $ps_script... ---"
        Invoke-WebRequest -Uri $download_url -Outfile ".\$ps_script"
        
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