# Define a log file path
$logFile = "C:\path\to\your\script.log"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    Add-Content -Path $logFile -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')): $message"
}

# Example usage
Log-Message "Starting script..."

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "Running as Administrator"
    Write-Host "Running elevated; good."
} else {
    Log-Message "Not running as Administrator. Starting elevated shell."
    Write-Host "Not running as elevated. Starting elevated shell."
    Start-Process powershell -WorkingDirectory $PWD.Path -Verb runAs -ArgumentList "-noprofile -noexit -file `"$PSCommandPath`""
    exit
}

try {
    Log-Message "Setting execution policy..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Log-Message "Setting TLS 1.2 for secure connections..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    Log-Message "Importing BitsTransfer module..."
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
        Log-Message "--- Downloading $ps_script... ---"
        Invoke-WebRequest -Uri $download_url -Outfile ".\$ps_script"
        $run_script = ".\$ps_script"
        Log-Message "Running $ps_script..."
        & $run_script
        Remove-Item ".\$ps_script"
    }

    Log-Message "Disposing of WebClient object..."
    $wco.Dispose()
    Log-Message "Script completed successfully."
    Write-Host "Script completed successfully."
} catch {
    Log-Message "An error occurred: $_"
    Write-Host "An error occurred: $_"
}

Log-Message "Press Enter to exit..."
Read-Host