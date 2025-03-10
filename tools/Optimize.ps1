if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Winutil needs to be run as Administrator. Attempting to relaunch."
    $argList = @()

    $PSBoundParameters.GetEnumerator() | ForEach-Object {
        $argList += if ($_.Value -is [switch] -and $_.Value) {
            "-$($_.Key)"
        } elseif ($_.Value -is [array]) {
            "-$($_.Key) $($_.Value -join ',')"
        } elseif ($_.Value) {
            "-$($_.Key) '$($_.Value)'"
        }
    }

    $script = if ($PSCommandPath) {
        "& { & `'$($PSCommandPath)`' $($argList -join ' ') }"
    } else {
        "&([ScriptBlock]::Create((irm https://github.com/gtumanyan/windows-tools/raw/master/tools/Optimize.ps1))) $($argList -join ' ')"
    }

    $powershellCmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
    $processCmd = if (Get-Command wt.exe -ErrorAction SilentlyContinue) { "wt.exe" } else { "$powershellCmd" }

    if ($processCmd -eq "wt.exe") {
        Start-Process $processCmd -ArgumentList "$powershellCmd -ExecutionPolicy Bypass -NoProfile -Command `"$script`"" -Verb RunAs
    } else {
        Start-Process $processCmd -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$script`"" -Verb RunAs
    }

    break
}
# If elevated, continue script execution
Write-Host "Running as Administrator..."

try {
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