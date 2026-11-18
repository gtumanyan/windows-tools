@echo off

echo --------------------------------------------
echo Download and Run All Optimize Script Applets
echo --------------------------------------------

echo:
echo Preparing...
echo ---
echo:
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -Command ^
"try {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]3072; $wc=New-Object System.Net.WebClient; $wc.DownloadFile('https://raw.githubusercontent.com/gtumanyan/windows-tools/master/tools/Optimize.ps1','Optimize.ps1') } catch { Write-Error $_; exit 1 } finally { if ($wc) { $wc.Dispose() } }"

if errorlevel 1 (
    echo Download failed. Check the .NET and TLS settings or update Powershell
    echo https://massgrave.dev/tsforge#windows-esu
    exit /b 1
)

echo:
echo Initiating...
echo ---
echo:
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command ".\Optimize.ps1"

@del Optimize.ps1

