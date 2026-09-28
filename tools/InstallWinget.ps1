# $OriginalErrorActionPreference = $ErrorActionPreference
# $ErrorActionPreference = 'Stop'

if ($Host.Version.Major -eq 5) {
    # Progress bar can significantly impact cmdlet performance
    # https://github.com/PowerShell/PowerShell/issues/2138
    $Script:ProgressPreference = "SilentlyContinue"
}

function Add-ToEnvironmentPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToAdd,

        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'System')]
        [string]$Scope
    )
    <#
    .SYNOPSIS
    Adds the specified path to the environment PATH variable.

    .DESCRIPTION
    This function adds a given path to the specified scope (user or system) and the current process environment PATH variable if it is not already present.

    .PARAMETER PathToAdd
    The directory path to add to the environment PATH variable.

    .PARAMETER Scope
    Specifies whether to add the path to the user or system environment PATH variable.

    .EXAMPLE
    Add-ToEnvironmentPath -PathToAdd "C:\Program Files\MyApp" -Scope 'System'
    #>

    # Check if the path is already in the environment PATH variable
    if (-not (Path-ExistsInEnvironment -PathToCheck $PathToAdd -Scope $Scope)) {
        if ($Scope -eq 'System') {
            # Get the current system PATH
            $systemEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)
            # Add to system PATH
            $systemEnvPath += ";$PathToAdd"
            [System.Environment]::SetEnvironmentVariable('PATH', $systemEnvPath, [System.EnvironmentVariableTarget]::Machine)
            Write-Debug "Adding $PathToAdd to the system PATH."
        }
        elseif ($Scope -eq 'User') {
            # Get the current user PATH
            $userEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User)
            # Add to user PATH
            $userEnvPath += ";$PathToAdd"
            [System.Environment]::SetEnvironmentVariable('PATH', $userEnvPath, [System.EnvironmentVariableTarget]::User)
            Write-Debug "Adding $PathToAdd to the user PATH."
        }

        # Update the current process environment PATH
        if (-not ($env:PATH -split ';').Contains($PathToAdd)) {
            $env:PATH += ";$PathToAdd"
            Write-Debug "Adding $PathToAdd to the current process environment PATH."
        }
    }
    else {
        Write-Debug "$PathToAdd is already in the PATH."
    }
}

function Set-PathPermissions {
    param (
        [string]$FolderPath
    )
    <#
    .SYNOPSIS
    Grants full control permissions for the Administrators group on the specified directory path.

    .DESCRIPTION
    This function sets full control permissions for the Administrators group on the specified directory path.
    Useful for ensuring that administrators have unrestricted access to a given folder.

    .PARAMETER FolderPath
    The directory path for which to set full control permissions.

    .EXAMPLE
    Set-PathPermissions -FolderPath "C:\Program Files\MyApp"

    Sets full control permissions for the Administrators group on "C:\Program Files\MyApp".
    #>

    Write-Debug "Setting full control permissions for the Administrators group on $FolderPath."

    # Define the SID for the Administrators group
    $administratorsGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $administratorsGroup = $administratorsGroupSid.Translate([System.Security.Principal.NTAccount])

    # Retrieve the current ACL for the folder
    try {
        $acl = Get-Acl -Path $FolderPath -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to retrieve ACL for '$FolderPath'. Error: $($_.Exception.Message)"
        return
    }

    # Define the access rule for full control inheritance
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $administratorsGroup,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )

    # Apply the access rule to the ACL and set it on the folder
    try {
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $FolderPath -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to apply ACL to '$FolderPath'. Error: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------ #
# Newest published release (stable + prerelease), by publish time
# ------------------------------------------------------------------------ #

$releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases?per_page=100'
$latest = $releases[0]
try { $VersionInstalled = & winget --version }
catch {
    Write-Verbose "winget.exe is not runnable: $($_.Exception.Message)"
}

$VersionAvailable = $latest.tag_name

if ($VersionInstalled -eq $VersionAvailable) {    
    Write-Verbose "Winget $VersionInstalled is already installed, exiting..."
    # $ErrorActionPreference = $OriginalErrorActionPreference
    return
}

if ($VersionInstalled -gt $VersionAvailable) {
    Write-Host ''
    Write-Warning "Installed $VersionInstalled is newer than the newest GitHub Release $VersionAvailable"
    Write-Host ''
    return
}

# ------------------------------------------------------------------------ #
# AppInstaller (winget)
# ------------------------------------------------------------------------ #
$WingetPkg = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
$bundleAsset = $latest.assets | Where-Object { $_.name -eq $WingetPkg }
if (-not $bundleAsset) { throw "Could not find msixbundle asset in latest release." }

$bundlePath = $bundleAsset.browser_download_url

# ============================================================================ #
# Beginning of installation process
# ============================================================================ #
# Install winget assuming dependencies are already installed
Write-Output "Installing winget..."
try { Add-AppxPackage $bundlePath -ForceUpdateFromAnyVersion -ForceApplicationShutdown -Verbose -ErrorAction Stop }
# Install with dependencies (slower)
catch {
    # ------------------------------------------------------------------------ #
    # Dependencies (only when winget is absent)
    # ------------------------------------------------------------------------ #

    $DepsZip = 'DesktopAppInstaller_Dependencies.zip'
    $depAsset = $latest.assets | Where-Object { $_.name -eq $DepsZip }
    if (-not $depAsset) { throw 'Could not find the dependencies ZIP asset in the latest release.' }

    $winget_dependencies_url = $depAsset.browser_download_url
    # --- Skip download of the DesktopAppInstaller_Dependencies.zip if hash hasn't changed and local files exist ---
    # Check also path set by TCPU in case script ran in total commander PowerUser evironment
    $cacheDir = if ($env:P -and (Test-Path "$env:P\Web-Install\Winget")) { "$env:P\Web-Install\Winget" } else { $env:TEMP }
    $DepsZip = Join-Path $cacheDir $DepsZip
    if ((Get-FileHash $DepsZip).Hash.ToLower() -eq ($depAsset.digest -replace '^sha256:')) {
        Write-Verbose "$DepsZip is current — skipping download."
    }
    else {
        Write-Verbose "Downloading winget dependencies from $winget_dependencies_url to $cacheDir`n`n"
        Invoke-WebRequest -Uri $winget_dependencies_url -OutFile $DepsZip       
        Expand-Archive $DepsZip -DestinationPath $cacheDir -Force
    }

    # Get OS details using Get-CimInstance because the registry key for Name is not always correct with Windows 11
    try {
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        throw "Unable to run the command ""Get-CimInstance -ClassName Win32_OperatingSystem"". If you're using Window Sandbox, this may be related to a known issue with winget on Windows Sandbox: https://github.com/microsoft/Windows-Sandbox/issues/67"
    }
    
    # Get architecture details of the OS (not the processor)
    # Get only the numbers
    $arch = ($osDetails.OSArchitecture -replace "[^\d]").Trim()
    
    # If 32-bit or 64-bit replace with x32 and x64
    if ($arch -eq "32") { $arch = "x86" }
    elseif ($arch -eq "64") { $arch = "x64" }

    $deps = Get-ChildItem -Path $arch -Recurse -Filter "*.appx" | Select-Object -ExpandProperty FullName    

    # Now install winget with dependencies
    Write-Verbose "Direct install failed, retrying with dependencies..."
    Add-AppxPackage $bundlePath -DependencyPath $deps -ForceUpdateFromAnyVersion -Verbose
}

# ------------------------------------------------------------------------ #
# Verify
# ------------------------------------------------------------------------ #

# --- Verify & fix PATH shim if needed ---
# Winget usually shims to %LOCALAPPDATA%\Microsoft\WindowsApps
$wingetPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
if (Test-Path $wingetPath) {
    Write-Host "`nDone! Running 'winget update' to check for available updates." -ForegroundColor Green
    & $wingetPath update --accept-source-agreements
    Write-Host "`nUpdate all?" -ForegroundColor Cyan
    $response = Read-Host "Press [Enter] to update, type anything else to exit"
    if ($response -eq '') {
        & $wingetPath update --all
    }
}
else {
    # Try to find a versioned install under Program Files\WindowsApps
    $WinGetFolderPath = (Get-ChildItem -Path ([System.IO.Path]::Combine($env:ProgramFiles, 'WindowsApps')) -Filter "Microsoft.DesktopAppInstaller_*_*${arch}__8wekyb3d8bbwe" | Sort-Object Name | Select-Object -Last 1).FullName
    Write-Debug "WinGetFolderPath: $WinGetFolderPath"

    if ($null -ne $WinGetFolderPath) {
        # Fix Permissions by adding Administrators group with FullControl
        Set-PathPermissions -FolderPath $WinGetFolderPath

        # Add Environment Path
        Add-ToEnvironmentPath -PathToAdd $WinGetFolderPath -Scope 'System'

        Write-Output "winget folder permissions and PATH updated successfully."
        Write-Output "A restart or new session may be required for changes to take effect."
    }
    else {
        Write-Warning "winget folder path not found. You may need to manually add winget's folder path to your system PATH environment variable."
    }

    # Output
    Write-Output "A restart may be required for winget path to continue to work as expected."

    Write-Host "If winget is still not recognized, open a NEW PowerShell window or sign out/in." -ForegroundColor Yellow
}