#=================================================================================================================
#                                           Scheduled Tasks - Telemetry
#=================================================================================================================
# Ends with '\'  -> delete the entire folder (all tasks + subfolders)
# No trailing '\' -> delete that single task

$ScheduledTasksList = @(
    '\Adobe Acrobat Update Task'
    '\Microsoft\Office\'
    '\Microsoft\Windows\Application Experience\'
    '\Microsoft\Windows\AppListBackup\'
    '\Microsoft\Windows\Autochk\Proxy'
    '\Microsoft\Windows\CloudRestore\'
    '\Microsoft\Windows\Customer Experience Improvement Program\' # <--- Deletes entire folder
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
    '\Microsoft\Windows\DiskFootprint\Diagnostics'
    '\Microsoft\Windows\EnterpriseMgmt\'
    '\Microsoft\Windows\International\'
    '\Microsoft\Windows\License Manager\'
    '\Microsoft\Windows\Maintenance\WinSAT'
    '\Microsoft\Windows\Management\Provisioning\'
    '\Microsoft\Windows\Maps\'
    '\Microsoft\Windows\MemoryDiagnostic\'
    '\Microsoft\Windows\Media Center\'            # <--- Deletes entire folder
    '\Microsoft\Windows\PI\Sqm-Tasks'
    '\Microsoft\Windows\Power Efficiency Diagnostics\'
    '\Microsoft\Windows\PushToInstall\'
    '\Microsoft\Windows\RecoveryEnvironment\'
    '\Microsoft\Windows\Shell\FamilySafetyMonitor'
    '\Microsoft\Windows\Shell\FamilySafetyRefreshTask'
    '\Microsoft\Windows\Shell\IndexerAutomaticMaintenance'
    '\Microsoft\Windows\SpacePort\'
    '\Microsoft\Windows\Speech\'
    '\Microsoft\Windows\Subscription\'
    '\Microsoft\Windows\User Profile Service\'
    '\Microsoft\Windows\WDI\'
    '\Microsoft\Windows\WindowsAI\'
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
    '\Microsoft\Windows\WwanSvc\'
    '\Microsoft\XblGameSave\'
)

function Test-NotFoundError {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    while ($ex) {
        # 0x80070002 = file not found, 0x80070003 = path not found
        if ($ex.HResult -in -2147024894, -2147024893) { return $true }
        $ex = $ex.InnerException
    }
    return $false
}

function Split-TaskPath {
    param([string]$Path)
    $Path = $Path.TrimEnd('\')
    $i = $Path.LastIndexOf('\')
    $parent = $Path.Substring(0, $i)
    if (-not $parent) { $parent = '\' }
    return $parent, $Path.Substring($i + 1)
}

function Remove-EmptyTaskFolder {
    param($Service, [string]$FolderPath)
    $FolderPath = $FolderPath.TrimEnd('\')
    if (-not $FolderPath) { return }   # never touch the root

    try {
        $folder = $Service.GetFolder($FolderPath)
        if ($folder.GetTasks(1).Count -eq 0 -and $folder.GetFolders(0).Count -eq 0) {
            $parent, $name = Split-TaskPath $FolderPath
            $Service.GetFolder($parent).DeleteFolder($name, 0)
            Write-Host "Removed : $FolderPath\"
        }
    }
    catch {
        if (-not (Test-NotFoundError $_)) {
            Write-Verbose "Folder  : $FolderPath - $($_.Exception.Message)"
        }
    }
}

function Remove-TaskFolderTree {
    param($Service, [string]$FolderPath)
    $FolderPath = $FolderPath.TrimEnd('\')
    if (-not $FolderPath) { throw 'Refusing to delete the Task Scheduler root.' }

    try { $folder = $Service.GetFolder($FolderPath) }
    catch {
        if (Test-NotFoundError $_) { Write-Verbose "Missing : $FolderPath\"; return }
        throw
    }

    # Subfolders first
    foreach ($sub in @($folder.GetFolders(0))) {
        Remove-TaskFolderTree -Service $Service -FolderPath $sub.Path
    }

    # All tasks, including hidden
    foreach ($task in @($folder.GetTasks(1))) {
        $name = $task.Name
        try { $task.Stop(0) } catch { }
        try {
            $folder.DeleteTask($name, 0)
            Write-Host "Deleted : $FolderPath\$name"
        }
        catch {
            if (-not (Test-NotFoundError $_)) {
                Write-Warning "Failed  : $FolderPath\$name - $($_.Exception.Message)"
            }
        }
    }

    Remove-EmptyTaskFolder -Service $Service -FolderPath $FolderPath
}
"***************************"
"   CLEAN SCHEDULED TASKS   "
"***************************"

$service = New-Object -ComObject 'Schedule.Service'
try {
    $service.Connect()

    foreach ($entry in $ScheduledTasksList) {

        # --- Whole folder ---
        if ($entry.EndsWith('\')) {
            Remove-TaskFolderTree -Service $service -FolderPath $entry
            continue
        }

        # --- Single task ---
        $folderPath, $taskName = Split-TaskPath $entry
        try {
            $folder = $service.GetFolder($folderPath)
            try { $folder.GetTask($taskName).Stop(0) } catch { }
            $folder.DeleteTask($taskName, 0)
            Write-Host "Deleted : $entry"
        }
        catch {
            if (Test-NotFoundError $_) { Write-Verbose "Missing : $entry" }
            else { Write-Warning "Failed  : $entry - $($_.Exception.Message)" }
            continue
        }

        Remove-EmptyTaskFolder -Service $service -FolderPath $folderPath
    }
}
finally {
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($service)
}