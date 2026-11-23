<#
.SYNOPSIS
    Removes orphaned kernel/filter drivers.
#>
param(
    # Collects space-separated names too; default covers Optimize.ps1's no-arg call
    [Parameter(ValueFromRemainingArguments = $true)]
    [ValidatePattern('^[A-Za-z0-9_-]+(\.sys)?$')]
    [string[]]$DriverName = @('mfeaacsk','mfehck','mfedisk')
)

function Get-DriverState {
    param([string]$Name)

    $Name       = [IO.Path]::GetFileNameWithoutExtension($Name.Trim())
    $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $classRoot  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class'
    $driverFile = Join-Path $env:SystemRoot "System32\drivers\$Name.sys"

    # 1. service keys — exact name AND ImagePath scan
    $services = @()
    $exactKey = Join-Path $svcRoot $Name
    if (Test-Path -LiteralPath $exactKey) {
        $p = Get-ItemProperty -LiteralPath $exactKey -EA SilentlyContinue
        $services += [pscustomobject]@{
            Key       = $exactKey
            Name      = $Name
            ImagePath = $p.ImagePath
            Start     = $p.Start
            Type      = $p.Type
            Group     = $p.Group
        }
    }
    Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath -EA SilentlyContinue
        if ($p.ImagePath -and $p.ImagePath -match [regex]::Escape("$Name.sys") -and
            $_.PSChildName -ne $Name) {
            $services += [pscustomobject]@{
                Key       = $_.PSPath
                Name      = $_.PSChildName
                ImagePath = $p.ImagePath
                Start     = $p.Start
                Type      = $p.Type
                Group     = $p.Group
            }
        }
    }

    # 2. class UpperFilters / LowerFilters
    $filters = @()
    Get-ChildItem $classRoot -EA 0 | ForEach-Object {
        $cls = $_
        $p   = Get-ItemProperty $cls.PSPath -EA 0
        foreach ($kind in 'UpperFilters','LowerFilters') {
            $vals = @($p.$kind)
            if ($vals -and ($vals -contains $Name)) {
                $filters += @{
                    ClassGUID = $cls.PSChildName
                    ClassKey  = $cls.PSPath
                    Kind      = $kind
                    Value     = @($vals)
                    Other     = @($vals | Where-Object { $_ -ne $Name })
                }
            }
        }
    }

    # 3. SafeBoot
    $safeBoot = @(
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot' -Recurse -EA 0 |
            Where-Object PSChildName -eq $Name |
            Select-Object -ExpandProperty PSPath
    )

    [pscustomobject]@{
        Name         = $Name
        DriverFile   = $driverFile
        Services     = $services
        ClassFilters = $filters
        SafeBoot     = $safeBoot
    }
}

function Remove-Driver {
    param([string]$Name)

    $Name       = [IO.Path]::GetFileNameWithoutExtension($Name.Trim())

    $state = Get-DriverState -Name $Name
    if (-not $state.Present) {
        "$Name`: not present."
        return [pscustomobject]@{ Name=$Name; Status='NotPresent'; RebootRequired=$false; Detail='No binary/service/filter found' }
    }

    # Service keys: disable first so early boot skips it even if delete is pending
    foreach ($s in $state.Services) {
        & sc.exe config $s.Name start= disabled | Out-Null
        & sc.exe delete  $s.Name              | Out-Null
    }

    # Class filters — keep partmgr etc.
    foreach ($f in $state.ClassFilters) {
        if ($f.Other.Count -eq 0) {
            Remove-ItemProperty -LiteralPath $f.ClassKey -Name $f.Kind -EA SilentlyContinue
        } else {
            Set-ItemProperty -LiteralPath $f.ClassKey -Name $f.Kind -Value ([string[]]$f.Other) -Type MultiString
        }
    }

    # SafeBoot
    foreach ($sb in $state.SafeBoot) {
        Remove-Item -LiteralPath $sb -Recurse -Force -EA SilentlyContinue
    }

    # Binary: delete now, or schedule on reboot
    $reboot = $false
    try {
        Remove-Item -LiteralPath $state.DriverFile -Force -EA Stop
        "$state.DriverFile deleted."
    } catch {
        $reboot = $true
        $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $existing = (Get-ItemProperty -LiteralPath $sm -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations
        $pend = if ($existing) { @($existing) } else { @() }
        $entry = "\??\$($state.DriverFile)"
        if ($pend -notcontains $entry) {
            $pend += $entry, ''
            Set-ItemProperty -LiteralPath $sm -Name PendingFileRenameOperations -Value ([string[]]$pend) -Type MultiString
        }
        "$state.DriverFile in use; deletion scheduled for next reboot."
    }

    [pscustomobject]@{
        Name            = $Name
        Status          = if ($reboot) { 'Scheduled' } else { 'Removed' }
        RebootRequired  = $reboot
        Detail          = if ($reboot) { 'File locked; pending rename set' } else { 'Binary/service/filters removed' }
    }
}

# Execution (after function definition)
foreach ($drv in $DriverName) {
    Remove-Driver -Name $drv
}