[CmdletBinding()]
param(
    [ValidateSet('Enable', 'Disable', 'Status')]
    [string]$Action = 'Enable',
    [ValidateSet('Mini', 'Full')]
    [string]$DumpType = 'Mini',
    [ValidateRange(1, 100)]
    [int]$DumpCount = 10,
    [string]$DumpFolder = '%LOCALAPPDATA%\CrashDumps',
    [switch]$NoPause
)

# Windows Error Reporting LocalDumps is an out-of-process fallback: WerFault
# writes the dump after EDF5.exe dies, so it also covers the Users DLL (no
# logger), /GS fast-fail (int 29h), stack overflow and crashes that happen
# before or inside the plugin's own crash handler. Mini keeps stacks and
# registers; Full contains all process memory. Neither is ever added to the
# sanitized debug report, and both can contain names, SteamIDs and addresses.

$ErrorActionPreference = 'Stop'
$keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\EDF5.exe'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-RecentCrashEvents {
    # Application Error 1000 is written even for the Users DLL and for
    # fast-fail. Only module, code and module-relative offset are printed:
    # no paths, names or process memory.
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                ProviderName = 'Application Error'
                Id = 1000
            } -MaxEvents 500 -ErrorAction Stop |
            Where-Object { [string]$_.Properties[0].Value -eq 'EDF5.exe' } |
            Select-Object -First 10)
    } catch {
        $events = @()
    }
    Write-Host ''
    Write-Host 'Recent EDF5.exe crashes in the Windows Application log:'
    if ($events.Count -eq 0) {
        Write-Host '  none recorded (or the log has already rotated)'
        return
    }
    foreach ($event in $events) {
        $code = [string]$event.Properties[6].Value
        if ($code -notmatch '^0x') { $code = "0x$code" }
        $offset = [string]$event.Properties[7].Value
        if ($offset -notmatch '^0x') { $offset = "0x$offset" }
        Write-Host ('  {0:yyyy-MM-dd HH:mm:ss}  module={1}  code={2}  offset={3}' -f
            $event.TimeCreated, $event.Properties[3].Value, $code, $offset)
    }
}

function Show-Status {
    Show-LocalDumpsStatus
    Show-RecentCrashEvents
}

function Show-LocalDumpsStatus {
    if (-not (Test-Path -LiteralPath $keyPath)) {
        Write-Host 'EDF5.exe LocalDumps: disabled'
        return
    }
    $values = Get-ItemProperty -LiteralPath $keyPath
    $type = switch ([int]$values.DumpType) {
        1 { 'Mini' }
        2 { 'Full' }
        default { "custom ($($values.DumpType))" }
    }
    $folder = [Environment]::ExpandEnvironmentVariables([string]$values.DumpFolder)
    Write-Host 'EDF5.exe LocalDumps: enabled'
    Write-Host "  DumpType : $type"
    Write-Host "  DumpCount: $($values.DumpCount)"
    Write-Host "  Folder   : $folder"
    if (Test-Path -LiteralPath $folder -PathType Container) {
        $dumps = @(Get-ChildItem -LiteralPath $folder -Filter 'EDF5.exe*.dmp' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10)
        if ($dumps.Count -eq 0) {
            Write-Host '  No EDF5 dumps yet.'
        }
        foreach ($dump in $dumps) {
            Write-Host ('  {0:yyyy-MM-dd HH:mm:ss}  {1,10:N0} KB  {2}' -f
                $dump.LastWriteTime, ($dump.Length / 1KB), $dump.Name)
        }
    }
}

if ($Action -eq 'Status') {
    Show-Status
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    return
}

if (-not (Test-Administrator)) {
    # HKLM needs elevation. Relaunch this exact action elevated and wait.
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Action', $Action,
        '-DumpType', $DumpType,
        '-DumpCount', $DumpCount,
        '-DumpFolder', "`"$DumpFolder`""
    )
    if ($NoPause) { $arguments += '-NoPause' }
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs `
        -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

if ($Action -eq 'Disable') {
    if (Test-Path -LiteralPath $keyPath) {
        Remove-Item -LiteralPath $keyPath -Recurse -Force
    }
    Write-Host 'EDF5.exe LocalDumps disabled. Existing dump files were kept.'
} else {
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -LiteralPath $keyPath -Name 'DumpFolder' `
        -PropertyType ExpandString -Value $DumpFolder -Force | Out-Null
    New-ItemProperty -LiteralPath $keyPath -Name 'DumpCount' `
        -PropertyType DWord -Value $DumpCount -Force | Out-Null
    $typeValue = if ($DumpType -eq 'Full') { 2 } else { 1 }
    New-ItemProperty -LiteralPath $keyPath -Name 'DumpType' `
        -PropertyType DWord -Value $typeValue -Force | Out-Null
    Write-Host 'EDF5.exe LocalDumps enabled.'
    Write-Host 'Dumps may contain names, SteamIDs and memory: send them only'
    Write-Host 'privately to the developer, never attach them publicly.'
}
Show-Status
if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
