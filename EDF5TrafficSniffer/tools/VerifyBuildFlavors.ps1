[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$buildScript = Join-Path $project 'build.ps1'
$diagnosticsDll = Join-Path $project 'build\EDF5_MultiSlotMod.dll'
$usersDll = Join-Path $project 'build\users\EDF5_MultiSlotMod.dll'
$diagnosticsIni = Join-Path $project 'build\EDF5_MultiSlotMod.ini'
$usersIni = Join-Path $project 'build\users\EDF5_MultiSlotMod.ini'
$usersObjects = Join-Path $project 'build\users\obj'
$smokeHarness = Join-Path $project 'build\smoke_harness.exe'

if (-not $SkipBuild) {
    & $buildScript -Configuration $Configuration -Flavor Diagnostics
    & $buildScript -Configuration $Configuration -Flavor Users
}

foreach ($required in @(
        $diagnosticsDll, $usersDll, $diagnosticsIni, $usersIni, $smokeHarness)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required build artifact is missing: $required"
    }
}

foreach ($entry in @('EML4_Load', 'EML5_Load', 'EML6_Load')) {
    & $smokeHarness $usersDll $entry
    if ($LASTEXITCODE -ne 0) {
        throw "Users DLL failed the $entry standalone smoke/self-test."
    }
}

$forbiddenObjects = @(
    'src_shared_diagnostics_logger.obj',
    'src_shared_diagnostics_crash_handler.obj',
    'src_shared_sniffer_winsock_hooks.obj',
    'src_games_edf41_coop8_native_roster_patch.obj',
    'src_games_edf41_coop8_room_bots.obj',
    'src_games_edf41_sniffer_callback_dispatch.obj',
    'src_games_edf41_sniffer_steam_bootstrap.obj',
    'src_games_edf41_sniffer_version_guard.obj'
)
foreach ($name in $forbiddenObjects) {
    $path = Join-Path $usersObjects $name
    if (Test-Path -LiteralPath $path) {
        throw "Diagnostics-only object leaked into Users flavor: $name"
    }
}

$bytes = [IO.File]::ReadAllBytes($usersDll)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$unicode = [Text.Encoding]::Unicode.GetString($bytes)
$forbiddenMarkers = @(
    '-diagnostics-win64',
    'snapshot_queued',
    'flow_stalled',
    'crash_handler_initialized',
    'first_chance_context',
    'startup-failures.log',
    'MSVC report_gsfailure',
    'diagnostics writer did not stop',
    'payloads.bin',
    'session.json',
    'EDF5MP_RequestDiagnosticSnapshot',
    'EDF5MP_SetDeepCapture'
)
foreach ($marker in $forbiddenMarkers) {
    if ($ascii.Contains($marker) -or $unicode.Contains($marker)) {
        throw "Diagnostics marker leaked into Users DLL: $marker"
    }
}

if (-not $ascii.Contains('-users-win64')) {
    throw 'Users build identity is missing from the Users DLL.'
}

$diagnostics = Get-Item -LiteralPath $diagnosticsDll
$users = Get-Item -LiteralPath $usersDll
if ($users.Length -ge $diagnostics.Length) {
    throw 'Users DLL is not smaller than the Diagnostics DLL.'
}

$diagnosticsHash =
    (Get-FileHash -LiteralPath $diagnosticsDll -Algorithm SHA256).Hash
$usersHash = (Get-FileHash -LiteralPath $usersDll -Algorithm SHA256).Hash
Write-Host "PASS Diagnostics: $($diagnostics.Length) bytes SHA256=$diagnosticsHash"
Write-Host "PASS Users:       $($users.Length) bytes SHA256=$usersHash"
Write-Host 'PASS Users contains no logger, crash handler, EDF4.1 sniffer, Winsock capture object or diagnostic marker.'
