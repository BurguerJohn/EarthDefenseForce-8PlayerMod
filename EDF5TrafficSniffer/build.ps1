[CmdletBinding()]
param(
    [string]$Zig = '',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [ValidateSet('Diagnostics', 'Users')]
    [string]$Flavor = 'Diagnostics'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Zig)) {
    $Zig = Join-Path $PSScriptRoot 'tools\zig\zig.exe'
}

if (-not (Test-Path -LiteralPath $Zig)) {
    throw "zig.exe not found at '$Zig'. See README.md for the pinned toolchain setup."
}

$project = $PSScriptRoot
$buildRoot = Join-Path $project 'build'
$output = if ($Flavor -eq 'Users') {
    Join-Path $buildRoot 'users'
} else {
    $buildRoot
}
$loaderApi = Join-Path $project '..\EDFModLoader\EDFModLoader'
$minhook = Join-Path $project 'third_party\minhook'

if (-not (Test-Path -LiteralPath (Join-Path $loaderApi 'PluginAPI.h'))) {
    throw "EDFModLoader PluginAPI.h not found at '$loaderApi'."
}

New-Item -ItemType Directory -Force -Path $output | Out-Null
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $project '.zig-global-cache'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $project '.zig-cache'
New-Item -ItemType Directory -Force -Path $env:ZIG_GLOBAL_CACHE_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $env:ZIG_LOCAL_CACHE_DIR | Out-Null

$optimization = if ($Configuration -eq 'Debug') { '-O0' } else { '-O2' }
$cppSources = @(
    (Join-Path $project 'src\core\plugin.cpp'),
    (Join-Path $project 'src\core\module_registry.cpp'),
    (Join-Path $project 'src\core\runtime_config.cpp'),
    (Join-Path $project 'src\core\hook_manager.cpp'),
    (Join-Path $project 'src\games\edf41\edf41_module.cpp'),
    (Join-Path $project 'src\games\edf5\edf5_module.cpp'),
    (Join-Path $project 'src\games\edf5\coop8\mission_spawn.cpp'),
    (Join-Path $project 'src\games\edf5\coop8\mission_result_recovery.cpp'),
    (Join-Path $project 'src\games\edf5\coop8\more_players.cpp'),
    (Join-Path $project 'src\games\edf5\coop8\game_patches.cpp'),
    (Join-Path $project 'src\games\edf5\sniffer\steam_hooks.cpp'),
    (Join-Path $project 'src\shared\steam_legacy\steam_user_auth.cpp'),
    (Join-Path $project 'src\shared\steam_legacy\steam_friends.cpp'),
    (Join-Path $project 'src\shared\steam_legacy\steam_game_policy.cpp'),
    (Join-Path $project 'src\shared\steam_legacy\steam_networking.cpp'),
    (Join-Path $project 'src\shared\steam_legacy\steam_matchmaking.cpp'),
    (Join-Path $project 'src\games\edf5\sniffer\steam_http.cpp'),
    (Join-Path $project 'src\games\edf6\edf6_module.cpp')
)
if ($Flavor -eq 'Diagnostics') {
    $cppSources += @(
        (Join-Path $project 'src\shared\diagnostics\logger.cpp'),
        (Join-Path $project 'src\shared\diagnostics\crash_handler.cpp'),
        (Join-Path $project 'src\shared\sniffer\winsock_hooks.cpp'),
        (Join-Path $project 'src\games\edf41\coop8\native_roster_patch.cpp'),
        (Join-Path $project 'src\games\edf41\coop8\room_bots.cpp'),
        (Join-Path $project 'src\games\edf41\sniffer\callback_dispatch.cpp'),
        (Join-Path $project 'src\games\edf41\sniffer\steam_bootstrap.cpp'),
        (Join-Path $project 'src\games\edf41\sniffer\version_guard.cpp')
    )
}
$cSources = @(
    (Join-Path $minhook 'src\buffer.c'),
    (Join-Path $minhook 'src\hook.c'),
    (Join-Path $minhook 'src\trampoline.c'),
    (Join-Path $minhook 'src\hde\hde64.c')
)

$sourceIncludeDirectories = @(
    (Join-Path $project 'src\core'),
    (Join-Path $project 'src\shared\diagnostics'),
    (Join-Path $project 'src\shared\sniffer'),
    (Join-Path $project 'src\shared\steam_legacy'),
    (Join-Path $project 'src\games\edf41'),
    (Join-Path $project 'src\games\edf41\sniffer'),
    (Join-Path $project 'src\games\edf41\coop8'),
    (Join-Path $project 'src\games\edf5'),
    (Join-Path $project 'src\games\edf5\sniffer'),
    (Join-Path $project 'src\games\edf5\coop8'),
    (Join-Path $project 'src\games\edf6'),
    (Join-Path $project 'src\games\edf6\sniffer'),
    (Join-Path $project 'src\games\edf6\coop8')
)
$commonArguments = @(
    '-target', 'x86_64-windows-gnu',
    $optimization,
    '-D_WIN64',
    '-DUNICODE',
    '-D_UNICODE',
    "-DEDF5_COMPILE_DIAGNOSTICS=$(if ($Flavor -eq 'Diagnostics') { 1 } else { 0 })",
    '-Wall',
    '-Wextra',
    '-I', (Join-Path $project '..\SteamworksSDK-Headers\public'),
    '-I', $loaderApi,
    '-I', (Join-Path $minhook 'include'),
    '-I', (Join-Path $minhook 'src'),
    '-I', (Join-Path $minhook 'src\hde')
)
foreach ($includeDirectory in $sourceIncludeDirectories) {
    $commonArguments += @('-I', $includeDirectory)
}
$firstPartyCppWarnings = @(
    '-Wconversion',
    '-Wsign-conversion',
    '-Wshadow',
    '-Wcast-align',
    '-Wformat=2',
    '-Wimplicit-fallthrough',
    '-Wnull-dereference',
    '-Wdouble-promotion',
    '-Wundef',
    '-Werror'
)

function Invoke-Zig {
    param([string[]]$Arguments)
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $Zig @Arguments
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($exitCode -ne 0) {
        throw "Zig build failed with exit code $exitCode."
    }
}

$objectDirectory = Join-Path $output 'obj'
$projectFullPath = [IO.Path]::GetFullPath($project).TrimEnd('\', '/') + `
    [IO.Path]::DirectorySeparatorChar
$objectDirectoryFullPath = [IO.Path]::GetFullPath($objectDirectory)
if (-not $objectDirectoryFullPath.StartsWith(
        $projectFullPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean object directory outside the project: $objectDirectoryFullPath"
}
if (Test-Path -LiteralPath $objectDirectoryFullPath) {
    Remove-Item -LiteralPath $objectDirectoryFullPath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $objectDirectory | Out-Null
$objects = @()

function Get-ObjectPath {
    param([string]$Source)
    $projectPrefix = $project.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $relative = if ($Source.StartsWith(
            $projectPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $Source.Substring($projectPrefix.Length)
    } else {
        [IO.Path]::GetFileName($Source)
    }
    $extension = [IO.Path]::GetExtension($relative)
    $withoutExtension = if ([string]::IsNullOrEmpty($extension)) {
        $relative
    } else {
        $relative.Substring(0, $relative.Length - $extension.Length)
    }
    $objectName = [Text.RegularExpressions.Regex]::Replace(
        $withoutExtension, '[^A-Za-z0-9_-]', '_') + '.obj'
    return Join-Path $objectDirectory $objectName
}

foreach ($source in $cppSources) {
    $object = Get-ObjectPath $source
    Invoke-Zig (@('c++') + $commonArguments + $firstPartyCppWarnings + @('-std=c++17', '-c', $source, '-o', $object))
    $objects += $object
}

foreach ($source in $cSources) {
    $object = Get-ObjectPath $source
    Invoke-Zig (@('cc') + $commonArguments + @('-std=c11', '-c', $source, '-o', $object))
    $objects += $object
}

Invoke-Zig (@('c++', '-target', 'x86_64-windows-gnu', '-shared', '-o',
    (Join-Path $output 'EDF5_MultiSlotMod.dll')) + $objects + @('-lws2_32', '-luser32'))
Copy-Item -LiteralPath (Join-Path $project 'config.ini') `
    -Destination (Join-Path $output 'EDF5_MultiSlotMod.ini') -Force

if ($Flavor -eq 'Diagnostics') {
Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    (Join-Path $project 'tools\smoke_harness.cpp'), '-o',
    (Join-Path $output 'smoke_harness.exe'), '-municode', '-lws2_32')

Invoke-Zig (@('c++') + $commonArguments + @('-std=c++17',
    (Join-Path $project 'tools\diagnostics_fixture.cpp'),
    (Get-ObjectPath (Join-Path $project 'src\core\runtime_config.cpp')),
    (Get-ObjectPath (Join-Path $project 'src\shared\diagnostics\logger.cpp')),
    (Get-ObjectPath (Join-Path $project 'src\shared\diagnostics\crash_handler.cpp')), '-o',
    (Join-Path $output 'diagnostics_fixture.exe'), '-municode',
    '-lws2_32', '-luser32'))

Invoke-Zig (@('c++') + $commonArguments + @('-std=c++17',
    (Join-Path $project 'tools\mission_record_harness.cpp'),
    (Get-ObjectPath (Join-Path $project 'src\games\edf5\coop8\game_patches.cpp')),
    (Get-ObjectPath (Join-Path $project 'src\core\runtime_config.cpp')),
    (Get-ObjectPath (Join-Path $project 'src\shared\diagnostics\logger.cpp')),
    (Get-ObjectPath (Join-Path $project 'src\shared\diagnostics\crash_handler.cpp')), '-o',
    (Join-Path $output 'mission_record_harness.exe'), '-municode',
    '-lws2_32', '-luser32'))

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'), (Join-Path $project 'tools\hde_dump.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o', (Join-Path $output 'hde_dump.exe'),
    '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'), (Join-Path $project 'tools\scan_disp.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o', (Join-Path $output 'scan_disp.exe'),
    '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'),
    (Join-Path $project 'tools\rip_xref_scanner.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o',
    (Join-Path $output 'rip_xref_scanner.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'),
    (Join-Path $project 'tools\steam_accessor_scanner.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o',
    (Join-Path $output 'steam_accessor_scanner.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'),
    (Join-Path $project 'tools\slot_capacity_scanner.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o',
    (Join-Path $output 'slot_capacity_scanner.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'),
    (Join-Path $project 'tools\player_flow_scanner.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o',
    (Join-Path $output 'player_flow_scanner.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $minhook 'src\hde'),
    (Join-Path $project 'tools\result_pipeline_scanner.cpp'),
    (Get-ObjectPath (Join-Path $minhook 'src\hde\hde64.c')), '-o',
    (Join-Path $output 'result_pipeline_scanner.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', '-O0', '-std=c++17', '-shared',
    '-I', (Join-Path $project '..\SteamworksSDK-Headers\public'),
    (Join-Path $project 'tools\fake_steam_api.cpp'), '-o',
    (Join-Path $output 'fake_steam_api64.dll'))

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    '-I', (Join-Path $project '..\SteamworksSDK-Headers\public'),
    (Join-Path $project 'tools\steam_integration_harness.cpp'), '-o',
    (Join-Path $output 'steam_integration_harness.exe'), '-municode')

Invoke-Zig @('c++', '-target', 'x86_64-windows-gnu', $optimization, '-std=c++17',
    (Join-Path $project 'tools\edf41_steam_harness.cpp'), '-o',
    (Join-Path $output 'edf41_steam_harness.exe'), '-municode')
}

Write-Host "Built $Flavor flavor: $(Join-Path $output 'EDF5_MultiSlotMod.dll')"
