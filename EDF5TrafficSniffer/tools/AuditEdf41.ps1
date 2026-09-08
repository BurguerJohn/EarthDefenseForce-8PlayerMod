[CmdletBinding()]
param(
    [string]$GameRoot = '',
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($GameRoot)) {
    $edf5Root = Split-Path -Parent (Split-Path -Parent $project)
    $steamCommon = Split-Path -Parent $edf5Root
    $GameRoot = Join-Path $steamCommon 'Earth Defense Force 4.1'
}
$GameRoot = [IO.Path]::GetFullPath($GameRoot)
$exe = Join-Path $GameRoot 'EDF41.exe'
$steam = Join-Path $GameRoot 'steam_api64.dll'
$resolveIat = Join-Path $PSScriptRoot 'resolve_iat.py'
$xrefScanner = Join-Path $project 'build\rip_xref_scanner.exe'
$accessorScanner = Join-Path $project 'build\steam_accessor_scanner.exe'
$capacityScanner = Join-Path $project 'build\slot_capacity_scanner.exe'
$flowScanner = Join-Path $project 'build\player_flow_scanner.exe'
$resultScanner = Join-Path $project 'build\result_pipeline_scanner.exe'
$hdeDump = Join-Path $project 'build\hde_dump.exe'
$disassembler = Join-Path $PSScriptRoot 'disassemble_rva.py'
$rttiResolver = Join-Path $PSScriptRoot 'resolve_rtti_vtable.py'

foreach ($required in @(
        $exe, $steam, $resolveIat, $xrefScanner, $accessorScanner,
        $capacityScanner, $flowScanner, $resultScanner, $hdeDump,
        $disassembler, $rttiResolver)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "EDF 4.1 audit input is missing: $required"
    }
}

function Assert-Equal {
    param([string]$Name, $Actual, $Expected)
    if ($Actual -ne $Expected) {
        throw "$Name changed: expected '$Expected', observed '$Actual'."
    }
}

Assert-Equal 'EDF41.exe bytes' (Get-Item -LiteralPath $exe).Length 13896192
Assert-Equal 'EDF41.exe SHA-256' `
    (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash `
    '39B4ABF7FE722175741A5E0A154063B27EF8C589A1AA5F86C84853571AC7BDA8'
Assert-Equal 'steam_api64.dll bytes' `
    (Get-Item -LiteralPath $steam).Length 204880
Assert-Equal 'steam_api64.dll SHA-256' `
    (Get-FileHash -LiteralPath $steam -Algorithm SHA256).Hash `
    'E61F3A4C3833CE48629D48D655C124F0ED552198D5A6CF82EB2F431688C00D2A'

$steamAscii = [Text.Encoding]::ASCII.GetString(
    [IO.File]::ReadAllBytes($steam))
foreach ($version in @(
        'SteamFriends015', 'SteamMatchMaking009',
        'SteamNetworking005', 'SteamUser018')) {
    if (-not $steamAscii.Contains($version)) {
        throw "Expected Steam interface is missing: $version"
    }
}

$iat = & $Python $resolveIat $exe --dll steam_api64.dll
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the EDF41 Steam IAT.' }
$expectedIat = @(
    '0x918c38: steam_api64.dll!SteamMatchmaking',
    '0x918c40: steam_api64.dll!SteamNetworking',
    '0x918c48: steam_api64.dll!SteamFriends',
    '0x918c80: steam_api64.dll!SteamAPI_Init',
    '0x918c90: steam_api64.dll!SteamUser'
)
foreach ($line in $expectedIat) {
    if ($iat -notcontains $line) { throw "EDF41 IAT entry changed: $line" }
}

$xrefs = & $xrefScanner $exe 0x918c38 0x918c40 0x918c48 0x918c80 0x918c90
if ($LASTEXITCODE -ne 0) { throw 'EDF41 Steam xref scan failed.' }
foreach ($summary in @(
        'target_rva=0x00918c38 xrefs=47',
        'target_rva=0x00918c40 xrefs=9',
        'target_rva=0x00918c48 xrefs=11',
        'target_rva=0x00918c80 xrefs=1',
        'target_rva=0x00918c90 xrefs=45')) {
    if ($xrefs -notcontains $summary) {
        throw "EDF41 Steam xref census changed: $summary"
    }
}

$matchmaking = & $accessorScanner $exe 0x918c38 37
$networking = & $accessorScanner $exe 0x918c40 21
$friends = & $accessorScanner $exe 0x918c48 63
$user = & $accessorScanner $exe 0x918c90 24
if ($LASTEXITCODE -ne 0) { throw 'EDF41 Steam accessor scan failed.' }
foreach ($evidence in @(
        @($matchmaking,
          'accessor_call=0x3bbb59 vcall=0x3bbb6b delta=0x12 slot=13 byte_offset=0x68'),
        @($matchmaking,
          'accessor_call=0x3b95fb vcall=0x3b960e delta=0x13 slot=17 byte_offset=0x88'),
        @($matchmaking,
          'accessor_call=0x3b9640 vcall=0x3b965b delta=0x1b slot=18 byte_offset=0x90'),
        @($networking,
          'summary accessor_iat_rva=0x918c40 accessor_calls=9 nearby_slot_candidates=9 window=0x40'),
        @($friends,
          'accessor_call=0x4e1585 vcall=0x4e159d delta=0x18 slot=33 byte_offset=0x108'),
        @($user,
          'accessor_call=0x3817c0 vcall=0x3817dd delta=0x1d slot=14 byte_offset=0x70'),
        @($user,
          'accessor_call=0x381fa5 vcall=0x381fc5 delta=0x20 slot=13 byte_offset=0x68'),
        @($user,
          'accessor_call=0x381ee9 vcall=0x381efb delta=0x12 slot=16 byte_offset=0x80'),
        @($user,
          'accessor_call=0x381f15 vcall=0x381f24 delta=0xf slot=15 byte_offset=0x78'))) {
    $lines = $evidence[0]
    $expected = $evidence[1]
    if ($lines -notcontains $expected) {
        throw "EDF41 accessor evidence changed: $expected"
    }
}

$nativeRoster = & $hdeDump $exe 0x3be120 0x3be34d
if ($LASTEXITCODE -ne 0) { throw 'EDF41 native roster decode failed.' }
foreach ($anchor in @(
        '003be129  48 39 be e0 00 00 00                          op=39 rex=00 modrm=be disp32=000000e0',
        '003be140  48 8b 86 d0 00 00 00                          op=8b rex=00 modrm=86 disp32=000000d0',
        '003be2f0  48 8b 86 d0 00 00 00                          op=8b rex=00 modrm=86 disp32=000000d0',
        '003be2f7  48 8d 1c c8                                   op=8d rex=00 modrm=1c sib=c8',
        '003be316  f0 0f c1 41 04                                op=0f/c1 modrm=41 disp8=04',
        '003be344  48 89 03                                      op=89 rex=00 modrm=03',
        '003be347  ff 86 e8 00 00 00                             op=ff modrm=86 disp32=000000e8')) {
    if ($nativeRoster -notcontains $anchor) {
        throw "EDF41 native four-slot roster anchor changed: $anchor"
    }
}
$nativeRosterCallers = & $Python $disassembler $exe --calls-to 0x3bdf60
if ($LASTEXITCODE -ne 0 -or
    $nativeRosterCallers -notcontains '003b6114  call -> 003bdf60' -or
    $nativeRosterCallers -notcontains '003b9bc6  call -> 003bdf60') {
    throw 'EDF41 native roster caller set changed.'
}

$nativeRosterConstructor = & $hdeDump $exe 0x3aa595 0x3aa5e7
if ($LASTEXITCODE -ne 0) { throw 'EDF41 net::Users constructor decode failed.' }
foreach ($anchor in @(
        '003aa5aa  48 8d 9f c8 00 00 00                          op=8d rex=00 modrm=9f disp32=000000c8',
        '003aa5c2  8d 56 04                                      op=8d modrm=56 disp8=04',
        '003aa5cd  e8 ce 60 d7 ff                                op=e8 imm32=ffd760ce relative',
        '003aa5d6  8d 56 04                                      op=8d modrm=56 disp8=04',
        '003aa5e1  e8 fa 64 d7 ff                                op=e8 imm32=ffd764fa relative')) {
    if ($nativeRosterConstructor -notcontains $anchor) {
        throw "EDF41 net::Users four-slot constructor anchor changed: $anchor"
    }
}
$nativeRosterDestructor = & $hdeDump $exe 0x3aa6df 0x3aa6f0
if ($LASTEXITCODE -ne 0 -or
    $nativeRosterDestructor -notcontains `
        '003aa6ea  e8 d1 60 d7 ff                                op=e8 imm32=ffd760d1 relative') {
    throw 'EDF41 net::Users dynamic roster destructor anchor changed.'
}
foreach ($target in @(
        @('0x1206a0', '003aa5cd  call -> 001206a0'),
        @('0x120ae0', '003aa5e1  call -> 00120ae0'),
        @('0x1207c0', '003aa6ea  call -> 001207c0'))) {
    $calls = & $Python $disassembler $exe --calls-to $target[0]
    if ($LASTEXITCODE -ne 0 -or $calls -notcontains $target[1]) {
        throw "EDF41 net::Users vector helper call changed: $($target[1])"
    }
}
$nativeRosterRtti = & $Python $rttiResolver $exe 0xaa50e0
if ($LASTEXITCODE -ne 0 -or $nativeRosterRtti -notcontains `
        'vtable_rva=0xaa50e0 locator_rva=0xb29880 type_rva=0xc7b4a0 hierarchy_rva=0xb29660 object_offset=0x0 ctor_offset=0x0 type=.?AVUsers@net@@') {
    throw 'EDF41 native roster owner RTTI changed.'
}

$sessionRosterConstructor = & $hdeDump $exe 0x394b47 0x394b7b
if ($LASTEXITCODE -ne 0) {
    throw 'EDF41 SessionController roster constructor decode failed.'
}
foreach ($anchor in @(
        '00394b58  48 83 7f 10 04                                op=83 rex=00 modrm=7f disp8=10 imm8=04',
        '00394b5f  e8 bc 43 00 00                                op=e8 imm32=000043bc relative',
        '00394b70  ba 04 00 00 00                                op=ba imm32=00000004',
        '00394b75  e8 36 4a 00 00                                op=e8 imm32=00004a36 relative')) {
    if ($sessionRosterConstructor -notcontains $anchor) {
        throw "EDF41 SessionController four-slot constructor anchor changed: $anchor"
    }
}
$sessionRosterReserve = & $hdeDump $exe 0x398f20 0x398ff5
if ($LASTEXITCODE -ne 0) {
    throw 'EDF41 SessionController reserve helper decode failed.'
}
foreach ($anchor in @(
        '00398f26  48 83 79 10 04                                op=83 rex=00 modrm=79 disp8=10 imm8=04',
        '00398f38  ba 10 00 00 00                                op=ba imm32=00000010',
        '00398f42  8d 4a 30                                      op=8d modrm=4a disp8=30',
        '00398f5c  bd 04 00 00 00                                op=bd imm32=00000004',
        '00398fae  e8 ad 20 d3 ff                                op=e8 imm32=ffd320ad relative',
        '00398fd3  e8 38 00 00 00                                op=e8 imm32=00000038 relative',
        '00398fe1  48 89 6f 18                                   op=89 rex=00 modrm=6f disp8=18',
        '00398fea  48 c7 47 10 04 00 00 00                       op=c7 rex=00 modrm=47 disp8=10 imm32=00000004')) {
    if ($sessionRosterReserve -notcontains $anchor) {
        throw "EDF41 SessionController reserve helper anchor changed: $anchor"
    }
}
$sessionRosterLookup = & $hdeDump $exe 0x3960d0 0x396127
if ($LASTEXITCODE -ne 0) {
    throw 'EDF41 SessionController roster lookup decode failed.'
}
foreach ($anchor in @(
        '003960fe  48 63 57 04                                   op=63 rex=00 modrm=57 disp8=04',
        '00396104  48 c1 e2 04                                   op=c1 rex=00 modrm=e2 imm8=04',
        '00396108  48 03 96 d0 00 00 00                          op=03 rex=00 modrm=96 disp32=000000d0',
        '0039611e  e8 3d 4f d3 ff                                op=e8 imm32=ffd34f3d relative')) {
    if ($sessionRosterLookup -notcontains $anchor) {
        throw "EDF41 SessionController P5 crash-path anchor changed: $anchor"
    }
}
$sessionConstructorCallers = & $Python $disassembler $exe --calls-to 0x394940
$sessionReserveCallers = & $Python $disassembler $exe --calls-to 0x398f20
$sessionLookupCallers = & $Python $disassembler $exe --calls-to 0x3960d0
$sessionTeardownCallers = & $Python $disassembler $exe --calls-to 0x399010
$expectedSessionReserveCallers = @(
    '00394b47  call -> 00398f20',
    '00394b5f  call -> 00398f20') -join "`n"
$expectedSessionTeardownCallers = @(
    '00394c8e  call -> 00399010',
    '00398fd3  call -> 00399010') -join "`n"
if ($LASTEXITCODE -ne 0 -or
    ($sessionConstructorCallers -join "`n") -ne '003ba138  call -> 00394940' -or
    ($sessionReserveCallers -join "`n") -ne $expectedSessionReserveCallers -or
    $sessionLookupCallers -notcontains '00395c12  call -> 003960d0' -or
    ($sessionTeardownCallers -join "`n") -ne $expectedSessionTeardownCallers) {
    throw 'EDF41 SessionController constructor/helper/lookup/teardown callers changed.'
}
$sessionBaseRtti = & $Python $rttiResolver $exe 0xaa4720
$sessionImplRtti = & $Python $rttiResolver $exe 0xaa5448
if ($LASTEXITCODE -ne 0 -or $sessionBaseRtti -notcontains `
        'vtable_rva=0xaa4720 locator_rva=0xb27c50 type_rva=0xc79f78 hierarchy_rva=0xb27ba8 object_offset=0x0 ctor_offset=0x0 type=.?AVSessionController@net@@' -or
    $sessionImplRtti -notcontains `
        'vtable_rva=0xaa5448 locator_rva=0xb2a368 type_rva=0xc7b7c0 hierarchy_rva=0xb2a060 object_offset=0x0 ctor_offset=0x0 type=.?AVSessionControllerImpl@net@@') {
    throw 'EDF41 SessionController RTTI changed.'
}

$capacity = & $capacityScanner $exe
$capacityExit = $LASTEXITCODE
$flow = & $flowScanner $exe
$flowExit = $LASTEXITCODE
$result = & $resultScanner $exe
$resultExit = $LASTEXITCODE
if ($capacityExit -ne 0 -or $flowExit -ne 5 -or $resultExit -ne 5) {
    throw "EDF41 negative portability scan exit codes changed: " +
        "capacity=$capacityExit flow=$flowExit result=$resultExit."
}
if ($capacity -notcontains `
        'summary known_capacity_anchors=0 unknown_capacity_anchors=98 experimental_reserve_anchors=24 deferred_four_anchors=11 reviewed_non_roster_anchors=6 contextual_immediates=187') {
    throw 'EDF41 capacity baseline changed; classify it before any patch.'
}
if (($flow -join "`n") -notmatch `
        'confirmed_mission_lookup_callers=0.*receive_owner_chain_valid=false') {
    throw 'EDF41 negative player-flow baseline changed.'
}
if (($result -join "`n") -notmatch `
        'unexpected=28 missing=15 unexpected_calls=7 missing_calls=6') {
    throw 'EDF41 negative result-pipeline baseline changed.'
}

Write-Host 'PASS EDF41.exe and steam_api64.dll fingerprints are pinned.'
Write-Host 'PASS Legacy Steam interfaces, IAT entries and xref counts are unchanged.'
Write-Host 'PASS CreateLobby, invite, User018 auth and P2P callsite evidence is unchanged.'
Write-Host 'PASS Room ingestion still enumerates Steam member count/index at the pinned callsites.'
Write-Host 'PASS Native four-slot roster lookup, replacement and both direct callers remain pinned.'
Write-Host 'PASS net::Users allocates and initializes four vector slots at the two transactional patch sites; teardown is dynamic.'
Write-Host 'PASS net::SessionController reserves, initializes and tears down its independent four-entry shared-pointer vector dynamically.'
Write-Host 'PASS The second P5 crash path indexes SessionController+0xD0 by 16-byte records and copies through the pinned shared-pointer helper.'
Write-Host 'PASS EDF5 capacity/player/result signatures remain invalid for EDF4.1.'
