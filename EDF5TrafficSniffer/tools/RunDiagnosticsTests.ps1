[CmdletBinding()]
param(
    [string]$OutputRoot = '',
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$fixture = Join-Path $project 'build\diagnostics_fixture.exe'
$fixtureSource = Join-Path $project 'tools\diagnostics_fixture.cpp'
$reportTool = Join-Path $project 'tools\CreateDebugReport.ps1'
$validator = Join-Path $project 'tools\validate_diagnostics.py'
$missionRecordHarness = Join-Path $project 'build\mission_record_harness.exe'
$missionRecordFixture = Join-Path $project `
    'tools\fixtures\mission-record-v046-append.json'
$slotCapacityScanner = Join-Path $project 'build\slot_capacity_scanner.exe'
$playerFlowScanner = Join-Path $project 'build\player_flow_scanner.exe'
$resultPipelineScanner = Join-Path $project 'build\result_pipeline_scanner.exe'
$pluginDll = Join-Path $project 'build\EDF5_MultiSlotMod.dll'
$pluginIni = Join-Path $project 'build\EDF5_MultiSlotMod.ini'
$fakeSteam = Join-Path $project 'build\fake_steam_api64.dll'
$edf41SteamHarness = Join-Path $project 'build\edf41_steam_harness.exe'
$edf5SteamHarness = Join-Path $project 'build\steam_integration_harness.exe'
$spawnResultLayoutValidator = Join-Path $project `
    'tools\validate_spawn_result_layout.py'
$playerControlAnalyzer = Join-Path $project 'tools\analyze_player_controls.py'
$playerControlFixture = Join-Path $project `
    'tools\fixtures\player-control-v056'
$playerFlowFixture = Join-Path $project `
    'tools\fixtures\player-flow-v060'
$playerFlowExactLoadoutFixture = Join-Path $project `
    'tools\fixtures\player-flow-v062'
$playerFlowPreMapRestoreFixture = Join-Path $project `
    'tools\fixtures\player-flow-v067'
$playerFlowLoadoutRewardRollbackFixture = Join-Path $project `
    'tools\fixtures\player-flow-v0610'
$playerLoadoutLateRestoreFixture = Join-Path $project `
    'tools\fixtures\player-loadout-late-restore-v067'
$playerResultEventMismatchFixture = Join-Path $project `
    'tools\fixtures\player-result-event-mismatch-v067'
$playerResultUiCloseFixture = Join-Path $project `
    'tools\fixtures\player-result-ui-close-v068'
$playerResultUiCloseMissingFixture = Join-Path $project `
    'tools\fixtures\player-result-ui-close-missing-v068'
$playerFlowPrivateIdentityFixture = Join-Path $project `
    'tools\fixtures\player-flow-v063'
$playerLoadoutClassMismatchFixture = Join-Path $project `
    'tools\fixtures\player-loadout-class-mismatch-v062'
$playerNameCollisionFixture = Join-Path $project `
    'tools\fixtures\player-name-collision-v063'
$playerNameSourceMismatchFixture = Join-Path $project `
    'tools\fixtures\player-name-source-mismatch-v0614'
$playerChatNameFixture = Join-Path $project `
    'tools\fixtures\player-chat-name-v066'
$playerChatNameCollisionFixture = Join-Path $project `
    'tools\fixtures\player-chat-name-collision-v066'
$playerReplicationFixture = Join-Path $project `
    'tools\fixtures\player-replication-v064'
$playerReplicationUnresolvedFixture = Join-Path $project `
    'tools\fixtures\player-replication-unresolved-v064'
$playerReplicationMissingHostFixture = Join-Path $project `
    'tools\fixtures\player-replication-missing-host-v0610'
$playerReplicationDuplicateIdentityFixture = Join-Path $project `
    'tools\fixtures\player-replication-duplicate-identity-v0611'
$playerReplicationFanoutIncompleteFixture = Join-Path $project `
    'tools\fixtures\player-replication-fanout-incomplete-v0616'
$playerTransportRouteCollisionFixture = Join-Path $project `
    'tools\fixtures\player-transport-route-collision-v0615'
$playerResultStallFixture = Join-Path $project `
    'tools\fixtures\player-result-stall-v060'
$playerResultRewardFixture = Join-Path $project `
    'tools\fixtures\player-result-reward-v065'
$playerResultRewardStallFixture = Join-Path $project `
    'tools\fixtures\player-result-reward-stall-v065'
$playerSpawnResultFixture = Join-Path $project `
    'tools\fixtures\player-spawn-result-v0632'
$playerSpawnUnsafeFixture = Join-Path $project `
    'tools\fixtures\player-spawn-unsafe-v0632'
$playerSpawnMultiplierDisabledFixture = Join-Path $project `
    'tools\fixtures\player-spawn-multiplier-disabled-v0638'
$playerSpawnZeroCallsFixture = Join-Path $project `
    'tools\fixtures\player-spawn-zero-calls-v0639'
$playerSpawnResultOnlyFixture = Join-Path $project `
    'tools\fixtures\player-spawn-result-only-v0633'
$playerGeneratorPollPointerLeakFixture = Join-Path $project `
    'tools\fixtures\player-generator-poll-pointer-leak-v0644'
$playerGeneratorPollGateUnknownFixture = Join-Path $project `
    'tools\fixtures\player-generator-poll-gate-unknown-v0646'
$playerResultNativeCancelFixture = Join-Path $project `
    'tools\fixtures\player-result-native-cancel-v0636'
$playerResultNativeCancelDuplicateFixture = Join-Path $project `
    'tools\fixtures\player-result-native-cancel-duplicate-v0636'
$gameExecutable = Join-Path $project '..\..\EDF5.exe'

if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw 'Build diagnostics_fixture.exe before running this script.'
}
if ((Get-Item -LiteralPath $fixtureSource).LastWriteTimeUtc -gt
        (Get-Item -LiteralPath $fixture).LastWriteTimeUtc) {
    throw 'diagnostics_fixture.exe is older than its source; run build.ps1 first.'
}
if (-not (Test-Path -LiteralPath $missionRecordHarness -PathType Leaf)) {
    throw 'Build mission_record_harness.exe before running this script.'
}
if (-not (Test-Path -LiteralPath $missionRecordFixture -PathType Leaf)) {
    throw 'Mission-record crash fixture is missing.'
}
if (-not (Test-Path -LiteralPath $slotCapacityScanner -PathType Leaf)) {
    throw 'Build slot_capacity_scanner.exe before running this script.'
}
if (-not (Test-Path -LiteralPath $playerFlowScanner -PathType Leaf)) {
    throw 'Build player_flow_scanner.exe before running this script.'
}
if (-not (Test-Path -LiteralPath $resultPipelineScanner -PathType Leaf)) {
    throw 'Build result_pipeline_scanner.exe before running this script.'
}
foreach ($steamArtifact in @(
        $pluginDll, $pluginIni, $fakeSteam,
        $edf41SteamHarness, $edf5SteamHarness)) {
    if (-not (Test-Path -LiteralPath $steamArtifact -PathType Leaf)) {
        throw "Steam integration artifact is missing: $steamArtifact"
    }
}
if (-not (Test-Path -LiteralPath $spawnResultLayoutValidator -PathType Leaf)) {
    throw 'Spawn/result layout validator is missing.'
}
if (-not (Test-Path -LiteralPath $playerControlAnalyzer -PathType Leaf) -or
    -not (Test-Path -LiteralPath $playerControlFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerFlowFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerFlowExactLoadoutFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerFlowPreMapRestoreFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerFlowLoadoutRewardRollbackFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerLoadoutLateRestoreFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultEventMismatchFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultUiCloseFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultUiCloseMissingFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerFlowPrivateIdentityFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerLoadoutClassMismatchFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerNameCollisionFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerNameSourceMismatchFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerChatNameFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerChatNameCollisionFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerReplicationFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerReplicationUnresolvedFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerReplicationMissingHostFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerReplicationDuplicateIdentityFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerReplicationFanoutIncompleteFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerTransportRouteCollisionFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultStallFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultRewardFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultRewardStallFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerSpawnResultFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerSpawnUnsafeFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerSpawnMultiplierDisabledFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerSpawnZeroCallsFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerSpawnResultOnlyFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerGeneratorPollPointerLeakFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultNativeCancelFixture -PathType Container) -or
    -not (Test-Path -LiteralPath $playerResultNativeCancelDuplicateFixture -PathType Container)) {
    throw 'Player-control analyzer or fixture is missing.'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $OutputRoot = Join-Path $project "test-output\diagnostics-$stamp"
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) {
    throw "Refusing to reuse an existing test directory: $OutputRoot"
}

function Invoke-FakeSteamIntegration {
    param(
        [string]$Name,
        [string]$Harness,
        [string]$ExpectedOutput
    )
    $stage = Join-Path $OutputRoot "steam-integration\$Name"
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    $stagedPlugin = Join-Path $stage 'EDF5_MultiSlotMod.dll'
    $stagedSteam = Join-Path $stage 'steam_api64.dll'
    $stagedHarness = Join-Path $stage ([IO.Path]::GetFileName($Harness))
    Copy-Item -LiteralPath $pluginDll -Destination $stagedPlugin
    Copy-Item -LiteralPath $pluginIni `
        -Destination (Join-Path $stage 'EDF5_MultiSlotMod.ini')
    if ($Name -eq 'edf41') {
        $stagedIni = Join-Path $stage 'EDF5_MultiSlotMod.ini'
        $stagedIniText = Get-Content -LiteralPath $stagedIni -Raw
        $stagedIniText = $stagedIniText.Replace(
            'ExperimentalRoomOverfill=false',
            'ExperimentalRoomOverfill=true')
        if (-not $stagedIniText.Contains('ExperimentalRoomOverfill=true')) {
            throw 'EDF 4.1 test INI cannot enable ExperimentalRoomOverfill.'
        }
        Set-Content -LiteralPath $stagedIni -Value $stagedIniText -NoNewline
    }
    Copy-Item -LiteralPath $fakeSteam -Destination $stagedSteam
    Copy-Item -LiteralPath $Harness -Destination $stagedHarness
    Push-Location $stage
    try {
        $output = & $stagedHarness $stagedPlugin $stagedSteam 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $output | Write-Host
    if ($exitCode -ne 0 -or ($output -join "`n") -notmatch $ExpectedOutput) {
        throw "$Name fake-Steam integration failed with exit code $exitCode."
    }
    return $stage
}

$edf41SteamStage = Invoke-FakeSteamIntegration `
    'edf41' $edf41SteamHarness `
    'edf41_steam_integration=pass accessors=4.*room_bots=pass'
$edf41Event = Get-ChildItem -LiteralPath `
    (Join-Path $edf41SteamStage 'Mods\TrafficSniffer\logs') `
    -Recurse -Filter 'events*.jsonl' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $edf41Event) {
    throw 'EDF 4.1 fake-Steam integration produced no event log.'
}
$edf41Events = Get-Content -LiteralPath $edf41Event.FullName -Raw
foreach ($marker in @(
        '"event":"integration_harness_accepted"',
        '"event":"bootstrap_installed"',
        '"user_accessor":true',
        '"layer":"edf41_steam_callback","event":"register"',
        '"layer":"edf41_steam_callback","event":"register_call_result"',
        '"layer":"edf41_steam_callback","event":"dispatch"',
        '"callback_name":"LobbyChatUpdate","invocation":"callback"',
        '"callback_name":"ValidateAuthTicketResponse","invocation":"callback"',
        '"auth_session_response":0',
        '"callback_name":"LobbyCreated","invocation":"call_result"',
        '"event":"activate_lobby_invite_dialog"',
        '"event":"get_auth_session_ticket"',
        '"ticket_payload_logged":false',
        '"event":"cancel_auth_ticket"',
        '"event":"begin_auth_session"',
        '"requested_max_members":4,"max_members":4',
        '"layer":"edf41_native_roster","event":"install","requested":true,"signature_matched":true',
        '"harness_simulation":true,"transactional_sites":true,"session_controller_sites":6,"net_users_sites":2,"room_ui_sites":2,"room_ui_member_windows":4,"room_ui_overflow_mode":"headless","patched_sites":10,"success":true',
        '"layer":"edf41_room_bots","event":"started","enabled":true',
        '"experimental_room_overfill":true,"native_roster_expansion_ready":true,"room_overfill_quarantined":false,"effective_room_limit":8',
        '"layer":"edf41_room_bots","event":"owned_lobby_detected"',
        '"layer":"edf41_room_bots","event":"member_template_resolved"',
        '"template_payload_logged":false',
        '"layer":"edf41_room_bots","event":"bot_added"',
        '"bot_number":7,"actual_members":1,"synthetic_members":7,"reported_members":8',
        '"reason":"configured room limit reached"',
        '"layer":"edf41_room_bots","event":"synthetic_p2p_send"',
        '"auth_ticket_echo_queued":true',
        '"layer":"edf41_room_bots","event":"auth_validation_dispatched"',
        '"layer":"edf41_room_bots","event":"bot_evicted_for_real_member"',
        '"layer":"edf41_room_bots","event":"bot_removed"')) {
    if (-not $edf41Events.Contains($marker)) {
        throw "EDF 4.1 integration log marker is missing: $marker"
    }
}
Write-Host 'EDF 4.1 legacy Steam integration passed with the transactional net::Users and SessionController roster expansion simulated at eight members.'

$null = Invoke-FakeSteamIntegration `
    'edf5' $edf5SteamHarness 'integration=true name=EDF5_MultiSlotMod'
Write-Host 'EDF5 fake-Steam Coop8 integration still passes through the shared ABI layer.'

& $missionRecordHarness $missionRecordFixture
if ($LASTEXITCODE -ne 0) {
    throw "Mission-record micro-harness failed with exit code $LASTEXITCODE."
}
Write-Host 'Mission-record native crash reproduction and patched replay passed.'

$capacityScan = & $slotCapacityScanner $gameExecutable
if ($LASTEXITCODE -ne 0) {
    throw "Slot-capacity scanner failed with exit code $LASTEXITCODE."
}
$expectedScan = 'summary known_capacity_anchors=8 unknown_capacity_anchors=41 experimental_reserve_anchors=24 deferred_four_anchors=11 reviewed_non_roster_anchors=6 contextual_immediates=109'
if ($capacityScan -notcontains $expectedScan) {
    throw 'Slot-capacity scanner result changed; review candidates before patching.'
}
Write-Host 'Slot-capacity audit passed: 8 proven, 24 experimental reserve, 11 deferred and 6 reviewed non-roster anchors.'

$playerFlowScan = & $playerFlowScanner $gameExecutable
if ($LASTEXITCODE -ne 0) {
    throw "Player-flow scanner failed with exit code $LASTEXITCODE."
}
$expectedPlayerFlow = 'summary seed_functions=9 indexed_lookup_callers=28 confirmed_mission_lookup_callers=3 compare_four=4 and_mask_3=0 and_mask_f=0 bit_index=0 variable_shift=0 scaled_index=74 indexed_near_four=15 direct_calls=326 receive_route_register_signature=true receive_route_unregister_signature=true receive_route_register_callers=1 receive_route_unregister_callers=1 unexpected_route_callers=0 receive_route_object_constructor_signature=true receive_route_user_control_copy_signature=true receive_parser_constructor_signature=true receive_parser_owner_store_signature=true receive_parser_call_signature=true receive_route_object_constructor_callers=1 receive_parser_constructor_callers=1 receive_owner_chain_valid=true'
if ($playerFlowScan -notcontains $expectedPlayerFlow) {
    throw 'Player-flow scanner result changed; review index/mask candidates before patching.'
}
Write-Host 'Player-flow audit passed: 28 indexed getter callers, exact route lifecycle callsites and the parser-to-UserImpl receive ownership chain are unchanged.'

$resultPipelineScan = & $resultPipelineScanner $gameExecutable
if ($LASTEXITCODE -ne 0) {
    throw "Result-pipeline scanner failed with exit code $LASTEXITCODE."
}
$expectedResultPipeline = 'summary ranges=12 decoded_instructions=2882 small_immediates=15 value_3=1 value_4=11 value_15=3 dynamic_stride_16=6 aggregate_divide_8=1 result_state_bit_flag=1 dynamic_vector_initial_reserve=1 online_participant_filters=2 fixed_item_accumulator_count=1 named_sync_constants=3 exec_begin_direct_callers=2 result_sync_begin_wrapper=true exec_update_direct_callers=2 result_sync_update_wrapper=true exec_finally_direct_callers=2 result_sync_finally_wrapper=true capacity_masks=0 unexpected=0 missing=0 unexpected_calls=0 missing_calls=0 decode_errors=0'
if ($resultPipelineScan -notcontains $expectedResultPipeline) {
    throw 'Result-pipeline immediate census changed; review every new candidate.'
}
Write-Host 'Result-pipeline audit passed: all 12 bodies contain only classified constants and Exec_Begin/Update/Finally have exactly the expected native and script callers.'

$spawnResultLayout = & $Python $spawnResultLayoutValidator $gameExecutable
if ($LASTEXITCODE -ne 0) {
    throw "Spawn/result layout audit failed with exit code $LASTEXITCODE."
}
$expectedSpawnResultLayout = 'summary enemy_callers=24 native_enemy_capacity=400 scale_offsets=0x290/0x294 source_offset=0x2b0 scale_default=0/1 scale_config_record=4 generator_request_precedes_timer=true participant_table_affects_timer=true generator_update_virtual_offset=0xa0 generator_update_method=0x1f8b40 generator_base_update=0x2da720 generator_base_tailcalls_gate=true generator_gate_cooldown_threshold=0x1cc generator_gate_outcomes=cooldown/quota/spawn_false/spawn_accepted generator_gate_virtual_offset=0x108 generator_spawn_method=0x1f90a0 generator_manager_offset=0x788 generator_return_low_byte_consumed=true native_participant_scaling_reads=56 leaf_scaling_reads=2 native_scaling_capacity=4 stored_participant_count_preserved=true result_native_item_accumulators=4 result_dynamic_handle_vectors=2 exec_begin_direct_callers=2 result_sync_begin_wrapper=true exec_begin_argument=-20000'
if ($spawnResultLayout -notcontains $expectedSpawnResultLayout) {
    throw 'Spawn/result layout summary changed; review ABI and offsets.'
}
Write-Host 'Spawn/result byte audit passed: ABI, 24 enemy callers, 56 scaling reads, GeneratorPoll update/base/gate/spawn chain, result storage and both Exec_Begin callers are unchanged.'

& $Python $playerControlAnalyzer $playerControlFixture `
    --expected-players 2 --strict
if ($LASTEXITCODE -ne 0) {
    throw "Player-control analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-control report analyzer passed its participant/local-controller fixture.'

& $Python $playerControlAnalyzer $playerFlowFixture `
    --expected-players 5 --strict
if ($LASTEXITCODE -ne 0) {
    throw "Player-flow compatibility analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted identity-preserving repair and completed result telemetry.'

& $Python $playerControlAnalyzer $playerFlowFixture `
    --expected-players 5 --require-extra-result-items --strict
if ($LASTEXITCODE -ne 0) {
    throw "Extra MissionResult Item analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted the safe P4 result Item aggregation.'

$missingResultItemOutput = & $Python $playerControlAnalyzer `
    $playerFlowFixture --expected-players 6 `
    --require-extra-result-items --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject a missing P5 result Item aggregation.'
}
if (($missingResultItemOutput -join "`n") -notmatch `
        'missing extra MissionResult item aggregation for P5') {
    throw 'Missing P5 result Item fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a missing P5 result Item aggregation.'

& $Python $playerControlAnalyzer $playerFlowExactLoadoutFixture `
    --expected-players 5 --require-exact-loadout --strict
if ($LASTEXITCODE -ne 0) {
    throw "Exact P4 loadout analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted exact P4 class/loadout restoration and host result recovery.'

& $Python $playerControlAnalyzer $playerFlowPreMapRestoreFixture `
    --expected-players 5 --require-exact-loadout `
    --require-pre-map-loadout-restore `
    --require-result-event-publish --strict
if ($LASTEXITCODE -ne 0) {
    throw "Pre-map P4 identity restoration fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted P4 identity restoration before native participant-map consumers.'

& $Python $playerControlAnalyzer $playerFlowLoadoutRewardRollbackFixture `
    --expected-players 5 --require-loadout-parser-rollback `
    --require-class-sidecar --require-visual-slot-remap `
    --require-effective-result-recovery --strict
if ($LASTEXITCODE -ne 0) {
    throw "P4 loadout/reward rollback fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted P4 parser rollback, class sidecar, visual-slot remap and effective result recovery.'

& $Python $playerControlAnalyzer $playerLoadoutLateRestoreFixture `
    --expected-players 5 --require-exact-loadout `
    --require-pre-map-loadout-restore --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate late P4 identity restoration.'
}
Write-Host 'Player-flow analyzer rejected P4 identity restoration after native participant-map consumers.'

& $Python $playerControlAnalyzer $playerResultEventMismatchFixture `
    --expected-players 2 --require-result-event-publish --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate MissionResult event mismatch.'
}
Write-Host 'Player-flow analyzer rejected a malformed MissionResult UI close event.'

& $Python $playerControlAnalyzer $playerResultUiCloseFixture `
    --expected-players 2 --require-result-event-publish `
    --require-result-ui-close-dispatch --strict
if ($LASTEXITCODE -ne 0) {
    throw "MissionResult UI close dispatch fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted UI close delivery to object id 2.'

& $Python $playerControlAnalyzer $playerResultUiCloseMissingFixture `
    --expected-players 2 --require-result-event-publish `
    --require-result-ui-close-dispatch --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the missing UI object-id-2 close target.'
}
Write-Host 'Player-flow analyzer rejected a close event that never reached UI object id 2.'

& $Python $playerControlAnalyzer $playerLoadoutClassMismatchFixture `
    --expected-players 5 --require-exact-loadout --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate P4 class mismatch.'
}
Write-Host 'Player-flow analyzer rejected the deliberate P4 class mismatch.'

& $Python $playerControlAnalyzer $playerFlowPrivateIdentityFixture `
    --expected-players 5 --require-exact-loadout `
    --require-name-identity --strict
if ($LASTEXITCODE -ne 0) {
    throw "Private nickname-identity analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted five private nickname identities without recording text.'

& $Python $playerControlAnalyzer $playerNameCollisionFixture `
    --expected-players 5 --require-name-identity --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate host/P4 nickname collision.'
}
Write-Host 'Player-flow analyzer rejected the deliberate host/P4 nickname collision.'

$nameSourceMismatchOutput = & $Python $playerControlAnalyzer `
    $playerNameSourceMismatchFixture --expected-players 2 `
    --require-name-identity --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject a mismatched nickname UserImpl source.'
}
if (($nameSourceMismatchOutput -join "`n") -notmatch `
        'display name came from a mismatched logical UserImpl source') {
    throw 'Nickname source mismatch fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a nickname built from the wrong logical UserImpl source.'

& $Python $playerControlAnalyzer $playerChatNameFixture `
    --expected-players 2 --require-chat-name-association --strict
if ($LASTEXITCODE -ne 0) {
    throw "Chat sender/name analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted a private matching chat sender/name association.'

& $Python $playerControlAnalyzer $playerChatNameCollisionFixture `
    --expected-players 2 --require-chat-name-association --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate chat sender/name collision.'
}
Write-Host 'Player-flow analyzer rejected the deliberate chat sender/name collision.'

& $Python $playerControlAnalyzer $playerReplicationFixture `
    --expected-players 2 --require-replication-association `
    --require-replication-matrix --require-receive-route-matrix `
    --require-transport-route-identity `
    --require-replication-send-fanout --strict
if ($LASTEXITCODE -ne 0) {
    throw "Participant-replication analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted resolved outgoing/incoming participant replication.'

$replicationFanoutIncompleteOutput = & $Python $playerControlAnalyzer `
    $playerReplicationFanoutIncompleteFixture --expected-players 2 `
    --require-replication-send-fanout --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject an incomplete serializer fan-out.'
}
if (($replicationFanoutIncompleteOutput -join "`n") -notmatch `
        'incomplete replication send fan-out for local P0 family 0x3300') {
    throw 'Replication fan-out fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a serializer fan-out missing its remote participant.'

$transportRouteCollisionOutput = & $Python $playerControlAnalyzer `
    $playerTransportRouteCollisionFixture --expected-players 2 `
    --require-transport-route-identity --require-receive-route-matrix `
    --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject a duplicated UserImpl+0xc8 transport route.'
}
if (($transportRouteCollisionOutput -join "`n") -notmatch `
        'transport route 0 shared by participants') {
    throw 'Transport-route collision fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a host/client UserImpl+0xc8 transport-route collision.'

& $Python $playerControlAnalyzer $playerReplicationUnresolvedFixture `
    --expected-players 2 --require-replication-association --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject unresolved incoming participant replication.'
}
Write-Host 'Player-flow analyzer rejected unresolved incoming participant replication.'

& $Python $playerControlAnalyzer $playerReplicationMissingHostFixture `
    --expected-players 3 --require-replication-association `
    --require-replication-matrix --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject missing incoming host replication.'
}
Write-Host 'Player-flow analyzer rejected a client capture with no incoming host replication.'

& $Python $playerControlAnalyzer $playerReplicationMissingHostFixture `
    --expected-players 3 --require-receive-route-matrix --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject a receive vector missing host P0.'
}
Write-Host 'Player-flow analyzer rejected a receive vector missing host P0.'

& $Python $playerControlAnalyzer $playerReplicationDuplicateIdentityFixture `
    --expected-players 2 --require-replication-association `
    --require-replication-matrix --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject a duplicated participant UserImpl.'
}
Write-Host 'Player-flow analyzer rejected a duplicated participant identity in the replication map.'

& $Python $playerControlAnalyzer $playerResultStallFixture `
    --expected-players 5 --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the five-second result stall fixture.'
}
Write-Host 'Player-flow analyzer rejected the deliberate five-second result stall fixture.'

& $Python $playerControlAnalyzer $playerResultRewardFixture `
    --expected-players 2 --require-result-reward-chain `
    --require-result-room-return --strict
if ($LASTEXITCODE -ne 0) {
    throw "MissionResult/reward analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted the complete Exec_Begin/Sync/ResolveResult/ApplyResult and room-return chain.'

$missingRoomReturnOutput = & $Python $playerControlAnalyzer `
    $playerFlowFixture --expected-players 5 `
    --require-result-room-return --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted a legacy completion without a room-return signal.'
}
if (($missingRoomReturnOutput -join "`n") -notmatch `
        'no confirmed clear-result return to room UI') {
    throw 'Missing room-return fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected completion without an explicit room UI return.'

& $Python $playerControlAnalyzer $playerResultRewardFixture `
    --expected-players 2 --require-result-item-matrix --strict
if ($LASTEXITCODE -ne 0) {
    throw "MissionResult Item-matrix analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted the complete sanitized P0-P1 result Item matrix.'

& $Python $playerControlAnalyzer $playerResultRewardStallFixture `
    --expected-players 2 --require-result-reward-chain --strict
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the deliberate Sync_MissionResult/reward stall.'
}
Write-Host 'Player-flow analyzer rejected incomplete result sync and missing reward application.'

$missingResultMatrixOutput = & $Python $playerControlAnalyzer `
    $playerResultRewardStallFixture --expected-players 2 `
    --require-result-item-matrix --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject the incomplete P0-P1 result Item matrix.'
}
if (($missingResultMatrixOutput -join "`n") -notmatch `
        'no complete P0-P1 MissionResult Item matrix') {
    throw 'Incomplete result Item matrix fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a result Item matrix missing P1.'

& $Python $playerControlAnalyzer $playerSpawnResultFixture `
    --expected-players 5 --require-enemy-spawn `
    --require-enemy-spawn-repair `
    --require-native-participant-scaling-clamp `
    --require-result-exec-recovery --strict
if ($LASTEXITCODE -ne 0) {
    throw "Enemy-spawn/result-recovery analyzer fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted native four-profile scaling clamp, guarded P5 enemy spawn and Exec_Begin recovery telemetry.'

$generatorPointerLeakOutput = & $Python $playerControlAnalyzer `
    $playerGeneratorPollPointerLeakFixture --expected-players 5 `
    --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted a GeneratorPoll pointer leak marker.'
}
if (($generatorPointerLeakOutput -join "`n") -notmatch `
        'GeneratorPoll telemetry retained a pointer or spawn payload') {
    throw 'GeneratorPoll pointer-leak fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected GeneratorPoll pointer/payload retention.'

$generatorGateUnknownOutput = & $Python $playerControlAnalyzer `
    $playerGeneratorPollGateUnknownFixture --expected-players 5 `
    --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted an unresolved GeneratorPoll gate outcome.'
}
if (($generatorGateUnknownOutput -join "`n") -notmatch `
        'invalid or unresolved GeneratorPoll native gate telemetry') {
    throw 'GeneratorPoll unknown-gate fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected an unresolved GeneratorPoll gate outcome.'

$missingScalingOutput = & $Python $playerControlAnalyzer `
    $playerSpawnZeroCallsFixture --expected-players 5 `
    --require-native-participant-scaling-clamp --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted a 5-player report without native scaling-clamp evidence.'
}
if (($missingScalingOutput -join "`n") -notmatch `
        'no proven native participant scaling clamp') {
    throw 'Missing native scaling-clamp fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected a 5-player report without native scaling-clamp evidence.'

$unsafeSpawnOutput = & $Python $playerControlAnalyzer `
    $playerSpawnUnsafeFixture --expected-players 5 `
    --require-enemy-spawn-repair --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject an unsafe enemy zero-scale repair.'
}
if (($unsafeSpawnOutput -join "`n") -notmatch `
        'unsafe enemy zero-scale repair') {
    throw 'Unsafe enemy spawn fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected an unsafe enemy zero-scale repair.'

$disabledMultiplierOutput = & $Python $playerControlAnalyzer `
    $playerSpawnMultiplierDisabledFixture --expected-players 5 --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted multiplication while its experiment was disabled.'
}
if (($disabledMultiplierOutput -join "`n") -notmatch `
        'experimental enemy multiplier policy') {
    throw 'Disabled enemy multiplier fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected enemy multiplication without explicit experimental opt-in.'

$zeroSpawnOutput = & $Python $playerControlAnalyzer `
    $playerSpawnZeroCallsFixture --expected-players 5 `
    --require-enemy-spawn --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer accepted an explicit zero-call enemy spawn summary.'
}
$zeroSpawnText = $zeroSpawnOutput -join "`n"
if ($zeroSpawnText -notmatch 'calls=0/0' -or
    $zeroSpawnText -notmatch 'no confirmed enemy spawn telemetry') {
    throw 'Zero-call enemy spawn fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer preserved explicit zero-call spawn evidence and rejected it as a successful spawn.'

$resultOnlyOutput = & $Python $playerControlAnalyzer `
    $playerSpawnResultOnlyFixture --expected-players 5 `
    --require-enemy-spawn --require-enemy-spawn-repair `
    --require-result-exec-recovery --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Result-only analyzer fixture unexpectedly passed without control assignments.'
}
$resultOnlyText = $resultOnlyOutput -join "`n"
if ($resultOnlyText -notmatch 'no control-assignment telemetry' -or
    $resultOnlyText -notmatch 'enemy spawn summary' -or
    $resultOnlyText -notmatch 'MissionResult Exec_Begin recovery' -or
    $resultOnlyText -match 'no confirmed enemy spawn observation' -or
    $resultOnlyText -match 'no accepted result Exec_Begin recovery') {
    throw 'Result-only fixture did not retain spawn/result diagnostics after missing assignments.'
}
Write-Host 'Player-flow analyzer retained spawn/result evidence when assignment telemetry was absent.'

& $Python $playerControlAnalyzer $playerResultNativeCancelFixture `
    --expected-players 5 --require-result-exec-native-cancel --strict
if ($LASTEXITCODE -ne 0) {
    throw "Native Exec_Begin cancellation fixture failed with exit code $LASTEXITCODE."
}
Write-Host 'Player-flow analyzer accepted native Exec_Begin cancellation without fallback duplication.'

$duplicateExecOutput = & $Python $playerControlAnalyzer `
    $playerResultNativeCancelDuplicateFixture --expected-players 5 --strict 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'Player-flow analyzer did not reject duplicated Exec_Begin recovery.'
}
$duplicateExecText = $duplicateExecOutput -join "`n"
if ($duplicateExecText -notmatch 'both cancelled and applied' -or
    $duplicateExecText -notmatch '2 accepted native Exec_Begin calls' -or
    $duplicateExecText -notmatch 'did not fully discard stale Exec_Begin') {
    throw 'Duplicated Exec_Begin fixture failed for an unrelated reason.'
}
Write-Host 'Player-flow analyzer rejected cancellation followed by duplicated Exec_Begin recovery.'

$disabledRoot = Join-Path $OutputRoot 'disabled'
& $fixture disabled $disabledRoot
if ($LASTEXITCODE -ne 0) {
    throw "Disabled-diagnostics fixture failed with exit code $LASTEXITCODE."
}
$disabledLogs = Join-Path $disabledRoot 'Mods\TrafficSniffer\logs'
if (Test-Path -LiteralPath $disabledLogs) {
    throw 'Diagnostics.Enabled=false unexpectedly created a log directory.'
}
Write-Host 'Disabled diagnostics preserved the existing exception filter and created no logs.'

foreach ($mode in @('clean', 'snapshot', 'network', 'deep', 'deep_limit', 'flood', 'rotate', 'fast_fail')) {
    & $fixture $mode (Join-Path $OutputRoot $mode)
    if ($LASTEXITCODE -ne 0) {
        throw "Diagnostic fixture '$mode' failed with exit code $LASTEXITCODE."
    }
}

& $fixture crash (Join-Path $OutputRoot 'crash')
if ($LASTEXITCODE -eq 0) {
    throw 'The intentional crash fixture unexpectedly returned success.'
}
& $fixture crash_off (Join-Path $OutputRoot 'crash_off')
if ($LASTEXITCODE -eq 0) {
    throw 'The no-dump crash fixture unexpectedly returned success.'
}

$retentionRoot = Join-Path $OutputRoot 'retention'
& $fixture crash $retentionRoot
if ($LASTEXITCODE -eq 0) {
    throw 'The retention crash fixture unexpectedly returned success.'
}
for ($index = 0; $index -lt 23; $index++) {
    & $fixture clean $retentionRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Retention clean fixture failed with exit code $LASTEXITCODE."
    }
}
$retentionLogs = Join-Path $retentionRoot 'Mods\TrafficSniffer\logs'
$cleanSessions = 0
$crashedSessions = 0
Get-ChildItem -LiteralPath $retentionLogs -Directory | ForEach-Object {
    $status = Get-Content -LiteralPath (Join-Path $_.FullName 'status.json') `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($status.state -eq 'clean') { $cleanSessions++ }
    if ($status.state -eq 'crashed') { $crashedSessions++ }
}
if ($cleanSessions -ne 20 -or $crashedSessions -ne 1) {
    throw "Retention mismatch: clean=$cleanSessions crashed=$crashedSessions."
}
Write-Host "Retention passed: clean=$cleanSessions crashed_preserved=$crashedSessions."

$reportGameRoot = Join-Path $OutputRoot 'report-game-root'
New-Item -ItemType Directory -Force -Path $reportGameRoot | Out-Null
$sensitiveLoaderLines = @(
    'peer=76561198012345678 endpoint=203.0.113.55:7777',
    'ipv6=[2001:db8::55]:27015',
    'Authorization: Basic dXNlcjpwYXNz',
    'Cookie=session_cookie_fixture',
    'persona=Fixture Log Persona',
    'url=https://api.fixture.invalid/private',
    'path=C:\private\EDF5.exe',
    'unc=\\private-server\Gabriel\secret.txt'
)
[IO.File]::WriteAllLines(
    (Join-Path $reportGameRoot 'ModLoader.log'),
    $sensitiveLoaderLines,
    [Text.UTF8Encoding]::new($false))

$reportPaths = @()
foreach ($mode in @('deep', 'rotate', 'crash')) {
    $logs = Join-Path $OutputRoot "$mode\Mods\TrafficSniffer\logs"
    $session = Get-ChildItem -LiteralPath $logs -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $session) { throw "No session produced for '$mode'." }
    $zip = Join-Path $OutputRoot "reports\$mode-sanitized.zip"
    & $reportTool -Session $session.FullName -Output $zip `
        -GameRoot $reportGameRoot
    $reportPaths += $zip
}

$arguments = @($validator, $OutputRoot)
foreach ($report in $reportPaths) { $arguments += @('--report', $report) }
& $Python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Diagnostic validation failed with exit code $LASTEXITCODE."
}

Write-Host "Offline diagnostic suite passed: $OutputRoot"
