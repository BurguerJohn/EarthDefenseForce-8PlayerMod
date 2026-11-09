EDF5_MultiSlotMod v0.6.80 - TEST PACKAGE (6+ PLAYERS)

Prerequisite:
- EDFModLoader 1.0.10 installed on each computer.
- All computers with this SAME Diagnostics package (not the Users/Nexus
  version: it does not write any log).

Installation:
1. Close the game.
2. Delete old versions of the mod in Mods\Plugins, if any:
   EDF5TrafficSniffer.dll, EDF5_MultiSlotMod.dll and EDF5_MultiSlotMod.ini.
3. Extract this ZIP into the root folder of EARTH DEFENSE FORCE 5 (where
   EDF5.exe is) and confirm merging the Mods folder.
4. Check that Mods\Plugins\EDF5_MultiSlotMod.dll and .ini exist.
5. When creating/joining a room, the chat should show
   `*** EDF5_MultiSlotMod v0.6.80 ***`.
   If the line does not appear, the mod disabled itself for safety: send the
   file Mods\TrafficSniffer\startup-failures.log.
6. Do NOT use v0.6.66: it disabled itself when the game opened.

IMPORTANT - IF THE GAME CLOSES WHEN JOINING A ROOM WITH 5+ PLAYERS:
- Almost always it is Windows blocking the mod (the game runs without the mod
  and closes). Check in Mods\..\ModLoader.log (or in the report) the line
  "Failed to load plugin: error 4551" = blocked by Windows.
- Fix: close the game, right-click the downloaded ZIP, Properties, check
  "Unblock" and OK. Extract and copy again.
  Or in PowerShell, in the game folder:
    Get-ChildItem .\Mods -Recurse | Unblock-File
- If it still blocks, it is the Windows 11 "Smart App Control", in Windows
  Security > App & browser control.

New in 0.6.80:
- The meter now shows each player's TOTAL DAMAGE since the start of the level
  (adding up the two parts of missions that come in two stages), no longer the
  damage per second. When returning to the room, ALL players (not only the
  host) see in their own chat, for example:
    [Damage] Total per player (12:34)
    Name1: 1,234,567 (54%)
    Name2: 845,210 (37%)
    Name3: ? (no data)
- Corrected numbers for anyone who is not the host: each computer measures
  its own player's damage (the only one that sees all of that player's hits)
  and sends the total to the others through the Steam lobby data at the end
  of the level. "? (no data)" appears for anyone without the mod / with an
  old version or if the total does not arrive within 10 seconds.
- The message is local: nothing is sent to the room chat.
- Enabled by default (DamageMeterChat=true). To turn the message off:
  DamageMeterChat=false in EDF5_MultiSlotMod.ini.
- It still does not count damage from vehicles, installed turrets/weapons and
  Air Raider air strikes (the attacker in those cases is not the soldier).
  Send the report (CreateDebugReport) from the host and the clients after a
  level so we can check.
- NEW: during the level, press TAB to show/hide a panel with the numbers for
  YOUR character: total damage, DPS (level average and last 10 s), kills,
  distance traveled, friendly fire on other players (damage and players
  downed, in orange when there is any), living enemies (the same count as the
  red dots on the radar, including those out of range) and level time. The
  panel already appears at the start of the mission
  (StatsOverlayStartVisible=true). It only works with the game window in
  focus (Alt+Tab does not toggle the panel). Configurable in
  EDF5_MultiSlotMod.ini: StatsOverlayEnabled, StatsOverlayHotkeyVK (9 = Tab),
  StatsOverlayX/Y (position in % of the screen; default 2/96 = bottom-left
  corner, where the game has no HUD) and StatsOverlayScale (size in %).
  Kill = your shot brought a hostile enemy's health to zero (parts of
  bosses/ships with their own health count separately). Damage to allied NPC
  soldiers does not count toward anything (neither damage nor friendly fire).
- Alt+F4 no longer opens the Steam invite (F4) when closing the game.
- NEW: ultrawide monitor (wider than 16:9, e.g. 2560x1080 or 3440x1440):
  during the mission, the 3D scenery fills the whole screen without
  stretching (same vertical view, more world visible at the sides), without
  the black bars. The HUD goes to the corners of the screen: armor on the
  left, radar and weapons on the right. The pause screen stays in the center,
  unstretched. Title screen, menus, room and result stay as in the original
  game. Press HOME during the mission to toggle to the original image (16:9
  with bars). 16:9 and 16:10 monitors change nothing. In
  EDF5_MultiSlotMod.ini: Ultrawide=false turns it off,
  UltrawideStartEnabled=false starts on the original image,
  UltrawideHudCorners=false leaves the HUD in the center, UltrawideHotkeyVK
  (36 = Home) changes the key.
- NEW: on the game's title screen, "EDF5_MultiSlotMod v0.6.80" appears in the
  top right corner (with "Diagnostics" in the test package). If it does not
  appear, the mod did not load. To hide it: ModWatermarkEnabled=false in the
  .ini.

New in 0.6.79:
- The DPS in chat was turned off for now: the numbers were wrong for anyone
  who is not the host. The mod keeps measuring in the log (for all players)
  so we can fix it. If you want to see it anyway: DamageMeterChat=true in the
  host's EDF5_MultiSlotMod.ini.
- To help: after a level, run Mods\TrafficSniffer\CreateDebugReport and send
  the ZIP (host and clients).

New in 0.6.78:
- Caliban (and cars with 5+ seats): players 5 to 8 can now ride in the back
  seat (before, they could only drive, and the game wrote outside the seat
  list). Contribution from another user (PR #1 of the mod's repository).
- Enemy HP keeps rising with 5 to 8 players (the game stopped at 4). On
  Inferno: 1.25 / 1.30 / 1.35 / 1.40 for 5/6/7/8 players. Configurable in
  EDF5_MultiSlotMod.ini: ExtendedEnemyHealthScaling=false turns it off;
  EnemyHealth5Players..EnemyHealth8Players accept a multiple of the HP for 4
  players (e.g. 1.5). Also from the same contribution.

New in 0.6.77:
- Fixed a crash in levels with certain script triggers (with 5+ players). Two
  game script commands walked through the player list and read data that only
  exists for 4; now players 5 to 8 use the data the mod stores for them.

New in 0.6.76:
- The DPS meter shows each player's Steam nick and the percentage of the
  team's total damage, for example:
    Name: 77/s (75k, 84%)
- More information in the log to check whether the damage is right (how many
  hits each player had and how many NPC soldiers dealt damage).

New in 0.6.75:
- The "Friends only" room is private again. With 5 or more players the game
  turned the room public and the mod advertised public slots, so strangers
  found the room and tried to join. Now friends/private rooms never become
  public (the extra slots are for friends), and public rooms stay visible
  until the 8 slots fill up.
- DPS meter fixed: 0.6.74 showed "(no damage recorded)" because the mod was
  storing the wrong pointer to each player's soldier.

New in 0.6.74:
- Damage meter (DPS). During the level the mod measures the damage each
  player deals. When returning to the room, the HOST sees in the room chat
  each player's DPS and, when the game allows identifying it, each weapon's.
  In this version only the host sees the message; sending it to everyone is
  left for the next version. To help: the host should type anything in the
  room chat once and send the report (CreateDebugReport) after a complete
  mission.
- It can be turned off in EDF5_MultiSlotMod.ini: DamageMeterEnabled=false
- The meter messages come out in English, for example:
    [DPS] Mission: 312s - damage dealt per player
    Name: 488/s (152k)
      Gatling 289/s, PileBanker 180/s, other 19/s

New in 0.6.73:
- Player list with 5+ people: the mouse wheel now moves one whole line at a
  time, and the list no longer jumps when someone joins, leaves or changes
  something (weapon, class, ready). Navigating with a controller/keyboard
  keeps working normally.
- More complete armor log: it now records which class the game used to split
  the armor, each player's class and the armor limit per class. Anyone who is
  "not gaining armor" should send the report after a complete mission and say
  which class they were using.

New in 0.6.72:
- The mouse wheel scrolls the game's menus inside the room again (e.g. weapon
  selection). Before, the mod used the wheel only for the player list and the
  game received nothing.

New in 0.6.71:
- Armor diagnostics: the log now shows what changed in the local soldier's
  profile when crediting the reward and when returning to the room. If you
  think you did not gain armor: finish the level, return to the room and run
  CreateDebugReport.bat. Also note the class's armor before and after.

New in 0.6.70:
- Rewards with 5+ players: the crates picked up by the 5th-8th player could
  vanish from EVERYONE's total, depending on the order in which the results
  arrived at the end of the level (the game overwrites the slot of player 1-4
  that the mod uses to add up the extra player). Now the sum is independent
  of order and of resends.

New in 0.6.69:
- The log now records the reward numbers at the end of the level (armor/weapon
  crates added up from all players and the total credited). If someone does
  not gain armor, run CreateDebugReport.bat on that PC right after the level.

New in 0.6.68:
- Weapons of players 5-8: the 5th/6th player received the right class,
  weapons and armor, but the rest of the loadout data (upgrades for each
  weapon: ammo, reload, rate of fire) came borrowed from the player 1-4 in
  whose block the character was created. That was the case with the Fencer's
  weaker 2nd weapon. Now the extra character is created with its own complete
  data.

Fixes for 6+ players (since 0.6.66/0.6.67):
1. Mission start message (0x1100): the game reserves 744 bytes and copies the
   content without checking the size. With 5 players it was up to 724 bytes;
   with 6 it goes over 744 and overflowed the HOST's memory when loading the
   level (0xC0000374, the Oct 3 crash). The mod increases the reserve to 2048
   bytes (also in message 0x3300/0x3400, which uses the same pattern).
2. Loadout of players 5-8: the game's parser wrote these players' class,
   weapons and armor outside the mission state object (into the memory of
   other objects). Now those writes go to an area of the mod itself. A good
   side effect: in one of the classes, the 5th weapon of the 5th player fell
   on top of the player counter and was discarded; now all 6 weapons arrive.
3. Mission entry (0x11D860): the spawn point loop did not stop at 4; the 6th
   player overwrote the /GS cookie and would close the game (0xC0000409) on
   all computers. The loop now stops at the 4 native points.
- In the report, with 6+ participants `mission_loadout_parser_redirect_hit`
  and `mission_spawn_transform_loop_clamped` should appear.

Log improvements:
- The crash JSON now carries registers and the stack (`stack_frames`) as
  module+RVA. The stack stays in the sanitized report.
- Mods\TrafficSniffer\EnableCrashDumps.bat turns on Windows' own dump for
  EDF5.exe (asks for administrator). It works even if the mod cannot write
  anything. `EnableCrashDumps.bat -Action Status` lists the latest EDF5
  crashes recorded by Windows (module, code and offset).
  The dumps (.dmp) contain game memory: send them only privately to the
  developer, never in public.

Local test before gathering 6 people (host only):
1. Create a room alone and press F3 several times:
   host+3 -> host+4 -> host+5 -> host+6 -> host+7 -> off.
   host+5 = 6 participants, host+6 = 7, host+7 = 8.
2. With host+5, start a mission and confirm that it loads, that there are
   enemies and that F5 (debug) completes the level and returns to the room.
3. Repeat with host+6 and host+7.

Real test with 6 players:
1. Everyone runs EnableCrashDumps.bat once (optional, recommended).
2. Play until the point of the problem (or until completing 2 missions).
3. If someone crashes, that person runs
   Mods\TrafficSniffer\CreateDebugReport.bat and sends the generated ZIP.
   Note at what moment it happened (room, Ready, loading, gameplay, result,
   return to the room).

------------------------------------------------------------------------------
History of previous versions:

EDF5_MultiSlotMod v0.6.52 - LOCAL/COORDINATED TEST PACKAGE

Prerequisite:
- EDFModLoader 1.0.10 installed on each computer.

Installation:
1. Close the game.
2. Extract this ZIP into the root folder of EARTH DEFENSE FORCE 5.
3. Confirm merging the Mods folder.
4. All computers must use these same files and config.ini.

Expected DLL:
Mods\Plugins\EDF5_MultiSlotMod.dll
SHA-256: 2FDE70233461AFD07861417329E29B8C146AEA61B5B99C51DBE070BB68BF51B6

Note for v0.6.52:
- MorePlayers now requires the complete set of Steam hooks used by
  callbacks and lifecycle. Winsock no longer masks the absence of a Steam
  hook.
- If a mandatory step fails, quarantine restores only exact signatures of
  this mod in EDF5.exe, including roster, panels, result, participant/spawn/
  scale relays and experimental reserves.
- The Release build treats strict warnings of the project's own C++ as errors.
  Smoke, full diagnostics and positive/negative Steam integration must pass.
- The receive base and final pipeline introduced in v0.6.51 remain active:
- Gameplay receive now associates each parser with the UserImpl through the
  real chain `parser -> route -> control -> UserImpl`. The report shows
  missing, duplicate or wrongly assigned routes without storing pointers,
  SteamIDs, endpoints or payloads.
- Register/unregister compares, only as a boolean, the owner that assigned
  UserImpl+0xC8 with the receive manager. This datum decides whether the
  native 8-byte loop and the 16-byte vector belong to the same object; no
  stride was changed before that proof.
- Level closing now also measures ResultSync_Update and
  ResultSync_Finally, exactly preserving the native return and ABI.
- The local notice now uses the classic IRC style, with ASCII characters:
  `*** EDF5_MultiSlotMod v0.6.52 ***`.
- `Reports\no_msg_2.zip` confirmed that the previous attempt with lobby+local
  player was also rejected. The banner now uses the native system message
  function of `Chat_Room`, which receives only room+text and inserts the line
  directly into the local list. It does not depend on a player, SteamID or a
  first real message and does not go through the Steam send routine.
- When creating/joining, confirm the line before writing anything. In the
  report, `chat_mod_banner_publish` should show `success=true` and
  `publish_path=room_update_system_message` and
  `identity_context=not_required` in a single attempt.
- `chat_identity_context` records only boolean comparisons; SteamID, lobby ID,
  nickname and message text are not recorded or fingerprinted.
- The telemetry and fixes base of v0.6.46 remains active:
- The new telemetry observes the native gate between the update and the spawn
  method. `generator_poll_gate_path` separates cooldown, internal quota, false
  return and accepted spawn. The hook is passive: it does not change timer,
  quota, scale, quantity, descriptor or game flow, nor store pointers/payloads.
- The update and method telemetries continue to record the full chain.
  Together, the three layers separate missing update, exact reason for the
  gate, missing manager and rejection at the boundary.
- The report now identifies whether `Exec_Begin` came from the mission
  dispatch, the native `ResultSync_Begin` wrapper or the mod's recovery. The
  executable has exactly two validated direct callers; this change adds
  observability and does not change the normal flow.
- The offline self-test now runs the 56 scaling relays with counts 3, 5 and 8
  and checks registers, flags, mask and preservation of the real count. This
  does not run during normal EDF5 loading and does not change the runtime
  behavior of v0.6.41.
- The artificial multiplier remains experimental and disabled. Do not change
  ExperimentalEnemySpawnMultiplier=false or EnemySpawnMultiplier=1 in this
  coordinated test.

Local Mission Harness test (host only):
1. Create a room and wait for the player list to appear.
2. With no real client, press F3 once. Three `Harness Dummy` should appear;
   they copy the host's loadout and go Ready.
3. Start the level. This is the host+3 baseline within the four native slots.
   v0.6.52 keeps the fix that lets EDF5 initialize MissionStart 0->1 and
   temporarily releases the gate before Update and concludes 4->5 only after
   Ready, l1/l2 and contact of the three dummies are complete. No packet is
   fabricated.
4. Go back to the room, press F3 again and start with host+4. This test
   exercises P4, the fifth participant that matters for development.
5. A third F3 turns off the harness and removes the dummies.
6. The dummies are remote and inert: they have no AI and no real Steam
   connection. This test covers entry/crash, characters, loadout, HUD, spawn
   and local exit; it does not cover P2P, remote movement, chat/nicks between
   computers or desynchronization.
7. If someone else joins, the harness turns itself off and frees all slots.
   F3 is also refused outside the room screen or if F8 fillers are active.

Five-player test:
0. Before gathering the clients, create a room alone and confirm that the
   lobby opens normally and that the chat shows exactly once
   `*** EDF5_MultiSlotMod v0.6.52 ***`. On one client, confirm the same line
   once after joining. The identification is local only: it is not sent
   through the Steam chat and each computer with the mod creates its own line.
   The fix for the RAX return of the PlayerInfo converter from v0.6.20
   remains active.
1. For 10-15 seconds, confirm that everyone sees the host move, shoot and
   perform actions. Then confirm the same for each client.
2. Check the five nicks in the lobby, chat and during the level.
   If possible, each player should send a short message in the chat so that
   the sender/nick association can be audited without storing the text.
3. Have the fifth player choose a different class from the host and check
   class, weapons and armor after loading.
   This test also validates the two fixes of the status panel: P4 keeps
   its logical index 4, reuses the native visual descriptor 0 and the class
   handed to the text table stays between 0 and 3.
   The sanitized event `mission_participant_visual_slot_remapped` should show
   `logical_participant_index=4`, `native_visual_slot=0` and
   `logical_user_index_preserved=true` on every computer that rendered P4.
4. Win the level naturally and check the rewards for everyone and the return
   to the lobby without staying forever in Connecting.
5. Do not use F5 in this first victory test; we need to observe the complete
   natural path. v0.6.52 preserves P4's identity, captures class/loadout in a
   sidecar before restoring the P4-P7 writes that invaded reward/result,
   resolves the extra class through PlayerInfo or the sidecar and includes
   the result Item of P4-P7 in the four
   native accumulators without exceeding the range that ends before rewards.
   The report separates: parser rollback; class; 0x3300/0x3400 replication;
   aggregation of the extra Items; closing of UI 2; Exec_Begin/Sync;
   ResolveResult/ApplyResult. It also
   confirms whether the five UserImpl are unique, whether each client received
   replication from the host and from the other participants and whether the
   real dynamic receive table contains exactly one route for P0-P4. The origin
   of each nick is now cross-referenced as participant -> UserImpl ->
   PlayerInfo -> chat, and the rewards checkpoint confirms whether P4's Item
   was already aggregated before ResolveResult. It also cross-references the
   internal index `UserImpl+0xC8` with the real slot of the dynamic receive
   table, making it possible to locate a missing, duplicate or out-of-position
   route. None of this records names, messages, SteamIDs, endpoints, payloads
   or reward contents.
   The first 0x3300/0x3400 message of each local participant also audits
   the serializer fan-out through 8-byte route descriptors: in a
   five-player room exactly the mask of the four remotes should appear,
   without recording descriptors, route indexes/keys or who the users are.
   The result decoder also records a sanitized P0-P4 mask, without
   weapon/reward values, even if the flow stops before ResolveResult.
   As an additional defense, if the fifth block still zeroes the native counter
   of local profiles, version 0.6.52 restores it from the real local
   collection before ApplyResult. The report records only 0->1/2 and the
   success, never weapons, rewards or profile data.
   This version also preserves the count 5 even when the parser returns
   boolean false and its failure out-parameter remains clean. If the class 1
   record of P4 overlaps a weapon with that count, only that field
   uses the safe value from the native block; the other five weapons keep
   coming from the sidecar.
6. v0.6.52 limits 56 native scaling reads to the existing four-player profile
   without changing the real count 5..8. This fixes timers and
   parameters that previously indexed beyond the tables even before reaching
   the common spawn routine. The event
   `native_participant_scaling_clamp_observed` should have `hits_total>0`,
   `site_mask>0`, capacity 4 and `participant_count_storage_preserved=true`.
   The common spawn routine remains audited. The multiplier is an
   optional experimental base for future development; keep
   `ExperimentalEnemySpawnMultiplier=false` and `EnemySpawnMultiplier=1` in
   this test. The first gate keeps the artificial increase out of MultiSlot
   even if the numeric value is accidentally changed.
   If the common boundary receives zero scale with a positive request in a
   five-player mission, the mod temporarily uses 1:1 scale only when caller,
   source, denominator and count are valid. The report preserves the original
   pair; the participant_count-1 table of GeneratorPoll affects a separate
   timer and is not treated as proof of the origin of this scale.
7. If the result enters Sync_MissionResult 0/0 without Exec_Begin, the mod
   waits 1000 ms for the native path. If the stall persists, it applies a
   single Exec_Begin call with the proven argument -20000 on the host and on
   real clients. If the native path arrives during the wait, it cancels the
   queue and prevents a second call.
8. When the room screen reappears, v0.6.52 records
   `mission_result_transition_completed` with
   `completion_signal=room_ui_update` and `room_ui_returned=true`. This event
   only observes the native room update; it does not force the transition. The
   gate uses the tick armed by MissionResultApply and works even if a client
   still reports the textual phase `mission`. It also
   summarizes the counts of Exec_Begin, sync, ResolveResult, ApplyResult and
   the Items mask without recording rewards or payloads.

After the test:
- On each computer, run Mods\TrafficSniffer\CreateDebugReport.bat.
- Label the ZIP as host or client before gathering them.
- Confirm in the summary.json of each ZIP that plugin_version is 0.6.52.
- In the F3 test, first confirm
  `local_mission_harness_controller_gate_observed` with native_gate_value=0,
  effective_gate_value=1, bypass_applied=true,
  temporary_value_restored=true and native_mission_state_forced=false. Also
  confirm the event
  `local_mission_harness_matching_gate_completed` with state 4->5, all the
  three or four masks complete, zero real peers and
  `gameplay_packet_fabricated=false`.
- When analyzing the ZIPs, use `--require-visual-slot-remap` to require proof
  that P4 went through the new visual route before the level was rendered.
- Confirm that `mission_loadout_parser_extra_blocks_restored` has
  `captured_sidecar_mask=1`, that `mission_loadout_block_synthesized` reports
  `loadout_source=parser_sidecar` when PlayerInfo is absent, and that
  `mission_participant_class_resolved` shows `safe_class_in_range=true`.
- In the same parser event, confirm `participant_count_preserved=5`,
  `participant_count_output_valid=true` and
  `participant_count_source=parser_output`.
  A partial sidecar is expected for P4/class 1:
  `partial_sidecar_weapon_mask=1`; the synthesized event should show
  `weapon_valid_mask=47` and `fallback_weapon_mask=16`.
- Look for `enemy_spawn_summary`: it should have `confirmed_enemy_calls>0`,
  `scale_restore_failures=0`, `actor_pointer_logged=false` and
  `spawn_payload_logged=false`. If there was a valid zero scale,
  `enemy_spawn_scale_repaired` should appear.
  If it shows `calls=0` and `common_spawn_reached=false`, the telemetry worked,
  but no enemy path reached the common routine; this does not count as a
  successful spawn.
- Look first for `generator_poll_update_path`. `original_returned=true` and
  `base_update_and_gate_reached=true` prove that the object was updated and
  the native gate ran. If `spawn_method_reached=false`, the block occurred at
  the gate before the +0x108 method. The `enemy_spawn_summary` aggregates the
  update counters. In case of a crash, the scope
  `generator_poll_update/before_original` proves that the original was started.
- Look for `generator_poll_gate_path`. The field `outcome` identifies
  `cooldown_blocked`, `quota_blocked_inside_time_window`,
  `spawn_returned_false` or `spawn_accepted`. Also require
  `method_call_count_valid=true`, `cooldown_threshold=460` and all the
  `*_pointer_logged`/`spawn_payload_logged` fields false. The summary
  aggregates the four classes; `generator_poll_native_gate_unknown` should
  remain zero.
- Also look for `generator_poll_spawn_path`. If the method was called, it
  shows `manager_present`, `common_spawn_reached` and
  `gate_return_low_byte_nonzero`. The same `enemy_spawn_summary` aggregates
  these counts. If the event does not exist, look in the crash context for the
  scope `generator_poll_spawn/before_original`: it distinguishes a crash
  inside the method from a computer on which GeneratorPoll was not called.
- In the same summary, require `native_participant_scaling_clamp_hits>0`, a
  nonzero mask, capacity 4 and preservation of the real count. The native
  getter still reports `participant_count=5`; it is not replaced by 4.
- If the result needed the new recovery, `mission_result_exec_recovery_queued`,
  an accepted `mission_result_exec_begin` and
  `mission_result_exec_recovery_applied` should appear. A native call during
  the window should produce only `mission_result_exec_recovery_cancelled`.
- In `mission_result_exec_begin`, check `caller_path`: the normal path can
  be `mission_script_dispatch` or `result_sync_begin_wrapper`; when the
  recovery queue is applied, it should be `mod_recovery` with `caller_rva=0`.
- If another level started with an old queue still pending,
  `mission_result_exec_recovery_generation_reset` should appear with
  `stale_pending_discarded=true` and `queue_cleared=true`.
- Require `--require-result-room-return` together with
  `--require-result-reward-chain`; success requires the `room_ui_update`
  signal, not just `leave_lobby`.
- Do not send the raw logs folder; the generator removes payloads, dumps and
  sensitive data from the shareable report.
