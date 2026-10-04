#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace game_patches {

// Expands the three internal lobby-roster pointer tables and their specialized
// grow helpers, constructs one room-information panel state block per expanded
// slot, replaces the room UI's fixed four-key lookup with a host/member mapping,
// and redirects the mission participant scratch data to an eight-int32 relay
// buffer without changing the native stack/unwind layout. Mission entry maps
// players 5-8 across four native spawn points and four external record
// sidecars. The MissionSync_Res participant filter follows MaxPlayers so
// extra users are retained by result/reward aggregation. Non-EDF5 test
// harnesses are skipped.
bool InstallRosterCapacity(unsigned max_players,
                           unsigned preallocated_roster_slots);

// Optionally expands 24 still-unidentified reserve(4) constructor groups to
// the requested preallocation. Every group validates and changes both its
// capacity comparison and reserve argument as one fail-closed transaction.
bool InstallExperimentalReserveCapacity(bool enabled, unsigned capacity);

// Restores every executable byte changed by a successful or partially
// completed startup transaction. Restoration is signature-gated: bytes are
// only written when the image still contains this plugin's exact replacement
// set (or is already fully original).
bool RestoreInstalledPatches();

// Polls counters updated directly by the mission-record and native participant
// scaling relays. Emits sanitized events when an extra-record redirect or a
// clamp to the native four-player scaling profile has occurred.
void PollMissionRelayTelemetry();

// Plugin-owned destination of mission-loadout parser blocks for logical
// indices 4..7 (four contiguous 0x3E90-byte blocks), or nullptr while the
// parser index relays are not installed in this EDF5 process. When non-null,
// the parser never writes those blocks into the 0x24600-byte mission state,
// and its four-block bulk-copy bound is raised, so every block it touches
// for indices 4..7 holds the complete native-format loadout image.
uint8_t* MissionLoadoutParserExtraBlocks();
uint64_t MissionLoadoutParserRedirectHits();
uint64_t MissionLoadoutParserDiscardHits();
// Offline self-test only: report the redirect as installed without patching.
void SetMissionLoadoutParserRedirectForTest(bool enabled);

// Aggregate evidence for the 56 proven mission-state participant-count reads.
// The real stored participant count is not modified by these relays.
uint64_t NativeParticipantScalingClampHits();

// With 5-8 participants, continue each enemy HP table's last per-player step
// (4-player factor + (count - 4) * (4-player - 3-player factor)) instead of
// staying on the 4-player factor (24 enemy initializers). Takes effect for
// enemies created afterwards; may be called before or after
// InstallRosterCapacity. Default: enabled.
void SetExtendedEnemyHealthScaling(bool enabled);
bool ExtendedEnemyHealthScaling();

// Optional fixed enemy HP for 5..8 participants as a multiple of the
// four-player HP (multipliers[0] = 5 players). 0 or a value outside 0.1..20
// keeps the continued per-player step for that count.
void SetEnemyHealthMultipliers(const float* multipliers, size_t count);
// 0 = automatic step, otherwise the multiplier in effect for that count.
float EnemyHealthMultiplier(unsigned participants);
uint64_t NativeParticipantScalingClampMask();

// Replays the exact v0.4.6 append-loop crash fixture in an isolated helper
// process. When patched=false the caller intentionally reaches the native
// access violation; patched=true must complete through the real relay bytes.
bool RunMissionRecordMicroTest(const wchar_t* fixture_path, bool patched,
                               std::string& report);

// Pure byte-signature test used by the standalone harness. It does not inspect
// or modify the host executable.
bool SelfTest(std::string& report);

}  // namespace game_patches
