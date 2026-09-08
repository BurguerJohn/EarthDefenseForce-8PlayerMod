#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "more_players.h"

#include "crash_handler.h"
#include "game_patches.h"
#include "hook_manager.h"
#include "logger.h"
#include "mission_result_recovery.h"
#include "mission_spawn.h"
#include "mod_info.h"
#include "steam_interfaces.h"
#include "win32_handle.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <deque>
#include <limits>
#include <string>
#include <vector>

// This translation unit deliberately owns the hook-private runtime state as a
// single unit. Its safe module boundaries and invariants are documented in
// CODE_STRUCTURE.md; split it only together with explicit state ownership and
// ABI-preservation tests for every moved detour.

namespace more_players {
namespace {

constexpr uint32_t kMemberEntered = 0x0001;
constexpr uint32_t kMemberLeft = 0x0002;
constexpr unsigned kLocalMissionHarnessBaselineDummies = 3;
constexpr unsigned kLocalMissionHarnessProbeDummies = 4;
// MissionStart::Update leaves the locally aggregated state at 4. In a real
// room, an incoming peer snapshot is copied to the global controller and
// supplies state 5; the controller immediately consumes the already-built
// mission data and advances. The host-only harness has no peer that can send
// that snapshot, so its narrowly gated hook completes only this global state.
constexpr uintptr_t kMissionStartUpdateRva = 0x41e420;
constexpr uintptr_t kMissionStartGlobalStateRva = 0x125b300;
constexpr uintptr_t kMissionStartControllerRva = 0x42b7d0;
constexpr uintptr_t kMissionStartControllerCallRva = 0x42b8e9;
constexpr uintptr_t kMissionStartControllerCompletedReadRva = 0x42b8ee;
constexpr uintptr_t kMissionStartControllerContextRva = 0xbbb9f0;
constexpr uintptr_t kMissionStartControllerVtableRva = 0xee1b20;
constexpr uintptr_t kMissionStartControllerGateGetterRva = 0x62e140;
constexpr size_t kMissionStartControllerGateRequestOffset = 0x1a8;
constexpr size_t kMissionStartControllerGateValueOffset = 0x1ac;
constexpr int32_t kMissionStartLocallyAggregatedState = 4;
constexpr int32_t kMissionStartCompletedState = 5;
constexpr uint64_t kMissionStartObservationIntervalMs = 5000;
constexpr const char* kFallbackMemberData =
    "RQBEAEYAIABCAG8AdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// net::UserImpl in the supported EDF5.exe build. The User base constructor
// initializes the transport predicate at object+0xc0 to zero and
// active/present at object+0xc1. A network-side query reads +0xc0 while
// holding the CRITICAL_SECTION at +0x78. The participant-property map is held
// by a shared pointer at +0xe8/+0xf0. The room Ready state machine consumes the
// per-participant string properties cm="c1" and ds="ds" from that map. During
// MissionStart, state 4 also waits for every participant's l1/l2 group list.
// Slot 10 returns the object's SteamID. The dword at +0x100 is voice-chat state
// and must not be changed by the Ready helper.
constexpr uintptr_t kUserConstructorRva = 0x452c50;
constexpr uintptr_t kUserDestructorRva = 0x452f70;
constexpr uintptr_t kUserStateFlagsInitializerRva = 0x4525ca;
constexpr uintptr_t kUserReadyStateReaderRva = 0x4327b2;
constexpr uintptr_t kUserPropertyObjectInitializerRva = 0x4526f4;
constexpr uintptr_t kUserPropertyGetterRva = 0x461ce0;
constexpr uintptr_t kUserPropertySetterRva = 0x462000;
constexpr uintptr_t kSharedPropertyReleaseRva = 0x7dd20;
constexpr uintptr_t kUserIdGetterRva = 0x452e70;
constexpr uintptr_t kUserVtableRva = 0xec2730;
// High-level EDF5 packet routing. Hooking above the Steam interface reveals
// the serializer caller and registered receive callback while retaining only
// RVAs and aggregate sizes (never packet contents or endpoint identities).
constexpr uintptr_t kGameplayP2PSendRva = 0x453890;
constexpr uintptr_t kGameplayP2PSendCallRva = 0x4538ef;
constexpr uintptr_t kGameplayP2PSendTargetRva = 0x41abe0;
constexpr uintptr_t kGameplayP2PDispatchRva = 0x41a770;
constexpr uintptr_t kGameplayP2PDispatchCallRva = 0x41a5db;
constexpr uintptr_t kGameplayP2PDispatchSpecialVtableRva = 0xec2038;
constexpr uintptr_t kGameplayP2PDispatchSpecialTargetRva = 0x4335a0;
// Adds one already-serialized logical message to EDF5's outgoing packet
// builder. Its first dword is a compact type/flags/length header. The hook
// records only decoded header fields and aggregate sizes, never message bytes.
constexpr uintptr_t kGameplayMessageEnqueueRva = 0x434cd0;
// High-level producer for the replicated logical-message families used by
// mission actors. Its SharedProperty at object+0x08 still identifies the
// originating UserImpl before 0x432d20 serializes the message. Keeping only a
// participant index here lets diagnostics prove actor association without
// retaining payload, endpoint identity, SteamID, pointers or display text.
constexpr uintptr_t kGameplayReplicationProducerRva = 0x45ead0;
// The producer forwards its serialized logical message to 0x432d20 together
// with a dynamic vector of eight-byte destination descriptors constructed at
// 0x45ed80 from UserImpl+0xc4/+0xc8. Auditing this exact boundary distinguishes
// a healthy local producer from an incomplete fan-out without retaining route
// keys, peer identities, handles, packets or payloads.
constexpr uintptr_t kGameplayReplicationSerializerRva = 0x432d20;
constexpr uintptr_t kGameplayReplicationSerializerCallRva = 0x45eb9b;
constexpr uintptr_t kGameplayReplicationTargetBuilderRva = 0x45ed80;
constexpr uintptr_t kGameplayReplicationTargetVectorLayoutRva = 0x45edb8;
constexpr uintptr_t kGameplayReplicationTargetAppendRva = 0x45ee26;
constexpr uintptr_t kGameplayReplicationTargetUserRouteCopyRva = 0x45ee3f;
constexpr uintptr_t kGameplayReplicationTargetResolveRva = 0x433f40;
constexpr uintptr_t kGameplayReplicationTargetRouteIndexReadRva = 0x433f6e;
constexpr uintptr_t kUserTransportRouteDescriptorInitializerRva = 0x4525ef;
// Periodic receive pump registered through callback thunk 0x451b90.  It
// walks a dynamic 0x10-byte SharedProperty vector at +0xd0 whose qword count
// lives at +0xe0, then invokes the per-UserImpl parser for every entry.  This
// is the earliest stable boundary where diagnostics can prove whether P0/P4
// were omitted or aliased before decoded actor messages reach MissionScript.
constexpr uintptr_t kGameplayReplicationReceivePumpRva = 0x4336f0;
constexpr uintptr_t kGameplayReplicationReceivePumpLoopRva = 0x4337a3;
constexpr uintptr_t kGameplayReplicationReceiveParserRva = 0x435670;
constexpr uintptr_t kGameplayReplicationReceiveParserCallRva = 0x4339dc;
constexpr size_t kGameplayReplicationOwnerOffset = 0x08;
constexpr size_t kGameplayReplicationFamilyOffset = 0x40;
// The receive vector does not contain UserImpl directly.  Each 0x10-byte
// slot owns a 0xa8-byte route object (constructed at 0x435da0).  That object
// retains the user's SharedProperty control block at +0x58.  The large parser
// passed to 0x435670 in turn retains its route owner at +0x498.  Following
// these two proven ownership links is required to attribute incoming messages
// to the correct participant; subtracting 0x88 from the parser is invalid.
constexpr uintptr_t kGameplayReplicationReceiveRouteObjectConstructorRva =
    0x435da0;
constexpr uintptr_t kGameplayReplicationReceiveRouteUserControlCopyRva =
    0x435e37;
constexpr uintptr_t kGameplayReplicationReceiveParserConstructorRva =
    0x4351f0;
constexpr uintptr_t kGameplayReplicationReceiveParserOwnerStoreRva =
    0x4352f0;
constexpr size_t kSharedPropertyControlObjectOffset = 0x08;
constexpr size_t kGameplayReplicationReceiveRouteUserControlOffset = 0x58;
constexpr size_t kGameplayReplicationReceiveRouteParserOffset = 0x88;
constexpr size_t kGameplayReplicationReceiveParserRouteOwnerOffset = 0x498;
// UserImpl+0xc8 is assigned by the dynamic transport-slot allocator before
// the UserImpl constructor returns.  The receive-route registrar at 0x433bd0
// reads it at 0x433c78 and stores that user's 0xa8-byte parser in the dynamic
// SharedProperty vector at manager+0xd0.  It is independent from the later
// mission/loadout identity at UserImpl+0xf8.  A duplicate +0xc8 would explain
// an asymmetric missing-host route even when the mission participant map is
// otherwise unique, so retain the integer only for consistency diagnostics.
constexpr size_t kUserTransportRouteIndexOffset = 0xc8;
constexpr uintptr_t kUserTransportRouteIndexInitializerRva = 0x4525fb;
constexpr uintptr_t kGameplayReplicationReceiveRouteRegisterRva = 0x433bd0;
constexpr uintptr_t kGameplayReplicationReceiveRouteIndexReadRva = 0x433c78;
constexpr uintptr_t kGameplayReplicationReceiveRouteUnregisterRva = 0x433dd0;
constexpr uintptr_t kGameplayReplicationReceiveRouteRemoveIndexReadRva =
    0x433e3c;
// The session controller owns the only two direct lifecycle callsites.  Their
// return addresses let diagnostics distinguish a genuine native route event
// from an unexpected caller without retaining object or endpoint addresses.
constexpr uintptr_t kGameplayReplicationReceiveRouteRegisterCallRva =
    0x451b64;
constexpr uintptr_t kGameplayReplicationReceiveRouteRegisterReturnRva =
    0x451b69;
constexpr uintptr_t kGameplayReplicationReceiveRouteUnregisterCallRva =
    0x451af6;
constexpr uintptr_t kGameplayReplicationReceiveRouteUnregisterReturnRva =
    0x451afb;
constexpr uintptr_t kUserTransportRouteSlotAllocatorRva = 0x45c8e3;
constexpr uintptr_t kUserTransportRouteUserConstructorCallRva = 0x45c948;
constexpr size_t kGameplayReplicationReceivePumpLockOffset = 0x80;
constexpr size_t kGameplayReplicationReceivePumpVectorOffset = 0xd0;
constexpr size_t kGameplayReplicationReceivePumpCapacityOffset = 0xd8;
constexpr size_t kGameplayReplicationReceivePumpCountOffset = 0xe0;
constexpr size_t kGameplayReplicationReceiveRouteAuditCapacity = 32;
constexpr size_t kTransportRouteAllocatorOwnerCapacity = 16;
constexpr size_t kUserReceiveRouteEligibleOffset = 0xc1;
constexpr uint32_t kGameplayReplicationFamily3300 = 0x3300;
constexpr uint32_t kGameplayReplicationFamily3400 = 0x3400;
constexpr size_t kReplicationParticipantCapacity = 8;
constexpr size_t kReplicationUnknownParticipant =
    kReplicationParticipantCapacity;
constexpr uint64_t kReplicationSummaryIntervalMs = 10000;
constexpr size_t kGameplayP2PDispatchLockOffset = 0x40;
constexpr size_t kGameplayP2PDispatchListOffset = 0x88;
constexpr size_t kGameplayP2PDispatchCallbackOffset = 0x18;
// Chat_Room funnels player-authored and remotely decoded messages through this
// publisher. It is retained only for sanitized room/sender diagnostics.
constexpr uintptr_t kChatMessagePublishRva = 0x3f0b70;
// Chat_Room also has a dedicated local system-message method. Its body builds
// a kind-1 record and inserts it into the room's local list directly. It does
// not call the player-send wrapper at 0x3f16c0 or transport at 0x44d940, and
// it requires only Chat_Room + text, making it the correct banner path.
constexpr uintptr_t kChatSystemMessagePublishRva = 0x3f09d0;
// The room-session setup allocates one 0xc0-byte Chat_Room and calls this
// constructor before storing it in its native shared handle. Capturing the
// constructed instance removes the incorrect dependency on a later native
// chat entry before the mod banner can be displayed.
constexpr uintptr_t kChatRoomConstructorRva = 0x3f0680;
constexpr uintptr_t kChatRoomVtableAssignmentRva = 0x3f06b8;
constexpr uintptr_t kChatRoomVtableRva = 0xebeda8;
constexpr int32_t kChatSystemMessageKind = 1;
// Builds the transient PlayerInfo vector consumed by HUiRoom::Update. Each
// PlayerInfo is 0x60 bytes: its display name is independent from the class,
// equipment and derived equipment-validity fields copied below.
constexpr uintptr_t kPlayerInfoBuilderRva = 0x421ea0;
constexpr uintptr_t kPlayerInfoDefaultsRva = 0x422e00;
// Converts one net::UserImpl shared property into the 0x60-byte PlayerInfo
// consumed by the room UI. This is the reliable object-to-selected-class
// boundary: UserImpl+0xf8 is only a native loadout-block index.
constexpr uintptr_t kPlayerInfoFromUserRva = 0x422f00;
// The converter returns its destination in RAX. Both callers immediately feed
// that return value into the PlayerInfo shared-pointer constructor, so a hook
// must preserve it even though the destination is also passed in RCX.
constexpr uintptr_t kPlayerInfoFromUserReturnRva = 0x42395a;
constexpr uintptr_t kRoomPlayerInfoCopyRva = 0x560b2b;
// Native UI functions in the supported EDF5.exe build. HUiRoom::Update is
// used as the UI-thread rendezvous for wheel events. The roster is not an
// HUiScrollBar: PlayersGroup is a ui::Layout whose automatically-created
// vertical scroll model lives at Layout+0xc0. Its requested normalized
// position is model+4; ui::Layout's native clamp copies it to the render-side
// position at model+0.
constexpr uintptr_t kUiLayoutCastRva = 0x4a9b90;
constexpr uintptr_t kUiLayoutClampRva = 0x4a9080;
constexpr uintptr_t kUiLayoutDestructorRva = 0x4aab40;
constexpr uintptr_t kPlayersGroupCastCallRva = 0x56580a;
constexpr uintptr_t kPlayersGroupCastReturnRva = 0x565817;
constexpr uintptr_t kHUiRoomUpdateRva = 0x5617f0;
// MSVC's native __report_gsfailure routine. The /GS verifier tail-jumps here
// only after a cookie mismatch, and this routine terminates with int 29h and
// FAST_FAIL_STACK_COOKIE_CHECK_FAILURE (2). Hooking this failure-only path
// preserves the verifier caller RVA and a minidump without adding overhead to
// every successful security-cookie check.
constexpr uintptr_t kReportGsFailureRva = 0x9c7670;
// Mission() is the script-facing update callback used throughout an active
// stage. The native result setter is also used by the unmodified game when the
// mission-clear condition is observed: result 1 advances the normal script
// flow, while results 2-4 are exit/restart variants that discard mission data.
constexpr uintptr_t kMissionUpdateRva = 0x3e1890;
constexpr uintptr_t kMissionResultSetterRva = 0x111080;
constexpr uintptr_t kMissionResultSetterPublishRva = 0x111098;
constexpr uintptr_t kMissionResultApplyRva = 0x114bb0;
constexpr uintptr_t kMissionResultEventPublishRva = 0x61e950;
constexpr uintptr_t kMissionResultEventPublisherSlotRva = 0x125ab70;
// xgs::ui::Object's generic typed-event callback. Event 1 carries a UI object
// id; payload 2 targets the object whose id field at +0x78 is 2, marks its
// closing flag at +0x18, and invokes its close transition. This is independent
// from net::MissionResult::Exec_Begin/Sync_MissionResult below.
constexpr uintptr_t kMissionResultUiEventDispatchRva = 0x4a1b70;
constexpr int32_t kMissionResultEventType = 1;
constexpr int32_t kMissionResultEventPayload = 2;
constexpr size_t kUiObjectEventFlagsOffset = 0x18;
constexpr size_t kUiObjectEventIdOffset = 0x78;
constexpr uint32_t kUiObjectClosingFlag = 0x1;
// Native result/reward pipeline. net::MissionResult::Exec_Begin owns the
// network result exchange. Its dword argument is opaque mission/script data,
// not the clear result enum (one proven direct caller supplies -20000). Two
// script/native callers use the same named-sync
// helpers for "Sync_MissionResult"; hook the helpers at their real function
// entries and classify only those four exact return addresses. ResolveResult
// and ApplyResult are the registered script wrappers that commit rewards to
// local save profiles after synchronization.
constexpr uintptr_t kMissionResultExecBeginRva = 0x42fd20;
constexpr uintptr_t kMissionResultExecBeginNativeCallerRva = 0x1153e9;
constexpr uintptr_t kMissionResultExecBeginNativeCallerReturnRva = 0x1153f3;
// Script registration names the wrapper at 0x42AC40
// `int ResultSync_Begin(int)`. It forwards ECX unchanged to Exec_Begin and
// returns the original argument, so its callsite is a second legitimate
// native entry into the same result exchange.
constexpr uintptr_t kMissionResultExecBeginScriptWrapperRva = 0x42ac40;
constexpr uintptr_t kMissionResultExecBeginScriptWrapperCallRva = 0x42ac48;
constexpr uintptr_t kMissionResultExecBeginScriptWrapperReturnRva = 0x42ac4d;
// Script registration maps ResultSync_Update to 0x42ac60. It and the native
// mission consumer at 0x12aa30 are the only proven callers of 0x430c20.  The
// boolean is deliberately kept opaque: each caller performs a different
// action on true, while the native mission caller invokes Finally on false.
constexpr uintptr_t kMissionResultExecUpdateRva = 0x430c20;
constexpr uintptr_t kMissionResultExecUpdateScriptWrapperRva = 0x42ac60;
constexpr uintptr_t kMissionResultExecUpdateScriptCallRva = 0x42ac9f;
constexpr uintptr_t kMissionResultExecUpdateScriptReturnRva = 0x42aca4;
constexpr uintptr_t kMissionResultExecUpdateNativeCallerRva = 0x12aa30;
constexpr uintptr_t kMissionResultExecUpdateNativeCallRva = 0x12aa8d;
constexpr uintptr_t kMissionResultExecUpdateNativeReturnRva = 0x12aa92;
// ResultSync_Finally is registered through the 0x42ac20 wrapper and is also
// reached by the native mission consumer when Update returns false.
constexpr uintptr_t kMissionResultExecFinallyRva = 0x42f090;
constexpr uintptr_t kMissionResultExecFinallyScriptWrapperRva = 0x42ac20;
constexpr uintptr_t kMissionResultExecFinallyScriptCallRva = 0x42ac28;
constexpr uintptr_t kMissionResultExecFinallyScriptReturnRva = 0x42ac2d;
constexpr uintptr_t kMissionResultExecFinallyNativeCallRva = 0x12aaa9;
constexpr uintptr_t kMissionResultExecFinallyNativeReturnRva = 0x12aaae;
// Common instantiation boundary reached only by the 24 enemy callsites
// classified in mission_spawn.h. The routine applies a native 400-actor cap,
// then scales the request through owner+0x290 / owner+0x294. The common
// configurator defaults those fields to 0/1 and replaces them from mission
// configuration. GeneratorPoll's separate participant_count-1 table writes a
// timer, not these scale fields. Treat a P5 zero scale as an experimental
// runtime recovery candidate and preserve its original value for telemetry.
constexpr uintptr_t kEnemySpawnRva = 0x1c1650;
constexpr size_t kEnemySpawnScaleNumeratorOffset = 0x290;
constexpr size_t kEnemySpawnScaleDenominatorOffset = 0x294;
constexpr size_t kEnemySpawnSourceOffset = 0x2b0;
// GeneratorPoll's virtual update at +0xA0 calls the shared GameObject update
// at 0x2DA720 unconditionally. That base update tail-calls the native gate at
// 0x2DC7C0, which invokes virtual slot +0x108. The concrete vtable maps that
// spawn slot to 0x1F90A0, which reaches the common spawn boundary at 0x1F9120
// only when self+0x788 is present. Both hooks below are telemetry-only: the
// update wrapper forwards its two registers unchanged and the spawn wrapper
// preserves the complete RAX value consumed through AL. Neither changes the
// object, timer, descriptor or spawn count.
constexpr uintptr_t kGeneratorPollUpdateRva = 0x1f8b40;
constexpr uintptr_t kGeneratorPollSpawnRva = 0x1f90a0;
constexpr uintptr_t kGeneratorPollVtableRva = 0xea0e38;
constexpr uintptr_t kGeneratorPollVtableUpdateEntryRva = 0xea0ed8;
constexpr uintptr_t kGeneratorPollVtableSpawnEntryRva = 0xea0f40;
constexpr uintptr_t kGeneratorPollBaseUpdateRva = 0x2da720;
constexpr uintptr_t kGeneratorPollBaseUpdateCallRva = 0x1f8b5b;
constexpr uintptr_t kGeneratorPollBaseGateTailRva = 0x2da9dd;
constexpr uintptr_t kGeneratorPollBaseGateTailCallRva = 0x2da9f4;
constexpr uintptr_t kGeneratorPollGateRva = 0x2dc7c0;
constexpr uintptr_t kGeneratorPollGateVirtualCallRva = 0x2dc821;
constexpr uintptr_t kGeneratorPollManagerGateRva = 0x1f90e8;
constexpr uintptr_t kGeneratorPollCommonSpawnCallRva = 0x1f9120;
constexpr uintptr_t kGeneratorPollReturnRva = 0x1f9480;
constexpr size_t kGeneratorPollManagerOffset = 0x788;
constexpr size_t kGeneratorPollVirtualUpdateOffset = 0xa0;
constexpr size_t kGeneratorPollVirtualSpawnOffset = 0x108;
constexpr size_t kGeneratorPollGateStateOffset = 0x400;
constexpr size_t kGeneratorPollGateRemainingOffset = 0x0;
constexpr size_t kGeneratorPollGateCooldownOffset = 0x4;
constexpr size_t kGeneratorPollGateLastTimeOffset = 0x8;
constexpr size_t kGeneratorPollPeriodScaleOffset = 0x1f8;
constexpr size_t kGeneratorPollCurrentTimeOffset = 0x1fc;
constexpr int32_t kGeneratorPollGateCooldownThreshold = 0x1cc;
// NetGameStatus decodes a dynamic Item count. Its fixed initialization loop
// at 0x430ef6 must remain four because the destination at mission state
// +0x2457c contains exactly four native eight-byte accumulators. The separate
// application filter at 0x430f23 is patched by game_patches to MaxPlayers;
// the common Item sink below folds P4-P7 into those native accumulators.
constexpr uintptr_t kMissionResultItemInitializeLimitRva = 0x430ef6;
constexpr uintptr_t kMissionResultItemApplyFilterRva = 0x430f23;
constexpr uintptr_t kMissionResultItemSinkRva = 0x132bb0;
constexpr size_t kMissionResultItemArrayOffset = 0x2457c;
constexpr unsigned kMissionResultNativeItemCount = 4;
constexpr size_t kMissionResultItemSize = 8;
constexpr uintptr_t kMissionNamedSyncBeginRva = 0x41f820;
constexpr uintptr_t kMissionNamedSyncPollRva = 0x41f920;
constexpr uintptr_t kMissionResultScriptSyncBeginCallRva = 0x3e2dd8;
constexpr uintptr_t kMissionResultScriptSyncBeginReturnRva = 0x3e2ddd;
constexpr uintptr_t kMissionResultScriptSyncPollCallRva = 0x3e2de4;
constexpr uintptr_t kMissionResultScriptSyncPollReturnRva = 0x3e2de9;
constexpr uintptr_t kMissionResultNetSyncBeginCallRva = 0x42c134;
constexpr uintptr_t kMissionResultNetSyncBeginReturnRva = 0x42c139;
constexpr uintptr_t kMissionResultNetSyncPollCallRva = 0x42c13b;
constexpr uintptr_t kMissionResultNetSyncPollReturnRva = 0x42c140;
constexpr uintptr_t kMissionRewardResolveRva = 0x3e3150;
constexpr uintptr_t kMissionRewardApplyRva = 0x3e3160;
constexpr uintptr_t kMissionRewardApplyCountReadRva = 0x3e3190;
constexpr uintptr_t kMissionRewardApplyProfileBaseRva = 0x3e31a4;
constexpr uintptr_t kMissionRewardApplyProfileStrideRva = 0x3e32ae;
constexpr uintptr_t kMissionRewardLocalProfileSetterRva = 0x55830;
constexpr uintptr_t kMissionScriptMessageDispatchRva = 0x114d50;
constexpr uintptr_t kMissionScriptClearApplyReturnRva = 0x114fef;
constexpr uintptr_t kMissionNaturalClearResultRva = 0x3d814b;
constexpr uintptr_t kMissionNaturalClearCallRva = 0x3d8153;
constexpr uintptr_t kMissionManagerLoadRva = 0x3e197d;
constexpr uintptr_t kMissionUiStateReadRva = 0x3e1a10;
constexpr uintptr_t kMissionUiResultReadRva = 0x3e1a40;
constexpr uintptr_t kMissionResultPreserveRva = 0x114c51;
constexpr uintptr_t kMissionManagerSlotRva = 0x125ab40;
// Mission entry asks the generic 16-byte shared-handle table getter for one
// net::UserImpl per participant. The session pipeline first copies the full
// session user collection and then the subset of locally controlled users into
// local vectors. Audit their ordinal relationship: if a real fifth source
// reaches the player builder, use it; otherwise preserve the proven
// modulo-four crash fallback.
constexpr uintptr_t kMissionSourceLookupRva = 0x7e240;
constexpr uintptr_t kMissionSourceLookupCallRva = 0x11cf08;
constexpr uintptr_t kMissionSourceLookupReturnRva = 0x11cf0d;
constexpr uintptr_t kMissionSourceTransferCallRva = 0x11dfce;
constexpr uintptr_t kMissionSourceTransferReturnRva = 0x11dfd3;
constexpr uintptr_t kMissionSourceAppendCallRva = 0x11e057;
constexpr uintptr_t kMissionSourceAppendReturnRva = 0x11e05c;
constexpr uintptr_t kMissionSourceConsumerRva = 0x3123a0;
// Both reads occur after the character consumer returns. UserImpl+0xf8 must
// already contain the unique logical participant index here, otherwise P4
// collides with host P0 in the native mission participant map.
constexpr uintptr_t kMissionPostConsumerIdentityReadRva = 0x11d0dd;
constexpr uintptr_t kMissionAppendIdentityReadRva = 0x11e05d;
constexpr uintptr_t kMissionSharedHandleCopyRva = 0x6e010;
constexpr uintptr_t kMissionSourceCollectionCopyRva = 0x12b200;
constexpr uintptr_t kMissionSourcePrimaryCopyCallRva = 0x11d6aa;
constexpr uintptr_t kMissionSourcePrimaryCopyReturnRva = 0x11d6af;
constexpr uintptr_t kMissionSourceReferenceCopyCallRva = 0x11d6cf;
constexpr uintptr_t kMissionSourceReferenceCopyReturnRva = 0x11d6d4;
// Both mission-entry paths pass one participant index and the corresponding
// local-controller index to this character builder. A negative controller
// index creates a remote character; a non-negative value is forwarded to the
// native local-control binder at 0x2dbbc0. Auditing this boundary tells us
// directly which character each process believes it controls.
constexpr uintptr_t kMissionPlayerCreateRva = 0x11ce60;
constexpr uintptr_t kMissionPlayerCreatePrimaryCallRva = 0x11dc34;
constexpr uintptr_t kMissionPlayerCreatePrimaryReturnRva = 0x11dc39;
constexpr uintptr_t kMissionPlayerCreateSecondaryCallRva = 0x11ece9;
constexpr uintptr_t kMissionPlayerCreateSecondaryReturnRva = 0x11ecee;
constexpr unsigned kNativeMissionSourceCount = 4;
// The session builder sorts UserImpl handles descending by the SteamID at
// +0x184 before participant indices are assigned. Never log that identifier;
// only audit whether the final vector obeys the native ordering.
constexpr size_t kUserMissionSortKeyOffset = 0x184;
// 0x3123a0 uses this dword as an index into four native loadout blocks before
// allocating a character. It is not the selected class. Extra participants
// keep unique values (4+) for identity/replication, so a native 0..3 fallback
// may only be installed temporarily while the character factory executes.
constexpr size_t kUserMissionLoadoutIndexOffset = 0xf8;
constexpr uintptr_t kMissionLoadoutStateSlotRva = 0x125ab30;
// MissionResult's participant/loadout parser still lays out only four native
// 0x3e90-byte blocks.  For logical participant indices 4..7 it writes past
// the end of those blocks into unrelated mission state, including the local
// reward-profile count at +0x2459c.  Keep the logical index intact for the
// serialized record, but roll back those out-of-bounds block writes when the
// parser returns.
constexpr uintptr_t kMissionLoadoutParserRva = 0x42f480;
constexpr uintptr_t kMissionParticipantClassResolverRva = 0x4b6710;
// The resolver derives its first output from the logical UserImpl+0xf8 index.
// All three direct callers use that output only as a transient visual index:
// 0x4b855e addresses 0x30-byte UI descriptors, 0x4bb5e1 addresses a native
// four-entry table of 0x40-byte status descriptors, and 0x4cf21f addresses a
// fixed four-entry stack array with 0x10-byte stride. P4 would therefore reach
// an unconstructed fifth descriptor and later fault while retaining its shared
// render property at 0xb1d60. Keep UserImpl+0xf8 unique, but fold only the
// resolver's transient output onto the four native visual assets.
constexpr uintptr_t kMissionParticipantVisualTableIndexRva = 0x4bb5e1;
constexpr uintptr_t kMissionParticipantVisualSubmitCallRva = 0x4bbc37;
// The status HUD independently indexes a second four-entry table: the
// localized class-name resources.  The August 28 crash reports reached this
// path with class 256/257 after the logical fifth loadout block had already
// been rolled back.  Keep these RVAs explicit so build validation covers the
// complete fault chain, not only the visual descriptor table above.
constexpr uintptr_t kMissionParticipantNativeClassReadRva = 0x4b6886;
constexpr uintptr_t kMissionParticipantClassTextTableIndexRva = 0x4bb5ce;
constexpr uintptr_t kMissionParticipantClassTextSelectRva = 0x4bc266;
constexpr uintptr_t kMissionTextMeasureInvalidReadRva = 0x5e741c;
constexpr uintptr_t kSharedRenderPropertyCopyRva = 0xb1cf0;
constexpr uintptr_t kSharedRenderPropertyRefReadRva = 0xb1d60;
constexpr uintptr_t kMissionLoadoutConsumerBlockRva = 0x31240c;
constexpr uintptr_t kMissionLoadoutConsumerRecordRva = 0x31242e;
constexpr uintptr_t kMissionLoadoutParserStrideRva = 0x42f7c9;
constexpr uintptr_t kMissionLoadoutParserRecordRva = 0x42f881;
// The parser stores its participant count unconditionally immediately before
// returning.  Its boolean return is therefore not the success contract for
// this output (real five-player captures return false with count 5).
constexpr uintptr_t kMissionLoadoutParserParticipantCountWriteRva = 0x42fa69;
constexpr size_t kMissionClassLoadoutStride = 0x3e90;
constexpr size_t kMissionSelectedLoadoutOffset = 0x14b30;
constexpr size_t kMissionLoadoutRecordOffset = 0x14b38;
constexpr size_t kMissionLoadoutRecordStride = 0x18;
constexpr int32_t kMissionLoadoutSlotLimit = 16;
constexpr int32_t kMissionCharacterClassLimit = 4;
constexpr size_t kMissionLoadoutArmorOffset = 0xf8;
constexpr size_t kMissionLoadoutWeaponCount = 6;
constexpr uint32_t kMissionLoadoutWeaponMask =
    (uint32_t{1} << kMissionLoadoutWeaponCount) - 1;
constexpr unsigned kMaximumMissionParticipants = 8;
constexpr size_t kMissionExtraLoadoutBlockCount =
    kMaximumMissionParticipants - kNativeMissionSourceCount;
constexpr size_t kMissionExtraLoadoutSpan =
    kMissionExtraLoadoutBlockCount * kMissionClassLoadoutStride;
// UserImpl virtual slot +0x60 reads this field when the session maps its
// local-control collection. Runtime evidence shows every PC normally reports
// zero here, so it is a local controller index, not a global room position.
constexpr size_t kUserLocalControllerIndexOffset = 0x190;
constexpr size_t kMissionSourceAuditCapacity = 32;
constexpr uintptr_t kUiLayoutVtableRva = 0xec8628;
constexpr size_t kUserStateLockOffset = 0x78;
constexpr size_t kUserReadyFlagOffset = 0xc0;
constexpr size_t kUserPropertyObjectOffset = 0xf0;
constexpr size_t kUiLayoutVerticalScrollOffset = 0xc0;
constexpr size_t kUiScrollRequestedPositionOffset = 0x04;
constexpr size_t kUiScrollEnabledOffset = 0x0c;
constexpr size_t kMissionManagerUiOffset = 0x28;
constexpr size_t kMissionManagerResultOffset = 0x34;
constexpr size_t kMissionUiStateOffset = 0xf8;
constexpr size_t kMissionUiResultOffset = 0xfc;
constexpr size_t kMissionRewardLocalProfileCountOffset = 0x2459c;
constexpr size_t kMissionResultParticipantCountOffset = 0x245a0;
constexpr int32_t kMissionRewardLocalProfileCapacity = 2;
constexpr int32_t kMissionUiStateRunning = 1;
constexpr int32_t kMissionUiStateFinishing = 2;
constexpr int32_t kMissionUiStateFinished = 3;
constexpr int32_t kMissionResultClear = 1;
constexpr int32_t kMissionResultSelfTestArgument =
    mission_result_recovery::kExecBeginArgument;
constexpr uint64_t kMissionUpdateFreshMs = 750;
constexpr uint64_t kMissionWarmupMs = 750;
constexpr uint64_t kMissionGenerationGapMs = 2500;
constexpr uint64_t kMissionRequestLifetimeMs = 2000;
constexpr uint64_t kMissionResultRecoveryGraceMs = 250;
constexpr std::array<uint64_t, 4> kMissionResultAuditAgesMs = {
    1000, 5000, 15000, 30000,
};
constexpr float kRosterWheelStep = 0.25f;
constexpr size_t kPlayerInfoClassOffset = 0x28;
constexpr size_t kPlayerInfoSecondaryLoadoutOffset = 0x2c;
constexpr size_t kPlayerInfoWeaponsOffset = 0x30;
constexpr size_t kPlayerInfoWeaponValidityOffset = 0x48;
constexpr size_t kPlayerInfoArmorOffset = 0x54;
constexpr size_t kPlayerInfoNameStorageOffset = 0x08;
constexpr size_t kPlayerInfoNameLengthOffset = 0x18;
constexpr size_t kPlayerInfoNameCapacityOffset = 0x20;
constexpr size_t kPlayerInfoNameInlineCapacity = 7;
constexpr size_t kPlayerInfoNameAuditMaximumLength = 64;
constexpr size_t kPlayerInfoSize = 0x60;
constexpr size_t kPlayerInfoObservationCapacity = 32;
constexpr size_t kMissionExtraLoadoutBeginOffset =
    kMissionSelectedLoadoutOffset +
    kNativeMissionSourceCount * kMissionClassLoadoutStride;
static_assert(kMissionExtraLoadoutBeginOffset == 0x24570,
              "fifth native loadout block boundary changed");
static_assert(kMissionResultItemArrayOffset +
                      kMissionResultNativeItemCount *
                          kMissionResultItemSize ==
                  kMissionRewardLocalProfileCountOffset,
              "four native NetGameStatus Items must end before rewards");
static_assert(kMissionRewardLocalProfileCountOffset >=
                  kMissionExtraLoadoutBeginOffset &&
              kMissionResultParticipantCountOffset + sizeof(int32_t) <=
                  kMissionExtraLoadoutBeginOffset +
                      kMissionExtraLoadoutSpan,
              "reward fields must overlap the protected extra block span");
constexpr uint8_t kUserConstructorSignature[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x30,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48,
    0x89, 0x5c, 0x24, 0x48, 0x49, 0x8b, 0xf8, 0x48, 0x8b, 0xd9,
    0xe8, 0x6d, 0xf8, 0xff, 0xff,
};
constexpr uint8_t kUserDestructorSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20,
    0x8b, 0xda, 0x48, 0x8b, 0xf9, 0xe8, 0x2c, 0x00, 0x00, 0x00,
};
constexpr uint8_t kUserStateFlagsInitializerSignature[] = {
    0xc6, 0x87, 0xc0, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x46, 0x18,
    0x88, 0x87, 0xc1, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x46, 0x19,
    0x88, 0x87, 0xc2, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x46, 0x1a,
    0x88, 0x87, 0xc3, 0x00, 0x00, 0x00,
};
constexpr uint8_t kUserReadyStateReaderSignature[] = {
    0x80, 0xbf, 0xc1, 0x00, 0x00, 0x00, 0x00,
    0x74, 0x24,
    0x48, 0x8d, 0x5f, 0x78,
    0x48, 0x8b, 0xcb,
    0xff, 0x15, 0xf0, 0x4b, 0x86, 0x00,
    0x0f, 0xb6, 0xbf, 0xc0, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xdb,
    0x74, 0x0e,
    0x48, 0x8b, 0xcb,
    0xff, 0x15, 0xd3, 0x4b, 0x86, 0x00,
};
constexpr uint8_t kUserPropertyObjectInitializerSignature[] = {
    0x48, 0x8b, 0x44, 0x24, 0x28,
    0x48, 0x89, 0x87, 0xe8, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x40, 0x08,
    0x48, 0x89, 0x87, 0xf0, 0x00, 0x00, 0x00,
};
constexpr uint8_t kUserPropertyGetterSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x48, 0x89, 0x6c, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18,
    0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x30,
};
constexpr uint8_t kUserPropertySetterSignature[] = {
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x57, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x40,
    0x48, 0xc7, 0x44, 0x24, 0x28, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x5c, 0x24, 0x60,
};
constexpr uint8_t kGameplayP2PSendSignature[] = {
    0x40, 0x57, 0x48, 0x83, 0xec, 0x40,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x5c, 0x24, 0x50,
    0x48, 0x89, 0x6c, 0x24, 0x58,
    0x48, 0x89, 0x74, 0x24, 0x60,
    0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8,
};
constexpr uint8_t kGameplayP2PSendCallSignature[] = {
    0xe8, 0xec, 0x72, 0xfc, 0xff,
};
constexpr uint8_t kGameplayP2PDispatchSignature[] = {
    0x4c, 0x8b, 0xdc, 0x4d, 0x89, 0x43, 0x18,
    0x56, 0x57, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x40,
    0x49, 0xc7, 0x43, 0xc8, 0xfe, 0xff, 0xff, 0xff,
    0x49, 0x89, 0x5b, 0x08, 0x49, 0x89, 0x6b, 0x10,
};
constexpr uint8_t kGameplayP2PDispatchCallSignature[] = {
    0xe8, 0x90, 0x01, 0x00, 0x00,
};
constexpr uint8_t kGameplayMessageEnqueueSignature[] = {
    0x48, 0x8b, 0xc4, 0x4c, 0x89, 0x48, 0x20,
    0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x30,
    0x48, 0xc7, 0x40, 0xb8, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kGameplayReplicationProducerSignature[] = {
    0x48, 0x8b, 0xc4,
    0x41, 0x56,
    0x48, 0x83, 0xec, 0x70,
    0x48, 0xc7, 0x40, 0xb8, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x58, 0x08,
    0x48, 0x89, 0x68, 0x10,
    0x48, 0x89, 0x70, 0x18,
    0x48, 0x89, 0x78, 0x20,
};
constexpr uint8_t kGameplayReplicationSerializerSignature[] = {
    0x48, 0x8b, 0xc4,
    0x55,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x68, 0xb1,
    0x48, 0x81, 0xec, 0x90, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationSerializerCallSignature[] = {
    0x48, 0x89, 0x74, 0x24, 0x28,
    0x48, 0x89, 0x6c, 0x24, 0x20,
    0x4c, 0x8d, 0x44, 0x24, 0x48,
    0x48, 0x8b, 0x4b, 0x38,
    0xe8, 0x80, 0x41, 0xfd, 0xff,
};
constexpr uint8_t kGameplayReplicationTargetBuilderSignature[] = {
    0x40, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x83, 0xec, 0x40,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kGameplayReplicationTargetVectorLayoutSignature[] = {
    0x4c, 0x89, 0x77, 0x18,
    0x48, 0x8b, 0x56, 0x28,
    0x48, 0x39, 0x57, 0x10,
};
constexpr uint8_t kGameplayReplicationTargetAppendSignature[] = {
    0x48, 0x8b, 0x4f, 0x18,
    0x48, 0x8b, 0x47, 0x08,
    0x48, 0x8d, 0x14, 0xc8,
    0x48, 0x8d, 0x41, 0x01,
    0x48, 0x89, 0x47, 0x18,
};
constexpr uint8_t kGameplayReplicationTargetUserRouteCopySignature[] = {
    0x48, 0x8b, 0x83, 0xc4, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x02,
};
constexpr uint8_t kGameplayReplicationTargetResolveSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x48, 0x89, 0x74, 0x24, 0x10,
    0x48, 0x89, 0x7c, 0x24, 0x18,
    0x41, 0x56,
    0x48, 0x83, 0xec, 0x20,
};
constexpr uint8_t kGameplayReplicationTargetRouteIndexReadSignature[] = {
    0x48, 0x63, 0x57, 0x04,
    0x33, 0xc0,
    0x48, 0xc1, 0xe2, 0x04,
    0x48, 0x03, 0x96, 0xd0, 0x00, 0x00, 0x00,
};
constexpr uint8_t kUserTransportRouteDescriptorInitializerSignature[] = {
    0x8b, 0x4e, 0x14,
    0x8b, 0x46, 0x10,
    0x89, 0x87, 0xc4, 0x00, 0x00, 0x00,
    0x89, 0x8f, 0xc8, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceivePumpSignature[] = {
    0x4c, 0x89, 0x44, 0x24, 0x18,
    0x89, 0x54, 0x24, 0x10,
    0x55, 0x53, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xe1,
    0x48, 0x81, 0xec, 0x98, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0x07, 0xfe, 0xff, 0xff, 0xff,
    0x4c, 0x8b, 0xe1,
};
constexpr uint8_t kGameplayReplicationReceivePumpLoopSignature[] = {
    0x33, 0xf6,
    0x8b, 0xc6,
    0x89, 0x45, 0x67,
    0x4d, 0x8b, 0xbc, 0x24, 0xe0, 0x00, 0x00, 0x00,
    0x4c, 0x89, 0x7d, 0xff,
    0x44, 0x8b, 0xee,
    0x4d, 0x85, 0xff,
    0x0f, 0x84, 0xb9, 0x03, 0x00, 0x00,
    0x49, 0x8d, 0xbc, 0x24, 0x80, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceiveParserSignature[] = {
    0x40, 0x55,
    0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xd9,
    0x48, 0x81, 0xec, 0xf0, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0xe7, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kGameplayReplicationReceiveParserCallSignature[] = {
    0x48, 0x8b, 0x88, 0x88, 0x00, 0x00, 0x00,
    0xe8, 0x8f, 0x1c, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceiveRouteObjectConstructorSignature[] = {
    0x48, 0x8b, 0xc4,
    0x48, 0x89, 0x48, 0x08,
    0x55, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xec, 0x30,
};
constexpr uint8_t kGameplayReplicationReceiveRouteUserControlCopySignature[] = {
    0x48, 0x8b, 0x46, 0x18,
    0x48, 0x89, 0x47, 0x58,
    0x48, 0x8b, 0x46, 0x20,
    0x48, 0x8b, 0x80, 0xc4, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x47, 0x60,
    0x48, 0x8b, 0x46, 0x10,
    0x48, 0x89, 0x47, 0x68,
};
constexpr uint8_t kGameplayReplicationReceiveParserConstructorSignature[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08,
    0x56, 0x57, 0x41, 0x56,
    0x48, 0x83, 0xec, 0x30,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kGameplayReplicationReceiveParserOwnerStoreSignature[] = {
    0x48, 0x89, 0xaf, 0x98, 0x04, 0x00, 0x00,
    0x48, 0x8b, 0x06,
    0x48, 0x89, 0x87, 0xa0, 0x04, 0x00, 0x00,
    0x48, 0xc7, 0x87, 0xa8, 0x04, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff,
};
constexpr uint8_t kUserTransportRouteIndexInitializerSignature[] = {
    0x89, 0x8f, 0xc8, 0x00, 0x00, 0x00,
    0x83, 0xcd, 0xff,
    0x89, 0xaf, 0xcc, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceiveRouteRegisterSignature[] = {
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x53, 0x55, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceiveRouteIndexReadSignature[] = {
    0x4d, 0x63, 0xb0, 0xc8, 0x00, 0x00, 0x00,
    0x49, 0x81, 0xc0, 0xc4, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGameplayReplicationReceiveRouteUnregisterSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x18,
    0x48, 0x89, 0x6c, 0x24, 0x20,
    0x57,
    0x48, 0x83, 0xec, 0x40,
};
constexpr uint8_t kGameplayReplicationReceiveRouteRemoveIndexReadSignature[] = {
    0x4c, 0x63, 0xb0, 0xc8, 0x00, 0x00, 0x00,
    0x4d, 0x03, 0xf6,
};
constexpr uint8_t kGameplayReplicationReceiveRouteRegisterCallSignature[] = {
    0xe8, 0x67, 0x20, 0xfe, 0xff,
    0x90,
    0x48, 0x8b, 0xcf,
};
constexpr uint8_t kGameplayReplicationReceiveRouteUnregisterCallSignature[] = {
    0xe8, 0xd5, 0x22, 0xfe, 0xff,
    0x48, 0x8b, 0xcb,
};
constexpr uint8_t kUserTransportRouteSlotAllocatorSignature[] = {
    0x48, 0x39, 0x9e, 0xe0, 0x00, 0x00, 0x00,
    0x76, 0x2c,
    0x49, 0x8b, 0xcd,
    0x90,
    0x48, 0x8b, 0x86, 0xd0, 0x00, 0x00, 0x00,
};
constexpr uint8_t kUserTransportRouteUserConstructorCallSignature[] = {
    0x4d, 0x8b, 0xc7,
    0x48, 0x8b, 0xd6,
    0x48, 0x8b, 0xc8,
    0xe8, 0x03, 0x63, 0xff, 0xff,
    0x90,
};
constexpr uint8_t kChatMessagePublishSignature[] = {
    0x40, 0x55, 0x53, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0x98,
    0x48, 0x81, 0xec, 0x68, 0x01, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0xa0, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kChatSystemMessagePublishSignature[] = {
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x55, 0x53, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x8b, 0xec,
    0x48, 0x83, 0xec, 0x70,
    0x48, 0xc7, 0x45, 0xc0, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kChatRoomConstructorSignature[] = {
    0x48, 0x8b, 0xc4,
    0x55,
    0x48, 0x8d, 0x68, 0xa1,
    0x48, 0x81, 0xec, 0xc0, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0xb7, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x58, 0x10,
};
constexpr uint8_t kChatRoomVtableAssignmentSignature[] = {
    0x48, 0x8d, 0x05, 0xe9, 0xe6, 0xac, 0x00,
    0x48, 0x89, 0x01,
    0x48, 0x83, 0xc1, 0x08,
    0xff, 0x15, 0x5c, 0x6c, 0x8a, 0x00,
};
constexpr uintptr_t kGameplayP2PDispatchBodyRva = 0x41a7ad;
constexpr uint8_t kGameplayP2PDispatchBodySignature[] = {
    0x48, 0x8d, 0x79, 0x40,
    0x49, 0x89, 0x7b, 0x18,
    0x48, 0x8b, 0xcf,
    0xff, 0x15, 0xfa, 0xcb, 0x87, 0x00,
    0x90,
    0x48, 0x8b, 0x9e, 0x88, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x1b,
    0x48, 0x3b, 0x9e, 0x88, 0x00, 0x00, 0x00,
    0x74, 0x4a,
    0x4c, 0x8d, 0x25, 0x5f, 0x78, 0xaa, 0x00,
    0x8b, 0xac, 0x24, 0x90, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x4b, 0x18,
    0x48, 0x8b, 0x01,
    0x4c, 0x8b, 0x50, 0x08,
    0x4c, 0x89, 0x74, 0x24, 0x20,
    0x4c, 0x8d, 0x0d, 0xa9, 0xf4, 0xe3, 0x00,
    0x44, 0x8b, 0xc5,
    0x49, 0x8b, 0xd7,
    0x49, 0x3b, 0xc4,
    0x75, 0x0b,
    0x48, 0x8b, 0x49, 0x18,
    0xe8, 0x95, 0x8d, 0x01, 0x00,
    0xeb, 0x03,
    0x41, 0xff, 0xd2,
};
constexpr uint8_t kSharedPropertyReleaseSignature[] = {
    0x48, 0x83, 0xec, 0x28,
    0x48, 0x83, 0x39, 0x00,
    0x0f, 0x84, 0x87, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x5c, 0x24, 0x30,
    0x48, 0x89, 0x6c, 0x24, 0x38,
    0x33, 0xed,
    0x48, 0x89, 0x69, 0x08,
};
constexpr uint8_t kUserIdGetterSignature[] = {
    0x48, 0x8b, 0x81, 0x84, 0x01, 0x00, 0x00, 0xc3,
};
constexpr uint8_t kPlayerInfoBuilderSignature[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x55, 0x53, 0x56, 0x57, 0x41,
    0x54, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8d, 0x6c, 0x24, 0xd9,
    0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00,
};
constexpr uint8_t kPlayerInfoDefaultsSignature[] = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48,
    0x8d, 0x15, 0xbc, 0xa1, 0xa6, 0x00, 0x48, 0x83, 0xc1, 0x08,
    0x45, 0x33, 0xc0,
};
constexpr uint8_t kPlayerInfoFromUserSignature[] = {
    0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8d, 0xac, 0x24, 0xd0, 0xfe, 0xff, 0xff,
    0x48, 0x81, 0xec, 0x30, 0x02, 0x00, 0x00,
};
constexpr uint8_t kPlayerInfoFromUserReturnSignature[] = {
    0x49, 0x8b, 0xcf,
    0xe8, 0xbe, 0x20, 0xc0, 0xff,
    0x49, 0x8b, 0xc6,
};
constexpr uint8_t kRoomPlayerInfoCopySignature[] = {
    0x49, 0x8b, 0xbe, 0x10, 0x09, 0x00, 0x00,
    0x41, 0x8b, 0x4d, 0x28, 0x83, 0xf9, 0xff, 0x74, 0x2b,
    0x48, 0x8b, 0x14, 0x3b, 0x39, 0x4a, 0x0c,
};
constexpr uint8_t kUiLayoutCastSignature[] = {
    0x40, 0x57, 0x48, 0x83, 0xec, 0x40,
    0x48, 0xc7, 0x44, 0x24, 0x30, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x5c, 0x24, 0x50,
    0x48, 0x89, 0x74, 0x24, 0x58,
};
constexpr uint8_t kUiLayoutClampSignature[] = {
    0x48, 0x8b, 0x81, 0xb0, 0x00, 0x00, 0x00,
    0x0f, 0x57, 0xc9,
    0xf3, 0x0f, 0x10, 0x15, 0x9e, 0xd3, 0xa3, 0x00,
};
constexpr uint8_t kUiLayoutDestructorSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x57, 0x48, 0x83, 0xec, 0x20,
    0x48, 0x8d, 0x05, 0xd7, 0xda, 0xa1, 0x00,
};
constexpr uint8_t kPlayersGroupCastCallSignature[] = {
    0x48, 0x8b, 0xd0,
    0x48, 0x8d, 0x4c, 0x24, 0x38,
    0xe8, 0x79, 0x43, 0xf4, 0xff,
    0x90,
};
constexpr uint8_t kHUiRoomUpdateSignature[] = {
    0x48, 0x8b, 0xc4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x8d, 0xa8, 0xd8, 0xfc, 0xff,
    0xff, 0x48, 0x81, 0xec, 0xf0, 0x03, 0x00, 0x00,
};
constexpr uint8_t kMissionStartUpdateSignature[] = {
    0x48, 0x8b, 0xc4, 0x55,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0xa8, 0xb8, 0xfc, 0xff, 0xff,
    0x48, 0x81, 0xec, 0x20, 0x04, 0x00, 0x00,
};
constexpr uint8_t kMissionStartControllerSignature[] = {
    0x48, 0x8b, 0xc4,
    0x55,
    0x48, 0x8d, 0x68, 0x98,
    0x48, 0x81, 0xec, 0x60, 0x01, 0x00, 0x00,
    0x48, 0xc7, 0x44, 0x24, 0x70, 0xfe, 0xff, 0xff, 0xff,
};
// xor edx,edx; lea rcx,[global MissionStart]; call MissionStart::Update;
// cmp [global MissionStart],5. This validates both the object identity and
// the exact state consumed by the controller after our post-update hook.
constexpr uint8_t kMissionStartControllerCallSignature[] = {
    0x33, 0xd2,
    0x48, 0x8d, 0x0d, 0x17, 0xfa, 0xe2, 0x00,
    0xe8, 0x32, 0x2b, 0xff, 0xff,
    0x83, 0x3d, 0x0b, 0xfa, 0xe2, 0x00, 0x05,
};
// Thread-local current room/session object resolver used verbatim by the
// controller. The supported concrete vtable inlines slot 53 as a read of
// object+0x1ac; host-only rooms leave it at zero forever.
constexpr uint8_t kMissionStartControllerContextSignature[] = {
    0x48, 0x83, 0xec, 0x28,
    0xe8, 0x27, 0xec, 0x00, 0x00,
    0x48, 0x8b, 0x48, 0x08,
    0x48, 0x85, 0xc9,
    0x75, 0x07,
    0x33, 0xc0,
    0x48, 0x83, 0xc4, 0x28,
    0xc3,
};
constexpr uint8_t kMissionStartControllerGateGetterSignature[] = {
    0x8b, 0x81, 0xac, 0x01, 0x00, 0x00,
    0xc3,
};
#if EDF5_COMPILE_DIAGNOSTICS
constexpr uint8_t kReportGsFailureSignature[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08,
    0x48, 0x83, 0xec, 0x38,
    0xb9, 0x17, 0x00, 0x00, 0x00,
    0xe8, 0x13, 0x0d, 0x00, 0x00,
    0x85, 0xc0,
    0x74, 0x07,
    0xb9, 0x02, 0x00, 0x00, 0x00,
    0xcd, 0x29,
};
#endif
constexpr uint8_t kMissionUpdateSignature[] = {
    0x48, 0x8b, 0xc4, 0x57, 0x48, 0x81, 0xec, 0x80, 0x00, 0x00,
    0x00, 0x48, 0xc7, 0x40, 0xb8, 0xfe, 0xff, 0xff, 0xff, 0x48,
    0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10,
};
constexpr uint8_t kMissionResultSetterSignature[] = {
    0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x41, 0x28, 0x48, 0x85,
    0xc0, 0x74, 0x49, 0x89, 0x51, 0x34, 0x48, 0x8b, 0xc8, 0xe8,
    0x18, 0x3b, 0x00, 0x00,
};
constexpr uint8_t kMissionResultApplySignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
    0x57, 0x48, 0x83, 0xec, 0x20, 0x8b, 0xf2, 0x48, 0x8b, 0xd9,
    0x48, 0x8b, 0x0d, 0x3d, 0x60, 0x14, 0x01, 0x33, 0xd2, 0xe8,
    0x0e, 0xe6, 0xff, 0xff, 0x48, 0x8b, 0x05, 0xb7, 0x5f, 0x14,
    0x01, 0x48, 0x8d, 0x78, 0x20, 0xc7, 0x83, 0xf8, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x89, 0xb3, 0xfc, 0x00, 0x00,
    0x00,
};
constexpr uint8_t kMissionResultSetterPublishSignature[] = {
    0x48, 0x8b, 0x0d, 0xd1, 0x9a, 0x14, 0x01,
    0xc7, 0x44, 0x24, 0x30, 0x02, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xc9,
    0x74, 0x1b,
    0x48, 0x81, 0xc1, 0x78, 0xff, 0xff, 0xff,
    0x4c, 0x8d, 0x44, 0x24, 0x30,
    0xba, 0x01, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionResultEventPublishSignature[] = {
    0x40, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x83, 0xec, 0x30,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff,
    0x48, 0x89, 0x5c, 0x24, 0x58,
    0x48, 0x89, 0x6c, 0x24, 0x60,
};
constexpr uint8_t kMissionResultUiEventDispatchSignature[] = {
    0x40, 0x53,
    0x48, 0x83, 0xec, 0x20,
    0x48, 0x8b, 0xd9,
    0x85, 0xd2,
    0x74, 0x46,
    0x83, 0xea, 0x01,
    0x74, 0x1a,
    0x83, 0xfa, 0x01,
    0x75, 0x53,
};
constexpr uint8_t kMissionResultUiCloseTargetSignature[] = {
    0x8b, 0x41, 0x78,
    0x41, 0x39, 0x00,
    0x75, 0x36,
    0xf6, 0x41, 0x18, 0x01,
    0x75, 0x30,
    0x83, 0x49, 0x18, 0x01,
    0x48, 0x8b, 0x01,
    0x48, 0x8b, 0x50, 0x20,
};
constexpr uint8_t kMissionResultExecBeginSignature[] = {
    0x48, 0x8b, 0xc4, 0x55, 0x41, 0x54, 0x41, 0x55,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x8d, 0x68, 0xa8,
    0x48, 0x81, 0xec, 0x30, 0x01, 0x00, 0x00,
    0x48, 0xc7, 0x45, 0x08, 0xfe, 0xff, 0xff, 0xff,
};
constexpr uint8_t kMissionResultExecBeginNativeCallerSignature[] = {
    // mov ecx,-20000; call net::MissionResult::Exec_Begin
    0xb9, 0xe0, 0xb1, 0xff, 0xff,
    0xe8, 0x2d, 0xa9, 0x31, 0x00,
};
constexpr uint8_t kMissionResultExecBeginScriptWrapperSignature[] = {
    // int ResultSync_Begin(int): preserve argument, call Exec_Begin, return it.
    0x40, 0x53,
    0x48, 0x83, 0xec, 0x20,
    0x8b, 0xd9,
    0xe8, 0xd3, 0x50, 0x00, 0x00,
    0x8b, 0xc3,
    0x48, 0x83, 0xc4, 0x20,
    0x5b,
    0xc3,
};
constexpr uint8_t kMissionResultExecUpdateSignature[] = {
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x55, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xf0,
    0x48, 0x81, 0xec, 0x10, 0x01, 0x00, 0x00,
};
constexpr uint8_t kMissionResultExecUpdateScriptWrapperSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x57,
    0x48, 0x83, 0xec, 0x60,
    0x8b, 0xf9,
    0xe8, 0xaf, 0xf9, 0x79, 0x00,
};
constexpr uint8_t kMissionResultExecUpdateScriptCallSignature[] = {
    0xe8, 0x7c, 0x5f, 0x00, 0x00,
    0x84, 0xc0,
    0x74, 0x23,
};
constexpr uint8_t kMissionResultExecUpdateNativeCallSignature[] = {
    0xe8, 0x8e, 0x61, 0x30, 0x00,
    0x84, 0xc0,
    0x74, 0x0e,
};
constexpr uint8_t kMissionResultExecFinallySignature[] = {
    0x40, 0x55, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xb9,
    0x48, 0x81, 0xec, 0xb0, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x35, 0x60, 0xbb, 0xe2, 0x00,
};
constexpr uint8_t kMissionResultExecFinallyScriptWrapperSignature[] = {
    0x40, 0x53,
    0x48, 0x83, 0xec, 0x20,
    0x8b, 0xd9,
    0xe8, 0x63, 0x44, 0x00, 0x00,
    0x8d, 0x43, 0x01,
};
constexpr uint8_t kMissionResultExecFinallyNativeCallSignature[] = {
    0xb9, 0xe0, 0xb1, 0xff, 0xff,
    0xe8, 0xe2, 0x45, 0x30, 0x00,
    0x4c, 0x8b, 0x05,
};
constexpr uint8_t kEnemySpawnSignature[] = {
    0x48, 0x8b, 0xc4, 0x55, 0x56, 0x57, 0x41, 0x54,
    0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0xa8, 0xd8, 0xfd, 0xff, 0xff,
    0x48, 0x81, 0xec, 0xf0, 0x02, 0x00, 0x00,
};
constexpr uint8_t kGeneratorPollUpdateSignature[] = {
    // Preserve self and the frame-update argument, then enter the shared
    // GameObject update before any GeneratorPoll-specific work.
    0x48, 0x89, 0x5c, 0x24, 0x20,
    0x57,
    0x48, 0x81, 0xec, 0xb0, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xac, 0x24, 0xc8, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0xf9,
    0x48, 0x8b, 0xea,
    0xe8, 0xc0, 0x1b, 0x0e, 0x00,
};
constexpr uint8_t kGeneratorPollBaseUpdateSignature[] = {
    // The base update consumes the same RCX/RDX pair. Its chained unwind
    // records split the body, but execution continues to the tail gate below.
    0x40, 0x53,
    0x48, 0x83, 0xec, 0x60,
    0xf3, 0x0f, 0x10, 0x02,
    0x48, 0x8b, 0xd9,
    0xf3, 0x0f, 0x58, 0x81, 0x14, 0x02, 0x00, 0x00,
};
constexpr uint8_t kGeneratorPollBaseGateTailSignature[] = {
    // After the common per-frame work, RCX receives owner+0x400 and RDX the
    // owner; the function restores its frame and tail-jumps to the gate.
    0x48, 0x8b, 0xcb,
    0xe8, 0x4b, 0x29, 0x00, 0x00,
    0x48, 0x8d, 0x8b, 0x00, 0x04, 0x00, 0x00,
    0x48, 0x8b, 0xd3,
    0x48, 0x83, 0xc4, 0x60,
    0x5b,
    0xe9, 0xc7, 0x1d, 0x00, 0x00,
};
constexpr uint8_t kGeneratorPollSpawnSignature[] = {
    // Save RCX/RDX as self/descriptor before any virtual spawn work.
    0x48, 0x89, 0x5c, 0x24, 0x18,
    0x48, 0x89, 0x6c, 0x24, 0x20,
    0x56, 0x57, 0x41, 0x56,
    0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,
    0x0f, 0x29, 0x74, 0x24, 0x70,
    0x48, 0x8b, 0x05, 0x2f, 0xa6, 0xf2, 0x00,
    0x48, 0x33, 0xc4,
    0x48, 0x89, 0x44, 0x24, 0x50,
    0x48, 0x8d, 0x99, 0x10, 0x0d, 0x00, 0x00,
    0x48, 0x8b, 0xf1,
    0x4c, 0x8b, 0xc1,
    0x48, 0x8b, 0xea,
};
constexpr uint8_t kGeneratorPollManagerAndSpawnSignature[] = {
    // self+0x788 is the early gate; the positive two-dword request is then
    // passed to the common enemy boundary with self+0x530 and descriptor.
    0x49, 0x8b, 0x88, 0x88, 0x07, 0x00, 0x00,
    0x48, 0x85, 0xc9,
    0x0f, 0x84, 0xce, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGeneratorPollReturnSignature[] = {
    // The final helper's RAX survives the compiler-known security-cookie
    // check and is returned unchanged; the caller consumes its low byte.
    0x48, 0x8b, 0xd5,
    0x48, 0x8b, 0xce,
    0xe8, 0x05, 0x15, 0x00, 0x00,
    0x48, 0x8b, 0x4c, 0x24, 0x50,
    0x48, 0x33, 0xcc,
    0xe8, 0xa8, 0xd9, 0x7c, 0x00,
    0x4c, 0x8d, 0x9c, 0x24, 0x80, 0x00, 0x00, 0x00,
    0x49, 0x8b, 0x5b, 0x30,
    0x49, 0x8b, 0x6b, 0x38,
    0x0f, 0x28, 0x74, 0x24, 0x70,
    0x49, 0x8b, 0xe3,
    0x41, 0x5e, 0x5f, 0x5e, 0xc3,
};
constexpr uint8_t kGeneratorPollGateSignature[] = {
    // The shared gate decrements state+4 and exits while the signed cooldown
    // remains at least 0x1cc.  RCX is owner+0x400 and RDX is the owner.
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x57,
    0x48, 0x83, 0xec, 0x30,
    0xff, 0x49, 0x04,
    0x48, 0x8b, 0xfa,
    0x81, 0x79, 0x04, 0xcc, 0x01, 0x00, 0x00,
    0x48, 0x8b, 0xd9,
    0x0f, 0x8d, 0x8c, 0x00, 0x00, 0x00,
};
constexpr uint8_t kGeneratorPollGateVirtualCallSignature[] = {
    // A positive gate count calls owner->vtable[0x108] and tests AL.
    0x83, 0x39, 0x00,
    0x7e, 0x41,
    0x48, 0x8b, 0x02,
    0x48, 0x8b, 0xcf,
    0xff, 0x90, 0x08, 0x01, 0x00, 0x00,
    0x84, 0xc0,
    0x74, 0x31,
};
constexpr uintptr_t kEnemySpawnCountAndCapRva = 0x1c16c6;
constexpr uint8_t kEnemySpawnCountAndCapSignature[] = {
    // Preserve R8D as the requested count, then clamp live+requested to 400.
    0x45, 0x8b, 0xc8,
    0x4c, 0x8b, 0xea,
    0x48, 0x8b, 0xf9,
    0x8b, 0x0d, 0xb7, 0xc6, 0x08, 0x01,
    0x42, 0x8d, 0x04, 0x01,
    0x3d, 0x90, 0x01, 0x00, 0x00,
    0x72, 0x0f,
    0x41, 0xb9, 0x90, 0x01, 0x00, 0x00,
    0x44, 0x2b, 0xc9,
    0x0f, 0x84, 0xe3, 0x06, 0x00, 0x00,
};
constexpr uintptr_t kEnemySpawnScaleLayoutRva = 0x1c16ef;
constexpr uint8_t kEnemySpawnScaleLayoutSignature[] = {
    // source(+2B0), denominator(+294), numerator(+290), then scaled division.
    0x48, 0x83, 0xbf, 0xb0, 0x02, 0x00, 0x00, 0x00,
    0x0f, 0x84, 0xd5, 0x06, 0x00, 0x00,
    0x44, 0x8b, 0x87, 0x94, 0x02, 0x00, 0x00,
    0x8b, 0x87, 0x90, 0x02, 0x00, 0x00,
    0x41, 0x0f, 0xaf, 0xc1,
    0x41, 0x8d, 0x48, 0xff,
    0x03, 0xc8,
    0x33, 0xd2,
    0x8b, 0xc1,
    0x41, 0xf7, 0xf0,
    0x2b, 0xca,
    0x33, 0xd2,
    0x8b, 0xc1,
    0x41, 0xf7, 0xf0,
    0x44, 0x8b, 0xc0,
};
constexpr uint8_t kMissionResultItemInitializeLimitSignature[] = {
    0x83, 0xfb, 0x04, 0x72, 0xd5,
};
constexpr uint8_t kMissionResultItemSinkSignature[] = {
    0x4c, 0x63, 0x0a,
    0x48, 0x8b, 0x05, 0x76, 0x7f, 0x12, 0x01,
    0x49, 0x8b, 0x08,
    0x4a, 0x89, 0x8c, 0xc8, 0x7c, 0x45, 0x02, 0x00,
    0xc3,
};
constexpr uint8_t kMissionNamedSyncBeginSignature[] = {
    0x48, 0x8b, 0xc4, 0x56, 0x57, 0x41, 0x56, 0x48,
    0x83, 0xec, 0x60, 0x48, 0xc7, 0x40, 0xa8, 0xfe,
    0xff, 0xff, 0xff, 0x48, 0x89, 0x58, 0x18,
    0x48, 0x89, 0x68, 0x20,
};
constexpr uint8_t kMissionNamedSyncPollSignature[] = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
    0xd9, 0x48, 0x8b, 0x49, 0x10, 0x48, 0x85, 0xc9,
    0x0f, 0x84, 0x91, 0x00, 0x00, 0x00, 0x48, 0x8b,
    0x09,
};
constexpr uint8_t kMissionResultScriptSyncBeginCallSignature[] = {
    0xe8, 0x43, 0xca, 0x03, 0x00,
};
constexpr uint8_t kMissionResultScriptSyncPollCallSignature[] = {
    0xe8, 0x37, 0xcb, 0x03, 0x00,
};
constexpr uint8_t kMissionResultNetSyncBeginCallSignature[] = {
    0xe8, 0xe7, 0x36, 0xff, 0xff,
};
constexpr uint8_t kMissionResultNetSyncPollCallSignature[] = {
    0xe8, 0xe0, 0x37, 0xff, 0xff,
};
constexpr uint8_t kMissionRewardResolveSignature[] = {
    0x48, 0x8b, 0x0d, 0x81, 0x7a, 0xe7, 0x00,
    0xe9, 0x74, 0x60, 0xdb, 0xff,
};
constexpr uint8_t kMissionRewardApplySignature[] = {
    0x40, 0x53, 0x41, 0x56, 0x48, 0x83, 0xec, 0x28,
    0x0f, 0xb6, 0xd9, 0x45, 0x32, 0xf6,
    0x48, 0x8b, 0x0d, 0x63, 0x7a, 0xe7, 0x00,
    0xe8, 0xd6, 0x6b, 0xdb, 0xff,
};
constexpr uint8_t kMissionRewardApplyCountReadSignature[] = {
    0x41, 0x8b, 0x80, 0x9c, 0x45, 0x02, 0x00,
    0x85, 0xc0, 0x0f, 0x84, 0x2f, 0x01, 0x00, 0x00,
};
constexpr uint8_t kMissionRewardApplyProfileBaseSignature[] = {
    0x49, 0x8d, 0xa8, 0x4c, 0x6d, 0x00, 0x00,
};
constexpr uint8_t kMissionRewardApplyProfileStrideSignature[] = {
    0x48, 0x81, 0xc5, 0x60, 0x3e, 0x00, 0x00,
};
constexpr uint8_t kMissionRewardLocalProfileSetterSignature[] = {
    0x48, 0x8b, 0x41, 0x08, 0x44, 0x8b, 0x00,
    0x41, 0x8d, 0x40, 0xff, 0x83, 0xf8, 0x01, 0x77, 0x1d,
    0x48, 0x8b, 0x15, 0xe9, 0x52, 0x20, 0x01,
    0x44, 0x89, 0x82, 0x9c, 0x45, 0x02, 0x00,
};
constexpr uint8_t kMissionScriptMessageDispatchSignature[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10,
    0x48, 0x89, 0x7c, 0x24, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55,
    0x41, 0x56, 0x41, 0x57, 0x48, 0x8d, 0x6c, 0x24, 0xd1, 0x48,
    0x81, 0xec, 0x00, 0x01, 0x00, 0x00,
};
constexpr uint8_t kMissionNaturalClearResultSignature[] = {
    0xba, 0x01, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionNaturalClearCallSignature[] = {
    0xe8, 0x28, 0x8f, 0xd3, 0xff,
};
constexpr uint8_t kMissionManagerLoadSignature[] = {
    0x48, 0x8b, 0x05, 0xbc, 0x91, 0xe7, 0x00,
};
constexpr uint8_t kMissionUiStateReadSignature[] = {
    0x8b, 0x81, 0xf8, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionUiResultReadSignature[] = {
    0x8b, 0x81, 0xfc, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionResultPreserveSignature[] = {
    0x83, 0xfe, 0x01, 0x74, 0x38,
};
constexpr uint8_t kMissionSourceLookupSignature[] = {
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xda,
    0x49, 0xc1, 0xe0, 0x04, 0x4c, 0x03, 0x41, 0x08, 0x48,
    0x8b, 0xcb, 0x49, 0x8b, 0xd0, 0xe8, 0xf4, 0xf9, 0xfe, 0xff,
};
constexpr uint8_t kMissionSourceLookupCallSignature[] = {
    0x4d, 0x8b, 0xc6,
    0x48, 0x8d, 0x54, 0x24, 0x40,
    0xe8, 0x33, 0x13, 0xf6, 0xff,
    0x90,
};
constexpr uint8_t kMissionSourceTransferCallSignature[] = {
    0x48, 0x63, 0xf7,
    0x4c, 0x8b, 0xc6,
    0x48, 0x8d, 0x55, 0x10,
    0x48, 0x8d, 0x4d, 0x30,
    0xe8, 0x6d, 0x02, 0xf6, 0xff,
};
constexpr uint8_t kMissionSourceAppendCallSignature[] = {
    0x4c, 0x8b, 0xc6,
    0x48, 0x8d, 0x55, 0x20,
    0x48, 0x8d, 0x4d, 0x30,
    0xe8, 0xe4, 0x01, 0xf6, 0xff,
    0x90,
};
constexpr uint8_t kMissionSourceConsumerSignature[] = {
    0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8d, 0x6c, 0x24, 0xd9, 0x48, 0x81, 0xec,
    0x00, 0x01, 0x00, 0x00,
};
constexpr uint8_t kMissionSourceConsumerBoundSignature[] = {
    0x49, 0x63, 0x99, 0xf8, 0x00, 0x00, 0x00,
    0x85, 0xdb,
    0x0f, 0x88, 0xb3, 0x03, 0x00, 0x00,
    0x83, 0xfb, 0x04,
    0x0f, 0x83, 0xaa, 0x03, 0x00, 0x00,
};
constexpr uint8_t kMissionPostConsumerIdentityReadSignature[] = {
    0x48, 0x8b, 0x4c, 0x24, 0x40,
    0x48, 0x85, 0xc9,
    0x74, 0x0e,
    0x48, 0x8b, 0x44, 0x24, 0x48,
    0x44, 0x8b, 0xb0, 0xf8, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionAppendIdentityReadSignature[] = {
    0x48, 0x8b, 0x40, 0x08,
    0x8b, 0x88, 0xf8, 0x00, 0x00, 0x00,
    0x89, 0x4d, 0xac,
};
constexpr uint8_t kMissionLoadoutConsumerBlockSignature[] = {
    0x48, 0x69, 0xfb, 0x90, 0x3e, 0x00, 0x00,
    0x4c, 0x8b, 0x05, 0x16, 0x87, 0xf4, 0x00,
    0x4e, 0x63, 0xa4, 0x07, 0x30, 0x4b, 0x01, 0x00,
    0x42, 0x8b, 0x84, 0x07, 0x28, 0x4c, 0x01, 0x00,
    0x89, 0x44, 0x24, 0x30,
};
constexpr uint8_t kMissionLoadoutConsumerRecordSignature[] = {
    0x42, 0x8b, 0x84, 0x07, 0x30, 0x4b, 0x01, 0x00,
    0x48, 0x8d, 0x0c, 0x40,
    0x48, 0x8d, 0x04, 0xcf,
    0x46, 0x8b, 0xb4, 0x00, 0x38, 0x4b, 0x01, 0x00,
};
constexpr uint8_t kMissionLoadoutParserStrideSignature[] = {
    0x4c, 0x69, 0xd1, 0x90, 0x3e, 0x00, 0x00,
    0x8b, 0x85, 0x0c, 0x01, 0x00, 0x00,
    0x43, 0x89, 0x84, 0x32, 0xe8, 0x01, 0x00, 0x00,
};
constexpr uint8_t kMissionLoadoutParserRecordSignature[] = {
    0x8b, 0x45, 0x14,
    0x43, 0x89, 0x84, 0x32, 0xf0, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x0c, 0x40,
    0x4c, 0x8d, 0x04, 0xcd, 0x00, 0x00, 0x00, 0x00,
    0x4d, 0x69, 0xc9, 0x90, 0x3e, 0x00, 0x00,
};
constexpr uint8_t kMissionLoadoutParserParticipantCountWriteSignature[] = {
    0x44, 0x89, 0xa6, 0xa0, 0x45, 0x02, 0x00,
};
constexpr uint8_t kMissionLoadoutParserSignature[] = {
    0x40, 0x55,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0xac, 0x24, 0x00, 0xc1, 0xff, 0xff,
    0xb8, 0x00, 0x40, 0x00, 0x00,
    0xe8, 0x94, 0x85, 0x59, 0x00,
};
constexpr uint8_t kMissionParticipantClassResolverSignature[] = {
    0x40, 0x55, 0x53, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0x6c, 0x24, 0xe9,
    0x48, 0x81, 0xec, 0xa8, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionParticipantVisualTableIndexSignature[] = {
    0x8b, 0x45, 0xa0,
    0x48, 0xc1, 0xe0, 0x06,
    0x48, 0x03, 0x87, 0xd8, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x45, 0xf8,
};
constexpr uint8_t kMissionParticipantNativeClassReadSignature[] = {
    0x48, 0x69, 0xc9, 0x90, 0x3e, 0x00, 0x00,
    0x48, 0x8b, 0x05, 0x9c, 0x42, 0xda, 0x00,
    0x8b, 0x8c, 0x01, 0x30, 0x4b, 0x01, 0x00,
};
constexpr uint8_t kMissionParticipantClassTextTableIndexSignature[] = {
    0x48, 0x63, 0x45, 0xf8,
    0x4c, 0x8d, 0x34, 0x40,
    0x49, 0xc1, 0xe6, 0x04,
    0x4c, 0x03, 0xb7, 0xb8, 0x00, 0x00, 0x00,
};
constexpr uint8_t kMissionParticipantClassTextSelectSignature[] = {
    0x49, 0x83, 0x7e, 0x18, 0x08,
    0x72, 0x05,
    0x4d, 0x8b, 0x06,
    0xeb, 0x03,
    0x4d, 0x8b, 0xc6,
};
constexpr uint8_t kMissionTextMeasureInvalidReadSignature[] = {
    0x66, 0x41, 0x3b, 0x18,
    0x0f, 0x84, 0xe4, 0x01, 0x00, 0x00,
};
constexpr uint8_t kSharedRenderPropertyRefReadSignature[] = {
    0x41, 0x8b, 0x40, 0x04,
    0x85, 0xc0,
    0x74, 0x4b,
    0x8d, 0x48, 0x01,
    0xf0, 0x41, 0x0f, 0xb1, 0x48, 0x04,
};
constexpr uint8_t kMissionSharedHandleCopySignature[] = {
    0x40, 0x53,
    0x48, 0x83, 0xec, 0x40,
    0x33, 0xc0,
    0x48, 0x8b, 0xda,
    0x48, 0x89, 0x02,
    0x48, 0x89, 0x42, 0x08,
    0x4c, 0x8b, 0x41, 0x08,
    0x48, 0x8b, 0x11,
};
constexpr uint8_t kMissionSourceCollectionCopySignature[] = {
    0x48, 0x89, 0x6c, 0x24, 0x18,
    0x48, 0x89, 0x7c, 0x24, 0x20,
    0x41, 0x56,
    0x48, 0x83, 0xec, 0x20,
    0x48, 0x8b, 0x6a, 0x18,
    0x4c, 0x8b, 0xf2,
    0x48, 0x8b, 0xf9,
    0xe8, 0x01, 0x2a, 0xf5, 0xff,
};
constexpr uint8_t kMissionSourcePrimaryCopyCallSignature[] = {
    0x48, 0x8b, 0x4d, 0xe7,
    0x48, 0x8b, 0x01,
    0x48, 0x8d, 0x55, 0xf7,
    0xff, 0x50, 0x20,
    0x90,
    0x48, 0x8b, 0xd0,
    0x48, 0x8d, 0x4d, 0xaf,
    0xe8, 0x51, 0xdb, 0x00, 0x00,
};
constexpr uint8_t kMissionSourceReferenceCopyCallSignature[] = {
    0x48, 0x8b, 0x4d, 0xe7,
    0x48, 0x8b, 0x01,
    0x48, 0x8d, 0x55, 0xf7,
    0xff, 0x50, 0x28,
    0x90,
    0x48, 0x8b, 0xd0,
    0x48, 0x8d, 0x4d, 0x8f,
    0xe8, 0x2c, 0xdb, 0x00, 0x00,
};
constexpr uint8_t kMissionPlayerCreateSignature[] = {
    0x48, 0x8b, 0xc4,
    0x55, 0x56, 0x57,
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x8d, 0xa8, 0xb8, 0xfe, 0xff, 0xff,
    0x48, 0x81, 0xec, 0x10, 0x02, 0x00, 0x00,
};
constexpr uint8_t kMissionPlayerCreatePrimaryCallSignature[] = {
    0x89, 0x5c, 0x24, 0x20,
    0x45, 0x8b, 0xce,
    0x4c, 0x8d, 0x85, 0xd0, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x95, 0x38, 0x01, 0x00, 0x00,
    0x48, 0x8b, 0xcf,
    0xe8, 0x27, 0xf2, 0xff, 0xff,
};
constexpr uint8_t kMissionPlayerCreateSecondaryCallSignature[] = {
    0x89, 0x4c, 0x24, 0x20,
    0x44, 0x8b, 0xce,
    0x48, 0x8d, 0x55, 0xa8,
    0x49, 0x8b, 0xcd,
    0xe8, 0x72, 0xe1, 0xff, 0xff,
};

using UserConstructorFn = void* (__fastcall*)(void*, void*, void*);
using UserDestructorFn = void* (__fastcall*)(void*, unsigned);
using UserIdGetterFn = uint64_t (__fastcall*)(void*);

struct SharedProperty {
    void* control = nullptr;
    void* object = nullptr;
};

static_assert(sizeof(SharedProperty) == 0x10,
              "native participant property handle layout changed");

using UserPropertySetterFn = SharedProperty* (__fastcall*)(
    void*, SharedProperty*, const char*, const char*);
using UserPropertyGetterFn = SharedProperty* (__fastcall*)(
    void*, SharedProperty*, const char*);
using SharedPropertyReleaseFn = void (__fastcall*)(SharedProperty*);
using MissionSourceLookupFn = SharedProperty* (__fastcall*)(
    void*, SharedProperty*, uint64_t);
using MissionSourceConsumerFn = void* (__fastcall*)(
    const SharedProperty*, void*);
using MissionSharedHandleCopyFn = SharedProperty* (__fastcall*)(
    const void*, SharedProperty*);

struct MissionSourceVector {
    uint64_t reserved = 0;
    SharedProperty* entries = nullptr;
    uint64_t capacity = 0;
    uint64_t size = 0;
};

static_assert(offsetof(MissionSourceVector, entries) == 0x08 &&
                  offsetof(MissionSourceVector, size) == 0x18 &&
                  sizeof(MissionSourceVector) == 0x20,
              "mission UserImpl vector layout changed");

// 0x45ed80 builds the serializer's destination vector by copying the adjacent
// UserImpl+0xc4/+0xc8 dwords into one eight-byte descriptor.  0x432e00 walks
// those descriptors with index*8 and 0x433f40 consumes only the second dword
// as the dynamic manager+0xd0 transport-route slot.  This is deliberately not
// a SharedProperty: treating it as a 16-byte handle would read past the vector.
struct GameplayReplicationTargetDescriptor {
    uint32_t opaque_route_key = 0;
    int32_t transport_route_index = -1;
};

struct GameplayReplicationTargetVector {
    uint64_t reserved = 0;
    GameplayReplicationTargetDescriptor* entries = nullptr;
    uint64_t capacity = 0;
    uint64_t size = 0;
};

static_assert(sizeof(GameplayReplicationTargetDescriptor) == 0x08 &&
                  offsetof(GameplayReplicationTargetDescriptor,
                           transport_route_index) == 0x04,
              "gameplay replication target descriptor layout changed");
static_assert(offsetof(GameplayReplicationTargetVector, entries) == 0x08 &&
                  offsetof(GameplayReplicationTargetVector, size) == 0x18 &&
                  sizeof(GameplayReplicationTargetVector) == 0x20,
              "gameplay replication target vector layout changed");

using MissionSourceCollectionCopyFn = void* (__fastcall*)(
    MissionSourceVector*, const MissionSourceVector*);
using MissionPlayerCreateFn = SharedProperty* (__fastcall*)(
    void*, SharedProperty*, void*, int32_t, int32_t, int32_t, int32_t,
    uintptr_t, int32_t, void*);

struct PlayerInfoEntry {
    uint8_t* object = nullptr;
    void* control = nullptr;
};

struct PlayerInfoVector {
    uint64_t reserved = 0;
    PlayerInfoEntry* entries = nullptr;
    uint64_t capacity = 0;
    uint64_t size = 0;
};

static_assert(sizeof(PlayerInfoEntry) == 0x10,
              "PlayerInfo shared-pointer entry layout changed");
static_assert(offsetof(PlayerInfoVector, entries) == 0x08 &&
                  offsetof(PlayerInfoVector, size) == 0x18,
              "PlayerInfo vector layout changed");

struct LoadoutCloneStats {
    unsigned requested = 0;
    unsigned recognized = 0;
    unsigned copied = 0;
    uint32_t recognized_mask = 0;
    int host_class = -1;
    int host_first_weapon = -1;
    int host_position = -1;
    bool used_single_real_fallback = false;
};

using PlayerInfoBuilderFn = int (__fastcall*)(void*, PlayerInfoVector*);
using PlayerInfoFromUserFn = uint8_t* (__fastcall*)(
    uint8_t*, const SharedProperty*);
using UiLayoutCastFn = void* (__fastcall*)(void*, void*);
using UiLayoutClampFn = void (__fastcall*)(void*);
using UiLayoutDestructorFn = void* (__fastcall*)(void*, unsigned);
using HUiRoomUpdateFn = void* (__fastcall*)(void*, void*);
using MissionStartUpdateFn = void (__fastcall*)(void*, bool);
using MissionStartControllerFn = bool (__fastcall*)();
using MissionStartControllerContextFn = void* (__fastcall*)();
using MissionUpdateFn = int (__fastcall*)();
using MissionLoadoutParserFn = bool (__fastcall*)(int32_t, bool*);
using MissionParticipantClassResolverFn = void (__fastcall*)(
    void*, int32_t*, int32_t*, void*, uint8_t*);
#if EDF5_COMPILE_DIAGNOSTICS
using ReportGsFailureFn = void (__fastcall*)(uintptr_t);
#endif
using MissionResultSetterFn = void (__fastcall*)(void*, int32_t);
using MissionResultApplyFn = void (__fastcall*)(void*, int32_t);
using MissionResultEventPublishFn = void (__fastcall*)(
    void*, int32_t, const void*);
using MissionResultUiEventDispatchFn = bool (__fastcall*)(
    void*, int32_t, const void*);
using MissionResultExecBeginFn = bool (__fastcall*)(int32_t);
using MissionResultExecUpdateFn = bool (__fastcall*)(int32_t, void*);
using MissionResultExecFinallyFn = void (__fastcall*)(int32_t);
using EnemySpawnFn = void (__fastcall*)(void*, void*, uint32_t);
// GeneratorPoll::Update forwards self and the native frame-update argument to
// the base update and has no consumed return value.
using GeneratorPollUpdateFn = void (__fastcall*)(void*, void*);
// Shared GameObject gate: RCX is the embedded state at owner+0x400 and RDX
// is the owning object.  The native function has no consumed return value.
using GeneratorPollGateFn = void (__fastcall*)(void*, void*);
// The native gate consumes AL, while the concrete method forwards the RAX
// from its final helper. uintptr_t preserves that binary return exactly even
// though the source-level type is unavailable.
using GeneratorPollSpawnFn = uintptr_t (__fastcall*)(void*, void*);
using MissionResultItemSinkFn = void (__fastcall*)(
    void*, const int32_t*, const uint64_t*);
using MissionNamedSyncBeginFn = void (__fastcall*)(void*, const char*);
using MissionNamedSyncPollFn = void (__fastcall*)(void*);
using MissionRewardResolveFn = void (__fastcall*)();
using MissionRewardApplyFn = bool (__fastcall*)(bool);
using GameplayP2PSendFn = bool (__fastcall*)(
    void*, uint64_t, const void*, uint64_t);
using GameplayP2PDispatchFn = void (__fastcall*)(
    void*, void*, void*, uint64_t, int32_t);
using GameplayMessageEnqueueFn = void (__fastcall*)(
    void*, const void*, uint64_t, const SharedProperty*);
using GameplayReplicationProducerFn = bool (__fastcall*)(
    void*, int32_t, const void*, uint64_t);
using GameplayReplicationSerializerFn = bool (__fastcall*)(
    void*, int32_t, const GameplayReplicationTargetVector*, uint32_t,
    const void*, uint64_t);
using GameplayReplicationReceivePumpFn = bool (__fastcall*)(
    void*, uint32_t, void*);
using GameplayReplicationReceiveParserFn = void (__fastcall*)(void*, void*);
using GameplayReplicationReceiveRouteFn = bool (__fastcall*)(
    void*, const SharedProperty*);
using MissionScriptMessageDispatchFn = uintptr_t (__fastcall*)(
    void*, void*, void*, int32_t, uint32_t);
using ChatRoomConstructorFn = void* (__fastcall*)(void*);
using ChatMessagePublishFn = bool (__fastcall*)(
    void*, const uint64_t*, void*, const wchar_t*, const void*, int32_t,
    uint16_t);
using ChatSystemMessagePublishFn = void (__fastcall*)(void*, const wchar_t*);

struct PlayerInfoObservation {
    void* user = nullptr;
    uint64_t name_fingerprint = 0;
    uint32_t name_token = 0;
    uint32_t name_length = 0;
    bool name_valid = false;
    uint32_t shared_name_user_count = 0;
    int32_t source_mission_loadout_index = -1;
    uint32_t shared_loadout_index_user_count = 0;
    int32_t transport_route_index = -1;
    uint32_t shared_transport_route_index_user_count = 0;
    int32_t selected_class = -1;
    int32_t secondary_loadout = -1;
    int32_t first_weapon = -1;
    std::array<int32_t, kMissionLoadoutWeaponCount> weapons = {
        -1, -1, -1, -1, -1, -1,
    };
    float armor = -1.0f;
    uint64_t observed_tick = 0;
};

struct TransportRouteAllocatorOwnerObservation {
    void* user = nullptr;
    void* allocator_owner = nullptr;
};

// MissionResult's parser does produce the fifth-through-eighth loadout data,
// but it writes those blocks over unrelated fixed-size result state.  The
// parser hook therefore captures only the fields proven to be consumed by
// character creation, then restores the native result state.  This sidecar is
// deliberately independent from PlayerInfo: some real clients never expose a
// usable PlayerInfo observation before the mission factory runs.
struct MissionExtraLoadoutSidecar {
    bool valid = false;
    int32_t logical_index = -1;
    int32_t selected_class = -1;
    std::array<int32_t, kMissionLoadoutWeaponCount> weapons = {
        -1, -1, -1, -1, -1, -1,
    };
    uint32_t weapon_valid_mask = 0;
    int32_t armor = -1;
    uint64_t captured_tick = 0;
    unsigned parser_call = 0;
};

struct MissionLoadoutSelection {
    bool valid = false;
    bool armor_valid = false;
    const char* source = "none";
    int32_t logical_index = -1;
    int32_t selected_class = -1;
    std::array<int32_t, kMissionLoadoutWeaponCount> weapons = {
        -1, -1, -1, -1, -1, -1,
    };
    uint32_t weapon_valid_mask = 0;
    int32_t armor = -1;
};

struct ChatNameAssociation {
    int sender_registered_order = -1;
    int display_name_owner_registered_order = -1;
    int sender_participant_index = -1;
    int display_name_owner_participant_index = -1;
    uint32_t expected_name_token = 0;
    uint32_t display_name_token = 0;
    uint32_t display_name_length = 0;
    bool sender_identity_valid = false;
    bool sender_resolved = false;
    bool display_name_valid = false;
    bool display_name_resolved = false;
    bool name_matches_sender = false;
};

struct MissionSourceCollectionSnapshot {
    bool valid = false;
    uint64_t source_count = 0;
    unsigned inspected_count = 0;
    unsigned unique_objects = 0;
    unsigned unique_controls = 0;
    unsigned recognized_users = 0;
    unsigned registered_users = 0;
    unsigned matched_registered_users = 0;
    unsigned valid_local_controller_indices = 0;
    unsigned duplicate_local_controller_indices = 0;
    int maximum_local_controller_index = -1;
    uint32_t local_controller_index_mask = 0;
    unsigned registered_order_matches = 0;
    unsigned registered_order_mismatches = 0;
    unsigned registered_order_unknown = 0;
    std::array<void*, kMissionSourceAuditCapacity> objects{};
    std::array<void*, kMissionSourceAuditCapacity> controls{};
    std::array<int32_t, kMissionSourceAuditCapacity> registered_ordinals{};
    std::array<int32_t, kMissionSourceAuditCapacity>
        local_controller_indices{};
};

struct MissionPlayerCreateTrace {
    bool active = false;
    int context = -1;
    int32_t participant_index = -1;
    uint64_t requested_source_index = 0;
    uint64_t effective_source_index = 0;
    bool source_fallback = false;
    const MissionSourceVector* sources = nullptr;
    void* temporary_loadout_object = nullptr;
    int32_t original_loadout_index = -1;
    int32_t temporary_loadout_index = -1;
    int32_t requested_player_info_class = -1;
    int32_t fallback_player_info_class = -1;
    bool temporary_loadout_block_patched = false;
    int32_t temporary_loadout_block_class = -1;
    int32_t temporary_loadout_block_first_weapon = -1;
    uint32_t temporary_loadout_block_weapon_valid_mask = 0;
    uint32_t temporary_loadout_block_fallback_weapon_mask = 0;
    int32_t temporary_loadout_block_armor = -1;
    const char* temporary_loadout_block_source = "none";
    bool temporary_loadout_block_restored = false;
    bool unique_loadout_index_restored = false;
    bool loadout_restored_before_post_create_consumers = false;
    int32_t observed_loadout_index_before_restore = -1;
    int32_t observed_loadout_index_after_restore = -1;
    const char* loadout_restoration_phase = "not_required";
};

struct MissionLoadoutBlockPatch {
    bool active = false;
    uint8_t* block = nullptr;
    int32_t source_index = -1;
    int32_t selected_class = -1;
    int32_t armor = -1;
    std::array<uint8_t, kMissionClassLoadoutStride> original{};
};

struct MissionLoadoutParserProtection {
    bool active = false;
    uint8_t* state = nullptr;
    size_t bytes = 0;
    std::array<uint8_t, kMissionExtraLoadoutSpan> original{};
};

struct SyntheticPacket {
    uint64_t peer = 0;
    int channel = 0;
    std::vector<uint8_t> bytes;
};

struct MembershipChange {
    uint64_t lobby = 0;
    uint64_t user = 0;
    uint32_t state = 0;
};

std::atomic<bool> g_running{false};
std::atomic<bool> g_started{false};
std::atomic<unsigned> g_bot_count{0};
std::atomic<uint32_t> g_gameplay_contact_mask{0};
std::atomic<bool> g_all_gameplay_contact_reported{false};
std::atomic<bool> g_room_full_reported{false};
std::atomic<bool> g_create_pending{false};
std::atomic<uint64_t> g_owned_lobby{0};
std::atomic<uint64_t> g_join_lobby_pending{0};
std::atomic<uint64_t> g_chat_banner_lobby{0};
std::atomic<bool> g_chat_banner_pending{false};
std::atomic<unsigned> g_chat_banner_publish_attempts{0};
std::atomic<unsigned> g_chat_banner_publish_successes{0};
std::atomic<uint32_t> g_chat_banner_wait_logged_mask{0};
std::atomic<unsigned> g_chat_room_capture_count{0};
std::atomic<int> g_last_actual_member_count{-1};
std::atomic<int> g_add_hotkey_test_override{-1};
std::atomic<int> g_remove_hotkey_test_override{-1};
std::atomic<int> g_ready_hotkey_test_override{-1};
std::atomic<int> g_invite_hotkey_test_override{-1};
std::atomic<int> g_local_mission_harness_hotkey_test_override{-1};
std::atomic<int> g_debug_stage_win_hotkey_test_override{-1};
std::atomic<int> g_scroll_hotkey_test_override{-1};
std::atomic<bool> g_ready_user_test_mode{false};
std::atomic<bool> g_scroll_test_mode{false};
std::atomic<unsigned> g_scroll_test_calls{0};
std::atomic<bool> g_suppress_hotkey_feedback{false};
std::atomic<uint64_t> g_last_loadout_log_signature{0};
std::atomic<uint64_t> g_last_room_model_tick{0};
std::atomic<bool> g_player_info_return_contract_logged{false};
std::atomic<unsigned> g_player_info_return_mismatch_count{0};
std::atomic<int> g_single_real_host_position{-1};
std::atomic<int> g_pending_wheel_detents{0};
std::atomic<uint64_t> g_pending_ready_lobby{0};
std::atomic<bool> g_pending_ready_feedback{false};
std::atomic<bool> g_mission_groups_pending{false};
std::atomic<bool> g_mission_groups_synchronized{false};
std::atomic<uint64_t> g_last_mission_group_log_signature{0};
// Debug-only host harness. Its dummies still use EDF5-created UserImpl
// objects, but no real Steam peers exist behind them. Keeping this state
// separate from g_bot_count lets ordinary F8 fillers retain their old
// behavior and makes every result-sync bypass fail closed.
std::atomic<unsigned> g_local_mission_harness_target{0};
std::atomic<uint32_t> g_local_mission_harness_result_sync_logged_mask{0};
std::atomic<unsigned> g_local_mission_harness_matching_completions{0};
std::atomic<uint64_t> g_local_mission_harness_mission_start_calls{0};
std::atomic<uint64_t> g_local_mission_harness_mission_start_observations{0};
std::atomic<int32_t> g_local_mission_harness_last_mission_start_state{
    std::numeric_limits<int32_t>::min()};
std::atomic<uint64_t> g_local_mission_harness_last_mission_start_log_tick{0};
std::atomic<uint64_t> g_local_mission_harness_controller_calls{0};
std::atomic<uint64_t> g_local_mission_harness_controller_bypasses{0};
std::atomic<int32_t> g_local_mission_harness_last_controller_state{
    std::numeric_limits<int32_t>::min()};
std::atomic<uint64_t> g_local_mission_harness_last_controller_log_tick{0};
std::atomic<bool> g_debug_stage_win_pending{false};
std::atomic<bool> g_debug_stage_win_active{false};
std::atomic<bool> g_debug_stage_win_consumed{false};
std::atomic<uint64_t> g_debug_stage_win_request_tick{0};
std::atomic<uint64_t> g_debug_stage_win_request_generation{0};
std::atomic<uint64_t> g_mission_update_tick{0};
std::atomic<uint64_t> g_mission_first_update_tick{0};
std::atomic<uint64_t> g_mission_generation{0};
std::atomic<int32_t> g_mission_ui_state{-1};
std::atomic<uint64_t> g_mission_result_tick{0};
std::atomic<uint64_t> g_mission_result_generation{0};
std::atomic<uint32_t> g_mission_result_audit_mask{0};
std::atomic<unsigned> g_mission_result_setter_calls{0};
std::atomic<unsigned> g_mission_result_apply_calls{0};
std::atomic<int32_t> g_mission_result_last_value{-1};
std::atomic<int32_t> g_mission_result_last_ui_state{-1};
std::atomic<int32_t> g_mission_result_last_ui_value{-1};
std::atomic<uintptr_t> g_mission_result_last_setter_caller_rva{0};
std::atomic<uintptr_t> g_mission_result_last_apply_caller_rva{0};
std::atomic<uint64_t> g_mission_result_last_setter_generation{0};
std::atomic<bool> g_mission_result_recovery_pending{false};
std::atomic<uint64_t> g_mission_result_recovery_tick{0};
std::atomic<uint64_t> g_mission_result_recovery_generation{0};
std::atomic<unsigned> g_mission_result_recovery_attempts{0};
std::atomic<unsigned> g_mission_result_event_publish_calls{0};
std::atomic<unsigned> g_mission_result_expected_event_publish_calls{0};
std::atomic<unsigned> g_mission_result_ui_dispatch_calls{0};
std::atomic<unsigned> g_mission_result_ui_target_match_calls{0};
std::atomic<unsigned> g_mission_result_exec_begin_calls{0};
std::atomic<uint64_t> g_mission_result_exec_update_calls{0};
std::atomic<uint64_t> g_mission_result_exec_update_true_calls{0};
std::atomic<uint64_t> g_mission_result_exec_update_false_calls{0};
std::atomic<uint32_t> g_mission_result_exec_update_observation_mask{0};
std::atomic<uint64_t> g_mission_result_exec_finally_calls{0};
std::atomic<uint32_t> g_mission_result_exec_finally_origin_mask{0};
std::atomic<bool> g_mission_result_exec_recovery_pending{false};
std::atomic<uint64_t> g_mission_result_exec_recovery_tick{0};
std::atomic<uint64_t> g_mission_result_exec_recovery_generation{0};
std::atomic<unsigned> g_mission_result_exec_recovery_attempts{0};
std::atomic<unsigned> g_mission_result_exec_recovery_native_cancels{0};
thread_local bool g_mission_result_exec_recovery_scope = false;
// Spawn telemetry is aggregate-only: counts, callsite RVAs and scale state.
// It never retains actor pointers, mission payloads or network identities.
std::atomic<uint64_t> g_enemy_spawn_calls{0};
std::atomic<uint64_t> g_enemy_spawn_confirmed_calls{0};
std::atomic<uint64_t> g_enemy_spawn_requested_total{0};
std::atomic<uint64_t> g_enemy_spawn_effective_total{0};
std::atomic<uint64_t> g_enemy_spawn_zero_scale_calls{0};
std::atomic<uint64_t> g_enemy_spawn_missing_source_calls{0};
std::atomic<uint64_t> g_enemy_spawn_scale_repairs{0};
std::atomic<uint64_t> g_enemy_spawn_scale_restore_failures{0};
std::atomic<uint32_t> g_enemy_spawn_observation_mask{0};
std::atomic<uint64_t> g_generator_poll_update_calls{0};
std::atomic<uint64_t> g_generator_poll_update_completed_calls{0};
std::atomic<uint64_t> g_generator_poll_updates_reaching_spawn_method{0};
std::atomic<uint64_t> g_generator_poll_spawn_method_calls_in_updates{0};
std::atomic<uint32_t> g_generator_poll_update_observation_mask{0};
thread_local unsigned g_generator_poll_update_scope_depth = 0;
thread_local uint64_t g_generator_poll_update_scope_spawn_calls = 0;
std::atomic<uint64_t> g_generator_poll_native_gate_calls{0};
std::atomic<uint64_t> g_generator_poll_native_gate_completed_calls{0};
std::atomic<uint64_t> g_generator_poll_native_gate_cooldown_blocks{0};
std::atomic<uint64_t> g_generator_poll_native_gate_quota_blocks{0};
std::atomic<uint64_t> g_generator_poll_native_gate_spawn_false{0};
std::atomic<uint64_t> g_generator_poll_native_gate_spawn_accepted{0};
std::atomic<uint64_t> g_generator_poll_native_gate_unknown{0};
std::atomic<uint32_t> g_generator_poll_native_gate_observation_mask{0};
thread_local unsigned g_generator_poll_native_gate_scope_depth = 0;
thread_local uint64_t g_generator_poll_native_gate_scope_spawn_calls = 0;
thread_local uint64_t g_generator_poll_native_gate_scope_spawn_true_calls = 0;
std::atomic<uint64_t> g_generator_poll_spawn_calls{0};
std::atomic<uint64_t> g_generator_poll_manager_readable_calls{0};
std::atomic<uint64_t> g_generator_poll_manager_present_calls{0};
std::atomic<uint64_t> g_generator_poll_methods_reaching_common_spawn{0};
std::atomic<uint64_t> g_generator_poll_common_spawn_calls{0};
std::atomic<uint64_t> g_generator_poll_gate_true_calls{0};
std::atomic<uint64_t> g_generator_poll_gate_false_calls{0};
std::atomic<uint32_t> g_generator_poll_observation_mask{0};
thread_local unsigned g_generator_poll_spawn_scope_depth = 0;
thread_local uint64_t g_generator_poll_scope_common_spawn_calls = 0;
std::atomic<unsigned> g_mission_result_extra_item_calls{0};
std::atomic<unsigned> g_mission_result_extra_item_aggregated_calls{0};
std::atomic<uint32_t> g_mission_result_extra_item_mask{0};
// Sanitized presence matrix for every decoded NetGameStatus::Item.  The bits
// identify only logical participants P0-P7; reward values are never retained.
std::atomic<uint32_t> g_mission_result_item_mask{0};
std::atomic<unsigned> g_mission_result_sync_begin_calls{0};
std::atomic<unsigned> g_mission_result_sync_poll_calls{0};
std::atomic<unsigned> g_mission_result_sync_complete_calls{0};
std::atomic<uint32_t> g_mission_result_sync_first_poll_logged_mask{0};
std::atomic<uint32_t> g_mission_result_sync_complete_logged_mask{0};
std::atomic<int32_t> g_mission_result_sync_last_state{-1};
std::atomic<int32_t> g_mission_result_sync_last_result{-1};
std::atomic<unsigned> g_mission_reward_resolve_calls{0};
std::atomic<unsigned> g_mission_reward_apply_calls{0};
// ApplyResult's boolean return reports an auxiliary native state transition,
// not whether rewards were applied. Track completed calls separately so a
// valid false return is never classified as a reward failure.
std::atomic<unsigned> g_mission_reward_apply_completed_calls{0};
// The session's local-control collection is the authoritative number of
// local save profiles.  MissionResult's fifth 0x3e90 block overlaps the
// native count at +0x2459c, so retain the independently observed value for a
// last-moment repair before ResolveResult/ApplyResult.
std::atomic<int32_t> g_mission_expected_local_profile_count{0};
std::atomic<unsigned> g_mission_reward_profile_count_repairs{0};
std::atomic<int> g_mission_result_sync_test_origin{-1};
std::atomic<uint64_t> g_diagnostic_flow_id{0};
std::atomic<uint64_t> g_diagnostic_progress_tick{0};
std::atomic<uint32_t> g_diagnostic_ready_mask{0};
std::atomic<uint32_t> g_diagnostic_mission_group_mask{0};
std::array<std::atomic<uint64_t>, 16> g_diagnostic_real_gameplay_peer_ids{};
std::atomic<unsigned> g_diagnostic_real_gameplay_peers{0};
std::atomic<const char*> g_diagnostic_phase{"idle"};
std::atomic<unsigned> g_debug_stage_win_test_set_calls{0};
std::atomic<uint32_t> g_mission_source_recycle_logged_mask{0};
std::atomic<uint32_t> g_mission_source_identity_repair_logged_mask{0};
std::atomic<uint32_t> g_mission_source_index_audit_logged_mask{0};
std::atomic<uint32_t> g_mission_source_consumer_audit_logged_mask{0};
std::atomic<uint32_t> g_mission_null_character_guard_logged_mask{0};
std::atomic<uint32_t> g_mission_player_control_audit_logged_mask{0};
std::atomic<uint32_t> g_mission_class_correction_logged_mask{0};
std::atomic<uint32_t> g_mission_visual_slot_remap_logged_mask{0};
std::atomic<unsigned> g_mission_loadout_parser_calls{0};
std::atomic<unsigned> g_mission_loadout_parser_protected_calls{0};
std::atomic<unsigned> g_mission_loadout_parser_oob_calls{0};
std::array<std::atomic<uintptr_t>, kReplicationParticipantCapacity>
    g_mission_participant_users{};
// One bit per participant whose local controller assignment was established
// by MissionPlayerCreate. This is the authoritative fallback when the
// replication producer's owner SharedProperty is empty or not a RuntimeUser.
std::atomic<uint32_t> g_mission_local_participant_mask{0};
std::atomic<bool> g_replication_participant_map_ready{false};
// Dimensions: direction (out/in), family (0x3300/0x3400), participant
// (0..7 plus one unresolved bucket). All values are aggregate counts only.
std::array<std::array<std::array<std::atomic<uint64_t>,
                                kReplicationParticipantCapacity + 1>, 2>, 2>
    g_replication_message_counts{};
std::array<std::array<std::array<std::atomic<uint64_t>,
                                kReplicationParticipantCapacity + 1>, 2>, 2>
    g_replication_last_summary_counts{};
std::array<std::array<std::atomic<uint16_t>, 2>, 2>
    g_replication_first_logged_masks{};
std::array<std::atomic<uint16_t>, 2>
    g_replication_send_fanout_first_logged_masks{};
std::atomic<uint64_t> g_replication_last_summary_tick{0};
std::atomic<uint64_t> g_replication_receive_route_signature{
    std::numeric_limits<uint64_t>::max()};
std::atomic<uint64_t> g_replication_receive_route_register_calls{0};
std::atomic<uint64_t> g_replication_receive_route_unregister_calls{0};
std::atomic<uint64_t> g_replication_receive_route_lifecycle_anomalies{0};
std::array<std::atomic<uint32_t>, kReplicationParticipantCapacity>
    g_chat_name_last_observed_tokens{};
std::atomic<uint32_t> g_chat_name_unresolved_first_logged{0};
std::atomic<uint64_t> g_chat_name_message_count{0};
std::atomic<uint64_t> g_chat_name_mismatch_count{0};
std::atomic<uintptr_t> g_game_window{0};
std::atomic<uintptr_t> g_original_window_proc{0};
HANDLE g_hotkey_thread = nullptr;
DWORD g_hotkey_thread_id = 0;
SRWLOCK g_state_lock = SRWLOCK_INIT;
SRWLOCK g_ready_user_lock = SRWLOCK_INIT;
SRWLOCK g_player_info_observation_lock = SRWLOCK_INIT;
SRWLOCK g_mission_extra_loadout_sidecar_lock = SRWLOCK_INIT;
// The result-sync hook and Mission() normally execute on the same thread, but
// native script dispatch is not contractually thread-affine. Keep the three
// recovery queue fields atomic for lock-free telemetry while serializing their
// publication/claim as one state transition.
SRWLOCK g_mission_result_exec_recovery_lock = SRWLOCK_INIT;
std::deque<SyntheticPacket> g_packets;
std::deque<MembershipChange> g_membership_changes;
std::deque<uint64_t> g_auth_validations;
std::string g_member_template = kFallbackMemberData;
std::vector<void*> g_ready_users;
std::array<TransportRouteAllocatorOwnerObservation,
           kTransportRouteAllocatorOwnerCapacity>
    g_transport_route_allocator_owners{};
std::array<PlayerInfoObservation, kPlayerInfoObservationCapacity>
    g_player_info_observations{};
std::array<MissionExtraLoadoutSidecar, kMissionExtraLoadoutBlockCount>
    g_mission_extra_loadout_sidecars{};
uint32_t g_next_player_info_name_token = 1;
UserConstructorFn g_user_constructor = nullptr;
UserDestructorFn g_user_destructor = nullptr;
UserPropertyGetterFn g_user_property_getter = nullptr;
UserPropertySetterFn g_user_property_setter = nullptr;
SharedPropertyReleaseFn g_shared_property_release = nullptr;
MissionSourceLookupFn g_mission_source_lookup = nullptr;
MissionSourceConsumerFn g_mission_source_consumer = nullptr;
MissionSharedHandleCopyFn g_mission_shared_handle_copy = nullptr;
MissionSourceCollectionCopyFn g_mission_source_collection_copy = nullptr;
MissionPlayerCreateFn g_mission_player_create = nullptr;
PlayerInfoBuilderFn g_player_info_builder = nullptr;
PlayerInfoFromUserFn g_player_info_from_user = nullptr;
UiLayoutCastFn g_ui_layout_cast = nullptr;
UiLayoutClampFn g_ui_layout_clamp = nullptr;
UiLayoutDestructorFn g_ui_layout_destructor = nullptr;
HUiRoomUpdateFn g_hui_room_update = nullptr;
MissionStartUpdateFn g_mission_start_update = nullptr;
MissionStartControllerFn g_mission_start_controller = nullptr;
MissionStartControllerContextFn g_mission_start_controller_context = nullptr;
MissionUpdateFn g_mission_update = nullptr;
MissionLoadoutParserFn g_mission_loadout_parser = nullptr;
MissionParticipantClassResolverFn g_mission_participant_class_resolver =
    nullptr;
#if EDF5_COMPILE_DIAGNOSTICS
ReportGsFailureFn g_report_gs_failure = nullptr;
#endif
MissionResultSetterFn g_mission_result_setter = nullptr;
MissionResultApplyFn g_mission_result_apply = nullptr;
MissionResultEventPublishFn g_mission_result_event_publish = nullptr;
MissionResultUiEventDispatchFn g_mission_result_ui_event_dispatch = nullptr;
MissionResultExecBeginFn g_mission_result_exec_begin = nullptr;
MissionResultExecUpdateFn g_mission_result_exec_update = nullptr;
MissionResultExecFinallyFn g_mission_result_exec_finally = nullptr;
EnemySpawnFn g_enemy_spawn = nullptr;
GeneratorPollUpdateFn g_generator_poll_update = nullptr;
GeneratorPollGateFn g_generator_poll_gate = nullptr;
GeneratorPollSpawnFn g_generator_poll_spawn = nullptr;
MissionResultItemSinkFn g_mission_result_item_sink = nullptr;
MissionNamedSyncBeginFn g_mission_named_sync_begin = nullptr;
MissionNamedSyncPollFn g_mission_named_sync_poll = nullptr;
MissionRewardResolveFn g_mission_reward_resolve = nullptr;
MissionRewardApplyFn g_mission_reward_apply = nullptr;
GameplayP2PSendFn g_gameplay_p2p_send = nullptr;
GameplayP2PDispatchFn g_gameplay_p2p_dispatch = nullptr;
GameplayMessageEnqueueFn g_gameplay_message_enqueue = nullptr;
GameplayReplicationProducerFn g_gameplay_replication_producer = nullptr;
GameplayReplicationSerializerFn g_gameplay_replication_serializer = nullptr;
GameplayReplicationReceivePumpFn g_gameplay_replication_receive_pump =
    nullptr;
GameplayReplicationReceiveParserFn g_gameplay_replication_receive_parser =
    nullptr;
GameplayReplicationReceiveRouteFn
    g_gameplay_replication_receive_route_register = nullptr;
GameplayReplicationReceiveRouteFn
    g_gameplay_replication_receive_route_unregister = nullptr;
MissionScriptMessageDispatchFn g_mission_script_message_dispatch = nullptr;
ChatRoomConstructorFn g_chat_room_constructor = nullptr;
ChatMessagePublishFn g_chat_message_publish = nullptr;
ChatSystemMessagePublishFn g_chat_system_message_publish = nullptr;
void** g_mission_manager_slot = nullptr;
void** g_mission_loadout_state_slot = nullptr;
void** g_mission_result_event_publisher_slot = nullptr;
thread_local bool g_mission_result_setter_publish_scope = false;
thread_local void* g_replication_outgoing_user = nullptr;
thread_local bool g_replication_outgoing_local_control_fallback = false;
void** g_runtime_user_vtable = nullptr;
void** g_runtime_ui_layout_vtable = nullptr;
void** g_runtime_chat_room_vtable = nullptr;
std::atomic<uintptr_t> g_chat_room_instance{0};
std::atomic<uintptr_t> g_players_group_layout{0};
std::atomic<uint64_t> g_players_group_capture_tick{0};
uintptr_t g_module_base = 0;
size_t g_module_image_size = 0;
thread_local MissionSourceCollectionSnapshot
    g_mission_source_primary_snapshot{};
thread_local MissionSourceCollectionSnapshot
    g_mission_source_local_snapshot{};
thread_local MissionPlayerCreateTrace g_mission_player_create_trace{};
thread_local MissionLoadoutBlockPatch g_mission_loadout_block_patch{};
thread_local MissionLoadoutParserProtection
    g_mission_loadout_parser_protection{};
thread_local void* g_replication_incoming_user = nullptr;

void PublishDiagnosticState(const char* phase = nullptr,
                            bool progress = false) {
    const char* previous = g_diagnostic_phase.load(std::memory_order_acquire);
    bool changed = false;
    if (phase && *phase) {
        previous = g_diagnostic_phase.exchange(phase,
                                                std::memory_order_acq_rel);
        changed = !previous || std::strcmp(previous, phase) != 0;
    }
    if (progress || changed) {
        g_diagnostic_progress_tick.store(GetTickCount64(),
                                         std::memory_order_release);
    }
    capture::RuntimeState state;
    state.flow_id = g_diagnostic_flow_id.load(std::memory_order_acquire);
    state.lobby_steam_id = g_owned_lobby.load(std::memory_order_acquire);
    state.last_progress_tick =
        g_diagnostic_progress_tick.load(std::memory_order_acquire);
    state.mission_generation =
        g_mission_generation.load(std::memory_order_acquire);
    state.gameplay_contact_mask =
        g_gameplay_contact_mask.load(std::memory_order_acquire);
    state.real_gameplay_peers =
        g_diagnostic_real_gameplay_peers.load(std::memory_order_acquire);
    state.ready_mask =
        g_diagnostic_ready_mask.load(std::memory_order_acquire);
    state.mission_group_mask =
        g_diagnostic_mission_group_mask.load(std::memory_order_acquire);
    state.actual_members =
        g_last_actual_member_count.load(std::memory_order_acquire);
    state.mission_ui_state =
        g_mission_ui_state.load(std::memory_order_acquire);
    state.synthetic_members = g_bot_count.load(std::memory_order_acquire);
    state.max_players = capture::GetConfig().max_players;
    std::snprintf(state.phase, sizeof(state.phase), "%s",
                  g_diagnostic_phase.load(std::memory_order_acquire));
    EDF5_CAPTURE_UPDATE_RUNTIME_STATE(state);
    if (changed) {
        EDF5_CRASH_BREADCRUMB("flow", "state_transition", state.phase,
                                  state.flow_id, state.lobby_steam_id);
        EDF5_CAPTURE_EVENT(capture::Level::Info, "flow", "state_transition",
                       capture::Fields().UInt("flow_id", state.flow_id)
                           .String("from", previous ? previous : "unknown")
                           .String("to", state.phase)
                           .UInt("lobby_steam_id", state.lobby_steam_id)
                           .Int("actual_members", state.actual_members)
                           .UInt("real_gameplay_peers",
                                 state.real_gameplay_peers)
                           .UInt("synthetic_members",
                                 state.synthetic_members));
    }
}

struct FakeReadyUser {
    void** vtable = nullptr;
    std::array<uint8_t, kUserReadyFlagOffset - sizeof(void*)> before_ready{};
    std::atomic<uint8_t> ready{0};
    uint64_t steam_id = 0;
    std::atomic<unsigned> write_calls{0};
    std::atomic<bool> cm_ready{false};
    std::atomic<bool> ds_ready{false};
    std::atomic<unsigned> cm_write_calls{0};
    std::atomic<unsigned> ds_write_calls{0};
    std::string l1;
    std::string l2;
    std::atomic<unsigned> l1_write_calls{0};
    std::atomic<unsigned> l2_write_calls{0};
};

static_assert(offsetof(FakeReadyUser, ready) == kUserReadyFlagOffset,
              "fake Ready flag must mirror net::Users::User");

struct FakeMissionUi {
    std::array<uint8_t, kMissionUiStateOffset> before_state{};
    int32_t state = kMissionUiStateRunning;
    int32_t result = 0;
};

struct FakeMissionManager {
    std::array<uint8_t, kMissionManagerUiOffset> before_ui{};
    FakeMissionUi* ui = nullptr;
    int32_t cached_result = 0;
    int32_t active_result = 0;
};

struct FakeMissionResultSyncState {
    int32_t phase = 0;
    int32_t result = -1;
};

struct FakeMissionResultUiObject {
    std::array<uint8_t, kUiObjectEventFlagsOffset> before_flags{};
    uint32_t flags = 0;
    std::array<uint8_t, kUiObjectEventIdOffset -
                           kUiObjectEventFlagsOffset - sizeof(flags)>
        before_id{};
    int32_t id = kMissionResultEventPayload;
};

std::atomic<unsigned> g_fake_mission_result_exec_begin_calls{0};
std::atomic<int32_t> g_fake_mission_result_exec_begin_argument{0};
std::atomic<unsigned> g_fake_mission_result_exec_update_calls{0};
std::atomic<int32_t> g_fake_mission_result_exec_update_argument{0};
std::atomic<bool> g_fake_mission_result_exec_update_result{false};
std::atomic<unsigned> g_fake_mission_result_exec_finally_calls{0};
std::atomic<int32_t> g_fake_mission_result_exec_finally_argument{0};
std::atomic<unsigned> g_fake_replication_route_register_calls{0};
std::atomic<unsigned> g_fake_replication_route_unregister_calls{0};
std::atomic<unsigned> g_fake_enemy_spawn_calls{0};
std::atomic<uint32_t> g_fake_enemy_spawn_requested_count{0};
std::atomic<uint32_t> g_fake_enemy_spawn_numerator_seen{0};
std::atomic<unsigned> g_fake_generator_poll_update_calls{0};
std::atomic<unsigned> g_fake_generator_poll_gate_calls{0};
std::atomic<unsigned> g_fake_generator_poll_spawn_calls{0};
std::atomic<uintptr_t> g_fake_generator_poll_spawn_result{0};
void* g_fake_generator_poll_spawn_owner = nullptr;
std::atomic<unsigned> g_fake_mission_result_item_sink_calls{0};
std::atomic<unsigned> g_fake_mission_result_event_publish_calls{0};
std::atomic<int32_t> g_fake_mission_result_event_type{0};
std::atomic<int32_t> g_fake_mission_result_event_payload{0};
std::atomic<unsigned> g_fake_mission_result_ui_dispatch_calls{0};
std::atomic<unsigned> g_fake_mission_sync_begin_calls{0};
std::atomic<unsigned> g_fake_mission_sync_poll_calls{0};
std::atomic<unsigned> g_fake_mission_reward_resolve_calls{0};
std::atomic<unsigned> g_fake_mission_reward_apply_calls{0};
std::atomic<int32_t> g_fake_mission_source_consumer_loadout_index{-1};
std::atomic<int32_t> g_fake_mission_update_override{-1};
std::atomic<unsigned> g_fake_mission_loadout_parser_calls{0};
std::atomic<unsigned> g_fake_mission_class_resolver_calls{0};
std::atomic<int32_t> g_fake_mission_class_resolver_index{4};
std::atomic<int32_t> g_fake_mission_class_resolver_class{0};
std::atomic<unsigned> g_fake_player_info_from_user_calls{0};
std::atomic<unsigned> g_fake_chat_system_publish_calls{0};
std::atomic<bool> g_fake_chat_system_publish_valid{false};
std::atomic<uintptr_t> g_fake_chat_expected_room_instance{0};

static_assert(offsetof(FakeMissionUi, state) == kMissionUiStateOffset &&
                  offsetof(FakeMissionUi, result) == kMissionUiResultOffset,
              "fake mission UI layout changed");
static_assert(offsetof(FakeMissionManager, ui) == kMissionManagerUiOffset &&
                  offsetof(FakeMissionManager, active_result) ==
                      kMissionManagerResultOffset,
              "fake mission manager layout changed");
static_assert(offsetof(FakeMissionResultUiObject, flags) ==
                      kUiObjectEventFlagsOffset &&
                  offsetof(FakeMissionResultUiObject, id) ==
                      kUiObjectEventIdOffset,
              "fake mission result UI object layout changed");

FakeMissionResultUiObject* g_fake_mission_result_ui_object = nullptr;

void __fastcall MissionResultEventPublishHook(void* publisher,
                                              int32_t event_type,
                                              const void* payload);
bool __fastcall MissionResultUiEventDispatchHook(void* listener,
                                                 int32_t event_type,
                                                 const void* payload);
void __fastcall EnemySpawnHook(void* owner, void* spawn_descriptor,
                               uint32_t requested_count);
void __fastcall GeneratorPollUpdateHook(void* generator,
                                        void* frame_context);
void __fastcall GeneratorPollGateHook(void* gate_state, void* owner);
uintptr_t __fastcall GeneratorPollSpawnHook(void* generator,
                                            void* spawn_descriptor);

uint64_t __fastcall FakeUserIdGetter(void* object) {
    return static_cast<FakeReadyUser*>(object)->steam_id;
}

uint64_t __fastcall FakeRuntimeUserIdGetter(void* object) {
    uint64_t value = 0;
    if (object) {
        std::memcpy(&value,
                    static_cast<const uint8_t*>(object) +
                        kUserMissionSortKeyOffset,
                    sizeof(value));
    }
    return value;
}

uint8_t* __fastcall FakePlayerInfoFromUser(
    uint8_t* destination, const SharedProperty*) {
    g_fake_player_info_from_user_calls.fetch_add(
        1, std::memory_order_acq_rel);
    return destination;
}

void __fastcall FakeChatSystemMessagePublish(void* room,
                                             const wchar_t* text) {
    const unsigned call = g_fake_chat_system_publish_calls.fetch_add(
        1, std::memory_order_acq_rel);
    const wchar_t* expected_text = nullptr;
    switch (call % 3) {
    case 0: expected_text = mod_info::kChatBanner; break;
    case 1: expected_text = mod_info::kChatInviteHintLine1; break;
    default: expected_text = mod_info::kChatInviteHintLine2; break;
    }
    const bool valid =
        reinterpret_cast<uintptr_t>(room) ==
            g_fake_chat_expected_room_instance.load(
                std::memory_order_acquire) &&
        text && std::wcscmp(text, expected_text) == 0;
    if (!valid) {
        g_fake_chat_system_publish_valid.store(
            false, std::memory_order_release);
    }
}

void __fastcall FakeMissionResultSetter(void* object, int32_t result) {
    auto* manager = static_cast<FakeMissionManager*>(object);
    if (!manager || !manager->ui) return;
    manager->active_result = result;
    manager->ui->state = kMissionUiStateFinished;
    manager->ui->result = result;
    if (g_mission_result_event_publish) {
        int32_t payload = kMissionResultEventPayload;
        void* publisher_owner = g_mission_result_event_publisher_slot
            ? *g_mission_result_event_publisher_slot : nullptr;
        MissionResultEventPublishHook(
            publisher_owner, kMissionResultEventType, &payload);
    }
    g_debug_stage_win_test_set_calls.fetch_add(1, std::memory_order_acq_rel);
}

int __fastcall FakeMissionUpdate() {
    const int32_t override_result = g_fake_mission_update_override.load(
        std::memory_order_acquire);
    if (override_result >= 0) return override_result;
    auto* manager = g_mission_manager_slot
        ? static_cast<FakeMissionManager*>(*g_mission_manager_slot)
        : nullptr;
    if (!manager || !manager->ui) return 0;
    return manager->ui->state == kMissionUiStateFinished
        ? manager->ui->result : 0;
}

bool __fastcall FakeMissionResultExecBegin(int32_t argument) {
    g_fake_mission_result_exec_begin_calls.fetch_add(
        1, std::memory_order_acq_rel);
    g_fake_mission_result_exec_begin_argument.store(
        argument, std::memory_order_release);
    return argument == kMissionResultSelfTestArgument;
}

bool __fastcall FakeMissionResultExecUpdate(int32_t argument, void*) {
    g_fake_mission_result_exec_update_calls.fetch_add(
        1, std::memory_order_acq_rel);
    g_fake_mission_result_exec_update_argument.store(
        argument, std::memory_order_release);
    return g_fake_mission_result_exec_update_result.load(
        std::memory_order_acquire);
}

void __fastcall FakeMissionResultExecFinally(int32_t argument) {
    g_fake_mission_result_exec_finally_calls.fetch_add(
        1, std::memory_order_acq_rel);
    g_fake_mission_result_exec_finally_argument.store(
        argument, std::memory_order_release);
}

bool __fastcall FakeReplicationReceiveRouteRegister(
    void*, const SharedProperty*) {
    g_fake_replication_route_register_calls.fetch_add(
        1, std::memory_order_acq_rel);
    return true;
}

bool __fastcall FakeReplicationReceiveRouteUnregister(
    void*, const SharedProperty*) {
    g_fake_replication_route_unregister_calls.fetch_add(
        1, std::memory_order_acq_rel);
    return false;
}

void __fastcall FakeEnemySpawn(void* owner, void*, uint32_t requested_count) {
    uint32_t numerator = 0;
    if (owner) {
        std::memcpy(&numerator,
                    static_cast<const uint8_t*>(owner) +
                        kEnemySpawnScaleNumeratorOffset,
                    sizeof(numerator));
    }
    g_fake_enemy_spawn_requested_count.store(
        requested_count, std::memory_order_release);
    g_fake_enemy_spawn_numerator_seen.store(
        numerator, std::memory_order_release);
    g_fake_enemy_spawn_calls.fetch_add(1, std::memory_order_acq_rel);
}

uintptr_t __fastcall FakeGeneratorPollSpawn(void*, void* spawn_descriptor) {
    g_fake_generator_poll_spawn_calls.fetch_add(
        1, std::memory_order_acq_rel);
    EnemySpawnHook(g_fake_generator_poll_spawn_owner,
                   spawn_descriptor, 1);
    return static_cast<uintptr_t>(0x101);
}

uintptr_t __fastcall FakeGeneratorPollSpawnFalse(void*, void*) {
    g_fake_generator_poll_spawn_calls.fetch_add(
        1, std::memory_order_acq_rel);
    return 0;
}

void __fastcall FakeGeneratorPollGate(void*, void* generator) {
    g_fake_generator_poll_gate_calls.fetch_add(
        1, std::memory_order_acq_rel);
    const uintptr_t result = GeneratorPollSpawnHook(generator, nullptr);
    g_fake_generator_poll_spawn_result.store(
        result, std::memory_order_release);
}

void __fastcall FakeGeneratorPollGateNoSpawn(void*, void*) {
    g_fake_generator_poll_gate_calls.fetch_add(
        1, std::memory_order_acq_rel);
}

void __fastcall FakeGeneratorPollUpdate(void* generator,
                                        void*) {
    g_fake_generator_poll_update_calls.fetch_add(
        1, std::memory_order_acq_rel);
    GeneratorPollGateHook(
        static_cast<uint8_t*>(generator) + kGeneratorPollGateStateOffset,
        generator);
}

void __fastcall FakeMissionResultItemSink(
    void*, const int32_t* participant_index, const uint64_t* item) {
    if (!participant_index || !item || !g_mission_loadout_state_slot ||
        !*g_mission_loadout_state_slot || *participant_index < 0 ||
        *participant_index >=
            static_cast<int32_t>(kMissionResultNativeItemCount)) {
        return;
    }
    auto* state = static_cast<uint8_t*>(*g_mission_loadout_state_slot);
    std::memcpy(state + kMissionResultItemArrayOffset +
                    static_cast<size_t>(*participant_index) *
                        kMissionResultItemSize,
                item, sizeof(*item));
    g_fake_mission_result_item_sink_calls.fetch_add(
        1, std::memory_order_acq_rel);
}

void __fastcall FakeMissionResultEventPublish(void*, int32_t event_type,
                                               const void* payload) {
    int32_t payload_value = 0;
    if (payload) {
        std::memcpy(&payload_value, payload, sizeof(payload_value));
    }
    g_fake_mission_result_event_type.store(
        event_type, std::memory_order_release);
    g_fake_mission_result_event_payload.store(
        payload_value, std::memory_order_release);
    g_fake_mission_result_event_publish_calls.fetch_add(
        1, std::memory_order_acq_rel);
    if (g_fake_mission_result_ui_object &&
        g_mission_result_ui_event_dispatch) {
        MissionResultUiEventDispatchHook(g_fake_mission_result_ui_object,
                                         event_type, payload);
    }
}

bool __fastcall FakeMissionResultUiEventDispatch(void* listener,
                                                 int32_t event_type,
                                                 const void* payload) {
    auto* object = static_cast<FakeMissionResultUiObject*>(listener);
    int32_t payload_value = -1;
    if (payload) {
        std::memcpy(&payload_value, payload, sizeof(payload_value));
    }
    if (object && event_type == kMissionResultEventType &&
        object->id == payload_value) {
        object->flags |= kUiObjectClosingFlag;
    }
    g_fake_mission_result_ui_dispatch_calls.fetch_add(
        1, std::memory_order_acq_rel);
    return true;
}

void __fastcall FakeMissionNamedSyncBegin(void* object, const char*) {
    auto* state = static_cast<FakeMissionResultSyncState*>(object);
    if (state) {
        state->phase = 1;
        state->result = 1;
    }
    g_fake_mission_sync_begin_calls.fetch_add(1,
                                               std::memory_order_acq_rel);
}

void __fastcall FakeMissionNamedSyncPoll(void* object) {
    auto* state = static_cast<FakeMissionResultSyncState*>(object);
    if (state) {
        state->phase = 1;
        state->result = 0;
    }
    g_fake_mission_sync_poll_calls.fetch_add(1,
                                              std::memory_order_acq_rel);
}

void __fastcall FakeMissionRewardResolve() {
    g_fake_mission_reward_resolve_calls.fetch_add(
        1, std::memory_order_acq_rel);
}

bool __fastcall FakeMissionRewardApply(bool is_mission_clear) {
    (void)is_mission_clear;
    g_fake_mission_reward_apply_calls.fetch_add(
        1, std::memory_order_acq_rel);
    // The real five-player reports returned false after a fully completed
    // reward call. Preserve that contract in the runtime self-test.
    return false;
}

void WriteReadyFlag(void* object, bool test_mode) {
    if (test_mode) {
        auto* user = static_cast<FakeReadyUser*>(object);
        user->ready.store(1, std::memory_order_release);
        user->write_calls.fetch_add(1, std::memory_order_acq_rel);
        return;
    }
    auto* state_lock = reinterpret_cast<CRITICAL_SECTION*>(
        static_cast<uint8_t*>(object) + kUserStateLockOffset);
    EnterCriticalSection(state_lock);
    *reinterpret_cast<volatile uint8_t*>(
        static_cast<uint8_t*>(object) + kUserReadyFlagOffset) = 1;
    LeaveCriticalSection(state_lock);
}

bool ReadReadyFlag(void* object, bool test_mode) {
    if (test_mode) {
        return static_cast<FakeReadyUser*>(object)->ready.load(
                   std::memory_order_acquire) != 0;
    }
    auto* state_lock = reinterpret_cast<CRITICAL_SECTION*>(
        static_cast<uint8_t*>(object) + kUserStateLockOffset);
    EnterCriticalSection(state_lock);
    const bool ready = *reinterpret_cast<volatile const uint8_t*>(
                           static_cast<const uint8_t*>(object) +
                           kUserReadyFlagOffset) != 0;
    LeaveCriticalSection(state_lock);
    return ready;
}

bool SetSyntheticUserProperty(void* object, const char* key,
                              const char* value, bool test_mode) {
    if (!object || !key || !value) return false;
    if (test_mode) {
        auto* user = static_cast<FakeReadyUser*>(object);
        if (std::strcmp(key, "cm") == 0) {
            const bool ready = std::strcmp(value, "c1") == 0;
            user->cm_ready.store(ready, std::memory_order_release);
            user->cm_write_calls.fetch_add(1, std::memory_order_acq_rel);
            return ready;
        }
        if (std::strcmp(key, "ds") == 0) {
            const bool ready = std::strcmp(value, "ds") == 0;
            user->ds_ready.store(ready, std::memory_order_release);
            user->ds_write_calls.fetch_add(1, std::memory_order_acq_rel);
            return ready;
        }
        if (std::strcmp(key, "l1") == 0) {
            user->l1 = value;
            user->l1_write_calls.fetch_add(1, std::memory_order_acq_rel);
            return true;
        }
        if (std::strcmp(key, "l2") == 0) {
            user->l2 = value;
            user->l2_write_calls.fetch_add(1, std::memory_order_acq_rel);
            return true;
        }
        return false;
    }

    if (!g_user_property_setter || !g_shared_property_release) return false;
    void* properties = *reinterpret_cast<void**>(
        static_cast<uint8_t*>(object) + kUserPropertyObjectOffset);
    if (!properties) return false;

    SharedProperty result{};
    g_user_property_setter(properties, &result, key, value);
    const bool success = result.control != nullptr && result.object != nullptr;
    g_shared_property_release(&result);
    return success;
}

bool ReadUserProperty(void* object, const char* key, std::string& value,
                      bool test_mode) {
    value.clear();
    if (!object || !key) return false;
    if (test_mode) {
        const auto* user = static_cast<const FakeReadyUser*>(object);
        if (std::strcmp(key, "l1") == 0) value = user->l1;
        else if (std::strcmp(key, "l2") == 0) value = user->l2;
        else return false;
        return true;
    }

    if (!g_user_property_getter || !g_shared_property_release) return false;
    void* properties = *reinterpret_cast<void**>(
        static_cast<uint8_t*>(object) + kUserPropertyObjectOffset);
    if (!properties) return false;

    SharedProperty result{};
    g_user_property_getter(properties, &result, key);
    bool success = false;
    if (result.control && result.object) {
        // The native property object stores its MSVC std::string value at
        // +0x28. Read that layout explicitly because this plugin is built
        // with MinGW and cannot bind to the game's C++ standard library ABI.
        const auto* native_string = static_cast<const uint8_t*>(result.object) + 0x28;
        const uint64_t length = *reinterpret_cast<const uint64_t*>(
            native_string + 0x10);
        const uint64_t capacity = *reinterpret_cast<const uint64_t*>(
            native_string + 0x18);
        if (length <= capacity && length <= 4096) {
            const char* text = capacity < 0x10
                ? reinterpret_cast<const char*>(native_string)
                : *reinterpret_cast<const char* const*>(native_string);
            if (text && text[length] == '\0') {
                value.assign(text, static_cast<size_t>(length));
                success = value.find('\0') == std::string::npos;
                if (!success) value.clear();
            }
        }
    }
    g_shared_property_release(&result);
    return success;
}

const wchar_t* BaseName(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* slash = std::wcsrchr(path, L'\\');
    const wchar_t* forward = std::wcsrchr(path, L'/');
    const wchar_t* last = slash;
    if (!last || (forward && forward > last)) last = forward;
    return last ? last + 1 : path;
}

bool IsEdf5Process() {
    wchar_t path[32768]{};
    if (!GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)))) {
        return false;
    }
    return _wcsicmp(BaseName(path), L"EDF5.exe") == 0;
}

bool TryPlayerInfoBotIndex(const uint8_t* object, unsigned requested,
                           unsigned& index) {
    if (!object || !requested) return false;
    const uint64_t length = *reinterpret_cast<const uint64_t*>(
        object + kPlayerInfoNameLengthOffset);
    const uint64_t capacity = *reinterpret_cast<const uint64_t*>(
        object + kPlayerInfoNameCapacityOffset);
    if (length < 9 || length > 10 || capacity < length) return false;
    const wchar_t* name = capacity >= 8
        ? *reinterpret_cast<const wchar_t* const*>(
              object + kPlayerInfoNameStorageOffset)
        : reinterpret_cast<const wchar_t*>(
              object + kPlayerInfoNameStorageOffset);
    if (!name) return false;
    constexpr wchar_t prefix[] = L"EDF Bot ";
    for (size_t offset = 0; offset < _countof(prefix) - 1; ++offset) {
        if (name[offset] != prefix[offset]) return false;
    }
    unsigned number = 0;
    for (uint64_t offset = _countof(prefix) - 1; offset < length; ++offset) {
        if (name[offset] < L'0' || name[offset] > L'9') return false;
        number = number * 10 + static_cast<unsigned>(name[offset] - L'0');
    }
    if (!number || number > requested) return false;
    index = number - 1;
    return true;
}

bool HasUsablePlayerInfoLoadout(const uint8_t* object) {
    if (!object || *reinterpret_cast<const int*>(
                       object + kPlayerInfoClassOffset) == -1) {
        return false;
    }
    for (size_t slot = 0; slot < 6; ++slot) {
        const int item = *reinterpret_cast<const int*>(
            object + kPlayerInfoWeaponsOffset + slot * sizeof(int));
        if (item != -1) return true;
    }
    return false;
}

void CopyPlayerInfoLoadout(uint8_t* destination, const uint8_t* source) {
    // Preserve name, identity-adjacent state (+0x00..+0x27), voice/status
    // fields (+0x50/+0x58), and copy only class/equipment-related values.
    std::memcpy(destination + kPlayerInfoClassOffset,
                source + kPlayerInfoClassOffset, 2 * sizeof(int));
    std::memcpy(destination + kPlayerInfoWeaponsOffset,
                source + kPlayerInfoWeaponsOffset, 6 * sizeof(int));
    std::memcpy(destination + kPlayerInfoWeaponValidityOffset,
                source + kPlayerInfoWeaponValidityOffset, 6);
    std::memcpy(destination + kPlayerInfoArmorOffset,
                source + kPlayerInfoArmorOffset, sizeof(float));
}

bool CloneHostLoadout(PlayerInfoVector* players, unsigned requested,
                      unsigned actual_members,
                      LoadoutCloneStats& stats) {
    stats = {};
    stats.requested = requested;
    if (!players || !players->entries || !requested ||
        players->size == 0 || players->size > 32 ||
        players->size > players->capacity) {
        return false;
    }

    const uint8_t* host = nullptr;
    unsigned usable_count = 0;
    int unique_usable_position = -1;
    for (uint64_t position = 0; position < players->size; ++position) {
        const uint8_t* object = players->entries[position].object;
        unsigned bot_index = 0;
        if (TryPlayerInfoBotIndex(object, requested, bot_index)) {
            const uint32_t bit = uint32_t{1} << bot_index;
            if ((stats.recognized_mask & bit) == 0) ++stats.recognized;
            stats.recognized_mask |= bit;
        } else if (HasUsablePlayerInfoLoadout(object)) {
            if (!host) {
                host = object;
                stats.host_position = static_cast<int>(position);
            }
            ++usable_count;
            unique_usable_position = static_cast<int>(position);
        }
    }
    const bool use_single_real_fallback = stats.recognized == 0 &&
        actual_members == 1 && players->size == requested + 1;
    stats.used_single_real_fallback = use_single_real_fallback;

    if (use_single_real_fallback) {
        // The synthetic Steam entries are appended after the real members, but
        // the transient display-name field cannot be used to recognize them.
        // Remember the unique equipped entry observed before the first clone;
        // on later frames every filler is equipped too, so the remembered
        // position prevents a filler from becoming the source accidentally.
        int preferred = g_single_real_host_position.load(
            std::memory_order_acquire);
        if (preferred < 0 ||
            static_cast<uint64_t>(preferred) >= players->size ||
            !HasUsablePlayerInfoLoadout(
                players->entries[preferred].object)) {
            preferred = usable_count == 1 ? unique_usable_position : 0;
            if (preferred < 0 ||
                static_cast<uint64_t>(preferred) >= players->size ||
                !HasUsablePlayerInfoLoadout(
                    players->entries[preferred].object)) {
                return false;
            }
            g_single_real_host_position.store(preferred,
                                               std::memory_order_release);
        }
        host = players->entries[preferred].object;
        stats.host_position = preferred;
    }
    if (!host) return false;

    stats.host_class = *reinterpret_cast<const int*>(
        host + kPlayerInfoClassOffset);
    stats.host_first_weapon = *reinterpret_cast<const int*>(
        host + kPlayerInfoWeaponsOffset);
    for (uint64_t position = 0; position < players->size; ++position) {
        uint8_t* object = players->entries[position].object;
        unsigned bot_index = 0;
        bool target = TryPlayerInfoBotIndex(object, requested, bot_index);
        if (!target && use_single_real_fallback && object != host) {
            target = true;
            bot_index = stats.copied;
        }
        if (!target) continue;
        CopyPlayerInfoLoadout(object, host);
        if (use_single_real_fallback && bot_index < 32) {
            stats.recognized_mask |= uint32_t{1} << bot_index;
            ++stats.recognized;
        }
        ++stats.copied;
    }
    const uint32_t expected_mask = (uint32_t{1} << requested) - 1;
    return stats.recognized_mask == expected_mask && stats.copied == requested;
}

bool ValidatePeImage(uint8_t* base, size_t& image_size) {
    if (!base) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    image_size = nt->OptionalHeader.SizeOfImage;
    return image_size >= std::max(
        std::max(kUserVtableRva + 11 * sizeof(void*),
                 kUiLayoutVtableRva + 2 * sizeof(void*)),
        kMissionManagerSlotRva + sizeof(void*));
}

bool SignatureMatches(const uint8_t* base, size_t image_size, uintptr_t rva,
                      const uint8_t* expected, size_t expected_size) {
    const bool matches = base && expected && rva <= image_size &&
                         expected_size <= image_size - rva &&
                         std::memcmp(base + rva, expected, expected_size) == 0;
    if (!matches) {
        char reason[128]{};
        std::snprintf(reason, sizeof(reason),
                      "EDF5 signature mismatch at RVA 0x%llx (%llu bytes)",
                      static_cast<unsigned long long>(rva),
                      static_cast<unsigned long long>(expected_size));
        hooks::ReportStartupFailure(reason);
    }
    return matches;
}

bool RelativeCallTargets(const uint8_t* base, size_t image_size,
                         uintptr_t call_rva, uintptr_t target_rva) {
    if (!base || call_rva > image_size || 5 > image_size - call_rva ||
        base[call_rva] != 0xe8) {
        return false;
    }
    int32_t displacement = 0;
    std::memcpy(&displacement, base + call_rva + 1,
                sizeof(displacement));
    const int64_t resolved = static_cast<int64_t>(call_rva) + 5 +
        static_cast<int64_t>(displacement);
    return resolved >= 0 &&
        static_cast<uintptr_t>(resolved) == target_rva;
}

bool RelativeJumpTargets(const uint8_t* base, size_t image_size,
                         uintptr_t jump_rva, uintptr_t target_rva) {
    if (!base || jump_rva > image_size || 5 > image_size - jump_rva ||
        base[jump_rva] != 0xe9) {
        return false;
    }
    int32_t displacement = 0;
    std::memcpy(&displacement, base + jump_rva + 1,
                sizeof(displacement));
    const int64_t resolved = static_cast<int64_t>(jump_rva) + 5 +
        static_cast<int64_t>(displacement);
    return resolved >= 0 &&
        static_cast<uintptr_t>(resolved) == target_rva;
}

bool ValidateEnemySpawnLayout(uint8_t* base, size_t image_size) {
    if (!SignatureMatches(base, image_size, kEnemySpawnRva,
                          kEnemySpawnSignature,
                          sizeof(kEnemySpawnSignature)) ||
        !SignatureMatches(base, image_size, kEnemySpawnCountAndCapRva,
                          kEnemySpawnCountAndCapSignature,
                          sizeof(kEnemySpawnCountAndCapSignature)) ||
        !SignatureMatches(base, image_size, kEnemySpawnScaleLayoutRva,
                          kEnemySpawnScaleLayoutSignature,
                          sizeof(kEnemySpawnScaleLayoutSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollUpdateRva,
                          kGeneratorPollUpdateSignature,
                          sizeof(kGeneratorPollUpdateSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollBaseUpdateRva,
                          kGeneratorPollBaseUpdateSignature,
                          sizeof(kGeneratorPollBaseUpdateSignature)) ||
        !SignatureMatches(base, image_size,
                          kGeneratorPollBaseGateTailRva,
                          kGeneratorPollBaseGateTailSignature,
                          sizeof(kGeneratorPollBaseGateTailSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollSpawnRva,
                          kGeneratorPollSpawnSignature,
                          sizeof(kGeneratorPollSpawnSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollManagerGateRva,
                          kGeneratorPollManagerAndSpawnSignature,
                          sizeof(kGeneratorPollManagerAndSpawnSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollReturnRva,
                          kGeneratorPollReturnSignature,
                          sizeof(kGeneratorPollReturnSignature)) ||
        !SignatureMatches(base, image_size, kGeneratorPollGateRva,
                          kGeneratorPollGateSignature,
                          sizeof(kGeneratorPollGateSignature)) ||
        !SignatureMatches(base, image_size,
                          kGeneratorPollGateVirtualCallRva,
                          kGeneratorPollGateVirtualCallSignature,
                          sizeof(kGeneratorPollGateVirtualCallSignature))) {
        return false;
    }
    if (!RelativeCallTargets(base, image_size,
                             kGeneratorPollBaseUpdateCallRva,
                             kGeneratorPollBaseUpdateRva) ||
        !RelativeJumpTargets(base, image_size,
                             kGeneratorPollBaseGateTailCallRva,
                             kGeneratorPollGateRva)) {
        hooks::ReportStartupFailure(
            "GeneratorPoll update/base/gate chain changed");
        return false;
    }
    if (!RelativeCallTargets(base, image_size,
                             kGeneratorPollCommonSpawnCallRva,
                             kEnemySpawnRva)) {
        hooks::ReportStartupFailure(
            "GeneratorPoll common spawn call target changed");
        return false;
    }
    if (kGeneratorPollVtableUpdateEntryRva > image_size ||
        sizeof(uintptr_t) >
            image_size - kGeneratorPollVtableUpdateEntryRva ||
        kGeneratorPollVtableSpawnEntryRva > image_size ||
        sizeof(uintptr_t) >
            image_size - kGeneratorPollVtableSpawnEntryRva) {
        hooks::ReportStartupFailure(
            "GeneratorPoll vtable update/spawn entry is outside EDF5 image");
        return false;
    }
    uintptr_t generator_poll_update_entry = 0;
    uintptr_t generator_poll_entry = 0;
    std::memcpy(&generator_poll_update_entry,
                base + kGeneratorPollVtableUpdateEntryRva,
                sizeof(generator_poll_update_entry));
    std::memcpy(&generator_poll_entry,
                base + kGeneratorPollVtableSpawnEntryRva,
                sizeof(generator_poll_entry));
    if (generator_poll_update_entry != reinterpret_cast<uintptr_t>(
            base + kGeneratorPollUpdateRva) ||
        kGeneratorPollVtableUpdateEntryRva - kGeneratorPollVtableRva !=
            kGeneratorPollVirtualUpdateOffset ||
        generator_poll_entry != reinterpret_cast<uintptr_t>(
            base + kGeneratorPollSpawnRva) ||
        kGeneratorPollVtableSpawnEntryRva - kGeneratorPollVtableRva !=
            kGeneratorPollVirtualSpawnOffset) {
        hooks::ReportStartupFailure(
            "GeneratorPoll vtable update/spawn mapping changed");
        return false;
    }
    for (const uintptr_t call_rva :
         mission_spawn::kConfirmedEnemySpawnCallRvas) {
        if (RelativeCallTargets(base, image_size, call_rva,
                                kEnemySpawnRva)) {
            continue;
        }
        char reason[160]{};
        std::snprintf(
            reason, sizeof(reason),
            "enemy spawn caller mismatch at RVA 0x%llx",
            static_cast<unsigned long long>(call_rva));
        hooks::ReportStartupFailure(reason);
        return false;
    }
    return true;
}

bool ValidateUserReadyLayout(uint8_t* base, size_t image_size) {
    if (!SignatureMatches(base, image_size, kUserConstructorRva,
                          kUserConstructorSignature,
                          sizeof(kUserConstructorSignature)) ||
        !SignatureMatches(base, image_size, kUserDestructorRva,
                          kUserDestructorSignature,
                          sizeof(kUserDestructorSignature)) ||
        !SignatureMatches(base, image_size, kUserStateFlagsInitializerRva,
                          kUserStateFlagsInitializerSignature,
                          sizeof(kUserStateFlagsInitializerSignature)) ||
        !SignatureMatches(base, image_size, kUserReadyStateReaderRva,
                          kUserReadyStateReaderSignature,
                          sizeof(kUserReadyStateReaderSignature)) ||
        !SignatureMatches(base, image_size, kUserPropertyObjectInitializerRva,
                          kUserPropertyObjectInitializerSignature,
                          sizeof(kUserPropertyObjectInitializerSignature)) ||
        !SignatureMatches(base, image_size, kUserPropertyGetterRva,
                          kUserPropertyGetterSignature,
                          sizeof(kUserPropertyGetterSignature)) ||
        !SignatureMatches(base, image_size, kUserPropertySetterRva,
                          kUserPropertySetterSignature,
                          sizeof(kUserPropertySetterSignature)) ||
        !SignatureMatches(base, image_size, kSharedPropertyReleaseRva,
                          kSharedPropertyReleaseSignature,
                          sizeof(kSharedPropertyReleaseSignature)) ||
        !SignatureMatches(base, image_size, kUserIdGetterRva,
                          kUserIdGetterSignature,
                          sizeof(kUserIdGetterSignature)) ||
        !SignatureMatches(base, image_size, kPlayerInfoBuilderRva,
                          kPlayerInfoBuilderSignature,
                          sizeof(kPlayerInfoBuilderSignature)) ||
        !SignatureMatches(base, image_size, kPlayerInfoDefaultsRva,
                          kPlayerInfoDefaultsSignature,
                          sizeof(kPlayerInfoDefaultsSignature)) ||
        !SignatureMatches(base, image_size, kPlayerInfoFromUserRva,
                          kPlayerInfoFromUserSignature,
                          sizeof(kPlayerInfoFromUserSignature)) ||
        !SignatureMatches(base, image_size, kPlayerInfoFromUserReturnRva,
                          kPlayerInfoFromUserReturnSignature,
                          sizeof(kPlayerInfoFromUserReturnSignature)) ||
        !SignatureMatches(base, image_size, kRoomPlayerInfoCopyRva,
                          kRoomPlayerInfoCopySignature,
                          sizeof(kRoomPlayerInfoCopySignature)) ||
        !SignatureMatches(base, image_size, kUiLayoutCastRva,
                          kUiLayoutCastSignature,
                          sizeof(kUiLayoutCastSignature)) ||
        !SignatureMatches(base, image_size, kUiLayoutClampRva,
                          kUiLayoutClampSignature,
                          sizeof(kUiLayoutClampSignature)) ||
        !SignatureMatches(base, image_size, kUiLayoutDestructorRva,
                          kUiLayoutDestructorSignature,
                          sizeof(kUiLayoutDestructorSignature)) ||
        !SignatureMatches(base, image_size, kPlayersGroupCastCallRva,
                          kPlayersGroupCastCallSignature,
                          sizeof(kPlayersGroupCastCallSignature)) ||
        !SignatureMatches(base, image_size, kHUiRoomUpdateRva,
                          kHUiRoomUpdateSignature,
                          sizeof(kHUiRoomUpdateSignature)) ||
        !SignatureMatches(base, image_size, kMissionStartUpdateRva,
                          kMissionStartUpdateSignature,
                          sizeof(kMissionStartUpdateSignature)) ||
        !SignatureMatches(base, image_size, kMissionStartControllerRva,
                          kMissionStartControllerSignature,
                          sizeof(kMissionStartControllerSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionStartControllerCallRva - 9,
            kMissionStartControllerCallSignature,
            sizeof(kMissionStartControllerCallSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionStartControllerContextRva,
            kMissionStartControllerContextSignature,
            sizeof(kMissionStartControllerContextSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionStartControllerGateGetterRva,
            kMissionStartControllerGateGetterSignature,
            sizeof(kMissionStartControllerGateGetterSignature)) ||
#if EDF5_COMPILE_DIAGNOSTICS
        !SignatureMatches(base, image_size, kReportGsFailureRva,
                          kReportGsFailureSignature,
                          sizeof(kReportGsFailureSignature)) ||
#endif
        !SignatureMatches(base, image_size, kMissionSourceLookupRva,
                          kMissionSourceLookupSignature,
                          sizeof(kMissionSourceLookupSignature)) ||
        !SignatureMatches(base, image_size, kMissionSourceLookupCallRva - 8,
                          kMissionSourceLookupCallSignature,
                          sizeof(kMissionSourceLookupCallSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionSourceTransferCallRva - 0x0e,
                          kMissionSourceTransferCallSignature,
                          sizeof(kMissionSourceTransferCallSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionSourceAppendCallRva - 0x0b,
                          kMissionSourceAppendCallSignature,
                          sizeof(kMissionSourceAppendCallSignature)) ||
        !SignatureMatches(base, image_size, kMissionSourceConsumerRva,
                          kMissionSourceConsumerSignature,
                          sizeof(kMissionSourceConsumerSignature)) ||
        !SignatureMatches(base, image_size, kMissionSourceConsumerRva + 0x54,
                          kMissionSourceConsumerBoundSignature,
                          sizeof(kMissionSourceConsumerBoundSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionPostConsumerIdentityReadRva,
                          kMissionPostConsumerIdentityReadSignature,
                          sizeof(kMissionPostConsumerIdentityReadSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionAppendIdentityReadRva,
                          kMissionAppendIdentityReadSignature,
                          sizeof(kMissionAppendIdentityReadSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionLoadoutConsumerBlockRva,
                          kMissionLoadoutConsumerBlockSignature,
                          sizeof(kMissionLoadoutConsumerBlockSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionLoadoutConsumerRecordRva,
                          kMissionLoadoutConsumerRecordSignature,
                          sizeof(kMissionLoadoutConsumerRecordSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionLoadoutParserStrideRva,
                          kMissionLoadoutParserStrideSignature,
                          sizeof(kMissionLoadoutParserStrideSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionLoadoutParserRecordRva,
                          kMissionLoadoutParserRecordSignature,
                          sizeof(kMissionLoadoutParserRecordSignature)) ||
        !SignatureMatches(
            base, image_size,
            kMissionLoadoutParserParticipantCountWriteRva,
            kMissionLoadoutParserParticipantCountWriteSignature,
            sizeof(kMissionLoadoutParserParticipantCountWriteSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionLoadoutParserRva,
                          kMissionLoadoutParserSignature,
                          sizeof(kMissionLoadoutParserSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionParticipantClassResolverRva,
            kMissionParticipantClassResolverSignature,
            sizeof(kMissionParticipantClassResolverSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionParticipantVisualTableIndexRva,
            kMissionParticipantVisualTableIndexSignature,
            sizeof(kMissionParticipantVisualTableIndexSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionParticipantNativeClassReadRva,
            kMissionParticipantNativeClassReadSignature,
            sizeof(kMissionParticipantNativeClassReadSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionParticipantClassTextTableIndexRva,
            kMissionParticipantClassTextTableIndexSignature,
            sizeof(kMissionParticipantClassTextTableIndexSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionParticipantClassTextSelectRva,
            kMissionParticipantClassTextSelectSignature,
            sizeof(kMissionParticipantClassTextSelectSignature)) ||
        !SignatureMatches(
            base, image_size, kMissionTextMeasureInvalidReadRva,
            kMissionTextMeasureInvalidReadSignature,
            sizeof(kMissionTextMeasureInvalidReadSignature)) ||
        !SignatureMatches(
            base, image_size, kSharedRenderPropertyRefReadRva,
            kSharedRenderPropertyRefReadSignature,
            sizeof(kSharedRenderPropertyRefReadSignature)) ||
        !SignatureMatches(base, image_size, kMissionSharedHandleCopyRva,
                          kMissionSharedHandleCopySignature,
                          sizeof(kMissionSharedHandleCopySignature)) ||
        !SignatureMatches(base, image_size, kMissionSourceCollectionCopyRva,
                          kMissionSourceCollectionCopySignature,
                          sizeof(kMissionSourceCollectionCopySignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionSourcePrimaryCopyCallRva - 0x16,
                          kMissionSourcePrimaryCopyCallSignature,
                          sizeof(kMissionSourcePrimaryCopyCallSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionSourceReferenceCopyCallRva - 0x16,
                          kMissionSourceReferenceCopyCallSignature,
                          sizeof(kMissionSourceReferenceCopyCallSignature)) ||
        !SignatureMatches(base, image_size, kMissionPlayerCreateRva,
                          kMissionPlayerCreateSignature,
                          sizeof(kMissionPlayerCreateSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionPlayerCreatePrimaryCallRva - 0x18,
                          kMissionPlayerCreatePrimaryCallSignature,
                          sizeof(kMissionPlayerCreatePrimaryCallSignature)) ||
        !SignatureMatches(base, image_size,
                          kMissionPlayerCreateSecondaryCallRva - 0x0e,
                          kMissionPlayerCreateSecondaryCallSignature,
                          sizeof(kMissionPlayerCreateSecondaryCallSignature))) {
        return false;
    }
    if (kMissionStartGlobalStateRva >
            image_size - sizeof(int32_t) ||
        kMissionStartControllerCompletedReadRva >= image_size ||
        kMissionStartControllerVtableRva >
            image_size - 54 * sizeof(void*)) {
        hooks::ReportStartupFailure(
            "EDF5 MissionStart controller data lies outside the PE image");
        return false;
    }
    auto** vtable = reinterpret_cast<void**>(base + kUserVtableRva);
    auto** layout_vtable = reinterpret_cast<void**>(base + kUiLayoutVtableRva);
    auto** controller_vtable = reinterpret_cast<void**>(
        base + kMissionStartControllerVtableRva);
    return vtable[0] == base + kUserDestructorRva &&
           vtable[10] == base + kUserIdGetterRva &&
           layout_vtable[0] == base + kUiLayoutDestructorRva &&
           controller_vtable[53] ==
               base + kMissionStartControllerGateGetterRva;
}

bool ValidateGameplayP2PLayout(uint8_t* base, size_t image_size) {
    return SignatureMatches(base, image_size, kGameplayP2PSendRva,
                            kGameplayP2PSendSignature,
                            sizeof(kGameplayP2PSendSignature)) &&
           SignatureMatches(base, image_size, kGameplayP2PSendCallRva,
                            kGameplayP2PSendCallSignature,
                            sizeof(kGameplayP2PSendCallSignature)) &&
           SignatureMatches(base, image_size, kGameplayP2PDispatchRva,
                            kGameplayP2PDispatchSignature,
                            sizeof(kGameplayP2PDispatchSignature)) &&
           SignatureMatches(base, image_size, kGameplayP2PDispatchCallRva,
                            kGameplayP2PDispatchCallSignature,
                            sizeof(kGameplayP2PDispatchCallSignature)) &&
           SignatureMatches(base, image_size, kGameplayP2PDispatchBodyRva,
                            kGameplayP2PDispatchBodySignature,
                            sizeof(kGameplayP2PDispatchBodySignature)) &&
           SignatureMatches(base, image_size, kGameplayMessageEnqueueRva,
                             kGameplayMessageEnqueueSignature,
                             sizeof(kGameplayMessageEnqueueSignature)) &&
           SignatureMatches(base, image_size,
                            kGameplayReplicationProducerRva,
                            kGameplayReplicationProducerSignature,
                            sizeof(kGameplayReplicationProducerSignature)) &&
           SignatureMatches(base, image_size,
                            kGameplayReplicationSerializerRva,
                            kGameplayReplicationSerializerSignature,
                            sizeof(kGameplayReplicationSerializerSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationSerializerCallRva - 0x13,
               kGameplayReplicationSerializerCallSignature,
               sizeof(kGameplayReplicationSerializerCallSignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationTargetBuilderRva,
               kGameplayReplicationTargetBuilderSignature,
               sizeof(kGameplayReplicationTargetBuilderSignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationTargetVectorLayoutRva,
               kGameplayReplicationTargetVectorLayoutSignature,
               sizeof(kGameplayReplicationTargetVectorLayoutSignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationTargetAppendRva,
               kGameplayReplicationTargetAppendSignature,
               sizeof(kGameplayReplicationTargetAppendSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationTargetUserRouteCopyRva,
               kGameplayReplicationTargetUserRouteCopySignature,
               sizeof(kGameplayReplicationTargetUserRouteCopySignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationTargetResolveRva,
               kGameplayReplicationTargetResolveSignature,
               sizeof(kGameplayReplicationTargetResolveSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationTargetRouteIndexReadRva,
               kGameplayReplicationTargetRouteIndexReadSignature,
               sizeof(kGameplayReplicationTargetRouteIndexReadSignature)) &&
           SignatureMatches(
               base, image_size,
               kUserTransportRouteDescriptorInitializerRva,
               kUserTransportRouteDescriptorInitializerSignature,
               sizeof(kUserTransportRouteDescriptorInitializerSignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationReceivePumpRva,
               kGameplayReplicationReceivePumpSignature,
               sizeof(kGameplayReplicationReceivePumpSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceivePumpLoopRva,
               kGameplayReplicationReceivePumpLoopSignature,
               sizeof(kGameplayReplicationReceivePumpLoopSignature)) &&
           SignatureMatches(
               base, image_size, kGameplayReplicationReceiveParserRva,
               kGameplayReplicationReceiveParserSignature,
               sizeof(kGameplayReplicationReceiveParserSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveParserCallRva - 0x07,
               kGameplayReplicationReceiveParserCallSignature,
               sizeof(kGameplayReplicationReceiveParserCallSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteObjectConstructorRva,
               kGameplayReplicationReceiveRouteObjectConstructorSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteObjectConstructorSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteUserControlCopyRva,
               kGameplayReplicationReceiveRouteUserControlCopySignature,
               sizeof(
                   kGameplayReplicationReceiveRouteUserControlCopySignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveParserConstructorRva,
               kGameplayReplicationReceiveParserConstructorSignature,
               sizeof(
                   kGameplayReplicationReceiveParserConstructorSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveParserOwnerStoreRva,
               kGameplayReplicationReceiveParserOwnerStoreSignature,
               sizeof(
                   kGameplayReplicationReceiveParserOwnerStoreSignature)) &&
           SignatureMatches(
               base, image_size, kUserTransportRouteIndexInitializerRva,
               kUserTransportRouteIndexInitializerSignature,
               sizeof(kUserTransportRouteIndexInitializerSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteRegisterRva,
               kGameplayReplicationReceiveRouteRegisterSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteRegisterSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteIndexReadRva,
               kGameplayReplicationReceiveRouteIndexReadSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteIndexReadSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteUnregisterRva,
               kGameplayReplicationReceiveRouteUnregisterSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteUnregisterSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteRemoveIndexReadRva,
               kGameplayReplicationReceiveRouteRemoveIndexReadSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteRemoveIndexReadSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteRegisterCallRva,
               kGameplayReplicationReceiveRouteRegisterCallSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteRegisterCallSignature)) &&
           SignatureMatches(
               base, image_size,
               kGameplayReplicationReceiveRouteUnregisterCallRva,
               kGameplayReplicationReceiveRouteUnregisterCallSignature,
               sizeof(
                   kGameplayReplicationReceiveRouteUnregisterCallSignature)) &&
           RelativeCallTargets(
               base, image_size,
               kGameplayReplicationReceiveRouteRegisterCallRva,
               kGameplayReplicationReceiveRouteRegisterRva) &&
           RelativeCallTargets(
               base, image_size,
               kGameplayReplicationReceiveRouteUnregisterCallRva,
               kGameplayReplicationReceiveRouteUnregisterRva) &&
           SignatureMatches(
               base, image_size, kUserTransportRouteSlotAllocatorRva,
               kUserTransportRouteSlotAllocatorSignature,
               sizeof(kUserTransportRouteSlotAllocatorSignature)) &&
           SignatureMatches(
               base, image_size,
               kUserTransportRouteUserConstructorCallRva - 0x09,
               kUserTransportRouteUserConstructorCallSignature,
               sizeof(
                   kUserTransportRouteUserConstructorCallSignature)) &&
           SignatureMatches(base, image_size, kChatMessagePublishRva,
                            kChatMessagePublishSignature,
                            sizeof(kChatMessagePublishSignature)) &&
           SignatureMatches(base, image_size, kChatRoomConstructorRva,
                            kChatRoomConstructorSignature,
                            sizeof(kChatRoomConstructorSignature)) &&
           SignatureMatches(base, image_size,
                            kChatRoomVtableAssignmentRva,
                            kChatRoomVtableAssignmentSignature,
                            sizeof(kChatRoomVtableAssignmentSignature)) &&
           SignatureMatches(base, image_size,
                            kChatSystemMessagePublishRva,
                            kChatSystemMessagePublishSignature,
                            sizeof(kChatSystemMessagePublishSignature)) &&
           SignatureMatches(base, image_size,
                             kMissionScriptMessageDispatchRva,
                            kMissionScriptMessageDispatchSignature,
                            sizeof(kMissionScriptMessageDispatchSignature)) &&
           kGameplayP2PDispatchSpecialVtableRva <=
               image_size - 2 * sizeof(void*) &&
           kChatRoomVtableRva <= image_size - 4 * sizeof(void*) &&
           kGameplayP2PDispatchSpecialTargetRva < image_size &&
           kGameplayP2PSendTargetRva < image_size;
}

bool ValidateDebugStageWinLayout(uint8_t* base, size_t image_size) {
    return SignatureMatches(base, image_size, kMissionUpdateRva,
                            kMissionUpdateSignature,
                            sizeof(kMissionUpdateSignature)) &&
           SignatureMatches(base, image_size, kMissionResultSetterRva,
                            kMissionResultSetterSignature,
                            sizeof(kMissionResultSetterSignature)) &&
           SignatureMatches(base, image_size,
                            kMissionResultSetterPublishRva,
                            kMissionResultSetterPublishSignature,
                            sizeof(kMissionResultSetterPublishSignature)) &&
           SignatureMatches(base, image_size, kMissionResultApplyRva,
                            kMissionResultApplySignature,
                            sizeof(kMissionResultApplySignature)) &&
           SignatureMatches(base, image_size,
                             kMissionResultEventPublishRva,
                             kMissionResultEventPublishSignature,
                             sizeof(kMissionResultEventPublishSignature)) &&
           SignatureMatches(base, image_size,
                            kMissionResultUiEventDispatchRva,
                            kMissionResultUiEventDispatchSignature,
                            sizeof(kMissionResultUiEventDispatchSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultUiEventDispatchRva + 0x2c,
               kMissionResultUiCloseTargetSignature,
               sizeof(kMissionResultUiCloseTargetSignature)) &&
           SignatureMatches(base, image_size,
                            kMissionResultExecBeginRva,
                            kMissionResultExecBeginSignature,
                            sizeof(kMissionResultExecBeginSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultExecBeginNativeCallerRva,
               kMissionResultExecBeginNativeCallerSignature,
               sizeof(kMissionResultExecBeginNativeCallerSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultExecBeginScriptWrapperRva,
               kMissionResultExecBeginScriptWrapperSignature,
               sizeof(kMissionResultExecBeginScriptWrapperSignature)) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecBeginNativeCallerRva + 5,
               kMissionResultExecBeginRva) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecBeginScriptWrapperCallRva,
               kMissionResultExecBeginRva) &&
           SignatureMatches(
               base, image_size, kMissionResultExecUpdateRva,
               kMissionResultExecUpdateSignature,
               sizeof(kMissionResultExecUpdateSignature)) &&
           SignatureMatches(
               base, image_size,
               kMissionResultExecUpdateScriptWrapperRva,
               kMissionResultExecUpdateScriptWrapperSignature,
               sizeof(kMissionResultExecUpdateScriptWrapperSignature)) &&
           SignatureMatches(
               base, image_size,
               kMissionResultExecUpdateScriptCallRva,
               kMissionResultExecUpdateScriptCallSignature,
               sizeof(kMissionResultExecUpdateScriptCallSignature)) &&
           SignatureMatches(
               base, image_size,
               kMissionResultExecUpdateNativeCallRva,
               kMissionResultExecUpdateNativeCallSignature,
               sizeof(kMissionResultExecUpdateNativeCallSignature)) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecUpdateScriptCallRva,
               kMissionResultExecUpdateRva) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecUpdateNativeCallRva,
               kMissionResultExecUpdateRva) &&
           SignatureMatches(
               base, image_size, kMissionResultExecFinallyRva,
               kMissionResultExecFinallySignature,
               sizeof(kMissionResultExecFinallySignature)) &&
           SignatureMatches(
               base, image_size,
               kMissionResultExecFinallyScriptWrapperRva,
               kMissionResultExecFinallyScriptWrapperSignature,
               sizeof(
                   kMissionResultExecFinallyScriptWrapperSignature)) &&
           SignatureMatches(
               base, image_size,
               kMissionResultExecFinallyNativeCallRva - 5,
               kMissionResultExecFinallyNativeCallSignature,
               sizeof(kMissionResultExecFinallyNativeCallSignature)) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecFinallyScriptCallRva,
               kMissionResultExecFinallyRva) &&
           RelativeCallTargets(
               base, image_size,
               kMissionResultExecFinallyNativeCallRva,
               kMissionResultExecFinallyRva) &&
           SignatureMatches(
               base, image_size, kMissionResultItemInitializeLimitRva,
               kMissionResultItemInitializeLimitSignature,
               sizeof(kMissionResultItemInitializeLimitSignature)) &&
           SignatureMatches(base, image_size,
                            kMissionResultItemSinkRva,
                            kMissionResultItemSinkSignature,
                            sizeof(kMissionResultItemSinkSignature)) &&
           SignatureMatches(base, image_size, kMissionNamedSyncBeginRva,
                            kMissionNamedSyncBeginSignature,
                            sizeof(kMissionNamedSyncBeginSignature)) &&
           SignatureMatches(base, image_size, kMissionNamedSyncPollRva,
                            kMissionNamedSyncPollSignature,
                            sizeof(kMissionNamedSyncPollSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultScriptSyncBeginCallRva,
               kMissionResultScriptSyncBeginCallSignature,
               sizeof(kMissionResultScriptSyncBeginCallSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultScriptSyncPollCallRva,
               kMissionResultScriptSyncPollCallSignature,
               sizeof(kMissionResultScriptSyncPollCallSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultNetSyncBeginCallRva,
               kMissionResultNetSyncBeginCallSignature,
               sizeof(kMissionResultNetSyncBeginCallSignature)) &&
           SignatureMatches(
               base, image_size, kMissionResultNetSyncPollCallRva,
               kMissionResultNetSyncPollCallSignature,
               sizeof(kMissionResultNetSyncPollCallSignature)) &&
           SignatureMatches(base, image_size, kMissionRewardResolveRva,
                            kMissionRewardResolveSignature,
                            sizeof(kMissionRewardResolveSignature)) &&
           SignatureMatches(base, image_size, kMissionRewardApplyRva,
                            kMissionRewardApplySignature,
                            sizeof(kMissionRewardApplySignature)) &&
           SignatureMatches(
               base, image_size, kMissionRewardApplyCountReadRva,
               kMissionRewardApplyCountReadSignature,
               sizeof(kMissionRewardApplyCountReadSignature)) &&
           SignatureMatches(
               base, image_size, kMissionRewardApplyProfileBaseRva,
               kMissionRewardApplyProfileBaseSignature,
               sizeof(kMissionRewardApplyProfileBaseSignature)) &&
           SignatureMatches(
               base, image_size, kMissionRewardApplyProfileStrideRva,
               kMissionRewardApplyProfileStrideSignature,
               sizeof(kMissionRewardApplyProfileStrideSignature)) &&
           SignatureMatches(
               base, image_size, kMissionRewardLocalProfileSetterRva,
               kMissionRewardLocalProfileSetterSignature,
               sizeof(kMissionRewardLocalProfileSetterSignature)) &&
           SignatureMatches(base, image_size, kMissionNaturalClearResultRva,
                            kMissionNaturalClearResultSignature,
                            sizeof(kMissionNaturalClearResultSignature)) &&
           SignatureMatches(base, image_size, kMissionNaturalClearCallRva,
                            kMissionNaturalClearCallSignature,
                            sizeof(kMissionNaturalClearCallSignature)) &&
           SignatureMatches(base, image_size, kMissionManagerLoadRva,
                            kMissionManagerLoadSignature,
                            sizeof(kMissionManagerLoadSignature)) &&
           SignatureMatches(base, image_size, kMissionUiStateReadRva,
                            kMissionUiStateReadSignature,
                            sizeof(kMissionUiStateReadSignature)) &&
           SignatureMatches(base, image_size, kMissionUiResultReadRva,
                            kMissionUiResultReadSignature,
                            sizeof(kMissionUiResultReadSignature)) &&
           SignatureMatches(base, image_size, kMissionResultPreserveRva,
                            kMissionResultPreserveSignature,
                            sizeof(kMissionResultPreserveSignature)) &&
           kMissionManagerSlotRva <= image_size - sizeof(void*);
}

void ClearMissionExtraLoadoutSidecars();

void RemovePlayerInfoObservation(void* user) {
    if (!user) return;
    AcquireSRWLockExclusive(&g_player_info_observation_lock);
    for (auto& observation : g_player_info_observations) {
        if (observation.user == user) observation = {};
    }
    ReleaseSRWLockExclusive(&g_player_info_observation_lock);
}

void ClearPlayerInfoObservations() {
    AcquireSRWLockExclusive(&g_player_info_observation_lock);
    for (auto& observation : g_player_info_observations) observation = {};
    g_next_player_info_name_token = 1;
    ReleaseSRWLockExclusive(&g_player_info_observation_lock);
    for (auto& token : g_chat_name_last_observed_tokens) {
        token.store(0, std::memory_order_release);
    }
    g_chat_name_unresolved_first_logged.store(
        0, std::memory_order_release);
    g_chat_name_message_count.store(0, std::memory_order_release);
    g_chat_name_mismatch_count.store(0, std::memory_order_release);
}

void RegisterReadyUser(void* user) {
    if (!user) return;
    AcquireSRWLockExclusive(&g_ready_user_lock);
    if (std::find(g_ready_users.begin(), g_ready_users.end(), user) ==
        g_ready_users.end()) {
        g_ready_users.push_back(user);
    }
    ReleaseSRWLockExclusive(&g_ready_user_lock);
}

void RecordTransportRouteAllocatorOwner(void* user, void* allocator_owner) {
    if (!user) return;
    AcquireSRWLockExclusive(&g_ready_user_lock);
    TransportRouteAllocatorOwnerObservation* available = nullptr;
    for (auto& observation : g_transport_route_allocator_owners) {
        if (observation.user == user) {
            observation.allocator_owner = allocator_owner;
            ReleaseSRWLockExclusive(&g_ready_user_lock);
            return;
        }
        if (!available && !observation.user) available = &observation;
    }
    if (available) {
        available->user = user;
        available->allocator_owner = allocator_owner;
    }
    ReleaseSRWLockExclusive(&g_ready_user_lock);
}

void* FindTransportRouteAllocatorOwner(void* user) {
    if (!user) return nullptr;
    void* result = nullptr;
    AcquireSRWLockShared(&g_ready_user_lock);
    for (const auto& observation : g_transport_route_allocator_owners) {
        if (observation.user != user) continue;
        result = observation.allocator_owner;
        break;
    }
    ReleaseSRWLockShared(&g_ready_user_lock);
    return result;
}

void UnregisterReadyUser(void* user) {
    AcquireSRWLockExclusive(&g_ready_user_lock);
    g_ready_users.erase(std::remove(g_ready_users.begin(), g_ready_users.end(), user),
                        g_ready_users.end());
    for (auto& observation : g_transport_route_allocator_owners) {
        if (observation.user == user) observation = {};
    }
    ReleaseSRWLockExclusive(&g_ready_user_lock);
    RemovePlayerInfoObservation(user);
}

void ClearReadyUsers() {
    AcquireSRWLockExclusive(&g_ready_user_lock);
    g_ready_users.clear();
    for (auto& observation : g_transport_route_allocator_owners) {
        observation = {};
    }
    ReleaseSRWLockExclusive(&g_ready_user_lock);
    ClearPlayerInfoObservations();
    ClearMissionExtraLoadoutSidecars();
}

void ResetReplicationParticipantTelemetry() {
    g_replication_participant_map_ready.store(
        false, std::memory_order_release);
    g_replication_receive_route_signature.store(
        std::numeric_limits<uint64_t>::max(),
        std::memory_order_release);
    g_replication_receive_route_register_calls.store(
        0, std::memory_order_release);
    g_replication_receive_route_unregister_calls.store(
        0, std::memory_order_release);
    g_replication_receive_route_lifecycle_anomalies.store(
        0, std::memory_order_release);
    for (auto& user : g_mission_participant_users) {
        user.store(0, std::memory_order_release);
    }
    g_mission_local_participant_mask.store(0, std::memory_order_release);
    for (size_t direction = 0; direction < 2; ++direction) {
        for (size_t family = 0; family < 2; ++family) {
            g_replication_first_logged_masks[direction][family].store(
                0, std::memory_order_release);
            for (size_t participant = 0;
                 participant <= kReplicationParticipantCapacity;
                 ++participant) {
                g_replication_message_counts[direction][family][participant]
                    .store(0, std::memory_order_release);
                g_replication_last_summary_counts
                    [direction][family][participant]
                        .store(0, std::memory_order_release);
            }
        }
    }
    for (auto& mask : g_replication_send_fanout_first_logged_masks) {
        mask.store(0, std::memory_order_release);
    }
    g_replication_last_summary_tick.store(0, std::memory_order_release);
}

struct ReplicationParticipantMapAudit {
    unsigned mapped_users = 0;
    unsigned unique_users = 0;
    uint32_t participant_mask = 0;
    uint32_t duplicate_participant_mask = 0;
};

ReplicationParticipantMapAudit InspectReplicationParticipantMap() {
    ReplicationParticipantMapAudit audit;
    std::array<uintptr_t, kReplicationParticipantCapacity> users{};
    for (size_t index = 0; index < users.size(); ++index) {
        users[index] = g_mission_participant_users[index].load(
            std::memory_order_acquire);
        if (!users[index]) continue;
        ++audit.mapped_users;
        audit.participant_mask |=
            uint32_t{1} << static_cast<unsigned>(index);
        bool duplicate = false;
        for (size_t previous = 0; previous < index; ++previous) {
            if (users[previous] == users[index]) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            audit.duplicate_participant_mask |=
                uint32_t{1} << static_cast<unsigned>(index);
        } else {
            ++audit.unique_users;
        }
    }
    return audit;
}

void RegisterMissionParticipantUser(int32_t participant_index, void* user) {
    if (participant_index < 0 ||
        static_cast<size_t>(participant_index) >=
            kReplicationParticipantCapacity ||
        !user) {
        return;
    }
    g_mission_participant_users[static_cast<size_t>(participant_index)].store(
        reinterpret_cast<uintptr_t>(user), std::memory_order_release);
}

void UnregisterMissionParticipantUser(void* user) {
    if (!user) return;
    const uintptr_t value = reinterpret_cast<uintptr_t>(user);
    for (auto& participant_user : g_mission_participant_users) {
        uintptr_t expected = value;
        participant_user.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel,
            std::memory_order_acquire);
    }
}

int MissionParticipantIndexForUser(void* user) {
    if (!user) return -1;
    const uintptr_t value = reinterpret_cast<uintptr_t>(user);
    for (size_t index = 0; index < g_mission_participant_users.size();
         ++index) {
        if (g_mission_participant_users[index].load(
                std::memory_order_acquire) == value) {
            return static_cast<int>(index);
        }
    }
    return -1;
}

void* MissionParticipantUserForIndex(int32_t participant_index) {
    if (participant_index < 0 ||
        static_cast<size_t>(participant_index) >=
            g_mission_participant_users.size()) {
        return nullptr;
    }
    return reinterpret_cast<void*>(
        g_mission_participant_users[static_cast<size_t>(participant_index)]
            .load(std::memory_order_acquire));
}

int SingleParticipantIndex(uint32_t mask) {
    if (!mask || (mask & (mask - 1)) != 0) return -1;
    int index = 0;
    while ((mask & uint32_t{1}) == 0) {
        mask >>= 1;
        ++index;
    }
    return index < static_cast<int>(kReplicationParticipantCapacity)
        ? index : -1;
}

void MaybeActivateReplicationParticipantMap(uint64_t expected_users) {
    if (!expected_users ||
        expected_users > kReplicationParticipantCapacity) {
        return;
    }
    const ReplicationParticipantMapAudit audit =
        InspectReplicationParticipantMap();
    if (audit.mapped_users < expected_users) return;
    bool expected = false;
    if (g_replication_participant_map_ready.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "replication_participant_map_ready",
            capture::Fields()
                .UInt("participant_count", audit.mapped_users)
                .UInt("source_count", expected_users)
                .UInt("unique_user_count", audit.unique_users)
                .UInt("participant_mask", audit.participant_mask)
                .UInt("duplicate_participant_mask",
                      audit.duplicate_participant_mask)
                .Bool("participant_identity_unique",
                      audit.unique_users == audit.mapped_users &&
                          audit.duplicate_participant_mask == 0)
                .UInt("participant_capacity",
                      kReplicationParticipantCapacity)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("steam_id_logged", false)
                .Bool("display_name_text_logged", false)
                .Bool("pointer_logged", false));
    }
}

void ResetMissionGroupSync() {
    // The regular filler path arms mirroring on the first channel-0 send. The
    // local harness has no peer behind each dummy, so begin polling as soon as
    // the host publishes l1/l2 instead of depending on a gameplay packet.
    const bool local_harness_armed =
        g_local_mission_harness_target.load(std::memory_order_acquire) != 0;
    g_mission_groups_pending.store(local_harness_armed,
                                   std::memory_order_release);
    g_mission_groups_synchronized.store(false, std::memory_order_release);
    g_last_mission_group_log_signature.store(0, std::memory_order_release);
    g_diagnostic_mission_group_mask.store(0, std::memory_order_release);
}

void ResetLocalMissionHarnessMatchingTelemetry() {
    g_local_mission_harness_matching_completions.store(
        0, std::memory_order_release);
    g_local_mission_harness_mission_start_calls.store(
        0, std::memory_order_release);
    g_local_mission_harness_mission_start_observations.store(
        0, std::memory_order_release);
    g_local_mission_harness_last_mission_start_state.store(
        std::numeric_limits<int32_t>::min(), std::memory_order_release);
    g_local_mission_harness_last_mission_start_log_tick.store(
        0, std::memory_order_release);
    g_local_mission_harness_controller_calls.store(
        0, std::memory_order_release);
    g_local_mission_harness_controller_bypasses.store(
        0, std::memory_order_release);
    g_local_mission_harness_last_controller_state.store(
        std::numeric_limits<int32_t>::min(), std::memory_order_release);
    g_local_mission_harness_last_controller_log_tick.store(
        0, std::memory_order_release);
}

bool RoomRosterActive() {
    if (!Enabled() ||
        !g_players_group_layout.load(std::memory_order_acquire)) return false;
    const uint64_t last_tick =
        g_last_room_model_tick.load(std::memory_order_acquire);
    const uint64_t now = GetTickCount64();
    return last_tick && now >= last_tick && now - last_tick <= 2500;
}

// Mission-scoped state is reset as one unit whenever a lobby flow starts or
// ends. Keeping result, spawn and debug-generation counters together prevents
// a late callback from a prior mission being mistaken for the current one.
void ResetEnemySpawnTelemetry() {
    g_enemy_spawn_calls.store(0, std::memory_order_release);
    g_enemy_spawn_confirmed_calls.store(0, std::memory_order_release);
    g_enemy_spawn_requested_total.store(0, std::memory_order_release);
    g_enemy_spawn_effective_total.store(0, std::memory_order_release);
    g_enemy_spawn_zero_scale_calls.store(0, std::memory_order_release);
    g_enemy_spawn_missing_source_calls.store(0,
                                              std::memory_order_release);
    g_enemy_spawn_scale_repairs.store(0, std::memory_order_release);
    g_enemy_spawn_scale_restore_failures.store(
        0, std::memory_order_release);
    g_enemy_spawn_observation_mask.store(0, std::memory_order_release);
    g_generator_poll_update_calls.store(0, std::memory_order_release);
    g_generator_poll_update_completed_calls.store(
        0, std::memory_order_release);
    g_generator_poll_updates_reaching_spawn_method.store(
        0, std::memory_order_release);
    g_generator_poll_spawn_method_calls_in_updates.store(
        0, std::memory_order_release);
    g_generator_poll_update_observation_mask.store(
        0, std::memory_order_release);
    g_generator_poll_update_scope_depth = 0;
    g_generator_poll_update_scope_spawn_calls = 0;
    g_generator_poll_native_gate_calls.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_completed_calls.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_cooldown_blocks.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_quota_blocks.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_spawn_false.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_spawn_accepted.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_unknown.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_observation_mask.store(
        0, std::memory_order_release);
    g_generator_poll_native_gate_scope_depth = 0;
    g_generator_poll_native_gate_scope_spawn_calls = 0;
    g_generator_poll_native_gate_scope_spawn_true_calls = 0;
    g_generator_poll_spawn_calls.store(0, std::memory_order_release);
    g_generator_poll_manager_readable_calls.store(
        0, std::memory_order_release);
    g_generator_poll_manager_present_calls.store(
        0, std::memory_order_release);
    g_generator_poll_methods_reaching_common_spawn.store(
        0, std::memory_order_release);
    g_generator_poll_common_spawn_calls.store(
        0, std::memory_order_release);
    g_generator_poll_gate_true_calls.store(0, std::memory_order_release);
    g_generator_poll_gate_false_calls.store(0, std::memory_order_release);
    g_generator_poll_observation_mask.store(0, std::memory_order_release);
    g_generator_poll_spawn_scope_depth = 0;
    g_generator_poll_scope_common_spawn_calls = 0;
}

// The pending flag, timestamp and generation form one logical queue entry.
// Callers must hold g_mission_result_exec_recovery_lock exclusively so a
// native Exec_Begin cannot observe a partially cleared recovery request.
void ClearMissionResultExecRecoveryQueueLocked() {
    g_mission_result_exec_recovery_pending.store(
        false, std::memory_order_release);
    g_mission_result_exec_recovery_tick.store(0,
                                               std::memory_order_release);
    g_mission_result_exec_recovery_generation.store(
        0, std::memory_order_release);
}

// A mission generation owns both the native-call counter and its fallback
// queue. Reset them under the same lock so a stale request cannot block the
// next stage in a lobby that remains open between missions.
bool ResetMissionResultExecRecoveryState() {
    AcquireSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    const bool discarded_pending =
        g_mission_result_exec_recovery_pending.load(
            std::memory_order_acquire);
    ClearMissionResultExecRecoveryQueueLocked();
    g_mission_result_exec_begin_calls.store(0, std::memory_order_release);
    g_mission_result_exec_recovery_attempts.store(
        0, std::memory_order_release);
    g_mission_result_exec_recovery_native_cancels.store(
        0, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    return discarded_pending;
}

void ResetMissionResultExecPipelineTelemetry() {
    g_mission_result_exec_update_calls.store(
        0, std::memory_order_release);
    g_mission_result_exec_update_true_calls.store(
        0, std::memory_order_release);
    g_mission_result_exec_update_false_calls.store(
        0, std::memory_order_release);
    g_mission_result_exec_update_observation_mask.store(
        0, std::memory_order_release);
    g_mission_result_exec_finally_calls.store(
        0, std::memory_order_release);
    g_mission_result_exec_finally_origin_mask.store(
        0, std::memory_order_release);
}

void ResetMissionRuntimeState() {
    g_debug_stage_win_pending.store(false, std::memory_order_release);
    g_debug_stage_win_active.store(false, std::memory_order_release);
    g_debug_stage_win_consumed.store(false, std::memory_order_release);
    g_debug_stage_win_request_tick.store(0, std::memory_order_release);
    g_debug_stage_win_request_generation.store(0, std::memory_order_release);
    g_mission_update_tick.store(0, std::memory_order_release);
    g_mission_first_update_tick.store(0, std::memory_order_release);
    g_mission_generation.store(0, std::memory_order_release);
    g_mission_ui_state.store(-1, std::memory_order_release);
    g_mission_result_tick.store(0, std::memory_order_release);
    g_mission_result_generation.store(0, std::memory_order_release);
    g_mission_result_audit_mask.store(0, std::memory_order_release);
    g_mission_result_setter_calls.store(0, std::memory_order_release);
    g_mission_result_apply_calls.store(0, std::memory_order_release);
    g_mission_result_last_value.store(-1, std::memory_order_release);
    g_mission_result_last_ui_state.store(-1, std::memory_order_release);
    g_mission_result_last_ui_value.store(-1, std::memory_order_release);
    g_mission_result_last_setter_caller_rva.store(
        0, std::memory_order_release);
    g_mission_result_last_apply_caller_rva.store(
        0, std::memory_order_release);
    g_mission_result_last_setter_generation.store(
        0, std::memory_order_release);
    g_mission_result_recovery_pending.store(false,
                                            std::memory_order_release);
    g_mission_result_recovery_tick.store(0, std::memory_order_release);
    g_mission_result_recovery_generation.store(
        0, std::memory_order_release);
    g_mission_result_recovery_attempts.store(0, std::memory_order_release);
    g_mission_result_event_publish_calls.store(
        0, std::memory_order_release);
    g_mission_result_expected_event_publish_calls.store(
        0, std::memory_order_release);
    g_mission_result_ui_dispatch_calls.store(0, std::memory_order_release);
    g_mission_result_ui_target_match_calls.store(
        0, std::memory_order_release);
    ResetMissionResultExecRecoveryState();
    ResetMissionResultExecPipelineTelemetry();
    g_mission_result_extra_item_calls.store(0,
                                             std::memory_order_release);
    g_mission_result_extra_item_aggregated_calls.store(
        0, std::memory_order_release);
    g_mission_result_extra_item_mask.store(0,
                                            std::memory_order_release);
    g_mission_result_item_mask.store(0, std::memory_order_release);
    g_mission_result_sync_begin_calls.store(0, std::memory_order_release);
    g_mission_result_sync_poll_calls.store(0, std::memory_order_release);
    g_mission_result_sync_complete_calls.store(0,
                                                std::memory_order_release);
    g_mission_result_sync_first_poll_logged_mask.store(
        0, std::memory_order_release);
    g_mission_result_sync_complete_logged_mask.store(
        0, std::memory_order_release);
    g_mission_result_sync_last_state.store(-1, std::memory_order_release);
    g_mission_result_sync_last_result.store(-1, std::memory_order_release);
    g_mission_reward_resolve_calls.store(0, std::memory_order_release);
    g_mission_reward_apply_calls.store(0, std::memory_order_release);
    g_mission_reward_apply_completed_calls.store(
        0, std::memory_order_release);
    g_mission_expected_local_profile_count.store(
        0, std::memory_order_release);
    g_mission_reward_profile_count_repairs.store(
        0, std::memory_order_release);
    g_mission_result_sync_test_origin.store(-1,
                                             std::memory_order_release);
    ResetEnemySpawnTelemetry();
}

void* CurrentMissionManager() {
    return g_mission_manager_slot ? *g_mission_manager_slot : nullptr;
}

void* CurrentMissionResultEventPublisherOwner() {
    return g_mission_result_event_publisher_slot
        ? *g_mission_result_event_publisher_slot : nullptr;
}

void* CurrentMissionUi(void* manager) {
    return manager ? *reinterpret_cast<void**>(
        static_cast<uint8_t*>(manager) + kMissionManagerUiOffset) : nullptr;
}

int32_t ReadMissionUiState(void* ui) {
    return ui ? *reinterpret_cast<int32_t*>(
        static_cast<uint8_t*>(ui) + kMissionUiStateOffset) : -1;
}

int32_t ReadMissionUiResult(void* ui) {
    return ui ? *reinterpret_cast<int32_t*>(
        static_cast<uint8_t*>(ui) + kMissionUiResultOffset) : -1;
}

int32_t ReadMissionManagerResult(void* manager) {
    return manager ? *reinterpret_cast<int32_t*>(
        static_cast<uint8_t*>(manager) + kMissionManagerResultOffset) : -1;
}

bool IsReadableMemoryRange(const void* address, size_t bytes);
bool IsWritableMemoryRange(const void* address, size_t bytes);

enum class MissionResultSyncOrigin : uint32_t {
    Unknown = 0,
    Script = 1,
    Network = 2,
};

uintptr_t ModuleRvaForAddress(uintptr_t address) {
    return address >= g_module_base &&
               address < g_module_base + g_module_image_size
        ? address - g_module_base : 0;
}

MissionResultSyncOrigin MissionResultSyncOriginForCaller(
    uintptr_t caller_rva, bool begin) {
    const int test_origin = g_mission_result_sync_test_origin.load(
        std::memory_order_acquire);
    if (test_origin == static_cast<int>(MissionResultSyncOrigin::Script) ||
        test_origin == static_cast<int>(MissionResultSyncOrigin::Network)) {
        return static_cast<MissionResultSyncOrigin>(test_origin);
    }
    if (begin) {
        if (caller_rva == kMissionResultScriptSyncBeginReturnRva) {
            return MissionResultSyncOrigin::Script;
        }
        if (caller_rva == kMissionResultNetSyncBeginReturnRva) {
            return MissionResultSyncOrigin::Network;
        }
    } else {
        if (caller_rva == kMissionResultScriptSyncPollReturnRva) {
            return MissionResultSyncOrigin::Script;
        }
        if (caller_rva == kMissionResultNetSyncPollReturnRva) {
            return MissionResultSyncOrigin::Network;
        }
    }
    return MissionResultSyncOrigin::Unknown;
}

[[maybe_unused]] const char* MissionResultSyncOriginName(
    MissionResultSyncOrigin origin) {
    switch (origin) {
        case MissionResultSyncOrigin::Script: return "script";
        case MissionResultSyncOrigin::Network: return "network";
        default: return "unknown";
    }
}

uint32_t MissionResultSyncOriginBit(MissionResultSyncOrigin origin) {
    const uint32_t value = static_cast<uint32_t>(origin);
    return value > 0 && value <= 2 ? uint32_t{1} << (value - 1) : 0;
}

bool ReadMissionResultSyncState(void* state, int32_t& phase,
                                int32_t& result) {
    phase = -1;
    result = -1;
    if (!state || !IsReadableMemoryRange(state, 2 * sizeof(int32_t))) {
        return false;
    }
    std::memcpy(&phase, state, sizeof(phase));
    std::memcpy(&result, static_cast<uint8_t*>(state) + sizeof(phase),
                sizeof(result));
    return true;
}

bool LocalMissionHarnessSessionReady() {
    const unsigned target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    return capture::GetConfig().local_mission_harness_enabled &&
        (target == kLocalMissionHarnessBaselineDummies ||
         target == kLocalMissionHarnessProbeDummies) &&
        g_owned_lobby.load(std::memory_order_acquire) != 0 &&
        g_last_actual_member_count.load(std::memory_order_acquire) == 1 &&
        g_bot_count.load(std::memory_order_acquire) == target;
}

bool LocalMissionHarnessCompletionPrerequisites(unsigned target) {
    if (!LocalMissionHarnessSessionReady() || target >= 32) return false;
    const uint32_t expected_mask = (uint32_t{1} << target) - 1;
    return g_mission_groups_synchronized.load(std::memory_order_acquire) &&
        g_diagnostic_ready_mask.load(std::memory_order_acquire) ==
            expected_mask &&
        g_diagnostic_mission_group_mask.load(std::memory_order_acquire) ==
            expected_mask &&
        g_gameplay_contact_mask.load(std::memory_order_acquire) ==
            expected_mask &&
        g_diagnostic_real_gameplay_peers.load(std::memory_order_acquire) == 0;
}

bool ShouldBypassLocalMissionHarnessControllerGate(
    int32_t native_gate_value, int32_t mission_start_state,
    unsigned target) {
    // State zero must take the native initialization branch once. Thereafter
    // only the controller's missing-real-peer predicate is virtualized; the
    // MissionStart state machine still advances 1->2->3->4 itself.
    return native_gate_value == 0 && mission_start_state >= 1 &&
        mission_start_state <= kMissionStartCompletedState &&
        LocalMissionHarnessCompletionPrerequisites(target);
}

void ObserveLocalMissionHarnessMissionStart(void* state, bool is_global,
                                           bool publish,
                                           int32_t native_before_state,
                                           const char* observation_point,
                                           bool native_update_called) {
    const unsigned target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    if (!is_global || !LocalMissionHarnessSessionReady() || !state ||
        target >= 32 || !IsReadableMemoryRange(state, sizeof(int32_t))) {
        return;
    }

    int32_t native_after_state = std::numeric_limits<int32_t>::min();
    std::memcpy(&native_after_state, state, sizeof(native_after_state));
    const uint64_t call = native_update_called
        ? g_local_mission_harness_mission_start_calls.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_local_mission_harness_mission_start_calls.load(
              std::memory_order_acquire);
    const int32_t previous_observed_state =
        g_local_mission_harness_last_mission_start_state.exchange(
            native_after_state, std::memory_order_acq_rel);
    const bool first_observation = previous_observed_state ==
        std::numeric_limits<int32_t>::min();
    const bool state_changed = !first_observation &&
        previous_observed_state != native_after_state;
    const uint64_t now = GetTickCount64();
    const uint64_t last_log_tick =
        g_local_mission_harness_last_mission_start_log_tick.load(
            std::memory_order_acquire);
    const bool periodic = !last_log_tick || now < last_log_tick ||
        now - last_log_tick >= kMissionStartObservationIntervalMs;
    if (!first_observation && !state_changed && !periodic) return;
    g_local_mission_harness_last_mission_start_log_tick.store(
        now, std::memory_order_release);

    const uint64_t observation =
        g_local_mission_harness_mission_start_observations.fetch_add(
            1, std::memory_order_acq_rel) + 1;
    const uint32_t expected_mask = (uint32_t{1} << target) - 1;
    const uint32_t ready_mask = g_diagnostic_ready_mask.load(
        std::memory_order_acquire);
    const uint32_t mission_group_mask =
        g_diagnostic_mission_group_mask.load(std::memory_order_acquire);
    const uint32_t gameplay_contact_mask = g_gameplay_contact_mask.load(
        std::memory_order_acquire);
    const unsigned real_gameplay_peers =
        g_diagnostic_real_gameplay_peers.load(std::memory_order_acquire);
    const bool mission_groups_synchronized =
        g_mission_groups_synchronized.load(std::memory_order_acquire);
    const bool completion_prerequisites =
        LocalMissionHarnessCompletionPrerequisites(target);

    if (first_observation || state_changed) {
        EDF5_CRASH_BREADCRUMB(
            "more_players", "local_mission_harness_mission_start",
            state_changed ? "state_changed" : "first_observation",
            static_cast<uint64_t>(static_cast<uint32_t>(native_before_state)),
            static_cast<uint64_t>(static_cast<uint32_t>(native_after_state)));
    }
    EDF5_CAPTURE_EVENT(
        "more_players", "local_mission_harness_mission_start_observed",
        capture::Fields()
            .UInt("observation", observation)
            .UInt("update_call", call)
            .String("observation_point", observation_point)
            .Bool("native_update_called", native_update_called)
            .UInt("dummy_count", target)
            .Int("actual_members",
                 g_last_actual_member_count.load(std::memory_order_acquire))
            .Int("native_before_state", native_before_state)
            .Int("native_after_state", native_after_state)
            .Int("previous_observed_state", previous_observed_state)
            .Bool("first_observation", first_observation)
            .Bool("state_changed", state_changed)
            .Bool("periodic", periodic)
            .Bool("publish", publish)
            .UInt("expected_mask", expected_mask)
            .UInt("ready_mask", ready_mask)
            .UInt("mission_group_mask", mission_group_mask)
            .UInt("gameplay_contact_mask", gameplay_contact_mask)
            .UInt("real_gameplay_peers", real_gameplay_peers)
            .Bool("mission_groups_synchronized",
                  mission_groups_synchronized)
            .Bool("completion_prerequisites", completion_prerequisites)
            .Bool("native_state_forced", false)
            .UInt("observation_interval_ms",
                  kMissionStartObservationIntervalMs)
            .UInt("mission_start_update_rva", kMissionStartUpdateRva)
            .UInt("mission_start_global_state_rva",
                  kMissionStartGlobalStateRva));
}

void ObserveLocalMissionHarnessMissionStartSnapshot(
    const char* observation_point) {
    if (!g_module_base) return;
    void* const state = reinterpret_cast<void*>(
        g_module_base + kMissionStartGlobalStateRva);
    if (!IsReadableMemoryRange(state, sizeof(int32_t))) return;
    int32_t current_state = std::numeric_limits<int32_t>::min();
    std::memcpy(&current_state, state, sizeof(current_state));
    ObserveLocalMissionHarnessMissionStart(
        state, true, false, current_state, observation_point, false);
}

bool CompleteLocalMissionHarnessMatchingGate(void* state, bool test_mode) {
    const unsigned target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    if (!LocalMissionHarnessSessionReady() || !state || target >= 32 ||
        !IsReadableMemoryRange(state, sizeof(int32_t))) {
        return false;
    }
    const void* const native_global = g_module_base
        ? reinterpret_cast<const void*>(g_module_base +
                                        kMissionStartGlobalStateRva)
        : nullptr;
    if (!test_mode && state != native_global) return false;

    const uint32_t expected_mask = (uint32_t{1} << target) - 1;
    const uint32_t ready_mask = g_diagnostic_ready_mask.load(
        std::memory_order_acquire);
    const uint32_t mission_group_mask =
        g_diagnostic_mission_group_mask.load(std::memory_order_acquire);
    const uint32_t gameplay_contact_mask = g_gameplay_contact_mask.load(
        std::memory_order_acquire);
    const unsigned real_gameplay_peers =
        g_diagnostic_real_gameplay_peers.load(std::memory_order_acquire);
    if (!LocalMissionHarnessCompletionPrerequisites(target)) {
        return false;
    }

    auto* phase = reinterpret_cast<volatile LONG*>(state);
    const LONG previous = InterlockedCompareExchange(
        phase, kMissionStartCompletedState,
        kMissionStartLocallyAggregatedState);
    if (previous != kMissionStartLocallyAggregatedState) return false;

    const unsigned completion =
        g_local_mission_harness_matching_completions.fetch_add(
            1, std::memory_order_acq_rel) + 1;
    EDF5_CRASH_BREADCRUMB(
        "more_players", "local_mission_harness_matching",
        "completed", target, expected_mask);
    EDF5_CAPTURE_EVENT(
        "more_players", "local_mission_harness_matching_gate_completed",
        capture::Fields()
            .UInt("completion", completion)
            .UInt("dummy_count", target)
            .Int("actual_members",
                 g_last_actual_member_count.load(std::memory_order_acquire))
            .Int("previous_state", previous)
            .Int("completed_state", kMissionStartCompletedState)
            .UInt("expected_mask", expected_mask)
            .UInt("ready_mask", ready_mask)
            .UInt("mission_group_mask", mission_group_mask)
            .UInt("gameplay_contact_mask", gameplay_contact_mask)
            .UInt("real_gameplay_peers", real_gameplay_peers)
            .UInt("mission_start_update_rva", kMissionStartUpdateRva)
            .UInt("mission_start_global_state_rva",
                  kMissionStartGlobalStateRva)
            .UInt("mission_start_controller_completed_read_rva",
                  kMissionStartControllerCompletedReadRva)
            .Bool("test_mode", test_mode)
            .Bool("native_peer_snapshot_received", false)
            .Bool("gameplay_packet_fabricated", false)
            .String("completion_scope", "host_only_local_harness"));
    return true;
}

bool CompleteLocalMissionHarnessResultSync(
    void* state, MissionResultSyncOrigin origin) {
    if (origin == MissionResultSyncOrigin::Unknown ||
        !LocalMissionHarnessSessionReady() || !state ||
        !IsReadableMemoryRange(state, 2 * sizeof(int32_t))) {
        return false;
    }
    auto* phase = reinterpret_cast<volatile LONG*>(state);
    auto* result = reinterpret_cast<volatile LONG*>(
        static_cast<uint8_t*>(state) + sizeof(int32_t));
    const LONG previous_phase = InterlockedExchange(phase, 1);
    const LONG previous_result = InterlockedExchange(result, 0);
    const uint32_t origin_bit = MissionResultSyncOriginBit(origin);
    const bool first = origin_bit &&
        !(g_local_mission_harness_result_sync_logged_mask.fetch_or(
              origin_bit, std::memory_order_acq_rel) & origin_bit);
    if (first) {
        EDF5_CAPTURE_EVENT(
            "more_players", "local_mission_harness_result_sync_completed",
            capture::Fields()
                .String("origin", MissionResultSyncOriginName(origin))
                .Int("previous_sync_state", previous_phase)
                .Int("previous_sync_result", previous_result)
                .Int("sync_state", 1)
                .Int("sync_result", 0)
                .UInt("dummy_count", g_local_mission_harness_target.load(
                                         std::memory_order_acquire))
                .Bool("real_network_ack_fabricated", false)
                .String("completion_scope", "local_harness_only"));
    }
    return true;
}

int32_t ReadMissionResultParticipantCount();

int32_t ReadMissionRewardLocalProfileCount() {
    if (!g_mission_loadout_state_slot ||
        !IsReadableMemoryRange(g_mission_loadout_state_slot,
                               sizeof(void*))) {
        return -1;
    }
    void* state = nullptr;
    std::memcpy(&state, g_mission_loadout_state_slot, sizeof(state));
    if (!state) return -1;
    const auto* field = static_cast<const uint8_t*>(state) +
        kMissionRewardLocalProfileCountOffset;
    if (!IsReadableMemoryRange(field, sizeof(int32_t))) return -1;
    int32_t count = -1;
    std::memcpy(&count, field, sizeof(count));
    return count;
}

bool RepairMissionRewardLocalProfileCount(const char* phase,
                                          bool mission_clear_only) {
    const int32_t before = ReadMissionRewardLocalProfileCount();
    const int32_t expected =
        g_mission_expected_local_profile_count.load(
            std::memory_order_acquire);
    const int32_t participant_count = ReadMissionResultParticipantCount();
    const int32_t participant_capacity = static_cast<int32_t>(std::min(
        MaxPlayers(), kMaximumMissionParticipants));
    const bool native_count_valid = before >= 1 &&
        before <= kMissionRewardLocalProfileCapacity;
    const bool expected_count_valid = expected >= 1 &&
        expected <= kMissionRewardLocalProfileCapacity;
    const bool extra_session = participant_count >
            static_cast<int32_t>(kNativeMissionSourceCount) &&
        participant_count <= participant_capacity;
    if (native_count_valid || !expected_count_valid || !extra_session ||
        !mission_clear_only || !g_mission_loadout_state_slot ||
        !IsReadableMemoryRange(g_mission_loadout_state_slot,
                               sizeof(void*))) {
        return false;
    }

    void* state = nullptr;
    std::memcpy(&state, g_mission_loadout_state_slot, sizeof(state));
    if (!state) return false;
    auto* field = reinterpret_cast<volatile LONG*>(
        static_cast<uint8_t*>(state) +
        kMissionRewardLocalProfileCountOffset);
    if (!IsReadableMemoryRange(
            const_cast<const LONG*>(field), sizeof(LONG))) {
        return false;
    }

    const LONG observed = InterlockedCompareExchange(
        field, static_cast<LONG>(expected), static_cast<LONG>(before));
    const int32_t after = ReadMissionRewardLocalProfileCount();
    const bool repaired = observed == before && after == expected;
    const unsigned repair = repaired
        ? g_mission_reward_profile_count_repairs.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_mission_reward_profile_count_repairs.load(
              std::memory_order_acquire);
    EDF5_CAPTURE_EVENT(
        repaired ? capture::Level::Warning : capture::Level::Error,
        "more_players", "mission_reward_profile_count_repair",
        capture::Fields()
            .String("phase", phase ? phase : "unknown")
            .Int("before_local_profile_count", before)
            .Int("expected_local_profile_count", expected)
            .Int("observed_compare_value", observed)
            .Int("after_local_profile_count", after)
            .Int("participant_count", participant_count)
            .UInt("repair", repair)
            .Bool("native_count_was_valid", native_count_valid)
            .Bool("expected_count_valid", expected_count_valid)
            .Bool("extra_session", extra_session)
            .Bool("mission_clear", mission_clear_only)
            .Bool("repaired", repaired)
            .UInt("local_profile_count_offset",
                  kMissionRewardLocalProfileCountOffset)
            .UInt("native_local_profile_capacity",
                  kMissionRewardLocalProfileCapacity)
            .Bool("reward_contents_logged", false)
            .Bool("payload_logged", false)
            .Bool("pointer_logged", false));
    return repaired;
}

int32_t ReadMissionResultParticipantCount() {
    if (!g_mission_loadout_state_slot ||
        !IsReadableMemoryRange(g_mission_loadout_state_slot,
                               sizeof(void*))) {
        return -1;
    }
    void* state = nullptr;
    std::memcpy(&state, g_mission_loadout_state_slot, sizeof(state));
    if (!state) return -1;
    const auto* field = static_cast<const uint8_t*>(state) +
        kMissionResultParticipantCountOffset;
    if (!IsReadableMemoryRange(field, sizeof(int32_t))) return -1;
    int32_t count = -1;
    std::memcpy(&count, field, sizeof(count));
    return count;
}

void EmitEnemySpawnSummary(const char* phase) {
    const uint64_t calls =
        g_enemy_spawn_calls.load(std::memory_order_acquire);
    const uint64_t confirmed_calls =
        g_enemy_spawn_confirmed_calls.load(std::memory_order_acquire);
    EDF5_CAPTURE_EVENT(
        "more_players", "enemy_spawn_summary",
        capture::Fields()
            .String("phase", phase ? phase : "unknown")
            .UInt("calls", calls)
            .UInt("confirmed_enemy_calls", confirmed_calls)
            .Bool("common_spawn_reached", calls != 0)
            .Bool("confirmed_enemy_path_reached", confirmed_calls != 0)
            .UInt("requested_total",
                  g_enemy_spawn_requested_total.load(
                      std::memory_order_acquire))
            .UInt("effective_requested_total",
                  g_enemy_spawn_effective_total.load(
                      std::memory_order_acquire))
            .UInt("zero_scale_calls",
                  g_enemy_spawn_zero_scale_calls.load(
                      std::memory_order_acquire))
            .UInt("missing_spawn_source_calls",
                  g_enemy_spawn_missing_source_calls.load(
                      std::memory_order_acquire))
            .UInt("zero_scale_repairs",
                  g_enemy_spawn_scale_repairs.load(
                      std::memory_order_acquire))
            .UInt("scale_restore_failures",
                  g_enemy_spawn_scale_restore_failures.load(
                      std::memory_order_acquire))
            .UInt("configured_multiplier",
                  capture::GetConfig().enemy_spawn_multiplier)
            .Bool("experimental_multiplier_enabled",
                  capture::GetConfig()
                      .experimental_enemy_spawn_multiplier)
            .UInt("effective_multiplier",
                  capture::GetConfig()
                          .experimental_enemy_spawn_multiplier
                      ? capture::GetConfig().enemy_spawn_multiplier
                      : mission_spawn::kMinimumMultiplier)
            .UInt("native_enemy_capacity",
                  mission_spawn::kNativeEnemyCapacity)
            .UInt("generator_poll_update_calls",
                  g_generator_poll_update_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_update_completed_calls",
                  g_generator_poll_update_completed_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_updates_reaching_spawn_method",
                  g_generator_poll_updates_reaching_spawn_method.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_spawn_method_calls_in_updates",
                  g_generator_poll_spawn_method_calls_in_updates.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_calls",
                  g_generator_poll_native_gate_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_completed_calls",
                  g_generator_poll_native_gate_completed_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_cooldown_blocks",
                  g_generator_poll_native_gate_cooldown_blocks.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_quota_blocks",
                  g_generator_poll_native_gate_quota_blocks.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_spawn_false",
                  g_generator_poll_native_gate_spawn_false.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_spawn_accepted",
                  g_generator_poll_native_gate_spawn_accepted.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_native_gate_unknown",
                  g_generator_poll_native_gate_unknown.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_calls",
                  g_generator_poll_spawn_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_manager_readable_calls",
                  g_generator_poll_manager_readable_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_manager_present_calls",
                  g_generator_poll_manager_present_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_methods_reaching_common_spawn",
                  g_generator_poll_methods_reaching_common_spawn.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_common_spawn_calls",
                  g_generator_poll_common_spawn_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_gate_true_calls",
                  g_generator_poll_gate_true_calls.load(
                      std::memory_order_acquire))
            .UInt("generator_poll_gate_false_calls",
                  g_generator_poll_gate_false_calls.load(
                      std::memory_order_acquire))
            .UInt("native_participant_scaling_clamp_hits",
                  game_patches::NativeParticipantScalingClampHits())
            .UInt("native_participant_scaling_clamp_site_mask",
                  game_patches::NativeParticipantScalingClampMask())
            .UInt("native_participant_scaling_capacity", 4)
            .Bool("participant_count_storage_preserved", true)
            .Int("participant_count",
                 ReadMissionResultParticipantCount())
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("actor_pointer_logged", false)
            .Bool("spawn_payload_logged", false));
}

bool RestoreEnemySpawnScale(volatile LONG* numerator_field,
                            LONG temporary_value, uint64_t call,
                            uintptr_t caller_rva,
                            bool record_failure = true) {
    if (!numerator_field) return false;
    const LONG observed = InterlockedCompareExchange(
        numerator_field, 0, temporary_value);
    if (observed == temporary_value) return true;
    if (!record_failure) return false;
    g_enemy_spawn_scale_restore_failures.fetch_add(
        1, std::memory_order_acq_rel);
    EDF5_CAPTURE_EVENT(
        capture::Level::Error, "more_players",
        "enemy_spawn_scale_restore_failed",
        capture::Fields()
            .UInt("call", call)
            .UInt("caller_rva", caller_rva)
            .Int("expected_temporary_value", temporary_value)
            .Int("observed_value", observed)
            .Bool("field_overwritten", false)
            .Bool("actor_pointer_logged", false));
    return false;
}

void DispatchEnemySpawn(void* owner, void* spawn_descriptor,
                        uint32_t requested_count, uintptr_t caller_rva,
                        unsigned configured_multiplier,
                        bool multiplier_enabled) {
    const uint64_t call = g_enemy_spawn_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;

    mission_spawn::Input input{};
    input.caller_return_rva = caller_rva;
    input.requested_count = requested_count;
    input.configured_multiplier = configured_multiplier;
    input.multiplier_enabled = multiplier_enabled;
    input.participant_count = ReadMissionResultParticipantCount();
    input.configured_max_players = MaxPlayers();

    auto* owner_bytes = static_cast<uint8_t*>(owner);
    const bool scale_fields_readable = owner_bytes &&
        IsReadableMemoryRange(
            owner_bytes + kEnemySpawnScaleNumeratorOffset,
            kEnemySpawnSourceOffset + sizeof(void*) -
                kEnemySpawnScaleNumeratorOffset);
    input.scale_fields_readable = scale_fields_readable;
    if (scale_fields_readable) {
        std::memcpy(&input.scale_numerator,
                    owner_bytes + kEnemySpawnScaleNumeratorOffset,
                    sizeof(input.scale_numerator));
        std::memcpy(&input.scale_denominator,
                    owner_bytes + kEnemySpawnScaleDenominatorOffset,
                    sizeof(input.scale_denominator));
        void* spawn_source = nullptr;
        std::memcpy(&spawn_source,
                    owner_bytes + kEnemySpawnSourceOffset,
                    sizeof(spawn_source));
        input.spawn_source_present = spawn_source != nullptr;
    }

    const mission_spawn::Decision decision =
        mission_spawn::Evaluate(input);
    if (decision.confirmed_enemy_caller) {
        g_enemy_spawn_confirmed_calls.fetch_add(
            1, std::memory_order_acq_rel);
        g_enemy_spawn_requested_total.fetch_add(
            requested_count, std::memory_order_acq_rel);
        g_enemy_spawn_effective_total.fetch_add(
            decision.effective_count, std::memory_order_acq_rel);
        if (scale_fields_readable && input.scale_numerator == 0 &&
            input.scale_denominator > 0) {
            g_enemy_spawn_zero_scale_calls.fetch_add(
                1, std::memory_order_acq_rel);
        }
        if (scale_fields_readable && !input.spawn_source_present) {
            g_enemy_spawn_missing_source_calls.fetch_add(
                1, std::memory_order_acq_rel);
        }
    }

    volatile LONG* numerator_field = nullptr;
    bool scale_repaired = false;
    bool scale_writable = false;
    if (decision.repair_zero_scale) {
        scale_writable = IsWritableMemoryRange(
            owner_bytes + kEnemySpawnScaleNumeratorOffset,
            sizeof(LONG));
        if (scale_writable) {
            numerator_field = reinterpret_cast<volatile LONG*>(
                owner_bytes + kEnemySpawnScaleNumeratorOffset);
            const LONG observed = InterlockedCompareExchange(
                numerator_field,
                static_cast<LONG>(input.scale_denominator), 0);
            scale_repaired = observed == 0;
            if (scale_repaired) {
                g_enemy_spawn_scale_repairs.fetch_add(
                    1, std::memory_order_acq_rel);
            }
        }
    }

    uint32_t observation_bit = 0;
    if (!decision.confirmed_enemy_caller) {
        observation_bit = uint32_t{1} << 5;
    } else if (scale_repaired) {
        observation_bit = uint32_t{1} << 2;
    } else if (decision.repair_zero_scale) {
        observation_bit = uint32_t{1} << 3;
    } else if (scale_fields_readable && !input.spawn_source_present &&
               requested_count > 0) {
        observation_bit = uint32_t{1} << 4;
    } else if (decision.multiplier_applied) {
        observation_bit = uint32_t{1} << 1;
    } else {
        observation_bit = uint32_t{1};
    }
    const bool first_observation =
        (g_enemy_spawn_observation_mask.fetch_or(
             observation_bit, std::memory_order_acq_rel) &
         observation_bit) == 0;
    if (first_observation) {
        const bool warning = decision.repair_zero_scale ||
            !decision.confirmed_enemy_caller ||
            (scale_fields_readable && !input.spawn_source_present);
        EDF5_CAPTURE_EVENT(
            warning ? capture::Level::Warning : capture::Level::Info,
            "more_players",
            scale_repaired ? "enemy_spawn_scale_repaired"
                           : "enemy_spawn_observed",
            capture::Fields()
                .UInt("call", call)
                .UInt("caller_rva", caller_rva)
                .Bool("confirmed_enemy_caller",
                      decision.confirmed_enemy_caller)
                .UInt("requested_count", requested_count)
                .UInt("effective_requested_count",
                      decision.effective_count)
                .UInt("multiplier", decision.multiplier)
                .Bool("experimental_multiplier_enabled",
                      decision.multiplier_enabled)
                .Bool("multiplier_applied",
                      decision.multiplier_applied)
                .Bool("saturated_at_native_capacity",
                      decision.saturated)
                .Int("participant_count", input.participant_count)
                .Bool("scale_fields_readable",
                      input.scale_fields_readable)
                .UInt("scale_numerator", input.scale_numerator)
                .UInt("scale_denominator", input.scale_denominator)
                .Bool("spawn_source_present",
                      input.spawn_source_present)
                .Bool("zero_scale_repair_eligible",
                      decision.repair_zero_scale)
                .Bool("scale_field_writable", scale_writable)
                .Bool("scale_repaired", scale_repaired)
                .UInt("native_enemy_capacity",
                      mission_spawn::kNativeEnemyCapacity)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("actor_pointer_logged", false)
                .Bool("spawn_payload_logged", false));
    }

    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "enemy_spawn", "before_original",
        requested_count, decision.effective_count);
    if (g_enemy_spawn) {
        g_enemy_spawn(owner, spawn_descriptor,
                      decision.effective_count);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned",
                            scale_repaired ? 1 : 0, call);

    if (scale_repaired && numerator_field) {
        RestoreEnemySpawnScale(
            numerator_field, static_cast<LONG>(input.scale_denominator),
            call, caller_rva);
    }
}

void __fastcall GeneratorPollUpdateHook(void* generator,
                                        void* frame_context) {
    const uint64_t call = g_generator_poll_update_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    const uint64_t spawn_before =
        g_generator_poll_update_scope_spawn_calls;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "generator_poll_update", "before_original",
        call, 0);
    ++g_generator_poll_update_scope_depth;
    if (g_generator_poll_update) {
        g_generator_poll_update(generator, frame_context);
    }
    --g_generator_poll_update_scope_depth;
    const uint64_t spawn_calls =
        g_generator_poll_update_scope_spawn_calls - spawn_before;
    const bool spawn_method_reached = spawn_calls != 0;
    g_generator_poll_update_completed_calls.fetch_add(
        1, std::memory_order_acq_rel);
    if (spawn_method_reached) {
        g_generator_poll_updates_reaching_spawn_method.fetch_add(
            1, std::memory_order_acq_rel);
        g_generator_poll_spawn_method_calls_in_updates.fetch_add(
            spawn_calls, std::memory_order_acq_rel);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", spawn_calls,
                            spawn_method_reached ? 1 : 0);

    const uint32_t observation_bit = spawn_method_reached
        ? uint32_t{1} << 1 : uint32_t{1};
    const bool first_observation =
        (g_generator_poll_update_observation_mask.fetch_or(
             observation_bit, std::memory_order_acq_rel) &
         observation_bit) == 0;
    if (first_observation) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Info,
            "more_players", "generator_poll_update_path",
            capture::Fields()
                .UInt("call", call)
                .Bool("original_returned", true)
                .Bool("original_completed", true)
                .Bool("base_update_and_gate_reached", true)
                .UInt("spawn_method_calls_in_update", spawn_calls)
                .Bool("spawn_method_reached", spawn_method_reached)
                .UInt("generator_poll_update_rva",
                      kGeneratorPollUpdateRva)
                .UInt("generator_poll_base_update_rva",
                      kGeneratorPollBaseUpdateRva)
                .UInt("generator_poll_gate_rva", kGeneratorPollGateRva)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("generator_pointer_logged", false)
                .Bool("frame_context_pointer_logged", false)
                .Bool("spawn_payload_logged", false));
    }
}

void __fastcall GeneratorPollGateHook(void* gate_state, void* owner) {
    void* owner_vtable = nullptr;
    const bool owner_vtable_readable = owner &&
        IsReadableMemoryRange(owner, sizeof(owner_vtable));
    if (owner_vtable_readable) {
        std::memcpy(&owner_vtable, owner, sizeof(owner_vtable));
    }
    const bool owner_is_generator_poll = owner_vtable_readable &&
        owner_vtable == reinterpret_cast<void*>(
            g_module_base + kGeneratorPollVtableRva);
    if (!owner_is_generator_poll) {
        if (g_generator_poll_gate) g_generator_poll_gate(gate_state, owner);
        return;
    }

    const uint64_t call = g_generator_poll_native_gate_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    const bool gate_state_matches_owner_offset =
        reinterpret_cast<uintptr_t>(gate_state) ==
            reinterpret_cast<uintptr_t>(owner) +
                kGeneratorPollGateStateOffset;
    const bool state_readable = gate_state &&
        IsReadableMemoryRange(gate_state,
                              kGeneratorPollGateLastTimeOffset +
                                  sizeof(uint32_t));
    const auto* owner_bytes = static_cast<const uint8_t*>(owner);
    const bool owner_time_fields_readable = owner_bytes &&
        IsReadableMemoryRange(
            owner_bytes + kGeneratorPollPeriodScaleOffset,
            sizeof(uint32_t) * 2);

    int32_t pre_remaining = 0;
    int32_t pre_cooldown = 0;
    int32_t cooldown_after_decrement = 0;
    uint32_t pre_last_time_bits = 0;
    uint32_t period_scale_bits = 0;
    uint32_t current_time_bits = 0;
    if (state_readable) {
        const auto* state_bytes = static_cast<const uint8_t*>(gate_state);
        std::memcpy(&pre_remaining,
                    state_bytes + kGeneratorPollGateRemainingOffset,
                    sizeof(pre_remaining));
        std::memcpy(&pre_cooldown,
                    state_bytes + kGeneratorPollGateCooldownOffset,
                    sizeof(pre_cooldown));
        std::memcpy(&pre_last_time_bits,
                    state_bytes + kGeneratorPollGateLastTimeOffset,
                    sizeof(pre_last_time_bits));
        uint32_t cooldown_bits = 0;
        std::memcpy(&cooldown_bits, &pre_cooldown,
                    sizeof(cooldown_bits));
        cooldown_bits -= 1u;
        std::memcpy(&cooldown_after_decrement, &cooldown_bits,
                    sizeof(cooldown_after_decrement));
    }
    if (owner_time_fields_readable) {
        std::memcpy(&period_scale_bits,
                    owner_bytes + kGeneratorPollPeriodScaleOffset,
                    sizeof(period_scale_bits));
        std::memcpy(&current_time_bits,
                    owner_bytes + kGeneratorPollCurrentTimeOffset,
                    sizeof(current_time_bits));
    }

    const uint64_t spawn_before =
        g_generator_poll_native_gate_scope_spawn_calls;
    const uint64_t true_before =
        g_generator_poll_native_gate_scope_spawn_true_calls;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "generator_poll_gate", "before_original",
        call, (state_readable ? uint64_t{1} : uint64_t{0}) |
                  (gate_state_matches_owner_offset ? uint64_t{2}
                                                   : uint64_t{0}));
    ++g_generator_poll_native_gate_scope_depth;
    if (g_generator_poll_gate) g_generator_poll_gate(gate_state, owner);
    --g_generator_poll_native_gate_scope_depth;
    const uint64_t spawn_calls =
        g_generator_poll_native_gate_scope_spawn_calls - spawn_before;
    const uint64_t spawn_true_calls =
        g_generator_poll_native_gate_scope_spawn_true_calls - true_before;
    g_generator_poll_native_gate_completed_calls.fetch_add(
        1, std::memory_order_acq_rel);

    int32_t post_remaining = 0;
    int32_t post_cooldown = 0;
    const bool post_state_readable = gate_state &&
        IsReadableMemoryRange(gate_state,
                              kGeneratorPollGateCooldownOffset +
                                  sizeof(post_cooldown));
    if (post_state_readable) {
        const auto* state_bytes = static_cast<const uint8_t*>(gate_state);
        std::memcpy(&post_remaining,
                    state_bytes + kGeneratorPollGateRemainingOffset,
                    sizeof(post_remaining));
        std::memcpy(&post_cooldown,
                    state_bytes + kGeneratorPollGateCooldownOffset,
                    sizeof(post_cooldown));
    }

    const char* outcome = "unknown";
    uint32_t observation_bit = uint32_t{1} << 4;
    if (spawn_calls != 0 && spawn_true_calls != 0) {
        outcome = "spawn_accepted";
        observation_bit = uint32_t{1} << 3;
        g_generator_poll_native_gate_spawn_accepted.fetch_add(
            1, std::memory_order_acq_rel);
    } else if (spawn_calls != 0) {
        outcome = "spawn_returned_false";
        observation_bit = uint32_t{1} << 2;
        g_generator_poll_native_gate_spawn_false.fetch_add(
            1, std::memory_order_acq_rel);
    } else if (state_readable &&
               cooldown_after_decrement >=
                   kGeneratorPollGateCooldownThreshold) {
        outcome = "cooldown_blocked";
        observation_bit = uint32_t{1};
        g_generator_poll_native_gate_cooldown_blocks.fetch_add(
            1, std::memory_order_acq_rel);
    } else if (state_readable && pre_remaining <= 0) {
        outcome = "quota_blocked_inside_time_window";
        observation_bit = uint32_t{1} << 1;
        g_generator_poll_native_gate_quota_blocks.fetch_add(
            1, std::memory_order_acq_rel);
    } else {
        g_generator_poll_native_gate_unknown.fetch_add(
            1, std::memory_order_acq_rel);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", spawn_calls,
                            spawn_true_calls);

    const bool first_observation =
        (g_generator_poll_native_gate_observation_mask.fetch_or(
             observation_bit, std::memory_order_acq_rel) &
         observation_bit) == 0;
    if (first_observation) {
        EDF5_CAPTURE_EVENT(
            std::strcmp(outcome, "spawn_accepted") == 0
                ? capture::Level::Info : capture::Level::Warning,
            "more_players", "generator_poll_gate_path",
            capture::Fields()
                .UInt("call", call)
                .String("outcome", outcome)
                .Bool("original_returned", true)
                .Bool("owner_is_generator_poll", true)
                .Bool("gate_state_matches_owner_offset",
                      gate_state_matches_owner_offset)
                .Bool("state_readable", state_readable)
                .Bool("owner_time_fields_readable",
                      owner_time_fields_readable)
                .Int("pre_remaining_count", pre_remaining)
                .Int("pre_cooldown_ticks", pre_cooldown)
                .Int("cooldown_after_decrement",
                     cooldown_after_decrement)
                .Int("post_remaining_count", post_remaining)
                .Int("post_cooldown_ticks", post_cooldown)
                .UInt("pre_last_time_bits", pre_last_time_bits)
                .UInt("period_scale_bits", period_scale_bits)
                .UInt("current_time_bits", current_time_bits)
                .UInt("spawn_method_calls_in_gate", spawn_calls)
                .UInt("spawn_method_true_calls_in_gate",
                      spawn_true_calls)
                .Bool("method_call_count_valid",
                      spawn_calls <= 1 &&
                          spawn_true_calls <= spawn_calls)
                .UInt("cooldown_threshold",
                      kGeneratorPollGateCooldownThreshold)
                .UInt("generator_poll_gate_rva", kGeneratorPollGateRva)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("gate_state_pointer_logged", false)
                .Bool("owner_pointer_logged", false)
                .Bool("spawn_payload_logged", false));
    }
}

uintptr_t __fastcall GeneratorPollSpawnHook(void* generator,
                                            void* spawn_descriptor) {
    if (g_generator_poll_update_scope_depth != 0) {
        ++g_generator_poll_update_scope_spawn_calls;
    }
    if (g_generator_poll_native_gate_scope_depth != 0) {
        ++g_generator_poll_native_gate_scope_spawn_calls;
    }
    const uint64_t call = g_generator_poll_spawn_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    const auto* generator_bytes = static_cast<const uint8_t*>(generator);
    const bool manager_readable = generator_bytes &&
        IsReadableMemoryRange(
            generator_bytes + kGeneratorPollManagerOffset, sizeof(void*));
    void* manager = nullptr;
    if (manager_readable) {
        std::memcpy(&manager,
                    generator_bytes + kGeneratorPollManagerOffset,
                    sizeof(manager));
        g_generator_poll_manager_readable_calls.fetch_add(
            1, std::memory_order_acq_rel);
        if (manager) {
            g_generator_poll_manager_present_calls.fetch_add(
                1, std::memory_order_acq_rel);
        }
    }

    const uint64_t common_before =
        g_generator_poll_scope_common_spawn_calls;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "generator_poll_spawn", "before_original",
        call, (manager_readable ? uint64_t{1} : uint64_t{0}) |
                  (manager ? uint64_t{2} : uint64_t{0}));
    ++g_generator_poll_spawn_scope_depth;
    const uintptr_t result = g_generator_poll_spawn
        ? g_generator_poll_spawn(generator, spawn_descriptor) : 0;
    --g_generator_poll_spawn_scope_depth;
    const uint64_t common_calls =
        g_generator_poll_scope_common_spawn_calls - common_before;
    const bool common_reached = common_calls != 0;
    const bool gate_true = static_cast<uint8_t>(result) != 0;
    if (g_generator_poll_native_gate_scope_depth != 0 && gate_true) {
        ++g_generator_poll_native_gate_scope_spawn_true_calls;
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", common_calls,
                            gate_true ? 1 : 0);
    if (common_reached) {
        g_generator_poll_methods_reaching_common_spawn.fetch_add(
            1, std::memory_order_acq_rel);
        g_generator_poll_common_spawn_calls.fetch_add(
            common_calls, std::memory_order_acq_rel);
    }
    (gate_true ? g_generator_poll_gate_true_calls
               : g_generator_poll_gate_false_calls)
        .fetch_add(1, std::memory_order_acq_rel);

    uint32_t observation_bit = 0;
    if (!manager_readable) {
        observation_bit = uint32_t{1};
    } else if (!manager) {
        observation_bit = uint32_t{1} << 1;
    } else if (!common_reached) {
        observation_bit = uint32_t{1} << 2;
    } else if (gate_true) {
        observation_bit = uint32_t{1} << 3;
    } else {
        observation_bit = uint32_t{1} << 4;
    }
    const bool first_observation =
        (g_generator_poll_observation_mask.fetch_or(
             observation_bit, std::memory_order_acq_rel) &
         observation_bit) == 0;
    if (first_observation) {
        EDF5_CAPTURE_EVENT(
            common_reached ? capture::Level::Info
                           : capture::Level::Warning,
            "more_players", "generator_poll_spawn_path",
            capture::Fields()
                .UInt("call", call)
                .Bool("manager_field_readable", manager_readable)
                .Bool("manager_present", manager != nullptr)
                .UInt("common_spawn_calls_in_method", common_calls)
                .Bool("common_spawn_reached", common_reached)
                .Bool("gate_return_low_byte_nonzero", gate_true)
                .UInt("generator_poll_spawn_rva", kGeneratorPollSpawnRva)
                .UInt("common_spawn_rva", kEnemySpawnRva)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("generator_pointer_logged", false)
                .Bool("descriptor_pointer_logged", false)
                .Bool("spawn_payload_logged", false));
    }
    return result;
}

void __fastcall EnemySpawnHook(void* owner, void* spawn_descriptor,
                               uint32_t requested_count) {
    if (g_generator_poll_spawn_scope_depth != 0) {
        ++g_generator_poll_scope_common_spawn_calls;
    }
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    DispatchEnemySpawn(
        owner, spawn_descriptor, requested_count,
        ModuleRvaForAddress(return_address),
        capture::GetConfig().enemy_spawn_multiplier,
        capture::GetConfig().experimental_enemy_spawn_multiplier);
}

uint32_t ExpectedMissionResultExtraItemMask(int32_t participant_count) {
    const int32_t capacity = static_cast<int32_t>(std::min(
        MaxPlayers(), kMaximumMissionParticipants));
    if (participant_count <=
            static_cast<int32_t>(kMissionResultNativeItemCount) ||
        participant_count > capacity) {
        return 0;
    }
    const uint32_t participants =
        (uint32_t{1} << static_cast<unsigned>(participant_count)) - 1;
    const uint32_t native =
        (uint32_t{1} << kMissionResultNativeItemCount) - 1;
    return participants & ~native;
}

uint32_t ExpectedMissionResultItemMask(int32_t participant_count) {
    const int32_t capacity = static_cast<int32_t>(std::min(
        MaxPlayers(), kMaximumMissionParticipants));
    if (participant_count < 1 || participant_count > capacity) return 0;
    return (uint32_t{1} << static_cast<unsigned>(participant_count)) - 1;
}

void __fastcall MissionResultItemSinkHook(
    void* callback, const int32_t* participant_index,
    const uint64_t* item) {
    if (!participant_index ||
        !IsReadableMemoryRange(participant_index,
                               sizeof(*participant_index))) {
        if (g_mission_result_item_sink) {
            g_mission_result_item_sink(callback, participant_index, item);
        }
        return;
    }
    int32_t logical_index = -1;
    std::memcpy(&logical_index, participant_index, sizeof(logical_index));
    const unsigned capacity = std::min(
        MaxPlayers(), kMaximumMissionParticipants);
    const bool decoded_item_readable = item &&
        IsReadableMemoryRange(item, sizeof(*item));
    if (logical_index >= 0 &&
        logical_index < static_cast<int32_t>(capacity) &&
        decoded_item_readable) {
        g_mission_result_item_mask.fetch_or(
            uint32_t{1} << static_cast<unsigned>(logical_index),
            std::memory_order_acq_rel);
    }
    if (logical_index >= 0 &&
        logical_index <
            static_cast<int32_t>(kMissionResultNativeItemCount)) {
        if (g_mission_result_item_sink) {
            g_mission_result_item_sink(callback, participant_index, item);
        }
        return;
    }

    const unsigned call = g_mission_result_extra_item_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    bool aggregated = false;
    int32_t native_slot = -1;
    const char* reason = "outside configured participant capacity";
    if (logical_index >=
            static_cast<int32_t>(kMissionResultNativeItemCount) &&
        logical_index < static_cast<int32_t>(capacity) &&
        decoded_item_readable &&
        g_mission_loadout_state_slot &&
        IsReadableMemoryRange(g_mission_loadout_state_slot,
                              sizeof(void*))) {
        uint8_t* state = nullptr;
        std::memcpy(&state, g_mission_loadout_state_slot, sizeof(state));
        native_slot = logical_index %
            static_cast<int32_t>(kMissionResultNativeItemCount);
        auto* destination = state
            ? state + kMissionResultItemArrayOffset +
                  static_cast<size_t>(native_slot) *
                      kMissionResultItemSize
            : nullptr;
        if (destination &&
            IsReadableMemoryRange(destination, kMissionResultItemSize)) {
            std::array<uint32_t, 2> values{};
            std::memcpy(values.data(), item, sizeof(values));
            for (size_t field = 0; field < values.size(); ++field) {
                InterlockedExchangeAdd(
                    reinterpret_cast<volatile LONG*>(
                        destination + field * sizeof(uint32_t)),
                    static_cast<LONG>(values[field]));
            }
            aggregated = true;
            reason = "folded into native accumulator";
            g_mission_result_extra_item_aggregated_calls.fetch_add(
                1, std::memory_order_acq_rel);
        } else {
            reason = "mission result accumulator unavailable";
        }
    } else if (logical_index >=
                   static_cast<int32_t>(kMissionResultNativeItemCount) &&
               logical_index < static_cast<int32_t>(capacity)) {
        reason = "decoded Item or mission state unavailable";
    }

    const uint32_t participant_bit = logical_index >= 0 &&
            logical_index < 32
        ? uint32_t{1} << static_cast<unsigned>(logical_index) : 0;
    const bool first_success = aggregated && participant_bit &&
        !(g_mission_result_extra_item_mask.fetch_or(
              participant_bit, std::memory_order_acq_rel) &
          participant_bit);
    if (first_success || !aggregated) {
        EDF5_CAPTURE_EVENT(
            aggregated ? capture::Level::Info : capture::Level::Warning,
            "more_players", "mission_result_item_aggregation",
            capture::Fields()
                .UInt("call", call)
                .Int("participant_index", logical_index)
                .Int("native_accumulator_slot", native_slot)
                .UInt("native_item_capacity",
                      kMissionResultNativeItemCount)
                .UInt("effective_participant_capacity", capacity)
                .Bool("aggregated", aggregated)
                .String("reason", reason)
                .UInt("item_apply_filter_rva",
                      kMissionResultItemApplyFilterRva)
                .UInt("item_sink_rva", kMissionResultItemSinkRva)
                .Bool("reward_contents_logged", false)
                .Bool("payload_logged", false));
    }
}

const char* MissionResultExecBeginCallerPath(uintptr_t caller_rva,
                                             bool recovery_scope) {
    if (recovery_scope) return "mod_recovery";
    if (caller_rva == kMissionResultExecBeginNativeCallerReturnRva) {
        return "mission_script_dispatch";
    }
    if (caller_rva == kMissionResultExecBeginScriptWrapperReturnRva) {
        return "result_sync_begin_wrapper";
    }
    return caller_rva ? "other_game_caller" : "external_or_unknown";
}

bool __fastcall MissionResultExecBeginHook(int32_t argument) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const bool recovery_scope = g_mission_result_exec_recovery_scope;
    const char* caller_path = MissionResultExecBeginCallerPath(
        caller_rva, recovery_scope);
    // Publish the native call before touching the queue. A concurrent
    // Mission() poll will then preserve this native path even while waiting
    // for the queue lock.
    const unsigned call = g_mission_result_exec_begin_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    AcquireSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    const bool cancelled_recovery =
        g_mission_result_exec_recovery_pending.exchange(
            false, std::memory_order_acq_rel);
    if (cancelled_recovery) {
        ClearMissionResultExecRecoveryQueueLocked();
    }
    ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    if (cancelled_recovery) {
        const unsigned cancellation =
            g_mission_result_exec_recovery_native_cancels.fetch_add(
                1, std::memory_order_acq_rel) + 1;
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_result_exec_recovery_cancelled",
            capture::Fields()
                .UInt("cancellation", cancellation)
                 .String("reason", "native Exec_Begin arrived during grace")
                 .Int("native_argument", argument)
                 .UInt("caller_rva", caller_rva)
                 .String("caller_path", caller_path)
                 .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .Bool("native_path_preserved", true));
    }
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_exec_begin", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(argument)), call);
    const bool accepted = g_mission_result_exec_begin
        ? g_mission_result_exec_begin(argument) : false;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", accepted ? 1 : 0, call);
    EDF5_CAPTURE_EVENT(
        accepted ? capture::Level::Info : capture::Level::Warning,
        "more_players", "mission_result_exec_begin",
        capture::Fields()
            .UInt("call", call)
             .Int("argument", argument)
             .String("argument_semantics", "opaque_mission_script_value")
             .UInt("caller_rva", caller_rva)
             .String("caller_path", caller_path)
             .Bool("accepted", accepted)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .UInt("exec_begin_rva", kMissionResultExecBeginRva));
    return accepted;
}

enum class MissionResultExecCallerOrigin : uint32_t {
    Unknown = 0,
    ResultSyncWrapper = 1,
    NativeMission = 2,
};

MissionResultExecCallerOrigin MissionResultExecUpdateOriginForCaller(
    uintptr_t caller_rva) {
    if (caller_rva == kMissionResultExecUpdateScriptReturnRva) {
        return MissionResultExecCallerOrigin::ResultSyncWrapper;
    }
    if (caller_rva == kMissionResultExecUpdateNativeReturnRva) {
        return MissionResultExecCallerOrigin::NativeMission;
    }
    return MissionResultExecCallerOrigin::Unknown;
}

MissionResultExecCallerOrigin MissionResultExecFinallyOriginForCaller(
    uintptr_t caller_rva) {
    if (caller_rva == kMissionResultExecFinallyScriptReturnRva) {
        return MissionResultExecCallerOrigin::ResultSyncWrapper;
    }
    if (caller_rva == kMissionResultExecFinallyNativeReturnRva) {
        return MissionResultExecCallerOrigin::NativeMission;
    }
    return MissionResultExecCallerOrigin::Unknown;
}

[[maybe_unused]] const char* MissionResultExecCallerOriginName(
    MissionResultExecCallerOrigin origin) {
    switch (origin) {
        case MissionResultExecCallerOrigin::ResultSyncWrapper:
            return "result_sync_wrapper";
        case MissionResultExecCallerOrigin::NativeMission:
            return "native_mission_consumer";
        default:
            return "external_or_unknown";
    }
}

[[maybe_unused]] const char* MissionResultExecUpdateTrueAction(
    MissionResultExecCallerOrigin origin) {
    switch (origin) {
        case MissionResultExecCallerOrigin::ResultSyncWrapper:
            return "set_script_object_flag_0x1a8";
        case MissionResultExecCallerOrigin::NativeMission:
            return "set_mission_owner_flag_0x68";
        default:
            return "unknown";
    }
}

[[maybe_unused]] const char* MissionResultExecUpdateFalseAction(
    MissionResultExecCallerOrigin origin) {
    switch (origin) {
        case MissionResultExecCallerOrigin::ResultSyncWrapper:
            return "return_without_setting_script_flag";
        case MissionResultExecCallerOrigin::NativeMission:
            return "invoke_result_sync_finally";
        default:
            return "unknown";
    }
}

bool IsDiagnosticMilestone(uint64_t call) {
    return call && (call & (call - 1)) == 0;
}

bool __fastcall MissionResultExecUpdateHook(int32_t argument,
                                             void* state_handle) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const MissionResultExecCallerOrigin origin =
        MissionResultExecUpdateOriginForCaller(caller_rva);
    const uint64_t call = g_mission_result_exec_update_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_exec_update", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(argument)), call);
    const bool native_result = g_mission_result_exec_update
        ? g_mission_result_exec_update(argument, state_handle) : false;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", native_result ? 1 : 0,
                            call);
    const uint64_t outcome_count = native_result
        ? g_mission_result_exec_update_true_calls.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_mission_result_exec_update_false_calls.fetch_add(
              1, std::memory_order_acq_rel) + 1;
    const unsigned outcome_bit_index =
        static_cast<unsigned>(origin) * 2U + (native_result ? 1U : 0U);
    const uint32_t outcome_bit = uint32_t{1} << outcome_bit_index;
    const bool first_outcome =
        !(g_mission_result_exec_update_observation_mask.fetch_or(
              outcome_bit, std::memory_order_acq_rel) & outcome_bit);
    const bool milestone = IsDiagnosticMilestone(call);
    if (first_outcome || milestone) {
        EDF5_CAPTURE_EVENT(
            origin == MissionResultExecCallerOrigin::Unknown
                ? capture::Level::Warning : capture::Level::Info,
            "more_players", "mission_result_exec_update",
            capture::Fields()
                .UInt("call", call)
                .UInt("outcome_count", outcome_count)
                .Int("argument", argument)
                .String("argument_semantics",
                        "opaque_mission_script_value")
                .UInt("caller_rva", caller_rva)
                .String("caller_path",
                        MissionResultExecCallerOriginName(origin))
                .Bool("expected_caller",
                      origin != MissionResultExecCallerOrigin::Unknown)
                .Bool("state_handle_present", state_handle != nullptr)
                .Bool("native_result", native_result)
                .String("caller_action_for_result",
                        native_result
                            ? MissionResultExecUpdateTrueAction(origin)
                            : MissionResultExecUpdateFalseAction(origin))
                .Bool("native_result_semantics_assumed", false)
                .Bool("first_caller_outcome", first_outcome)
                .Bool("call_count_milestone", milestone)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .UInt("exec_update_rva", kMissionResultExecUpdateRva)
                .Bool("payload_logged", false)
                .Bool("pointer_logged", false));
    }
    return native_result;
}

void __fastcall MissionResultExecFinallyHook(int32_t argument) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const MissionResultExecCallerOrigin origin =
        MissionResultExecFinallyOriginForCaller(caller_rva);
    const uint64_t call = g_mission_result_exec_finally_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_exec_finally", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(argument)), call);
    if (g_mission_result_exec_finally) {
        g_mission_result_exec_finally(argument);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", call,
                            static_cast<uint64_t>(
                                static_cast<int64_t>(argument)));
    const uint32_t origin_bit = uint32_t{1} <<
        static_cast<unsigned>(origin);
    const bool first_origin =
        !(g_mission_result_exec_finally_origin_mask.fetch_or(
              origin_bit, std::memory_order_acq_rel) & origin_bit);
    const bool milestone = IsDiagnosticMilestone(call);
    if (first_origin || milestone) {
        EDF5_CAPTURE_EVENT(
            origin == MissionResultExecCallerOrigin::Unknown
                ? capture::Level::Warning : capture::Level::Info,
            "more_players", "mission_result_exec_finally",
            capture::Fields()
                .UInt("call", call)
                .Int("argument", argument)
                .String("argument_semantics",
                        "opaque_mission_script_value")
                .UInt("caller_rva", caller_rva)
                .String("caller_path",
                        MissionResultExecCallerOriginName(origin))
                .Bool("expected_caller",
                      origin != MissionResultExecCallerOrigin::Unknown)
                .Bool("first_caller_origin", first_origin)
                .Bool("call_count_milestone", milestone)
                .UInt("mission_generation",
                      g_mission_generation.load(
                          std::memory_order_acquire))
                .UInt("exec_finally_rva", kMissionResultExecFinallyRva)
                .Bool("payload_logged", false)
                .Bool("pointer_logged", false));
    }
}

bool QueueMissionResultExecRecovery(MissionResultSyncOrigin origin,
                                    bool sync_state_readable,
                                    int32_t sync_state,
                                    int32_t sync_result) {
    mission_result_recovery::QueueInput input{};
    input.script_origin = origin == MissionResultSyncOrigin::Script;
    input.sync_state_readable = sync_state_readable;
    input.sync_state = sync_state;
    input.sync_result = sync_result;
    input.participant_count = ReadMissionResultParticipantCount();
    input.configured_max_players = MaxPlayers();
    input.local_mission_harness = LocalMissionHarnessSessionReady();
    input.native_exec_begin_present = g_mission_result_exec_begin != nullptr;
    input.native_exec_begin_calls = g_mission_result_exec_begin_calls.load(
        std::memory_order_acquire);
    input.mission_generation = g_mission_generation.load(
        std::memory_order_acquire);
    if (!mission_result_recovery::ShouldQueueExecBegin(input)) return false;

    const uint64_t now = GetTickCount64();
    AcquireSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    const bool native_path_started =
        g_mission_result_exec_begin_calls.load(std::memory_order_acquire) !=
        input.native_exec_begin_calls;
    const bool already_pending =
        g_mission_result_exec_recovery_pending.load(
            std::memory_order_acquire);
    if (native_path_started || already_pending) {
        ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
        return false;
    }
    g_mission_result_exec_recovery_tick.store(now,
                                               std::memory_order_release);
    g_mission_result_exec_recovery_generation.store(
        input.mission_generation, std::memory_order_release);
    g_mission_result_exec_recovery_pending.store(
        true, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "more_players",
        "mission_result_exec_recovery_queued",
        capture::Fields()
            .UInt("mission_generation", input.mission_generation)
            .Int("participant_count", input.participant_count)
            .Int("sync_state", sync_state)
            .Int("sync_result", sync_result)
            .UInt("native_exec_begin_calls", input.native_exec_begin_calls)
            .Int("exec_begin_argument",
                 mission_result_recovery::kExecBeginArgument)
            .UInt("grace_ms",
                  mission_result_recovery::kExecBeginGraceMs)
            .String("execution_thread", "Mission() after native update")
            .Bool("host_only", false)
            .Bool("local_mission_harness", false));
    return true;
}

void __fastcall MissionNamedSyncBeginHook(void* state,
                                          const char* sync_name) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const MissionResultSyncOrigin origin =
        MissionResultSyncOriginForCaller(caller_rva, true);
    if (g_mission_named_sync_begin) {
        g_mission_named_sync_begin(state, sync_name);
    }
    if (origin == MissionResultSyncOrigin::Unknown) return;
    const bool harness_completed =
        CompleteLocalMissionHarnessResultSync(state, origin);
    const unsigned call = g_mission_result_sync_begin_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    int32_t phase = -1;
    int32_t result = -1;
    const bool readable = ReadMissionResultSyncState(state, phase, result);
    if (readable) {
        g_mission_result_sync_last_state.store(phase,
                                               std::memory_order_release);
        g_mission_result_sync_last_result.store(result,
                                                std::memory_order_release);
    }
    const bool exec_recovery_queued = QueueMissionResultExecRecovery(
        origin, readable, phase, result);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_result_sync_begin",
        capture::Fields()
            .UInt("call", call)
            .String("origin", MissionResultSyncOriginName(origin))
            .UInt("caller_rva", caller_rva)
            .Int("sync_state", phase)
            .Int("sync_result", result)
            .Bool("sync_state_readable", readable)
            .Bool("local_harness_completed", harness_completed)
            .Bool("exec_begin_recovery_queued", exec_recovery_queued)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("sync_name_logged", false)
            .Bool("payload_logged", false));
}

void __fastcall MissionNamedSyncPollHook(void* state) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const MissionResultSyncOrigin origin =
        MissionResultSyncOriginForCaller(caller_rva, false);
    if (g_mission_named_sync_poll) g_mission_named_sync_poll(state);
    if (origin == MissionResultSyncOrigin::Unknown) return;
    const bool harness_completed =
        CompleteLocalMissionHarnessResultSync(state, origin);
    const unsigned call = g_mission_result_sync_poll_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    int32_t phase = -1;
    int32_t result = -1;
    const bool readable = ReadMissionResultSyncState(state, phase, result);
    const bool complete = readable && phase == 1 && result == 0;
    if (readable) {
        g_mission_result_sync_last_state.store(phase,
                                               std::memory_order_release);
        g_mission_result_sync_last_result.store(result,
                                                std::memory_order_release);
    }
    const uint32_t origin_bit = MissionResultSyncOriginBit(origin);
    const bool first_observation =
        !(g_mission_result_sync_first_poll_logged_mask.fetch_or(
              origin_bit, std::memory_order_acq_rel) & origin_bit);
    bool first_completion = false;
    if (complete) {
        first_completion =
            !(g_mission_result_sync_complete_logged_mask.fetch_or(
                  origin_bit, std::memory_order_acq_rel) & origin_bit);
        if (first_completion) {
            g_mission_result_sync_complete_calls.fetch_add(
                1, std::memory_order_acq_rel);
        }
    }
    if (!first_observation && !first_completion) return;
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_result_sync_poll",
        capture::Fields()
            .UInt("call", call)
            .String("origin", MissionResultSyncOriginName(origin))
            .UInt("caller_rva", caller_rva)
            .Int("sync_state", phase)
            .Int("sync_result", result)
            .Bool("sync_state_readable", readable)
            .Bool("first_observation", first_observation)
            .Bool("complete", complete)
            .Bool("first_completion", first_completion)
            .Bool("local_harness_completed", harness_completed)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("payload_logged", false));
}

void __fastcall MissionRewardResolveHook() {
    const unsigned call = g_mission_reward_resolve_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    const int32_t local_profiles = ReadMissionRewardLocalProfileCount();
    const int32_t expected_local_profiles =
        g_mission_expected_local_profile_count.load(
            std::memory_order_acquire);
    const int32_t participant_count = ReadMissionResultParticipantCount();
    const uint32_t expected_extra_item_mask =
        ExpectedMissionResultExtraItemMask(participant_count);
    const uint32_t observed_extra_item_mask =
        g_mission_result_extra_item_mask.load(std::memory_order_acquire);
    const uint32_t expected_item_mask =
        ExpectedMissionResultItemMask(participant_count);
    const uint32_t observed_item_mask =
        g_mission_result_item_mask.load(std::memory_order_acquire);
    const bool participant_count_valid = participant_count >= 1 &&
        participant_count <= static_cast<int32_t>(std::min(
            MaxPlayers(), kMaximumMissionParticipants));
    const bool extra_items_complete = participant_count_valid &&
        (observed_extra_item_mask & expected_extra_item_mask) ==
            expected_extra_item_mask;
    const bool item_matrix_complete = participant_count_valid &&
        expected_item_mask != 0 &&
        (observed_item_mask & expected_item_mask) == expected_item_mask;
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_reward_resolve",
        capture::Fields()
            .UInt("call", call)
            .String("phase", "before_original")
            .Int("local_profile_count", local_profiles)
            .Int("expected_local_profile_count",
                 expected_local_profiles)
            .Bool("local_profile_count_valid",
                  local_profiles >= 1 &&
                      local_profiles <= kMissionRewardLocalProfileCapacity)
            .Int("participant_count", participant_count)
            .Bool("participant_count_valid", participant_count_valid)
            .UInt("expected_extra_result_item_mask",
                  expected_extra_item_mask)
            .UInt("observed_extra_result_item_mask",
                  observed_extra_item_mask)
            .Bool("extra_result_items_complete", extra_items_complete)
            .UInt("expected_result_item_mask", expected_item_mask)
            .UInt("observed_result_item_mask", observed_item_mask)
            .Bool("result_items_complete", item_matrix_complete)
            .UInt("resolve_rva", kMissionRewardResolveRva)
            .Bool("reward_contents_logged", false)
            .Bool("payload_logged", false));
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_reward_resolve", "before_original",
        call, static_cast<uint64_t>(static_cast<int64_t>(local_profiles)));
    if (g_mission_reward_resolve) g_mission_reward_resolve();
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", call, 1);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_reward_resolve",
        capture::Fields()
            .UInt("call", call)
            .String("phase", "original_returned")
            .Int("local_profile_count",
                 ReadMissionRewardLocalProfileCount())
            .Int("expected_local_profile_count",
                 expected_local_profiles)
            .Int("participant_count",
                 ReadMissionResultParticipantCount())
            .Bool("participant_count_valid", participant_count_valid)
            .UInt("expected_extra_result_item_mask",
                  expected_extra_item_mask)
            .UInt("observed_extra_result_item_mask",
                  g_mission_result_extra_item_mask.load(
                      std::memory_order_acquire))
            .Bool("extra_result_items_complete", extra_items_complete)
            .UInt("expected_result_item_mask", expected_item_mask)
            .UInt("observed_result_item_mask",
                  g_mission_result_item_mask.load(
                      std::memory_order_acquire))
            .Bool("result_items_complete", item_matrix_complete)
            .UInt("resolve_rva", kMissionRewardResolveRva)
            .Bool("returned", true)
            .Bool("reward_contents_logged", false)
            .Bool("payload_logged", false));
}

bool __fastcall MissionRewardApplyHook(bool is_mission_clear) {
    const unsigned call = g_mission_reward_apply_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    const int32_t before_profiles = ReadMissionRewardLocalProfileCount();
    const int32_t expected_local_profiles =
        g_mission_expected_local_profile_count.load(
            std::memory_order_acquire);
    const bool profile_count_repaired =
        RepairMissionRewardLocalProfileCount(
            "before_apply_result", is_mission_clear);
    const int32_t effective_profiles =
        ReadMissionRewardLocalProfileCount();
    const int32_t participant_count = ReadMissionResultParticipantCount();
    const uint32_t expected_extra_item_mask =
        ExpectedMissionResultExtraItemMask(participant_count);
    const uint32_t observed_extra_item_mask =
        g_mission_result_extra_item_mask.load(std::memory_order_acquire);
    const uint32_t expected_item_mask =
        ExpectedMissionResultItemMask(participant_count);
    const uint32_t observed_item_mask =
        g_mission_result_item_mask.load(std::memory_order_acquire);
    const bool participant_count_valid = participant_count >= 1 &&
        participant_count <= static_cast<int32_t>(std::min(
            MaxPlayers(), kMaximumMissionParticipants));
    const bool item_matrix_complete = participant_count_valid &&
        expected_item_mask != 0 &&
        (observed_item_mask & expected_item_mask) == expected_item_mask;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_reward_apply", "before_original",
        is_mission_clear ? 1 : 0, call);
    const bool call_completed = g_mission_reward_apply != nullptr;
    const bool native_result = call_completed
        ? g_mission_reward_apply(is_mission_clear) : false;
    if (call_completed) {
        g_mission_reward_apply_completed_calls.fetch_add(
            1, std::memory_order_acq_rel);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", native_result ? 1 : 0,
                            call);
    const int32_t after_profiles = ReadMissionRewardLocalProfileCount();
    EDF5_CAPTURE_EVENT(
        call_completed ? capture::Level::Info : capture::Level::Warning,
        "more_players", "mission_reward_apply",
        capture::Fields()
            .UInt("call", call)
            .Bool("is_mission_clear", is_mission_clear)
            .Bool("call_completed", call_completed)
            .Bool("native_result", native_result)
            .Bool("native_result_is_apply_success", false)
            .String("native_result_semantics",
                    "auxiliary_state_transition")
            .Int("before_local_profile_count", before_profiles)
            .Int("expected_local_profile_count",
                 expected_local_profiles)
            .Int("effective_local_profile_count",
                 effective_profiles)
            .Bool("local_profile_count_repaired",
                  profile_count_repaired)
            .Int("after_local_profile_count", after_profiles)
            .Bool("local_profile_count_valid",
                  after_profiles >= 1 &&
                      after_profiles <= kMissionRewardLocalProfileCapacity)
            .UInt("native_local_profile_capacity",
                  kMissionRewardLocalProfileCapacity)
            .Int("participant_count", participant_count)
            .Bool("participant_count_valid", participant_count_valid)
            .UInt("expected_extra_result_item_mask",
                  expected_extra_item_mask)
            .UInt("observed_extra_result_item_mask",
                  observed_extra_item_mask)
            .Bool("extra_result_items_complete",
                  participant_count_valid &&
                      (observed_extra_item_mask &
                       expected_extra_item_mask) ==
                          expected_extra_item_mask)
            .UInt("expected_result_item_mask", expected_item_mask)
            .UInt("observed_result_item_mask", observed_item_mask)
            .Bool("result_items_complete", item_matrix_complete)
            .UInt("apply_rva", kMissionRewardApplyRva)
            .Bool("online_player_count_used", false)
            .Bool("reward_contents_logged", false)
            .Bool("payload_logged", false));
    return native_result;
}

void RecordMissionResultObservation(uint64_t now, int32_t result,
                                    int32_t ui_state,
                                    int32_t ui_result) {
    uint64_t expected = 0;
    if (g_mission_result_tick.compare_exchange_strong(
            expected, now, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        g_mission_result_generation.store(
            g_mission_generation.load(std::memory_order_acquire),
            std::memory_order_release);
        g_mission_result_audit_mask.store(0, std::memory_order_release);
    }
    g_mission_result_last_value.store(result, std::memory_order_release);
    g_mission_result_last_ui_state.store(ui_state,
                                         std::memory_order_release);
    g_mission_result_last_ui_value.store(ui_result,
                                         std::memory_order_release);
}

void ArmMissionResultRecovery(uintptr_t caller_rva, uint64_t now,
                              int32_t result, int32_t ui_state,
                              int32_t ui_result) {
    const uint64_t generation =
        g_mission_generation.load(std::memory_order_acquire);
    const int actual_members =
        g_last_actual_member_count.load(std::memory_order_acquire);
    const bool local_harness = LocalMissionHarnessSessionReady();
    if (caller_rva != kMissionScriptClearApplyReturnRva ||
        result != kMissionResultClear ||
        ui_state != kMissionUiStateFinished ||
        ui_result != kMissionResultClear || !generation ||
        !g_owned_lobby.load(std::memory_order_acquire) ||
        (actual_members <= static_cast<int>(kNativeMissionSourceCount) &&
         !local_harness) ||
        g_mission_result_last_setter_generation.load(
            std::memory_order_acquire) == generation) {
        return;
    }
    if (g_mission_result_recovery_pending.load(std::memory_order_acquire)) {
        return;
    }
    g_mission_result_recovery_tick.store(now, std::memory_order_release);
    g_mission_result_recovery_generation.store(
        generation, std::memory_order_release);
    g_mission_result_recovery_pending.store(true,
                                            std::memory_order_release);
    EDF5_CAPTURE_EVENT(
        capture::Level::Warning, "more_players",
        "mission_result_recovery_queued",
        capture::Fields()
            .UInt("mission_generation", generation)
            .UInt("caller_rva", caller_rva)
            .Int("result", result)
            .Int("ui_state", ui_state)
            .Int("ui_result", ui_result)
            .Int("actual_members", actual_members)
            .Bool("local_mission_harness", local_harness)
            .UInt("grace_ms", kMissionResultRecoveryGraceMs)
            .String("execution_thread", "Mission() after native update")
            .Bool("result_event_publisher_owner_present",
                  CurrentMissionResultEventPublisherOwner() != nullptr)
            .Bool("host_only", true));
}

void __fastcall MissionResultApplyHook(void* ui, int32_t result) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva =
        return_address >= g_module_base &&
                return_address < g_module_base + g_module_image_size
            ? return_address - g_module_base : 0;
    const int32_t before_state = ReadMissionUiState(ui);
    const int32_t before_result = ReadMissionUiResult(ui);
    const unsigned call = g_mission_result_apply_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    RecordMissionResultObservation(GetTickCount64(), result, before_state,
                                   before_result);
    g_mission_result_last_apply_caller_rva.store(
        caller_rva, std::memory_order_release);
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_apply", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(result)), call);
    if (g_mission_result_apply) g_mission_result_apply(ui, result);
    const int32_t after_state = ReadMissionUiState(ui);
    const int32_t after_result = ReadMissionUiResult(ui);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned",
                            static_cast<uint64_t>(static_cast<int64_t>(
                                after_state)),
                            static_cast<uint64_t>(static_cast<int64_t>(
                                after_result)));
    RecordMissionResultObservation(GetTickCount64(), result, after_state,
                                   after_result);
    ArmMissionResultRecovery(caller_rva, GetTickCount64(), result,
                             after_state, after_result);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_result_apply",
        capture::Fields()
            .UInt("call", call)
            .Int("result", result)
            .Int("before_ui_state", before_state)
            .Int("before_ui_result", before_result)
            .Int("after_ui_state", after_state)
            .Int("after_ui_result", after_result)
            .UInt("caller_rva", caller_rva)
            .Bool("mission_script_clear_dispatch",
                  caller_rva == kMissionScriptClearApplyReturnRva)
            .UInt("apply_rva", kMissionResultApplyRva)
            .Bool("finished", after_state == kMissionUiStateFinished));
    EmitEnemySpawnSummary("mission_result_apply");
}

void __fastcall MissionResultEventPublishHook(void* publisher,
                                              int32_t event_type,
                                              const void* payload) {
    const bool setter_scope = g_mission_result_setter_publish_scope;
    if (!setter_scope) {
        if (g_mission_result_event_publish) {
            g_mission_result_event_publish(publisher, event_type, payload);
        }
        return;
    }
    int32_t payload_value = -1;
    const bool payload_readable = payload &&
        IsReadableMemoryRange(payload, sizeof(payload_value));
    if (payload_readable) {
        std::memcpy(&payload_value, payload, sizeof(payload_value));
    }
    const bool expected_ui_close_event = setter_scope &&
        event_type == kMissionResultEventType && payload_readable &&
        payload_value == kMissionResultEventPayload;
    unsigned call = 0;
    call = g_mission_result_event_publish_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    if (expected_ui_close_event) {
        g_mission_result_expected_event_publish_calls.fetch_add(
            1, std::memory_order_acq_rel);
    }
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_event_publish",
        "setter_scope",
        static_cast<uint64_t>(static_cast<int64_t>(event_type)),
        static_cast<uint64_t>(static_cast<int64_t>(payload_value)));
    if (g_mission_result_event_publish) {
        g_mission_result_event_publish(publisher, event_type, payload);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", call,
                            expected_ui_close_event ? 1 : 0);
    EDF5_CAPTURE_EVENT(
        expected_ui_close_event ? capture::Level::Info
                                : capture::Level::Warning,
        "more_players", "mission_result_event_publish",
        capture::Fields()
            .UInt("call", call)
            .Int("event_type", event_type)
            .Int("payload_value", payload_value)
            .Bool("payload_readable", payload_readable)
            .Bool("publisher_present", publisher != nullptr)
            .Bool("setter_scope", true)
            .Bool("expected_ui_close_event", expected_ui_close_event)
            .UInt("ui_close_dispatch_calls",
                  g_mission_result_ui_dispatch_calls.load(
                      std::memory_order_acquire))
            .UInt("ui_close_target_match_calls",
                  g_mission_result_ui_target_match_calls.load(
                      std::memory_order_acquire))
            .UInt("mission_generation",
                  g_mission_generation.load(
                      std::memory_order_acquire))
            .UInt("publisher_rva", kMissionResultEventPublishRva)
            .Bool("payload_contents_logged", false));
}

bool __fastcall MissionResultUiEventDispatchHook(void* listener,
                                                 int32_t event_type,
                                                 const void* payload) {
    const bool setter_scope = g_mission_result_setter_publish_scope;
    if (!setter_scope) {
        return g_mission_result_ui_event_dispatch
            ? g_mission_result_ui_event_dispatch(listener, event_type, payload)
            : false;
    }

    int32_t payload_value = -1;
    const bool payload_readable = payload &&
        IsReadableMemoryRange(payload, sizeof(payload_value));
    if (payload_readable) {
        std::memcpy(&payload_value, payload, sizeof(payload_value));
    }

    int32_t listener_id = -1;
    uint32_t before_flags = 0;
    bool listener_fields_readable = false;
    if (listener) {
        const auto* bytes = static_cast<const uint8_t*>(listener);
        const void* flags_field = bytes + kUiObjectEventFlagsOffset;
        const void* id_field = bytes + kUiObjectEventIdOffset;
        listener_fields_readable =
            IsReadableMemoryRange(flags_field, sizeof(before_flags)) &&
            IsReadableMemoryRange(id_field, sizeof(listener_id));
        if (listener_fields_readable) {
            std::memcpy(&before_flags, flags_field, sizeof(before_flags));
            std::memcpy(&listener_id, id_field, sizeof(listener_id));
        }
    }

    const bool expected_ui_close_event =
        event_type == kMissionResultEventType && payload_readable &&
        payload_value == kMissionResultEventPayload;
    const bool target_match = expected_ui_close_event &&
        listener_fields_readable && listener_id == payload_value;
    const unsigned call = g_mission_result_ui_dispatch_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    if (target_match) {
        g_mission_result_ui_target_match_calls.fetch_add(
            1, std::memory_order_acq_rel);
    }

    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_ui_close_dispatch",
        target_match ? "target_match" : "listener_dispatch", call,
        static_cast<uint64_t>(static_cast<int64_t>(listener_id)));
    const bool accepted = g_mission_result_ui_event_dispatch
        ? g_mission_result_ui_event_dispatch(listener, event_type, payload)
        : false;

    uint32_t after_flags = before_flags;
    if (listener_fields_readable) {
        const auto* flags_field = static_cast<const uint8_t*>(listener) +
            kUiObjectEventFlagsOffset;
        if (IsReadableMemoryRange(flags_field, sizeof(after_flags))) {
            std::memcpy(&after_flags, flags_field, sizeof(after_flags));
        }
    }
    const bool close_flag_before =
        (before_flags & kUiObjectClosingFlag) != 0;
    const bool close_flag_after =
        (after_flags & kUiObjectClosingFlag) != 0;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", accepted ? 1 : 0,
                            close_flag_after ? 1 : 0);
    EDF5_CAPTURE_EVENT(
        target_match ? capture::Level::Info : capture::Level::Debug,
        "more_players", "mission_result_ui_close_dispatch",
        capture::Fields()
            .UInt("call", call)
            .Int("event_type", event_type)
            .Int("payload_value", payload_value)
            .Bool("payload_readable", payload_readable)
            .Int("listener_id", listener_id)
            .Bool("listener_fields_readable", listener_fields_readable)
            .Bool("target_match", target_match)
            .Bool("close_flag_before", close_flag_before)
            .Bool("close_flag_after", close_flag_after)
            .Bool("accepted", accepted)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .UInt("dispatch_rva", kMissionResultUiEventDispatchRva)
            .Bool("payload_contents_logged", false));
    return accepted;
}

void __fastcall MissionResultSetterHook(void* manager, int32_t result) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva =
        return_address >= g_module_base &&
                return_address < g_module_base + g_module_image_size
            ? return_address - g_module_base : 0;
    void* ui = CurrentMissionUi(manager);
    const int32_t before_manager_result = ReadMissionManagerResult(manager);
    const int32_t before_state = ReadMissionUiState(ui);
    const int32_t before_result = ReadMissionUiResult(ui);
    const unsigned call = g_mission_result_setter_calls.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    g_mission_result_last_setter_caller_rva.store(
        caller_rva, std::memory_order_release);
    if (result == kMissionResultClear) {
        g_mission_result_last_setter_generation.store(
            g_mission_generation.load(std::memory_order_acquire),
            std::memory_order_release);
        g_mission_result_recovery_pending.store(
            false, std::memory_order_release);
    }
    RecordMissionResultObservation(GetTickCount64(), result, before_state,
                                   before_result);
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_setter", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(result)), caller_rva);
    const bool previous_publish_scope =
        g_mission_result_setter_publish_scope;
    g_mission_result_setter_publish_scope = result == kMissionResultClear;
    if (g_mission_result_setter) g_mission_result_setter(manager, result);
    g_mission_result_setter_publish_scope = previous_publish_scope;
    ui = CurrentMissionUi(manager);
    const int32_t after_manager_result = ReadMissionManagerResult(manager);
    const int32_t after_state = ReadMissionUiState(ui);
    const int32_t after_result = ReadMissionUiResult(ui);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned",
                            static_cast<uint64_t>(static_cast<int64_t>(
                                after_state)),
                            static_cast<uint64_t>(static_cast<int64_t>(
                                after_result)));
    RecordMissionResultObservation(GetTickCount64(), result, after_state,
                                   after_result);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_result_setter",
        capture::Fields()
            .UInt("call", call)
            .Int("result", result)
            .UInt("caller_rva", caller_rva)
            .Bool("natural_clear_caller",
                  caller_rva == kMissionNaturalClearCallRva + 5)
            .Int("before_manager_result", before_manager_result)
            .Int("after_manager_result", after_manager_result)
            .Int("before_ui_state", before_state)
            .Int("before_ui_result", before_result)
            .Int("after_ui_state", after_state)
            .Int("after_ui_result", after_result)
            .UInt("setter_rva", kMissionResultSetterRva)
            .UInt("apply_calls",
                  g_mission_result_apply_calls.load(
                      std::memory_order_acquire))
            .UInt("result_event_publish_calls",
                  g_mission_result_event_publish_calls.load(
                      std::memory_order_acquire))
            .UInt("expected_result_event_publish_calls",
                  g_mission_result_expected_event_publish_calls.load(
                      std::memory_order_acquire))
            .UInt("ui_close_dispatch_calls",
                  g_mission_result_ui_dispatch_calls.load(
                      std::memory_order_acquire))
            .UInt("ui_close_target_match_calls",
                  g_mission_result_ui_target_match_calls.load(
                      std::memory_order_acquire))
            .Bool("finished", after_state == kMissionUiStateFinished));
    if (after_state == kMissionUiStateFinished) {
        PublishDiagnosticState("result", true);
    }
}

void PollMissionResultTelemetry() {
    const uint64_t tick = g_mission_result_tick.load(
        std::memory_order_acquire);
    if (!tick) return;
    const uint64_t now = GetTickCount64();
    if (now < tick) return;
    const uint64_t age = now - tick;
    for (unsigned index = 0; index < kMissionResultAuditAgesMs.size();
         ++index) {
        if (age < kMissionResultAuditAgesMs[index]) continue;
        const uint32_t bit = uint32_t{1} << index;
        const uint32_t previous = g_mission_result_audit_mask.fetch_or(
            bit, std::memory_order_acq_rel);
        if (previous & bit) continue;
        const char* phase = g_diagnostic_phase.load(
            std::memory_order_acquire);
        const uint64_t last_update = g_mission_update_tick.load(
            std::memory_order_acquire);
        const int32_t participant_count =
            ReadMissionResultParticipantCount();
        const uint32_t expected_item_mask =
            ExpectedMissionResultItemMask(participant_count);
        const uint32_t observed_item_mask =
            g_mission_result_item_mask.load(std::memory_order_acquire);
        const bool item_matrix_complete = expected_item_mask != 0 &&
            (observed_item_mask & expected_item_mask) == expected_item_mask;
        EDF5_CAPTURE_EVENT(
            capture::Level::Info,
            "more_players", "mission_result_progress",
            capture::Fields()
                .UInt("age_ms", age)
                .UInt("checkpoint_ms", kMissionResultAuditAgesMs[index])
                .UInt("mission_generation",
                      g_mission_result_generation.load(
                          std::memory_order_acquire))
                .String("diagnostic_phase", phase ? phase : "unknown")
                .Int("result",
                     g_mission_result_last_value.load(
                         std::memory_order_acquire))
                .Int("last_ui_state",
                     g_mission_result_last_ui_state.load(
                         std::memory_order_acquire))
                .Int("last_ui_result",
                     g_mission_result_last_ui_value.load(
                         std::memory_order_acquire))
                .UInt("setter_calls",
                      g_mission_result_setter_calls.load(
                          std::memory_order_acquire))
                .UInt("apply_calls",
                      g_mission_result_apply_calls.load(
                          std::memory_order_acquire))
                .UInt("result_event_publish_calls",
                      g_mission_result_event_publish_calls.load(
                          std::memory_order_acquire))
                .UInt("expected_result_event_publish_calls",
                      g_mission_result_expected_event_publish_calls.load(
                          std::memory_order_acquire))
                .UInt("ui_close_dispatch_calls",
                      g_mission_result_ui_dispatch_calls.load(
                          std::memory_order_acquire))
                .UInt("ui_close_target_match_calls",
                      g_mission_result_ui_target_match_calls.load(
                          std::memory_order_acquire))
                .UInt("exec_begin_calls",
                      g_mission_result_exec_begin_calls.load(
                          std::memory_order_acquire))
                .UInt("exec_update_calls",
                      g_mission_result_exec_update_calls.load(
                          std::memory_order_acquire))
                .UInt("exec_update_true_calls",
                      g_mission_result_exec_update_true_calls.load(
                          std::memory_order_acquire))
                .UInt("exec_update_false_calls",
                      g_mission_result_exec_update_false_calls.load(
                          std::memory_order_acquire))
                .UInt("exec_finally_calls",
                      g_mission_result_exec_finally_calls.load(
                          std::memory_order_acquire))
                .Bool("exec_begin_recovery_pending",
                      g_mission_result_exec_recovery_pending.load(
                          std::memory_order_acquire))
                .UInt("exec_begin_recovery_attempts",
                      g_mission_result_exec_recovery_attempts.load(
                          std::memory_order_acquire))
                .UInt("exec_begin_recovery_native_cancels",
                      g_mission_result_exec_recovery_native_cancels.load(
                          std::memory_order_acquire))
                .UInt("extra_result_item_calls",
                      g_mission_result_extra_item_calls.load(
                          std::memory_order_acquire))
                .UInt("extra_result_item_aggregated_calls",
                      g_mission_result_extra_item_aggregated_calls.load(
                          std::memory_order_acquire))
                .UInt("extra_result_item_mask",
                      g_mission_result_extra_item_mask.load(
                          std::memory_order_acquire))
                .Int("result_participant_count", participant_count)
                .UInt("expected_result_item_mask", expected_item_mask)
                .UInt("observed_result_item_mask", observed_item_mask)
                .Bool("result_items_complete", item_matrix_complete)
                .UInt("sync_begin_calls",
                      g_mission_result_sync_begin_calls.load(
                          std::memory_order_acquire))
                .UInt("sync_poll_calls",
                      g_mission_result_sync_poll_calls.load(
                          std::memory_order_acquire))
                .UInt("sync_complete_calls",
                      g_mission_result_sync_complete_calls.load(
                          std::memory_order_acquire))
                .Int("sync_last_state",
                     g_mission_result_sync_last_state.load(
                         std::memory_order_acquire))
                .Int("sync_last_result",
                     g_mission_result_sync_last_result.load(
                         std::memory_order_acquire))
                .UInt("reward_resolve_calls",
                      g_mission_reward_resolve_calls.load(
                          std::memory_order_acquire))
                .UInt("reward_apply_calls",
                      g_mission_reward_apply_calls.load(
                          std::memory_order_acquire))
                .UInt("reward_apply_completed_calls",
                      g_mission_reward_apply_completed_calls.load(
                          std::memory_order_acquire))
                .Int("local_profile_count",
                     ReadMissionRewardLocalProfileCount())
                .Int("expected_local_profile_count",
                     g_mission_expected_local_profile_count.load(
                         std::memory_order_acquire))
                .UInt("local_profile_count_repairs",
                      g_mission_reward_profile_count_repairs.load(
                          std::memory_order_acquire))
                .UInt("last_setter_caller_rva",
                      g_mission_result_last_setter_caller_rva.load(
                          std::memory_order_acquire))
                .UInt("last_apply_caller_rva",
                      g_mission_result_last_apply_caller_rva.load(
                          std::memory_order_acquire))
                .Bool("recovery_pending",
                      g_mission_result_recovery_pending.load(
                          std::memory_order_acquire))
                .UInt("mission_update_age_ms",
                      last_update && now >= last_update
                          ? now - last_update : 0)
                .UInt("real_gameplay_peers",
                      g_diagnostic_real_gameplay_peers.load(
                          std::memory_order_acquire))
                .UInt("identity_repair_mask",
                      g_mission_source_identity_repair_logged_mask.load(
                          std::memory_order_acquire))
                .Bool("transition_pending",
                      !phase || (std::strcmp(phase, "leaving") != 0 &&
                                 std::strcmp(phase, "idle") != 0)));
    }
}

bool CompleteMissionResultTransition(const char* completion_signal) {
    const uint64_t result_tick = g_mission_result_tick.exchange(
        0, std::memory_order_acq_rel);
    if (!result_tick) return false;

    const uint64_t now = GetTickCount64();
    const char* diagnostic_phase = g_diagnostic_phase.load(
        std::memory_order_acquire);
    const int32_t participant_count = ReadMissionResultParticipantCount();
    const uint32_t expected_item_mask =
        ExpectedMissionResultItemMask(participant_count);
    const uint32_t observed_item_mask =
        g_mission_result_item_mask.load(std::memory_order_acquire);
    const bool item_matrix_complete = expected_item_mask != 0 &&
        (observed_item_mask & expected_item_mask) == expected_item_mask;
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_result_transition_completed",
        capture::Fields()
            .UInt("elapsed_ms", now >= result_tick ? now - result_tick : 0)
            .Int("result", g_mission_result_last_value.load(
                               std::memory_order_acquire))
            .Int("last_ui_state", g_mission_result_last_ui_state.load(
                                      std::memory_order_acquire))
            .Int("last_ui_result", g_mission_result_last_ui_value.load(
                                       std::memory_order_acquire))
            .UInt("setter_calls", g_mission_result_setter_calls.load(
                                      std::memory_order_acquire))
            .UInt("apply_calls", g_mission_result_apply_calls.load(
                                     std::memory_order_acquire))
            .UInt("exec_begin_calls",
                  g_mission_result_exec_begin_calls.load(
                      std::memory_order_acquire))
            .UInt("exec_update_calls",
                  g_mission_result_exec_update_calls.load(
                      std::memory_order_acquire))
            .UInt("exec_update_true_calls",
                  g_mission_result_exec_update_true_calls.load(
                      std::memory_order_acquire))
            .UInt("exec_update_false_calls",
                  g_mission_result_exec_update_false_calls.load(
                      std::memory_order_acquire))
            .UInt("exec_finally_calls",
                  g_mission_result_exec_finally_calls.load(
                      std::memory_order_acquire))
            .UInt("sync_complete_calls",
                  g_mission_result_sync_complete_calls.load(
                      std::memory_order_acquire))
            .UInt("reward_resolve_calls",
                  g_mission_reward_resolve_calls.load(
                      std::memory_order_acquire))
            .UInt("reward_apply_calls",
                  g_mission_reward_apply_calls.load(
                      std::memory_order_acquire))
            .UInt("reward_apply_completed_calls",
                  g_mission_reward_apply_completed_calls.load(
                      std::memory_order_acquire))
            .Int("participant_count", participant_count)
            .UInt("expected_result_item_mask", expected_item_mask)
            .UInt("observed_result_item_mask", observed_item_mask)
            .Bool("result_items_complete", item_matrix_complete)
            .String("completion_signal",
                    completion_signal ? completion_signal : "unknown")
            .String("diagnostic_phase_before_completion",
                    diagnostic_phase ? diagnostic_phase : "unknown")
            .Bool("room_ui_returned",
                  completion_signal &&
                      std::strcmp(completion_signal, "room_ui_update") == 0)
            .Bool("reward_contents_logged", false)
            .Bool("payload_logged", false));
    return true;
}

bool MissionUiCanFinish(int32_t state) {
    return state == kMissionUiStateRunning ||
           state == kMissionUiStateFinishing;
}

void ObserveMissionUpdate(uint64_t now, int32_t state) {
    const uint64_t previous = g_mission_update_tick.exchange(
        now, std::memory_order_acq_rel);
    if (!previous || now < previous ||
        now - previous > kMissionGenerationGapMs) {
        const uint64_t generation = g_mission_generation.fetch_add(
            1, std::memory_order_acq_rel) + 1;
        g_mission_first_update_tick.store(now, std::memory_order_release);
        g_debug_stage_win_consumed.store(false, std::memory_order_release);
        g_mission_result_recovery_pending.store(
            false, std::memory_order_release);
        g_mission_result_recovery_tick.store(0,
                                             std::memory_order_release);
        g_mission_result_tick.store(0, std::memory_order_release);
        g_mission_result_audit_mask.store(0, std::memory_order_release);
        g_mission_result_event_publish_calls.store(
            0, std::memory_order_release);
        g_mission_result_expected_event_publish_calls.store(
            0, std::memory_order_release);
        g_mission_result_ui_dispatch_calls.store(
            0, std::memory_order_release);
        g_mission_result_ui_target_match_calls.store(
            0, std::memory_order_release);
        const bool discarded_exec_recovery =
            ResetMissionResultExecRecoveryState();
        ResetMissionResultExecPipelineTelemetry();
        if (discarded_exec_recovery) {
            EDF5_CAPTURE_EVENT(
                capture::Level::Warning, "more_players",
                "mission_result_exec_recovery_generation_reset",
                capture::Fields()
                    .UInt("mission_generation", generation)
                    .String("reason", "new mission generation")
                    .Bool("stale_pending_discarded", true)
                    .Bool("queue_cleared", true)
                    .Bool("payload_logged", false));
        }
        g_mission_result_extra_item_calls.store(
            0, std::memory_order_release);
        g_mission_result_extra_item_aggregated_calls.store(
            0, std::memory_order_release);
        g_mission_result_extra_item_mask.store(
            0, std::memory_order_release);
        g_mission_result_item_mask.store(0, std::memory_order_release);
        g_mission_result_sync_begin_calls.store(
            0, std::memory_order_release);
        g_mission_result_sync_poll_calls.store(
            0, std::memory_order_release);
        g_mission_result_sync_complete_calls.store(
            0, std::memory_order_release);
        g_mission_result_sync_first_poll_logged_mask.store(
            0, std::memory_order_release);
        g_mission_result_sync_complete_logged_mask.store(
            0, std::memory_order_release);
        g_mission_result_sync_last_state.store(
            -1, std::memory_order_release);
        g_mission_result_sync_last_result.store(
            -1, std::memory_order_release);
        g_mission_reward_resolve_calls.store(
            0, std::memory_order_release);
        g_mission_reward_apply_calls.store(
            0, std::memory_order_release);
        g_mission_reward_apply_completed_calls.store(
            0, std::memory_order_release);
        g_mission_reward_profile_count_repairs.store(
            0, std::memory_order_release);
        PublishDiagnosticState("mission", true);
    }
    g_mission_ui_state.store(state, std::memory_order_release);
    g_debug_stage_win_active.store(MissionUiCanFinish(state),
                                   std::memory_order_release);
    if (state == kMissionUiStateFinished) {
        PublishDiagnosticState("result", true);
    }
}

void RejectDebugStageWin(const char* reason, bool user_feedback) {
    const uint64_t now = GetTickCount64();
    const uint64_t last = g_mission_update_tick.load(std::memory_order_acquire);
    const uint64_t age = last && now >= last ? now - last : 0;
    EDF5_CAPTURE_EVENT("more_players", "debug_stage_win_rejected",
                   capture::Fields().String("reason", reason)
                       .UInt("hotkey_vk",
                             capture::GetConfig().debug_stage_win_hotkey_vk)
                       .UInt("mission_generation",
                             g_mission_generation.load(std::memory_order_acquire))
                       .UInt("mission_update_age_ms", age)
                       .Int("mission_ui_state",
                            g_mission_ui_state.load(std::memory_order_acquire))
                       .Bool("request_pending",
                             g_debug_stage_win_pending.load(
                                 std::memory_order_acquire))
                       .Bool("already_consumed",
                             g_debug_stage_win_consumed.load(
                                 std::memory_order_acquire)));
    if (user_feedback) MessageBeep(MB_ICONWARNING);
}

bool QueueDebugStageWin(bool user_feedback) {
    if (!capture::GetConfig().debug_stage_win_enabled) return false;
    const uint64_t now = GetTickCount64();
    const uint64_t last = g_mission_update_tick.load(std::memory_order_acquire);
    const uint64_t first =
        g_mission_first_update_tick.load(std::memory_order_acquire);
    if (!g_debug_stage_win_active.load(std::memory_order_acquire) || !last ||
        now < last || now - last > kMissionUpdateFreshMs) {
        RejectDebugStageWin("no active mission", user_feedback);
        return false;
    }
    if (!first || now < first || now - first < kMissionWarmupMs) {
        RejectDebugStageWin("mission is still starting", user_feedback);
        return false;
    }
    if (g_debug_stage_win_consumed.load(std::memory_order_acquire)) {
        RejectDebugStageWin("mission clear already requested", user_feedback);
        return false;
    }
    if (g_debug_stage_win_pending.load(std::memory_order_acquire)) {
        RejectDebugStageWin("mission clear request already queued",
                            user_feedback);
        return false;
    }
    g_debug_stage_win_request_tick.store(now, std::memory_order_release);
    g_debug_stage_win_request_generation.store(
        g_mission_generation.load(std::memory_order_acquire),
        std::memory_order_release);
    // HotkeyMain is the only producer. Publish pending last so Mission() never
    // observes a request before its timestamp and generation are visible.
    g_debug_stage_win_pending.store(true, std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "debug_stage_win_queued",
                   capture::Fields()
                       .UInt("hotkey_vk",
                             capture::GetConfig().debug_stage_win_hotkey_vk)
                       .UInt("mission_generation",
                             g_mission_generation.load(std::memory_order_acquire))
                       .Int("mission_ui_state",
                            g_mission_ui_state.load(std::memory_order_acquire))
                       .Int("native_result", kMissionResultClear)
                       .String("execution_thread", "Mission()")
                       .Bool("success", true));
    if (user_feedback) MessageBeep(MB_OK);
    return true;
}

bool ApplyPendingDebugStageWin(uint64_t now) {
    if (!g_debug_stage_win_pending.exchange(false,
                                             std::memory_order_acq_rel)) {
        return false;
    }
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "debug_stage_win", "consume", now,
        g_mission_generation.load(std::memory_order_acquire));
    const uint64_t request_tick =
        g_debug_stage_win_request_tick.exchange(0, std::memory_order_acq_rel);
    const uint64_t request_generation =
        g_debug_stage_win_request_generation.exchange(
            0, std::memory_order_acq_rel);
    if (!request_tick || now < request_tick ||
        now - request_tick > kMissionRequestLifetimeMs ||
        request_generation !=
            g_mission_generation.load(std::memory_order_acquire)) {
        RejectDebugStageWin("queued request expired", false);
        return false;
    }
    if (g_debug_stage_win_consumed.load(std::memory_order_acquire)) {
        RejectDebugStageWin("mission clear already requested", false);
        return false;
    }

    void* manager = CurrentMissionManager();
    void* ui = CurrentMissionUi(manager);
    void* event_publisher_owner =
        CurrentMissionResultEventPublisherOwner();
    const int32_t before_state = ReadMissionUiState(ui);
    const int32_t before_result = ReadMissionUiResult(ui);
    if (!manager || !ui || !event_publisher_owner ||
        !g_mission_result_setter || !g_mission_result_event_publish ||
        !MissionUiCanFinish(before_state)) {
        RejectDebugStageWin("native mission state is not finishable", false);
        return false;
    }

    MissionResultSetterHook(manager, kMissionResultClear);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "native_setter_returned",
                            reinterpret_cast<uintptr_t>(manager),
                            kMissionResultClear);
    const int32_t after_state = ReadMissionUiState(ui);
    const int32_t after_result = ReadMissionUiResult(ui);
    const bool success = after_state == kMissionUiStateFinished &&
                         after_result == kMissionResultClear;
    if (success) {
        g_debug_stage_win_consumed.store(true, std::memory_order_release);
        g_debug_stage_win_active.store(false, std::memory_order_release);
    }
    EDF5_CAPTURE_EVENT("more_players", "debug_stage_win_applied",
                   capture::Fields()
                       .UInt("mission_generation", request_generation)
                       .Int("before_ui_state", before_state)
                       .Int("before_result", before_result)
                       .Int("after_ui_state", after_state)
                       .Int("after_result", after_result)
                       .UInt("mission_update_rva", kMissionUpdateRva)
                       .UInt("mission_result_setter_rva",
                             kMissionResultSetterRva)
                       .UInt("mission_result_setter_publish_rva",
                             kMissionResultSetterPublishRva)
                       .String("execution_thread", "Mission()")
                       .Bool("success", success));
    return success;
}

bool ApplyPendingMissionResultRecovery(uint64_t now) {
    if (!g_mission_result_recovery_pending.load(
            std::memory_order_acquire)) {
        return false;
    }
    const uint64_t queued_tick = g_mission_result_recovery_tick.load(
        std::memory_order_acquire);
    const uint64_t queued_generation =
        g_mission_result_recovery_generation.load(
            std::memory_order_acquire);
    if (!queued_tick || now < queued_tick ||
        now - queued_tick < kMissionResultRecoveryGraceMs) {
        return false;
    }
    if (!g_mission_result_recovery_pending.exchange(
            false, std::memory_order_acq_rel)) {
        return false;
    }

    const uint64_t current_generation =
        g_mission_generation.load(std::memory_order_acquire);
    const uint64_t setter_generation =
        g_mission_result_last_setter_generation.load(
            std::memory_order_acquire);
    const int actual_members =
        g_last_actual_member_count.load(std::memory_order_acquire);
    const bool local_harness = LocalMissionHarnessSessionReady();
    void* manager = CurrentMissionManager();
    void* ui = CurrentMissionUi(manager);
    void* event_publisher_owner =
        CurrentMissionResultEventPublisherOwner();
    const int32_t before_manager_result =
        ReadMissionManagerResult(manager);
    const int32_t before_state = ReadMissionUiState(ui);
    const int32_t before_result = ReadMissionUiResult(ui);
    const bool eligible = queued_generation &&
        queued_generation == current_generation &&
        setter_generation != current_generation &&
        g_owned_lobby.load(std::memory_order_acquire) != 0 &&
        (actual_members > static_cast<int>(kNativeMissionSourceCount) ||
         local_harness) &&
        manager && ui && event_publisher_owner &&
        g_mission_result_setter && g_mission_result_event_publish &&
        before_state == kMissionUiStateFinished &&
        before_result == kMissionResultClear;
    if (!eligible) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "more_players",
            "mission_result_recovery_skipped",
            capture::Fields()
                .UInt("queued_generation", queued_generation)
                .UInt("current_generation", current_generation)
                .UInt("setter_generation", setter_generation)
                .Int("actual_members", actual_members)
                .Bool("local_mission_harness", local_harness)
                .Int("manager_result", before_manager_result)
                .Int("ui_state", before_state)
                .Int("ui_result", before_result)
                .Bool("manager_present", manager != nullptr)
                .Bool("ui_present", ui != nullptr)
                .Bool("result_event_publisher_owner_present",
                      event_publisher_owner != nullptr)
                .Bool("native_setter_present",
                      g_mission_result_setter != nullptr)
                .Bool("native_event_publish_present",
                      g_mission_result_event_publish != nullptr));
        return false;
    }

    const unsigned attempt = g_mission_result_recovery_attempts.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_recovery", "native_setter",
        queued_generation, attempt);
    MissionResultSetterHook(manager, kMissionResultClear);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "native_setter_returned", attempt,
                            kMissionResultClear);
    ui = CurrentMissionUi(manager);
    const int32_t after_manager_result =
        ReadMissionManagerResult(manager);
    const int32_t after_state = ReadMissionUiState(ui);
    const int32_t after_result = ReadMissionUiResult(ui);
    const bool success = after_manager_result == kMissionResultClear &&
        after_state == kMissionUiStateFinished &&
        after_result == kMissionResultClear;
    EDF5_CAPTURE_EVENT(
        success ? capture::Level::Info : capture::Level::Warning,
        "more_players", "mission_result_recovery_applied",
        capture::Fields()
            .UInt("attempt", attempt)
            .UInt("mission_generation", queued_generation)
            .UInt("age_ms", now - queued_tick)
            .Int("actual_members", actual_members)
            .Bool("local_mission_harness", local_harness)
            .Int("before_manager_result", before_manager_result)
            .Int("after_manager_result", after_manager_result)
            .Int("before_ui_state", before_state)
            .Int("before_ui_result", before_result)
            .Int("after_ui_state", after_state)
            .Int("after_ui_result", after_result)
            .UInt("result_event_publish_calls",
                  g_mission_result_event_publish_calls.load(
                      std::memory_order_acquire))
            .UInt("expected_result_event_publish_calls",
                  g_mission_result_expected_event_publish_calls.load(
                      std::memory_order_acquire))
            .UInt("ui_close_dispatch_calls",
                  g_mission_result_ui_dispatch_calls.load(
                      std::memory_order_acquire))
            .UInt("ui_close_target_match_calls",
                  g_mission_result_ui_target_match_calls.load(
                      std::memory_order_acquire))
            .UInt("setter_rva", kMissionResultSetterRva)
            .String("execution_thread", "Mission() after native update")
            .Bool("success", success));
    return success;
}

bool ApplyPendingMissionResultExecRecovery(uint64_t now) {
    AcquireSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    mission_result_recovery::ApplyInput input{};
    input.pending = g_mission_result_exec_recovery_pending.load(
        std::memory_order_acquire);
    input.now = now;
    input.queued_tick = g_mission_result_exec_recovery_tick.load(
        std::memory_order_acquire);
    input.queued_generation =
        g_mission_result_exec_recovery_generation.load(
            std::memory_order_acquire);
    input.current_generation = g_mission_generation.load(
        std::memory_order_acquire);
    input.participant_count = ReadMissionResultParticipantCount();
    input.configured_max_players = MaxPlayers();
    input.local_mission_harness = LocalMissionHarnessSessionReady();
    input.native_exec_begin_present = g_mission_result_exec_begin != nullptr;
    input.native_exec_begin_calls = g_mission_result_exec_begin_calls.load(
        std::memory_order_acquire);
    const mission_result_recovery::ApplyAction action =
        mission_result_recovery::EvaluateExecBeginApply(input);
    if (action == mission_result_recovery::ApplyAction::Wait) {
        ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
        return false;
    }
    ClearMissionResultExecRecoveryQueueLocked();
    ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);

    if (action == mission_result_recovery::ApplyAction::Cancel) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "more_players",
            "mission_result_exec_recovery_skipped",
            capture::Fields()
                .UInt("queued_generation", input.queued_generation)
                .UInt("current_generation", input.current_generation)
                .Int("participant_count", input.participant_count)
                .Bool("local_mission_harness",
                      input.local_mission_harness)
                .Bool("native_exec_begin_present",
                      input.native_exec_begin_present)
                .UInt("native_exec_begin_calls",
                      input.native_exec_begin_calls)
                .Bool("native_path_preserved", true));
        return false;
    }

    const unsigned attempt =
        g_mission_result_exec_recovery_attempts.fetch_add(
            1, std::memory_order_acq_rel) + 1;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_result_exec_recovery",
        "exec_begin", input.queued_generation, attempt);
    const bool previous_recovery_scope =
        g_mission_result_exec_recovery_scope;
    g_mission_result_exec_recovery_scope = true;
    const bool accepted = MissionResultExecBeginHook(
        mission_result_recovery::kExecBeginArgument);
    g_mission_result_exec_recovery_scope = previous_recovery_scope;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "exec_begin_returned", accepted ? 1 : 0,
                            attempt);
    EDF5_CAPTURE_EVENT(
        accepted ? capture::Level::Info : capture::Level::Warning,
        "more_players", "mission_result_exec_recovery_applied",
        capture::Fields()
            .UInt("attempt", attempt)
            .UInt("mission_generation", input.queued_generation)
            .UInt("age_ms", now - input.queued_tick)
            .Int("participant_count", input.participant_count)
            .Int("argument", mission_result_recovery::kExecBeginArgument)
            .Bool("accepted", accepted)
            .String("execution_thread", "Mission() after native update")
            .Bool("host_only", false)
            .Bool("payload_logged", false));
    return accepted;
}

int __fastcall MissionUpdateHook() {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_update", "before_original");
    const uint64_t now = GetTickCount64();
    void* manager = CurrentMissionManager();
    void* ui = CurrentMissionUi(manager);
    ObserveMissionUpdate(now, ReadMissionUiState(ui));
    const bool injected = ApplyPendingDebugStageWin(now);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "call_original", now,
                            g_mission_generation.load(std::memory_order_acquire));
    const int result = g_mission_update ? g_mission_update() : 0;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope,
        "original_returned",
        static_cast<uint64_t>(static_cast<int64_t>(result)), 0);
    const bool recovered = ApplyPendingMissionResultRecovery(
        GetTickCount64());
    ApplyPendingMissionResultExecRecovery(GetTickCount64());
    // Mission() reads its script return before the recovery setter runs.  A
    // successful late recovery must therefore surface result 1 on this same
    // invocation; returning the stale zero closes the UI but never advances
    // into Sync_MissionResult/ResolveResult/ApplyResult.
    const int effective_result =
        recovered && result == 0 ? kMissionResultClear : result;
    if (injected) {
        EDF5_CAPTURE_EVENT("more_players", "debug_stage_win_returned",
                       capture::Fields().Int("mission_result", result)
                           .Int("expected_result", kMissionResultClear)
                           .Bool("success", result == kMissionResultClear));
    }
    if (recovered) {
        EDF5_CAPTURE_EVENT("more_players", "mission_result_recovery_returned",
                       capture::Fields()
                           .Int("native_update_result", result)
                           .Int("effective_update_result", effective_result)
                           .Int("expected_result", kMissionResultClear)
                           .Bool("stale_zero_overridden",
                                 result == 0 &&
                                     effective_result ==
                                         kMissionResultClear)
                           .Bool("native_update_already_clear",
                                 result == kMissionResultClear));
    }
    return effective_result;
}

void QueueWheelDetents(int detents) {
    detents = std::max(-4, std::min(4, detents));
    if (!detents) return;
    int current = g_pending_wheel_detents.load(std::memory_order_acquire);
    for (;;) {
        const int desired = std::max(-8, std::min(8, current + detents));
        if (g_pending_wheel_detents.compare_exchange_weak(
                current, desired, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return;
        }
    }
}

LRESULT CALLBACK GameWindowProc(HWND window, UINT message, WPARAM wparam,
                                LPARAM lparam) {
    if (message == WM_MOUSEWHEEL && RoomRosterActive()) {
        const int wheel_delta = static_cast<short>(HIWORD(wparam));
        int detents = wheel_delta / WHEEL_DELTA;
        if (!detents && wheel_delta) detents = wheel_delta > 0 ? 1 : -1;
        if (detents) {
            QueueWheelDetents(detents);
            return 0;
        }
    }
    const auto original = reinterpret_cast<WNDPROC>(
        g_original_window_proc.load(std::memory_order_acquire));
    return original ? CallWindowProcW(original, window, message, wparam, lparam)
                    : DefWindowProcW(window, message, wparam, lparam);
}

BOOL CALLBACK FindGameWindow(HWND window, LPARAM output) {
    DWORD process_id = 0;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id != GetCurrentProcessId() || !IsWindowVisible(window) ||
        GetWindow(window, GW_OWNER)) {
        return TRUE;
    }
    *reinterpret_cast<HWND*>(output) = window;
    return FALSE;
}

bool InstallGameWindowProc() {
    if (g_game_window.load(std::memory_order_acquire)) return true;
    HWND window = nullptr;
    EnumWindows(&FindGameWindow, reinterpret_cast<LPARAM>(&window));
    if (!window) return false;
    SetLastError(ERROR_SUCCESS);
    const LONG_PTR previous = SetWindowLongPtrW(
        window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&GameWindowProc));
    if (!previous && GetLastError() != ERROR_SUCCESS) return false;
    g_original_window_proc.store(static_cast<uintptr_t>(previous),
                                 std::memory_order_release);
    g_game_window.store(reinterpret_cast<uintptr_t>(window),
                        std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "room_wheel_hook_installed",
                   capture::Fields().String("mode", "window_mouse_wheel")
                       .Bool("cursor_hit_test", false));
    return true;
}

void RestoreGameWindowProc() {
    const auto window = reinterpret_cast<HWND>(
        g_game_window.exchange(0, std::memory_order_acq_rel));
    const auto original = reinterpret_cast<WNDPROC>(
        g_original_window_proc.exchange(0, std::memory_order_acq_rel));
    if (!window || !original || !IsWindow(window)) return;
    const auto current = reinterpret_cast<WNDPROC>(
        GetWindowLongPtrW(window, GWLP_WNDPROC));
    if (current == &GameWindowProc) {
        SetWindowLongPtrW(window, GWLP_WNDPROC,
                          reinterpret_cast<LONG_PTR>(original));
    }
}

int FindPointerIndex(
    const std::array<void*, kMissionSourceAuditCapacity>& values,
    unsigned count, void* value) {
    if (!value) return -1;
    const unsigned bounded = std::min<unsigned>(
        count, static_cast<unsigned>(values.size()));
    for (unsigned index = 0; index < bounded; ++index) {
        if (values[index] == value) return static_cast<int>(index);
    }
    return -1;
}

bool PointerSeen(const std::array<void*, kMissionSourceAuditCapacity>& values,
                 unsigned count, void* value) {
    return FindPointerIndex(values, count, value) >= 0;
}

std::string OrdinalArrayJson(
    const std::array<int32_t, kMissionSourceAuditCapacity>& values,
    unsigned count) {
    std::string json = "[";
    const unsigned bounded = std::min<unsigned>(
        count, static_cast<unsigned>(values.size()));
    for (unsigned index = 0; index < bounded; ++index) {
        if (index) json += ',';
        if (values[index] < 0) {
            json += "null";
        } else {
            json += std::to_string(values[index]);
        }
    }
    json += ']';
    return json;
}

std::array<int32_t, kMissionSourceAuditCapacity> ObjectOrderMap(
    const MissionSourceCollectionSnapshot& source,
    const MissionSourceCollectionSnapshot& reference) {
    std::array<int32_t, kMissionSourceAuditCapacity> result{};
    result.fill(-1);
    for (unsigned index = 0; index < source.inspected_count; ++index) {
        result[index] = FindPointerIndex(reference.objects,
                                         reference.inspected_count,
                                         source.objects[index]);
    }
    return result;
}

std::array<int32_t, kMissionSourceAuditCapacity> ControlOrderMap(
    const MissionSourceCollectionSnapshot& source,
    const MissionSourceCollectionSnapshot& reference) {
    std::array<int32_t, kMissionSourceAuditCapacity> result{};
    result.fill(-1);
    for (unsigned index = 0; index < source.inspected_count; ++index) {
        result[index] = FindPointerIndex(reference.controls,
                                         reference.inspected_count,
                                         source.controls[index]);
    }
    return result;
}

uint32_t ObjectMembershipMask(
    const MissionSourceCollectionSnapshot& source,
    const MissionSourceCollectionSnapshot& reference) {
    uint32_t mask = 0;
    const unsigned bounded = std::min<unsigned>(source.inspected_count, 32);
    for (unsigned index = 0; index < bounded; ++index) {
        if (FindPointerIndex(reference.objects, reference.inspected_count,
                             source.objects[index]) >= 0) {
            mask |= uint32_t{1} << index;
        }
    }
    return mask;
}

MissionSourceCollectionSnapshot SnapshotMissionSourceCollection(
    const MissionSourceVector* sources) {
    MissionSourceCollectionSnapshot snapshot;
    snapshot.registered_ordinals.fill(-1);
    snapshot.local_controller_indices.fill(-1);
    if (!sources || sources->capacity < sources->size ||
        (sources->size && !sources->entries)) {
        return snapshot;
    }
    snapshot.valid = true;
    snapshot.source_count = sources->size;
    snapshot.inspected_count = static_cast<unsigned>(std::min<uint64_t>(
        sources->size, kMissionSourceAuditCapacity));
    for (unsigned index = 0; index < snapshot.inspected_count; ++index) {
        const SharedProperty& entry = sources->entries[index];
        const bool object_seen = PointerSeen(snapshot.objects, index,
                                             entry.object);
        const bool control_seen = PointerSeen(snapshot.controls, index,
                                              entry.control);
        snapshot.objects[index] = entry.object;
        snapshot.controls[index] = entry.control;
        if (entry.object && !object_seen) ++snapshot.unique_objects;
        if (entry.control && !control_seen) ++snapshot.unique_controls;
        if (!entry.object ||
            *reinterpret_cast<void***>(entry.object) !=
                g_runtime_user_vtable) {
            continue;
        }
        ++snapshot.recognized_users;
        const int local_controller_index = *reinterpret_cast<const int*>(
            static_cast<const uint8_t*>(entry.object) +
            kUserLocalControllerIndexOffset);
        snapshot.local_controller_indices[index] = local_controller_index;
        if (local_controller_index < 0 || local_controller_index >= 32) {
            continue;
        }
        ++snapshot.valid_local_controller_indices;
        snapshot.maximum_local_controller_index = std::max(
            snapshot.maximum_local_controller_index, local_controller_index);
        const uint32_t bit = uint32_t{1} <<
            static_cast<unsigned>(local_controller_index);
        if (snapshot.local_controller_index_mask & bit) {
            ++snapshot.duplicate_local_controller_indices;
        }
        snapshot.local_controller_index_mask |= bit;
    }

    std::array<void*, kMissionSourceAuditCapacity> registered{};
    unsigned registered_inspected = 0;
    AcquireSRWLockShared(&g_ready_user_lock);
    snapshot.registered_users = static_cast<unsigned>(g_ready_users.size());
    registered_inspected = std::min<unsigned>(
        snapshot.registered_users, static_cast<unsigned>(registered.size()));
    for (unsigned index = 0; index < registered_inspected; ++index) {
        registered[index] = g_ready_users[index];
    }
    ReleaseSRWLockShared(&g_ready_user_lock);
    for (unsigned index = 0; index < registered_inspected; ++index) {
        if (PointerSeen(snapshot.objects, snapshot.inspected_count,
                        registered[index])) {
            ++snapshot.matched_registered_users;
        }
    }
    for (unsigned index = 0; index < snapshot.inspected_count; ++index) {
        const int registered_ordinal = FindPointerIndex(
            registered, registered_inspected, snapshot.objects[index]);
        snapshot.registered_ordinals[index] = registered_ordinal;
        if (registered_ordinal < 0) {
            ++snapshot.registered_order_unknown;
        } else if (registered_ordinal == static_cast<int>(index)) {
            ++snapshot.registered_order_matches;
        } else {
            ++snapshot.registered_order_mismatches;
        }
    }
    return snapshot;
}

unsigned CountObjectsMissingFrom(
    const MissionSourceCollectionSnapshot& left,
    const MissionSourceCollectionSnapshot& right) {
    unsigned missing = 0;
    for (unsigned index = 0; index < left.inspected_count; ++index) {
        void* object = left.objects[index];
        if (!object || PointerSeen(left.objects, index, object)) continue;
        if (!PointerSeen(right.objects, right.inspected_count, object)) {
            ++missing;
        }
    }
    return missing;
}

void EmitMissionSourceCollectionAudit(
    const char* collection,
    const MissionSourceCollectionSnapshot& snapshot,
    uintptr_t caller_rva) {
    const unsigned missing_registered =
        snapshot.registered_users > snapshot.matched_registered_users
            ? snapshot.registered_users - snapshot.matched_registered_users
            : 0;
    EDF5_CRASH_BREADCRUMB("more_players", "mission_source_collection",
                              collection, snapshot.source_count,
                              snapshot.local_controller_index_mask);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_source_collection_audit",
        capture::Fields()
            .String("collection", collection)
            .Bool("valid", snapshot.valid)
            .UInt("source_count", snapshot.source_count)
            .UInt("inspected_count", snapshot.inspected_count)
            .Bool("inspection_truncated",
                  snapshot.source_count > snapshot.inspected_count)
            .UInt("unique_objects", snapshot.unique_objects)
            .UInt("unique_controls", snapshot.unique_controls)
            .UInt("recognized_user_impl", snapshot.recognized_users)
            .UInt("registered_user_count", snapshot.registered_users)
            .UInt("matched_registered", snapshot.matched_registered_users)
            .UInt("missing_registered", missing_registered)
            .Raw("source_to_registered_order",
                 OrdinalArrayJson(snapshot.registered_ordinals,
                                  snapshot.inspected_count))
            .UInt("registered_order_matches",
                  snapshot.registered_order_matches)
            .UInt("registered_order_mismatches",
                  snapshot.registered_order_mismatches)
            .UInt("registered_order_unknown",
                  snapshot.registered_order_unknown)
            .UInt("valid_local_controller_index_count",
                  snapshot.valid_local_controller_indices)
            .UInt("local_controller_index_mask",
                  snapshot.local_controller_index_mask)
            .UInt("duplicate_local_controller_index_count",
                  snapshot.duplicate_local_controller_indices)
            .Int("maximum_local_controller_index",
                 snapshot.maximum_local_controller_index)
            .UInt("copy_rva", kMissionSourceCollectionCopyRva)
            .UInt("caller_rva", caller_rva));
}

void* __fastcall MissionSourceCollectionCopyHook(
    MissionSourceVector* destination, const MissionSourceVector* source) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva =
        return_address >= g_module_base ? return_address - g_module_base : 0;
    void* result = g_mission_source_collection_copy
        ? g_mission_source_collection_copy(destination, source) : destination;
    if (caller_rva != kMissionSourcePrimaryCopyReturnRva &&
        caller_rva != kMissionSourceReferenceCopyReturnRva) {
        return result;
    }

    const MissionSourceCollectionSnapshot snapshot =
        SnapshotMissionSourceCollection(destination);
    if (caller_rva == kMissionSourcePrimaryCopyReturnRva) {
        // This is the beginning of a new mission's participant pipeline.
        // Discard associations and counters from the prior stage before the
        // character builder repopulates them.
        ResetReplicationParticipantTelemetry();
        g_mission_source_primary_snapshot = snapshot;
        g_mission_source_local_snapshot = {};
        g_mission_expected_local_profile_count.store(
            0, std::memory_order_release);
        EmitMissionSourceCollectionAudit("session_all_users", snapshot,
                                         caller_rva);
        return result;
    }

    g_mission_source_local_snapshot = snapshot;
    const bool local_profile_collection_valid = snapshot.valid &&
        snapshot.source_count >= 1 &&
        snapshot.source_count <= kMissionRewardLocalProfileCapacity &&
        snapshot.recognized_users == snapshot.source_count &&
        snapshot.unique_objects == snapshot.source_count;
    const int32_t expected_local_profiles =
        local_profile_collection_valid
            ? static_cast<int32_t>(snapshot.source_count) : 0;
    g_mission_expected_local_profile_count.store(
        expected_local_profiles, std::memory_order_release);
    EmitMissionSourceCollectionAudit("session_local_controls", snapshot,
                                     caller_rva);
    const MissionSourceCollectionSnapshot& primary =
        g_mission_source_primary_snapshot;
    const auto all_to_local_order = ObjectOrderMap(primary, snapshot);
    const auto local_to_all_order = ObjectOrderMap(snapshot, primary);
    const auto all_to_local_control_order = ControlOrderMap(primary, snapshot);
    const auto local_to_all_control_order = ControlOrderMap(snapshot, primary);
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_source_collection_compare",
        capture::Fields()
            .Bool("primary_valid", primary.valid)
            .Bool("reference_valid", snapshot.valid)
            .UInt("primary_count", primary.source_count)
            .UInt("reference_count", snapshot.source_count)
            .Int("reference_count_delta",
                 static_cast<int64_t>(snapshot.source_count) -
                     static_cast<int64_t>(primary.source_count))
            .String("primary_semantics", "session_all_users")
            .String("reference_semantics", "session_local_controls")
            .Raw("all_users_to_local_control_order",
                 OrdinalArrayJson(all_to_local_order,
                                  primary.inspected_count))
            .Raw("local_controls_to_all_user_order",
                 OrdinalArrayJson(local_to_all_order,
                                  snapshot.inspected_count))
            .Raw("all_users_to_local_control_block_order",
                 OrdinalArrayJson(all_to_local_control_order,
                                  primary.inspected_count))
            .Raw("local_controls_to_all_control_block_order",
                 OrdinalArrayJson(local_to_all_control_order,
                                  snapshot.inspected_count))
            .UInt("all_user_entries_in_local_controls_mask",
                  ObjectMembershipMask(primary, snapshot))
            .UInt("local_control_entries_in_all_users_mask",
                  ObjectMembershipMask(snapshot, primary))
            .UInt("primary_only_object_count",
                  CountObjectsMissingFrom(primary, snapshot))
            .UInt("reference_only_object_count",
                  CountObjectsMissingFrom(snapshot, primary))
            .Int("expected_local_profile_count",
                 expected_local_profiles)
            .Bool("local_profile_collection_valid",
                  local_profile_collection_valid)
            .UInt("native_local_profile_capacity",
                  kMissionRewardLocalProfileCapacity));
    const unsigned harness_target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    if (harness_target) {
        const uint64_t expected_sources =
            static_cast<uint64_t>(harness_target) + 1;
        const bool primary_complete = primary.valid &&
            primary.source_count == expected_sources &&
            primary.recognized_users == expected_sources &&
            primary.unique_objects == expected_sources &&
            primary.unique_controls == expected_sources;
        const bool local_host_only = snapshot.valid &&
            snapshot.source_count == 1 && snapshot.recognized_users == 1 &&
            snapshot.unique_objects == 1 && snapshot.unique_controls == 1;
        const bool valid = primary_complete && local_host_only;
        EDF5_CRASH_BREADCRUMB(
            "more_players", "local_mission_harness", valid ? "ready" : "invalid",
            primary.source_count, snapshot.source_count);
        EDF5_CAPTURE_EVENT(
            valid ? capture::Level::Info : capture::Level::Warning,
            "more_players", "local_mission_harness_mission_sources",
            capture::Fields()
                .UInt("dummy_count", harness_target)
                .UInt("expected_source_count", expected_sources)
                .UInt("all_user_source_count", primary.source_count)
                .UInt("all_user_unique_objects", primary.unique_objects)
                .UInt("all_user_unique_controls", primary.unique_controls)
                .UInt("local_control_source_count", snapshot.source_count)
                .Bool("primary_complete", primary_complete)
                .Bool("local_host_only", local_host_only)
                .Bool("dummy_control_mode_remote", true)
                .Bool("gameplay_ai_present", false)
                .Bool("success", valid));
    }
    return result;
}

int MissionSourceContextIndex(uintptr_t caller_rva) {
    if (caller_rva == kMissionSourceLookupReturnRva) return 0;
    if (caller_rva == kMissionSourceTransferReturnRva) return 1;
    if (caller_rva == kMissionSourceAppendReturnRva) return 2;
    return -1;
}

[[maybe_unused]] const char* MissionSourceContextName(int context) {
    switch (context) {
    case 0: return "player_create";
    case 1: return "record_transfer";
    case 2: return "record_append";
    default: return "unrelated";
    }
}

bool IsRuntimeUserImpl(void* object) {
    return object && g_runtime_user_vtable &&
        *reinterpret_cast<void***>(object) == g_runtime_user_vtable;
}

int RegisteredUserOrdinal(void* object);

int MissionUserLoadoutIndex(void* object) {
    if (!IsRuntimeUserImpl(object)) return -1;
    return *reinterpret_cast<const int32_t*>(
        static_cast<const uint8_t*>(object) +
        kUserMissionLoadoutIndexOffset);
}

int TransportRouteIndex(void* object) {
    if (!IsRuntimeUserImpl(object)) return -1;
    return *reinterpret_cast<const int32_t*>(
        static_cast<const uint8_t*>(object) +
        kUserTransportRouteIndexOffset);
}

void* __fastcall FakeMissionSourceConsumer(
    const SharedProperty* source, void*) {
    const int32_t observed = MissionUserLoadoutIndex(
        source ? source->object : nullptr);
    g_fake_mission_source_consumer_loadout_index.store(
        observed, std::memory_order_release);
    return source ? source->object : nullptr;
}

PlayerInfoObservation FindPlayerInfoObservation(void* user) {
    PlayerInfoObservation result;
    if (!user) return result;
    AcquireSRWLockShared(&g_player_info_observation_lock);
    for (const auto& observation : g_player_info_observations) {
        if (observation.user == user) {
            result = observation;
            break;
        }
    }
    ReleaseSRWLockShared(&g_player_info_observation_lock);
    return result;
}

void ClearMissionExtraLoadoutSidecars() {
    AcquireSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
    for (auto& sidecar : g_mission_extra_loadout_sidecars) sidecar = {};
    ReleaseSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
}

MissionExtraLoadoutSidecar FindMissionExtraLoadoutSidecar(
    int32_t logical_index) {
    MissionExtraLoadoutSidecar result;
    if (logical_index < static_cast<int32_t>(kNativeMissionSourceCount) ||
        logical_index >= static_cast<int32_t>(
                             kMaximumMissionParticipants)) {
        return result;
    }
    const size_t slot = static_cast<size_t>(logical_index) -
        kNativeMissionSourceCount;
    AcquireSRWLockShared(&g_mission_extra_loadout_sidecar_lock);
    result = g_mission_extra_loadout_sidecars[slot];
    ReleaseSRWLockShared(&g_mission_extra_loadout_sidecar_lock);
    return result;
}

uint32_t MissionLoadoutWeaponValidMask(int32_t logical_index,
                                       int32_t selected_class) {
    if (logical_index < 0 ||
        logical_index >= static_cast<int32_t>(kMaximumMissionParticipants) ||
        selected_class < 0 ||
        selected_class >= kMissionCharacterClassLimit) {
        return 0;
    }
    uint32_t mask = kMissionLoadoutWeaponMask;
    const size_t active_record_offset =
        kMissionSelectedLoadoutOffset +
        static_cast<size_t>(logical_index) * kMissionClassLoadoutStride +
        (kMissionLoadoutRecordOffset - kMissionSelectedLoadoutOffset) +
        static_cast<size_t>(selected_class) * kMissionLoadoutRecordStride;
    const size_t participant_count_begin =
        kMissionResultParticipantCountOffset;
    const size_t participant_count_end = participant_count_begin +
        sizeof(int32_t);
    for (size_t weapon = 0; weapon < kMissionLoadoutWeaponCount;
         ++weapon) {
        const size_t field_begin = active_record_offset +
            weapon * sizeof(int32_t);
        const size_t field_end = field_begin + sizeof(int32_t);
        if (field_begin < participant_count_end &&
            field_end > participant_count_begin) {
            mask &= ~(uint32_t{1} << static_cast<unsigned>(weapon));
        }
    }
    return mask;
}

bool CaptureMissionExtraLoadoutSidecar(const uint8_t* block,
                                       int32_t logical_index,
                                       unsigned parser_call) {
    if (!block ||
        logical_index < static_cast<int32_t>(kNativeMissionSourceCount) ||
        logical_index >= static_cast<int32_t>(
                             kMaximumMissionParticipants)) {
        return false;
    }
    MissionExtraLoadoutSidecar incoming;
    incoming.logical_index = logical_index;
    const size_t slot = static_cast<size_t>(logical_index) -
        kNativeMissionSourceCount;
    std::memcpy(&incoming.selected_class, block,
                sizeof(incoming.selected_class));
    if (incoming.selected_class < 0 ||
        incoming.selected_class >= kMissionCharacterClassLimit) {
        AcquireSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
        g_mission_extra_loadout_sidecars[slot] = {};
        ReleaseSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
        return false;
    }
    const auto* active_record = block +
        (kMissionLoadoutRecordOffset - kMissionSelectedLoadoutOffset) +
        static_cast<size_t>(incoming.selected_class) *
            kMissionLoadoutRecordStride;
    std::memcpy(incoming.weapons.data(), active_record,
                sizeof(incoming.weapons));
    incoming.weapon_valid_mask = MissionLoadoutWeaponValidMask(
        logical_index, incoming.selected_class);
    std::memcpy(&incoming.armor, block + kMissionLoadoutArmorOffset,
                sizeof(incoming.armor));
    incoming.valid = true;
    incoming.captured_tick = GetTickCount64();
    incoming.parser_call = parser_call;
    AcquireSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
    g_mission_extra_loadout_sidecars[slot] = incoming;
    ReleaseSRWLockExclusive(&g_mission_extra_loadout_sidecar_lock);
    return true;
}

MissionLoadoutSelection SelectMissionLoadout(
    void* user, int32_t logical_index) {
    MissionLoadoutSelection result;
    result.logical_index = logical_index;
    const PlayerInfoObservation player_info =
        FindPlayerInfoObservation(user);
    if (player_info.user == user && player_info.selected_class >= 0 &&
        player_info.selected_class < kMissionCharacterClassLimit) {
        result.valid = true;
        result.source = "player_info";
        result.selected_class = player_info.selected_class;
        result.weapons = player_info.weapons;
        result.weapon_valid_mask = kMissionLoadoutWeaponMask;
        if (std::isfinite(player_info.armor) &&
            player_info.armor >= 0.0f) {
            const double rounded = std::round(
                static_cast<double>(player_info.armor));
            result.armor = rounded >= static_cast<double>(
                                         std::numeric_limits<int32_t>::max())
                ? std::numeric_limits<int32_t>::max()
                : static_cast<int32_t>(rounded);
            result.armor_valid = true;
        }
        return result;
    }
    const MissionExtraLoadoutSidecar sidecar =
        FindMissionExtraLoadoutSidecar(logical_index);
    if (!sidecar.valid || sidecar.logical_index != logical_index ||
        sidecar.selected_class < 0 ||
        sidecar.selected_class >= kMissionCharacterClassLimit) {
        return result;
    }
    result.valid = true;
    result.armor_valid = sidecar.armor >= 0;
    result.source = "parser_sidecar";
    result.selected_class = sidecar.selected_class;
    result.weapons = sidecar.weapons;
    result.weapon_valid_mask = sidecar.weapon_valid_mask;
    result.armor = sidecar.armor;
    return result;
}

bool IsReadableMemoryRange(const void* address, size_t bytes) {
    if (!address || !bytes) return false;
    uintptr_t current = reinterpret_cast<uintptr_t>(address);
    if (current > std::numeric_limits<uintptr_t>::max() - bytes) return false;
    const uintptr_t end = current + bytes;
    while (current < end) {
        MEMORY_BASIC_INFORMATION information{};
        if (!VirtualQuery(reinterpret_cast<const void*>(current),
                          &information, sizeof(information)) ||
            information.State != MEM_COMMIT ||
            (information.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            return false;
        }
        const DWORD protection = information.Protect & 0xff;
        if (protection != PAGE_READONLY &&
            protection != PAGE_READWRITE &&
            protection != PAGE_WRITECOPY &&
            protection != PAGE_EXECUTE_READ &&
            protection != PAGE_EXECUTE_READWRITE &&
            protection != PAGE_EXECUTE_WRITECOPY) {
            return false;
        }
        const uintptr_t region_begin =
            reinterpret_cast<uintptr_t>(information.BaseAddress);
        if (region_begin > std::numeric_limits<uintptr_t>::max() -
                               information.RegionSize) {
            return false;
        }
        const uintptr_t region_end = region_begin + information.RegionSize;
        if (region_end <= current) return false;
        current = std::min(end, region_end);
    }
    return true;
}

bool IsWritableMemoryRange(const void* address, size_t bytes) {
    if (!address || !bytes) return false;
    uintptr_t current = reinterpret_cast<uintptr_t>(address);
    if (current > std::numeric_limits<uintptr_t>::max() - bytes) return false;
    const uintptr_t end = current + bytes;
    while (current < end) {
        MEMORY_BASIC_INFORMATION information{};
        if (!VirtualQuery(reinterpret_cast<const void*>(current),
                          &information, sizeof(information)) ||
            information.State != MEM_COMMIT ||
            (information.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            return false;
        }
        const DWORD protection = information.Protect & 0xff;
        if (protection != PAGE_READWRITE &&
            protection != PAGE_WRITECOPY &&
            protection != PAGE_EXECUTE_READWRITE &&
            protection != PAGE_EXECUTE_WRITECOPY) {
            return false;
        }
        const uintptr_t region_begin =
            reinterpret_cast<uintptr_t>(information.BaseAddress);
        if (region_begin > std::numeric_limits<uintptr_t>::max() -
                               information.RegionSize) {
            return false;
        }
        const uintptr_t region_end = region_begin + information.RegionSize;
        if (region_end <= current) return false;
        current = std::min(end, region_end);
    }
    return true;
}

void* FindMissionUserForLogicalIndex(int32_t logical_index) {
    if (logical_index < 0) return nullptr;
    if (void* mapped = MissionParticipantUserForIndex(logical_index)) {
        return mapped;
    }
    void* result = nullptr;
    AcquireSRWLockShared(&g_ready_user_lock);
    for (void* user : g_ready_users) {
        if (IsRuntimeUserImpl(user) &&
            MissionUserLoadoutIndex(user) == logical_index) {
            result = user;
            break;
        }
    }
    ReleaseSRWLockShared(&g_ready_user_lock);
    return result;
}

void __fastcall FakeMissionParticipantClassResolver(
    void*, int32_t* participant_index, int32_t* selected_class,
    void*, uint8_t* resolved) {
    if (participant_index) {
        *participant_index = g_fake_mission_class_resolver_index.load(
            std::memory_order_acquire);
    }
    if (selected_class) {
        *selected_class = g_fake_mission_class_resolver_class.load(
            std::memory_order_acquire);
    }
    if (resolved) *resolved = 1;
    g_fake_mission_class_resolver_calls.fetch_add(
        1, std::memory_order_acq_rel);
}

void __fastcall MissionParticipantClassResolverHook(
    void* context, int32_t* participant_index, int32_t* selected_class,
    void* text_output, uint8_t* resolved) {
    if (g_mission_participant_class_resolver) {
        g_mission_participant_class_resolver(
            context, participant_index, selected_class, text_output,
            resolved);
    }
    if (!participant_index ||
        *participant_index < static_cast<int32_t>(kNativeMissionSourceCount) ||
        *participant_index >= static_cast<int32_t>(
                                  kMaximumMissionParticipants)) {
        return;
    }

    const int32_t logical_index = *participant_index;
    const int32_t native_visual_slot = logical_index %
        static_cast<int32_t>(kNativeMissionSourceCount);
    void* user = FindMissionUserForLogicalIndex(logical_index);
    const PlayerInfoObservation observation =
        FindPlayerInfoObservation(user);
    const MissionExtraLoadoutSidecar parser_sidecar =
        FindMissionExtraLoadoutSidecar(logical_index);
    const int32_t native_class = selected_class ? *selected_class : -1;
    const bool player_info_class_valid =
        observation.user == user && observation.selected_class >= 0 &&
        observation.selected_class < kMissionCharacterClassLimit;
    const bool parser_sidecar_class_valid = parser_sidecar.valid &&
        parser_sidecar.logical_index == logical_index &&
        parser_sidecar.selected_class >= 0 &&
        parser_sidecar.selected_class < kMissionCharacterClassLimit;
    const bool native_class_valid = native_class >= 0 &&
        native_class < kMissionCharacterClassLimit;
    int32_t safe_class = native_visual_slot;
    const char* class_source = "visual_fallback";
    if (player_info_class_valid) {
        safe_class = observation.selected_class;
        class_source = "player_info";
    } else if (parser_sidecar_class_valid) {
        safe_class = parser_sidecar.selected_class;
        class_source = "parser_sidecar";
    } else if (native_class_valid) {
        safe_class = native_class;
        class_source = "native_resolver";
    }
    if (selected_class) *selected_class = safe_class;

    // This changes only the resolver's stack output. The UserImpl field stays
    // logical/unique for mission identity, control and replication.  The class
    // output must independently remain in 0..3 because the same HUD routine
    // later computes class*0x30 into a fixed localized-text table.
    *participant_index = native_visual_slot;
    const uint32_t bit = uint32_t{1} <<
        static_cast<unsigned>(logical_index);
    const uint32_t previous_visual =
        g_mission_visual_slot_remap_logged_mask.fetch_or(
            bit, std::memory_order_acq_rel);
    if (!(previous_visual & bit)) {
#if defined(__clang__) || defined(__GNUC__)
        const uintptr_t caller_rva = ModuleRvaForAddress(
            reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
#else
        const uintptr_t caller_rva = 0;
#endif
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_participant_visual_slot_remapped",
            capture::Fields()
                .Int("logical_participant_index", logical_index)
                .Int("native_visual_slot", native_visual_slot)
                .UInt("native_visual_slot_count",
                      kNativeMissionSourceCount)
                .Int("registered_order", RegisteredUserOrdinal(user))
                .Int("native_class", native_class)
                .Int("player_info_class", observation.selected_class)
                .Bool("player_info_class_valid", player_info_class_valid)
                .Int("parser_sidecar_class",
                     parser_sidecar.selected_class)
                .Bool("parser_sidecar_class_valid",
                      parser_sidecar_class_valid)
                .Int("safe_class", safe_class)
                .String("class_source", class_source)
                .Bool("native_class_was_out_of_range",
                      !native_class_valid)
                .Bool("logical_user_index_preserved", true)
                .Bool("resolver_output_remapped", true)
                .UInt("resolver_caller_rva", caller_rva)
                .UInt("visual_table_index_rva",
                      kMissionParticipantVisualTableIndexRva)
                .UInt("visual_submit_call_rva",
                      kMissionParticipantVisualSubmitCallRva)
                .UInt("previous_crash_rva",
                      kSharedRenderPropertyRefReadRva)
                .UInt("class_text_table_index_rva",
                      kMissionParticipantClassTextTableIndexRva)
                .UInt("class_text_select_rva",
                      kMissionParticipantClassTextSelectRva)
                .UInt("current_crash_rva",
                      kMissionTextMeasureInvalidReadRva)
                .Bool("display_name_text_logged", false)
                .Bool("steam_id_logged", false)
                .Bool("pointer_logged", false));
    }

    const uint32_t previous =
        g_mission_class_correction_logged_mask.fetch_or(
            bit, std::memory_order_acq_rel);
    if (!(previous & bit)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_participant_class_resolved",
            capture::Fields()
                .Int("participant_index", logical_index)
                .Int("registered_order", RegisteredUserOrdinal(user))
                .Int("native_class", native_class)
                .Int("player_info_class", observation.selected_class)
                .Int("parser_sidecar_class",
                     parser_sidecar.selected_class)
                .Int("resolved_class", safe_class)
                .String("class_source", class_source)
                .Bool("class_corrected",
                      native_class != safe_class)
                .Bool("safe_class_in_range",
                      safe_class >= 0 &&
                          safe_class < kMissionCharacterClassLimit)
                .Bool("logical_index_preserved", true)
                .Int("native_visual_slot", native_visual_slot)
                .Bool("resolver_output_remapped", true)
                .UInt("resolver_rva",
                      kMissionParticipantClassResolverRva)
                .UInt("native_class_read_rva",
                      kMissionParticipantNativeClassReadRva)
                .UInt("class_text_table_index_rva",
                      kMissionParticipantClassTextTableIndexRva)
                .UInt("class_text_invalid_read_rva",
                      kMissionTextMeasureInvalidReadRva)
                .Bool("display_name_text_logged", false)
                .Bool("steam_id_logged", false)
                .Bool("pointer_logged", false));
    }
}

bool __fastcall FakeMissionLoadoutParser(int32_t, bool* failed) {
    if (failed) *failed = false;
    g_fake_mission_loadout_parser_calls.fetch_add(
        1, std::memory_order_acq_rel);
    if (!g_mission_loadout_state_slot ||
        !*g_mission_loadout_state_slot) {
        return false;
    }
    auto* state = static_cast<uint8_t*>(*g_mission_loadout_state_slot);
    const unsigned participant_capacity = std::min(
        MaxPlayers(), kMaximumMissionParticipants);
    const size_t extra_blocks = participant_capacity >
            kNativeMissionSourceCount
        ? participant_capacity - kNativeMissionSourceCount : 0;
    if (extra_blocks) {
        std::memset(state + kMissionExtraLoadoutBeginOffset, 0xa5,
                    extra_blocks * kMissionClassLoadoutStride);
        // Class 1 deliberately places weapon 4 over participant_count.  The
        // native parser writes all weapons first and then stores count 5, so
        // the sidecar must mark only that overwritten weapon as unavailable.
        auto* fifth = state + kMissionExtraLoadoutBeginOffset;
        const int32_t selected_class = 1;
        const std::array<int32_t, kMissionLoadoutWeaponCount> weapons = {
            1040, 1041, 1042, 1043, 1044, 1045,
        };
        const int32_t armor = 456;
        std::memcpy(fifth, &selected_class, sizeof(selected_class));
        std::memcpy(
            fifth + (kMissionLoadoutRecordOffset -
                     kMissionSelectedLoadoutOffset) +
                static_cast<size_t>(selected_class) *
                    kMissionLoadoutRecordStride,
            weapons.data(), sizeof(weapons));
        std::memcpy(fifth + kMissionLoadoutArmorOffset, &armor,
                    sizeof(armor));
    }
    const int32_t participant_count = 5;
    std::memcpy(state + kMissionResultParticipantCountOffset,
                &participant_count, sizeof(participant_count));
    // Real successful five-player captures return false here.  The count
    // written above, plus the separate failed out-parameter, is authoritative.
    return false;
}

bool __fastcall MissionLoadoutParserHook(int32_t argument, bool* failed) {
    const unsigned parser_call =
        g_mission_loadout_parser_calls.fetch_add(
            1, std::memory_order_acq_rel) + 1;
    if (!g_mission_loadout_parser) return false;

    MissionLoadoutParserProtection& protection =
        g_mission_loadout_parser_protection;
    if (protection.active) {
        return g_mission_loadout_parser(argument, failed);
    }

    const unsigned participant_capacity = std::min(
        MaxPlayers(), kMaximumMissionParticipants);
    const size_t extra_blocks = participant_capacity >
            kNativeMissionSourceCount
        ? participant_capacity - kNativeMissionSourceCount : 0;
    const size_t bytes = extra_blocks * kMissionClassLoadoutStride;
    uint8_t* state = nullptr;
    if (bytes && g_mission_loadout_state_slot &&
        IsReadableMemoryRange(g_mission_loadout_state_slot,
                              sizeof(void*))) {
        std::memcpy(&state, g_mission_loadout_state_slot, sizeof(state));
    }
    uint8_t* extra_begin = state
        ? state + kMissionExtraLoadoutBeginOffset : nullptr;
    const bool protected_call = bytes &&
        IsReadableMemoryRange(extra_begin, bytes);
    int32_t local_profiles_before = -1;
    int32_t participant_count_before = -1;
    if (protected_call) {
        protection.active = true;
        protection.state = state;
        protection.bytes = bytes;
        std::memcpy(protection.original.data(), extra_begin, bytes);
        std::memcpy(&local_profiles_before,
                    state + kMissionRewardLocalProfileCountOffset,
                    sizeof(local_profiles_before));
        std::memcpy(&participant_count_before,
                    state + kMissionResultParticipantCountOffset,
                    sizeof(participant_count_before));
        g_mission_loadout_parser_protected_calls.fetch_add(
            1, std::memory_order_acq_rel);
    }

    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_loadout_parser", "call_original",
        extra_blocks, bytes);
    const bool result = g_mission_loadout_parser(argument, failed);
    const bool parser_failed = failed && *failed;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", result ? 1 : 0,
                            parser_failed ? 1 : 0);
    if (!protected_call) return result;

    uint8_t* current_state = nullptr;
    if (g_mission_loadout_state_slot &&
        IsReadableMemoryRange(g_mission_loadout_state_slot,
                              sizeof(void*))) {
        std::memcpy(&current_state, g_mission_loadout_state_slot,
                    sizeof(current_state));
    }
    const bool state_stable = current_state == protection.state &&
        IsReadableMemoryRange(extra_begin, bytes);
    if (!state_stable) {
        protection.active = false;
        protection.state = nullptr;
        protection.bytes = 0;
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "more_players",
            "mission_loadout_parser_restore_skipped",
            capture::Fields()
                .String("reason", "mission state changed during parser")
                .UInt("protected_extra_blocks", extra_blocks)
                .UInt("protected_bytes", bytes)
                .Bool("parser_result", result)
                .Bool("pointer_logged", false));
        return result;
    }

    int32_t local_profiles_during = -1;
    int32_t participant_count_after = -1;
    std::memcpy(&local_profiles_during,
                state + kMissionRewardLocalProfileCountOffset,
                sizeof(local_profiles_during));
    std::memcpy(&participant_count_after,
                state + kMissionResultParticipantCountOffset,
                sizeof(participant_count_after));
    const size_t participant_count_relative =
        kMissionResultParticipantCountOffset -
        kMissionExtraLoadoutBeginOffset;
    size_t changed_bytes = 0;
    uint32_t changed_block_mask = 0;
    for (size_t index = 0; index < bytes; ++index) {
        const bool participant_count_byte =
            index >= participant_count_relative &&
            index < participant_count_relative + sizeof(int32_t);
        if (!participant_count_byte &&
            extra_begin[index] != protection.original[index]) {
            ++changed_bytes;
            changed_block_mask |= uint32_t{1} << static_cast<unsigned>(
                index / kMissionClassLoadoutStride);
        }
    }
    if (changed_bytes) {
        g_mission_loadout_parser_oob_calls.fetch_add(
            1, std::memory_order_acq_rel);
    }

    uint32_t captured_sidecar_mask = 0;
    uint32_t invalid_sidecar_mask = 0;
    uint32_t complete_sidecar_weapon_mask = 0;
    uint32_t partial_sidecar_weapon_mask = 0;
    for (size_t extra_index = 0; extra_index < extra_blocks;
         ++extra_index) {
        const uint32_t bit = uint32_t{1} <<
            static_cast<unsigned>(extra_index);
        if (!(changed_block_mask & bit)) continue;
        const int32_t logical_index = static_cast<int32_t>(
            kNativeMissionSourceCount + extra_index);
        if (CaptureMissionExtraLoadoutSidecar(
                extra_begin +
                    extra_index * kMissionClassLoadoutStride,
                logical_index, parser_call)) {
            captured_sidecar_mask |= bit;
            const MissionExtraLoadoutSidecar sidecar =
                FindMissionExtraLoadoutSidecar(logical_index);
            if (sidecar.weapon_valid_mask == kMissionLoadoutWeaponMask) {
                complete_sidecar_weapon_mask |= bit;
            } else {
                partial_sidecar_weapon_mask |= bit;
            }
        } else {
            invalid_sidecar_mask |= bit;
        }
    }

    std::memcpy(extra_begin, protection.original.data(), bytes);
    const bool participant_count_output_valid =
        !parser_failed && participant_count_after >= 0 &&
        participant_count_after <=
            static_cast<int32_t>(participant_capacity);
    const int32_t preserved_participant_count =
        participant_count_output_valid
            ? participant_count_after : participant_count_before;
    std::memcpy(state + kMissionResultParticipantCountOffset,
                &preserved_participant_count,
                sizeof(preserved_participant_count));
    int32_t local_profiles_restored = -1;
    int32_t participant_count_restored = -1;
    std::memcpy(&local_profiles_restored,
                state + kMissionRewardLocalProfileCountOffset,
                sizeof(local_profiles_restored));
    std::memcpy(&participant_count_restored,
                state + kMissionResultParticipantCountOffset,
                sizeof(participant_count_restored));
    const bool restored =
        local_profiles_restored == local_profiles_before &&
        participant_count_restored == preserved_participant_count;
    protection.active = false;
    protection.state = nullptr;
    protection.bytes = 0;

    EDF5_CAPTURE_EVENT(
        restored ? capture::Level::Info : capture::Level::Warning,
        "more_players", "mission_loadout_parser_extra_blocks_restored",
        capture::Fields()
            .UInt("protected_extra_blocks", extra_blocks)
            .UInt("protected_bytes", bytes)
            .UInt("changed_bytes_excluding_participant_count",
                  changed_bytes)
            .UInt("changed_extra_block_mask", changed_block_mask)
            .UInt("captured_sidecar_mask", captured_sidecar_mask)
            .UInt("invalid_sidecar_mask", invalid_sidecar_mask)
            .UInt("complete_sidecar_weapon_mask",
                  complete_sidecar_weapon_mask)
            .UInt("partial_sidecar_weapon_mask",
                  partial_sidecar_weapon_mask)
            .UInt("parser_call", parser_call)
            .Int("local_profile_count_before", local_profiles_before)
            .Int("local_profile_count_during", local_profiles_during)
            .Int("local_profile_count_after", local_profiles_restored)
            .Int("participant_count_before", participant_count_before)
            .Int("participant_count_after_parser",
                 participant_count_after)
            .Int("participant_count_preserved",
                 participant_count_restored)
            .Bool("participant_count_output_valid",
                  participant_count_output_valid)
            .String("participant_count_source",
                    participant_count_output_valid
                        ? "parser_output" : "pre_parser_fallback")
            .Bool("local_profile_count_was_corrupted",
                  local_profiles_during != local_profiles_before)
            .Bool("parser_result", result)
            .Bool("parser_failed", parser_failed)
            .Bool("parser_return_controls_participant_count", false)
            .Bool("restored", restored)
            .Bool("sidecar_captured_before_restore",
                  captured_sidecar_mask != 0)
            .UInt("parser_rva", kMissionLoadoutParserRva)
            .UInt("participant_count_write_rva",
                  kMissionLoadoutParserParticipantCountWriteRva)
            .UInt("extra_block_begin_offset",
                  kMissionExtraLoadoutBeginOffset)
            .UInt("local_profile_count_offset",
                  kMissionRewardLocalProfileCountOffset)
            .UInt("participant_count_offset",
                  kMissionResultParticipantCountOffset)
            .Bool("loadout_contents_logged", false)
            .Bool("pointer_logged", false));
    return result;
}

bool PlayerInfoNameFingerprint(const uint8_t* player_info,
                               uint64_t& fingerprint,
                               uint32_t& length_out) {
    static_assert(sizeof(wchar_t) == 2,
                  "EDF5 PlayerInfo uses 16-bit wide strings");
    fingerprint = 0;
    length_out = 0;
    if (!player_info) return false;
    uint64_t length = 0;
    uint64_t capacity = 0;
    std::memcpy(&length, player_info + kPlayerInfoNameLengthOffset,
                sizeof(length));
    std::memcpy(&capacity, player_info + kPlayerInfoNameCapacityOffset,
                sizeof(capacity));
    if (!length || length > kPlayerInfoNameAuditMaximumLength ||
        capacity < length) {
        return false;
    }
    const wchar_t* value = nullptr;
    if (capacity <= kPlayerInfoNameInlineCapacity) {
        value = reinterpret_cast<const wchar_t*>(
            player_info + kPlayerInfoNameStorageOffset);
    } else {
        std::memcpy(&value, player_info + kPlayerInfoNameStorageOffset,
                    sizeof(value));
    }
    const size_t bytes = static_cast<size_t>(length) * sizeof(wchar_t);
    if (!IsReadableMemoryRange(value, bytes)) return false;
    uint64_t hash = 1469598103934665603ULL;
    const auto* raw = reinterpret_cast<const uint8_t*>(value);
    for (size_t index = 0; index < bytes; ++index) {
        hash ^= raw[index];
        hash *= 1099511628211ULL;
    }
    fingerprint = hash ? hash : 1;
    length_out = static_cast<uint32_t>(length);
    return true;
}

void RecordPlayerInfoObservation(void* user, const uint8_t* player_info) {
    if (!IsRuntimeUserImpl(user) || !player_info) return;
    PlayerInfoObservation incoming;
    incoming.user = user;
    incoming.source_mission_loadout_index = MissionUserLoadoutIndex(user);
    incoming.transport_route_index = TransportRouteIndex(user);
    incoming.name_valid = PlayerInfoNameFingerprint(
        player_info, incoming.name_fingerprint, incoming.name_length);
    incoming.shared_name_user_count = incoming.name_valid ? 1 : 0;
    incoming.shared_loadout_index_user_count =
        incoming.source_mission_loadout_index >= 0 ? 1 : 0;
    incoming.shared_transport_route_index_user_count =
        incoming.transport_route_index >= 0 ? 1 : 0;
    incoming.selected_class = *reinterpret_cast<const int32_t*>(
        player_info + kPlayerInfoClassOffset);
    incoming.secondary_loadout = *reinterpret_cast<const int32_t*>(
        player_info + kPlayerInfoSecondaryLoadoutOffset);
    std::memcpy(incoming.weapons.data(),
                player_info + kPlayerInfoWeaponsOffset,
                sizeof(incoming.weapons));
    incoming.first_weapon = incoming.weapons[0];
    std::memcpy(&incoming.armor, player_info + kPlayerInfoArmorOffset,
                sizeof(incoming.armor));
    incoming.observed_tick = GetTickCount64();
    bool changed = false;
    bool stored = false;
    AcquireSRWLockExclusive(&g_player_info_observation_lock);
    PlayerInfoObservation* empty = nullptr;
    if (incoming.name_valid) {
        for (const auto& observation : g_player_info_observations) {
            if (!observation.user || !observation.name_valid ||
                observation.name_fingerprint != incoming.name_fingerprint ||
                observation.name_length != incoming.name_length) {
                continue;
            }
            if (observation.user != user) {
                ++incoming.shared_name_user_count;
            }
            if (!incoming.name_token &&
                observation.name_fingerprint == incoming.name_fingerprint &&
                observation.name_length == incoming.name_length) {
                incoming.name_token = observation.name_token;
            }
        }
        if (!incoming.name_token) {
            incoming.name_token = g_next_player_info_name_token++;
            if (!g_next_player_info_name_token) {
                g_next_player_info_name_token = 1;
            }
        }
    }
    if (incoming.source_mission_loadout_index >= 0) {
        for (const auto& observation : g_player_info_observations) {
            if (observation.user && observation.user != user &&
                observation.source_mission_loadout_index ==
                    incoming.source_mission_loadout_index) {
                ++incoming.shared_loadout_index_user_count;
            }
        }
    }
    if (incoming.transport_route_index >= 0) {
        for (const auto& observation : g_player_info_observations) {
            if (observation.user && observation.user != user &&
                observation.transport_route_index ==
                    incoming.transport_route_index) {
                ++incoming.shared_transport_route_index_user_count;
            }
        }
    }
    for (auto& observation : g_player_info_observations) {
        if (!observation.user && !empty) empty = &observation;
        if (observation.user != user) continue;
        changed = observation.name_valid != incoming.name_valid ||
            observation.name_fingerprint != incoming.name_fingerprint ||
            observation.name_token != incoming.name_token ||
            observation.name_length != incoming.name_length ||
            observation.shared_name_user_count !=
                incoming.shared_name_user_count ||
            observation.source_mission_loadout_index !=
                incoming.source_mission_loadout_index ||
            observation.shared_loadout_index_user_count !=
                incoming.shared_loadout_index_user_count ||
            observation.transport_route_index !=
                incoming.transport_route_index ||
            observation.shared_transport_route_index_user_count !=
                incoming.shared_transport_route_index_user_count ||
            observation.selected_class != incoming.selected_class ||
            observation.secondary_loadout != incoming.secondary_loadout ||
            observation.weapons != incoming.weapons ||
            observation.armor != incoming.armor;
        observation = incoming;
        stored = true;
        break;
    }
    if (!stored && empty) {
        *empty = incoming;
        changed = true;
        stored = true;
    }
    ReleaseSRWLockExclusive(&g_player_info_observation_lock);
    if (changed) {
        EDF5_CAPTURE_EVENT(
            "more_players", "player_info_class_observed",
            capture::Fields()
                .Int("registered_order", RegisteredUserOrdinal(user))
                .Bool("display_name_valid", incoming.name_valid)
                .UInt("display_name_token", incoming.name_token)
                .UInt("display_name_length", incoming.name_length)
                .Bool("display_name_text_logged", false)
                .UInt("shared_name_user_count",
                      incoming.shared_name_user_count)
                .Bool("display_name_owned_by_different_user",
                      incoming.shared_name_user_count > 1)
                .Int("source_mission_loadout_index",
                     incoming.source_mission_loadout_index)
                .UInt("shared_loadout_index_user_count",
                      incoming.shared_loadout_index_user_count)
                .Bool("source_loadout_index_unique",
                      incoming.shared_loadout_index_user_count == 1)
                .Int("transport_route_index",
                     incoming.transport_route_index)
                .UInt("shared_transport_route_index_user_count",
                      incoming.shared_transport_route_index_user_count)
                .Bool("transport_route_index_unique",
                      incoming.shared_transport_route_index_user_count == 1)
                .UInt("transport_route_index_offset",
                      kUserTransportRouteIndexOffset)
                .Int("selected_class", incoming.selected_class)
                .Int("secondary_loadout", incoming.secondary_loadout)
                .Int("first_weapon", incoming.first_weapon)
                .Bool("stored", stored)
                .UInt("builder_rva", kPlayerInfoFromUserRva)
                .Bool("user_identity_logged", false));
    }
}

bool ChatDisplayNameFingerprint(const wchar_t* value,
                                uint64_t& fingerprint,
                                uint32_t& length_out) {
    fingerprint = 0;
    length_out = 0;
    if (!value) return false;
    size_t length = 0;
    for (; length <= kPlayerInfoNameAuditMaximumLength; ++length) {
        if (!IsReadableMemoryRange(value + length, sizeof(wchar_t))) {
            return false;
        }
        if (value[length] == L'\0') break;
    }
    if (!length || length > kPlayerInfoNameAuditMaximumLength) return false;
    const size_t bytes = length * sizeof(wchar_t);
    uint64_t hash = 1469598103934665603ULL;
    const auto* raw = reinterpret_cast<const uint8_t*>(value);
    for (size_t index = 0; index < bytes; ++index) {
        hash ^= raw[index];
        hash *= 1099511628211ULL;
    }
    fingerprint = hash ? hash : 1;
    length_out = static_cast<uint32_t>(length);
    return true;
}

ChatNameAssociation InspectChatNameAssociation(
    const uint64_t* sender_identity, const wchar_t* display_name) {
    ChatNameAssociation association;
    uint64_t sender_id = 0;
    if (sender_identity &&
        IsReadableMemoryRange(sender_identity, sizeof(sender_id))) {
        std::memcpy(&sender_id, sender_identity, sizeof(sender_id));
        association.sender_identity_valid = sender_id != 0;
    }

    void* sender_user = nullptr;
    if (association.sender_identity_valid) {
        AcquireSRWLockShared(&g_ready_user_lock);
        for (size_t index = 0; index < g_ready_users.size(); ++index) {
            void* user = g_ready_users[index];
            if (!IsRuntimeUserImpl(user)) continue;
            auto** vtable = *reinterpret_cast<void***>(user);
            if (!vtable || !vtable[10]) continue;
            const auto get_user_id =
                reinterpret_cast<UserIdGetterFn>(vtable[10]);
            if (!get_user_id || get_user_id(user) != sender_id) continue;
            sender_user = user;
            association.sender_registered_order =
                static_cast<int>(index);
            association.sender_resolved = true;
            break;
        }
        ReleaseSRWLockShared(&g_ready_user_lock);
    }

    uint64_t display_fingerprint = 0;
    association.display_name_valid = ChatDisplayNameFingerprint(
        display_name, display_fingerprint,
        association.display_name_length);
    void* display_name_owner = nullptr;
    AcquireSRWLockShared(&g_player_info_observation_lock);
    for (const auto& observation : g_player_info_observations) {
        if (!observation.user) continue;
        if (observation.user == sender_user && observation.name_valid) {
            association.expected_name_token = observation.name_token;
        }
        if (association.display_name_valid && observation.name_valid &&
            observation.name_fingerprint == display_fingerprint &&
            observation.name_length == association.display_name_length) {
            association.display_name_token = observation.name_token;
            display_name_owner = observation.user;
        }
    }
    ReleaseSRWLockShared(&g_player_info_observation_lock);
    association.display_name_resolved =
        association.display_name_token != 0;
    association.name_matches_sender = association.sender_resolved &&
        association.expected_name_token != 0 &&
        association.display_name_resolved &&
        association.expected_name_token == association.display_name_token;
    association.display_name_owner_registered_order =
        RegisteredUserOrdinal(display_name_owner);
    association.sender_participant_index =
        MissionParticipantIndexForUser(sender_user);
    association.display_name_owner_participant_index =
        MissionParticipantIndexForUser(display_name_owner);
    return association;
}

bool InstallTemporaryMissionLoadoutBlock(void* requested_object,
                                         int32_t native_loadout_index,
                                         int32_t logical_loadout_index) {
    if (g_mission_loadout_block_patch.active ||
        !g_mission_loadout_state_slot ||
        native_loadout_index < 0 ||
        native_loadout_index >=
            static_cast<int32_t>(kNativeMissionSourceCount)) {
        return false;
    }
    const MissionLoadoutSelection requested = SelectMissionLoadout(
        requested_object, logical_loadout_index);
    if (!requested.valid) return false;
    auto* state = static_cast<uint8_t*>(*g_mission_loadout_state_slot);
    if (!state) return false;
    auto* block = state + kMissionSelectedLoadoutOffset +
        static_cast<size_t>(native_loadout_index) *
            kMissionClassLoadoutStride;
    MissionLoadoutBlockPatch& patch = g_mission_loadout_block_patch;
    std::memcpy(patch.original.data(), block, patch.original.size());
    patch.active = true;
    patch.block = block;
    patch.source_index = native_loadout_index;
    patch.selected_class = requested.selected_class;

    // Static flow at 0x42f881..0x42f945 writes the selected class at block+0
    // and its six equipment ids at block+8+class*0x18. Character creation at
    // 0x31241a..0x3124d2 reads those exact fields. Rebuild only that active
    // record from PlayerInfo or the pre-rollback parser sidecar and restore the
    // whole native block immediately after the character factory returns.
    std::memcpy(block, &requested.selected_class,
                sizeof(requested.selected_class));
    auto* active_record = block +
        (kMissionLoadoutRecordOffset - kMissionSelectedLoadoutOffset) +
        static_cast<size_t>(requested.selected_class) *
            kMissionLoadoutRecordStride;
    const uint32_t weapon_valid_mask =
        requested.weapon_valid_mask & kMissionLoadoutWeaponMask;
    const uint32_t fallback_weapon_mask =
        kMissionLoadoutWeaponMask & ~weapon_valid_mask;
    for (size_t weapon = 0; weapon < kMissionLoadoutWeaponCount;
         ++weapon) {
        if (!(weapon_valid_mask &
              (uint32_t{1} << static_cast<unsigned>(weapon)))) {
            continue;
        }
        std::memcpy(active_record + weapon * sizeof(int32_t),
                    &requested.weapons[weapon], sizeof(int32_t));
    }
    int32_t effective_first_weapon = -1;
    std::memcpy(&effective_first_weapon, active_record,
                sizeof(effective_first_weapon));

    int32_t armor = *reinterpret_cast<int32_t*>(
        block + kMissionLoadoutArmorOffset);
    if (requested.armor_valid) {
        armor = requested.armor;
        std::memcpy(block + kMissionLoadoutArmorOffset, &armor,
                    sizeof(armor));
    }
    patch.armor = armor;
    if (g_mission_player_create_trace.active) {
        g_mission_player_create_trace.temporary_loadout_block_patched = true;
        g_mission_player_create_trace.temporary_loadout_block_class =
            requested.selected_class;
        g_mission_player_create_trace.temporary_loadout_block_first_weapon =
            effective_first_weapon;
        g_mission_player_create_trace
            .temporary_loadout_block_weapon_valid_mask = weapon_valid_mask;
        g_mission_player_create_trace
            .temporary_loadout_block_fallback_weapon_mask =
                fallback_weapon_mask;
        g_mission_player_create_trace.temporary_loadout_block_armor = armor;
        g_mission_player_create_trace.temporary_loadout_block_source =
            requested.source;
    }
    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_loadout_block", "temporary_synthesized",
        static_cast<uint64_t>(native_loadout_index),
        static_cast<uint64_t>(requested.selected_class));
    EDF5_CAPTURE_EVENT(
        "more_players", "mission_loadout_block_synthesized",
        capture::Fields()
            .Int("logical_participant_index", logical_loadout_index)
            .Int("native_loadout_index", native_loadout_index)
            .Int("selected_class", requested.selected_class)
            .Int("first_weapon", effective_first_weapon)
            .UInt("weapon_valid_mask", weapon_valid_mask)
            .UInt("fallback_weapon_mask", fallback_weapon_mask)
            .Int("armor", armor)
            .String("loadout_source", requested.source)
            .Bool("armor_from_source", requested.armor_valid)
            .Bool("native_block_restored_after_factory", true)
            .Bool("loadout_contents_logged", false)
            .Bool("pointer_logged", false));
    return true;
}

bool RestoreTemporaryMissionLoadoutBlock() {
    MissionLoadoutBlockPatch& patch = g_mission_loadout_block_patch;
    if (!patch.active || !patch.block) return false;
    const int32_t source_index = patch.source_index;
    const int32_t selected_class = patch.selected_class;
    std::memcpy(patch.block, patch.original.data(), patch.original.size());
    patch.active = false;
    patch.block = nullptr;
    patch.source_index = -1;
    patch.selected_class = -1;
    patch.armor = -1;
    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_loadout_block", "restored",
        static_cast<uint64_t>(static_cast<int64_t>(source_index)),
        static_cast<uint64_t>(static_cast<int64_t>(selected_class)));
    return true;
}

bool RestoreTemporaryMissionSourceState(
    MissionPlayerCreateTrace& trace, const char* phase,
    bool before_post_create_consumers) {
    bool attempted = false;
    if (trace.temporary_loadout_block_patched &&
        !trace.temporary_loadout_block_restored) {
        attempted = true;
        trace.temporary_loadout_block_restored =
            RestoreTemporaryMissionLoadoutBlock();
    }

    if (trace.temporary_loadout_object &&
        trace.original_loadout_index >=
            static_cast<int32_t>(kNativeMissionSourceCount) &&
        trace.temporary_loadout_index >= 0 &&
        trace.temporary_loadout_index <
            static_cast<int32_t>(kNativeMissionSourceCount) &&
        !trace.unique_loadout_index_restored) {
        attempted = true;
        auto* destination = reinterpret_cast<volatile LONG*>(
            static_cast<uint8_t*>(trace.temporary_loadout_object) +
            kUserMissionLoadoutIndexOffset);
        trace.observed_loadout_index_before_restore =
            InterlockedCompareExchange(
                destination, trace.original_loadout_index,
                trace.temporary_loadout_index);
        trace.observed_loadout_index_after_restore =
            InterlockedCompareExchange(destination, 0, 0);
        trace.unique_loadout_index_restored =
            trace.observed_loadout_index_after_restore ==
                trace.original_loadout_index;
    }

    if (!attempted) return false;
    trace.loadout_restoration_phase = phase ? phase : "unknown";
    trace.loadout_restored_before_post_create_consumers =
        before_post_create_consumers &&
        (!trace.temporary_loadout_block_patched ||
         trace.temporary_loadout_block_restored) &&
        trace.unique_loadout_index_restored;
    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_source_identity",
        trace.loadout_restored_before_post_create_consumers
            ? "restored_before_post_create"
            : (trace.unique_loadout_index_restored
                   ? "restored_late_fallback"
                   : "loadout_restore_failed"),
        static_cast<uint64_t>(static_cast<int64_t>(
            trace.participant_index)),
        static_cast<uint64_t>(static_cast<int64_t>(
            trace.observed_loadout_index_after_restore)));
    return trace.unique_loadout_index_restored &&
        (!trace.temporary_loadout_block_patched ||
         trace.temporary_loadout_block_restored);
}

struct MissionSourceLoadoutStatus {
    int32_t loadout_index = -1;
    int32_t selected_loadout = -1;
    int32_t resource_selector = -1;
    bool runtime_user = false;
    bool loadout_state_available = false;
    bool selection_inspected = false;
    bool usable = false;
};

MissionSourceLoadoutStatus InspectMissionSourceLoadout(void* object) {
    MissionSourceLoadoutStatus status;
    status.runtime_user = IsRuntimeUserImpl(object);
    if (!status.runtime_user) return status;
    status.loadout_index = MissionUserLoadoutIndex(object);
    if (status.loadout_index < 0 || status.loadout_index >= 4 ||
        !g_mission_loadout_state_slot) {
        return status;
    }
    const auto* state = static_cast<const uint8_t*>(
        *g_mission_loadout_state_slot);
    if (!state) return status;
    status.loadout_state_available = true;
    const size_t class_offset = static_cast<size_t>(status.loadout_index) *
        kMissionClassLoadoutStride;
    status.selected_loadout = *reinterpret_cast<const int32_t*>(
        state + class_offset + kMissionSelectedLoadoutOffset);
    if (status.selected_loadout < 0 ||
        status.selected_loadout >= kMissionLoadoutSlotLimit) {
        status.selection_inspected = true;
        return status;
    }
    const size_t loadout_offset =
        static_cast<size_t>(status.selected_loadout) *
        kMissionLoadoutRecordStride;
    status.resource_selector = *reinterpret_cast<const int32_t*>(
        state + class_offset + kMissionLoadoutRecordOffset + loadout_offset);
    status.selection_inspected = true;
    status.usable = status.resource_selector >= 0;
    return status;
}

const char* MissionSourceConsumerNullStage(
    const SharedProperty* source,
    const MissionSourceLoadoutStatus& status,
    bool result_present) {
    if (result_present) return "none";
    if (!source || !source->object) return "missing_source_object";
    if (!status.runtime_user) return "source_not_user_impl";
    if (status.loadout_index < 0 || status.loadout_index >= 4) {
        return "invalid_native_loadout_index";
    }
    if (!status.loadout_state_available) {
        return "loadout_state_unavailable";
    }
    if (status.selected_loadout < 0 ||
        status.selected_loadout >= kMissionLoadoutSlotLimit) {
        return "invalid_selected_loadout";
    }
    if (status.resource_selector < 0) return "negative_resource_selector";
    // Static flow at 0x31259a..0x3125b8 proves this is the only remaining
    // null return after all selectors above pass. The later wrapper call at
    // 0x3125d8 may return null, but the consumer still returns the non-null
    // factory object kept in rdi.
    return "character_resource_factory_0x6138e0_returned_null";
}

struct MissionSourceTableAudit {
    unsigned count = 0;
    std::array<int32_t, kMissionSourceAuditCapacity> loadout_indices{};
    std::array<int32_t, kMissionSourceAuditCapacity>
        transport_route_indices{};
    std::array<int32_t, kMissionSourceAuditCapacity> selected_loadouts{};
    std::array<int32_t, kMissionSourceAuditCapacity> resources{};
    uint32_t runtime_user_mask = 0;
    uint32_t loadout_inspected_mask = 0;
    uint32_t usable_mask = 0;
    uint32_t local_control_membership_mask = 0;
    uint32_t transport_route_index_mask = 0;
    uint32_t duplicate_transport_route_participant_mask = 0;
    bool sort_key_complete = false;
    bool sorted_by_user_id_descending = false;
    bool sort_keys_unique = false;
    bool transport_route_indices_complete = false;
    bool transport_route_indices_unique = false;
};

MissionSourceTableAudit AuditMissionSourceTable(
    const MissionSourceVector* sources) {
    MissionSourceTableAudit audit;
    audit.loadout_indices.fill(-1);
    audit.transport_route_indices.fill(-1);
    audit.selected_loadouts.fill(-1);
    audit.resources.fill(-1);
    if (!sources || sources->capacity < sources->size ||
        (sources->size && !sources->entries)) {
        return audit;
    }
    audit.count = static_cast<unsigned>(std::min<uint64_t>(
        sources->size, kMissionSourceAuditCapacity));
    audit.sort_key_complete = true;
    audit.sorted_by_user_id_descending = true;
    audit.sort_keys_unique = true;
    audit.transport_route_indices_complete = true;
    std::array<int32_t, kMissionSourceAuditCapacity> route_owners{};
    route_owners.fill(-1);
    uint64_t previous_sort_key = 0;
    bool have_previous_sort_key = false;
    for (unsigned index = 0; index < audit.count; ++index) {
        void* object = sources->entries[index].object;
        const MissionSourceLoadoutStatus status =
            InspectMissionSourceLoadout(object);
        audit.loadout_indices[index] = status.loadout_index;
        audit.transport_route_indices[index] = TransportRouteIndex(object);
        audit.selected_loadouts[index] = status.selected_loadout;
        audit.resources[index] = status.resource_selector;
        const uint32_t bit = index < 32 ? uint32_t{1} << index : 0;
        if (status.runtime_user) audit.runtime_user_mask |= bit;
        if (status.selection_inspected) audit.loadout_inspected_mask |= bit;
        if (status.usable) audit.usable_mask |= bit;
        if (FindPointerIndex(g_mission_source_local_snapshot.objects,
                             g_mission_source_local_snapshot.inspected_count,
                             object) >= 0) {
            audit.local_control_membership_mask |= bit;
        }
        if (!status.runtime_user) {
            audit.sort_key_complete = false;
            audit.sorted_by_user_id_descending = false;
            audit.sort_keys_unique = false;
            audit.transport_route_indices_complete = false;
            continue;
        }
        const int32_t route_index = audit.transport_route_indices[index];
        if (route_index < 0 ||
            route_index >= static_cast<int32_t>(
                               kMissionSourceAuditCapacity)) {
            audit.transport_route_indices_complete = false;
        } else {
            const uint32_t route_bit = uint32_t{1} <<
                static_cast<unsigned>(route_index);
            audit.transport_route_index_mask |= route_bit;
            const int32_t previous_owner = route_owners[
                static_cast<size_t>(route_index)];
            if (previous_owner >= 0) {
                audit.duplicate_transport_route_participant_mask |= bit;
                audit.duplicate_transport_route_participant_mask |=
                    uint32_t{1} << static_cast<unsigned>(previous_owner);
            } else {
                route_owners[static_cast<size_t>(route_index)] =
                    static_cast<int32_t>(index);
            }
        }
        uint64_t sort_key = 0;
        std::memcpy(&sort_key,
                    static_cast<const uint8_t*>(object) +
                        kUserMissionSortKeyOffset,
                    sizeof(sort_key));
        if (have_previous_sort_key) {
            if (previous_sort_key < sort_key) {
                audit.sorted_by_user_id_descending = false;
            }
            if (previous_sort_key == sort_key) {
                audit.sort_keys_unique = false;
            }
        }
        previous_sort_key = sort_key;
        have_previous_sort_key = true;
    }
    audit.transport_route_indices_unique =
        audit.transport_route_indices_complete &&
        audit.duplicate_transport_route_participant_mask == 0;
    return audit;
}

int RegisteredUserOrdinal(void* object) {
    if (!object) return -1;
    int ordinal = -1;
    AcquireSRWLockShared(&g_ready_user_lock);
    const auto found = std::find(g_ready_users.begin(), g_ready_users.end(),
                                 object);
    if (found != g_ready_users.end()) {
        ordinal = static_cast<int>(found - g_ready_users.begin());
    }
    ReleaseSRWLockShared(&g_ready_user_lock);
    return ordinal;
}

int ReplicationFamilyIndex(uint32_t message_code) {
    switch (message_code & 0x0000ff00U) {
    case kGameplayReplicationFamily3300: return 0;
    case kGameplayReplicationFamily3400: return 1;
    default: return -1;
    }
}

[[maybe_unused]] uint32_t ReplicationFamilyCode(size_t family_index) {
    return family_index == 0 ? kGameplayReplicationFamily3300
                             : kGameplayReplicationFamily3400;
}

void RecordReplicationParticipantMessage(
    bool outgoing, uint32_t message_code, void* context_user,
    bool local_control_fallback = false) {
    if (!g_replication_participant_map_ready.load(
            std::memory_order_acquire)) {
        return;
    }
    const int family_index = ReplicationFamilyIndex(message_code);
    if (family_index < 0) return;
    const size_t direction_index = outgoing ? 0 : 1;
    const int participant_index = MissionParticipantIndexForUser(context_user);
    const size_t participant_bucket = participant_index >= 0
        ? static_cast<size_t>(participant_index)
        : kReplicationUnknownParticipant;
    const uint64_t count =
        g_replication_message_counts[direction_index]
                                    [static_cast<size_t>(family_index)]
                                    [participant_bucket]
            .fetch_add(1, std::memory_order_acq_rel) + 1;
    const uint16_t bit = static_cast<uint16_t>(
        uint16_t{1} << static_cast<unsigned>(participant_bucket));
    const uint16_t previous =
        g_replication_first_logged_masks[direction_index]
                                          [static_cast<size_t>(family_index)]
            .fetch_or(bit, std::memory_order_acq_rel);
    if (previous & bit) return;

    const bool context_readable = context_user &&
        IsReadableMemoryRange(context_user, sizeof(void*));
    const bool context_runtime_user = context_readable &&
        IsRuntimeUserImpl(context_user);
    const PlayerInfoObservation player_info =
        FindPlayerInfoObservation(context_user);
    EDF5_CAPTURE_EVENT(
        "more_players", "replication_participant_first_observed",
        capture::Fields()
            .String("direction", outgoing ? "outgoing" : "incoming")
            .String("association_boundary",
                    outgoing
                        ? (local_control_fallback
                               ? "mission_local_control"
                               : "producer_owner_user")
                        : "receive_parser_user_scope")
            .UInt("message_family", ReplicationFamilyCode(
                                        static_cast<size_t>(family_index)))
            .UInt("message_code", message_code)
            .Int("participant_index", participant_index)
            .Bool("participant_association_resolved",
                  participant_index >= 0)
            .Bool("local_control_fallback", local_control_fallback)
            .Bool("context_present", context_user != nullptr)
            .Bool("context_runtime_user", context_runtime_user)
            .Int("source_registered_order",
                 RegisteredUserOrdinal(context_user))
            .Int("mission_loadout_index",
                 context_runtime_user
                     ? MissionUserLoadoutIndex(context_user) : -1)
            .Int("transport_route_index",
                 context_runtime_user
                     ? TransportRouteIndex(context_user) : -1)
            .UInt("transport_route_index_offset",
                  kUserTransportRouteIndexOffset)
            .Bool("player_info_display_name_valid", player_info.name_valid)
            .UInt("player_info_display_name_token", player_info.name_token)
            .UInt("player_info_display_name_length", player_info.name_length)
            .Bool("player_info_display_name_text_logged", false)
            .UInt("messages", count)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("payload_captured", false)
            .Bool("endpoint_identity_captured", false)
            .Bool("steam_id_logged", false)
            .Bool("pointer_logged", false));
}

void PollReplicationParticipantTelemetry() {
    const uint64_t now = GetTickCount64();
    uint64_t previous_tick = g_replication_last_summary_tick.load(
        std::memory_order_acquire);
    if (previous_tick && now >= previous_tick &&
        now - previous_tick < kReplicationSummaryIntervalMs) {
        return;
    }
    if (!g_replication_last_summary_tick.compare_exchange_strong(
            previous_tick, now, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }

    for (size_t direction = 0; direction < 2; ++direction) {
        for (size_t family = 0; family < 2; ++family) {
            for (size_t participant = 0;
                 participant <= kReplicationParticipantCapacity;
                 ++participant) {
                const uint64_t total =
                    g_replication_message_counts[direction][family]
                                                [participant]
                        .load(std::memory_order_acquire);
                const uint64_t prior =
                    g_replication_last_summary_counts[direction][family]
                                                     [participant]
                        .exchange(total, std::memory_order_acq_rel);
                if (!total || total == prior) continue;
                EDF5_CAPTURE_EVENT(
                    "more_players", "replication_participant_progress",
                    capture::Fields()
                        .String("direction", direction == 0
                                                 ? "outgoing" : "incoming")
                        .UInt("message_family",
                              ReplicationFamilyCode(family))
                        .Int("participant_index",
                             participant < kReplicationParticipantCapacity
                                 ? static_cast<int64_t>(participant) : -1)
                        .Bool("participant_association_resolved",
                              participant <
                                  kReplicationParticipantCapacity)
                        .UInt("messages_total", total)
                        .UInt("messages_delta",
                              total >= prior ? total - prior : total)
                        .UInt("summary_interval_ms",
                              kReplicationSummaryIntervalMs)
                        .UInt("mission_generation",
                              g_mission_generation.load(
                                  std::memory_order_acquire))
                        .Bool("payload_captured", false)
                        .Bool("endpoint_identity_captured", false));
            }
        }
    }
}

bool ExpectedMissionLocalController(const MissionSourceVector* sources,
                                    int32_t participant_index,
                                    int32_t& controller_index,
                                    int& local_collection_index) {
    const MissionSourceCollectionSnapshot& local =
        g_mission_source_local_snapshot;
    local_collection_index = -1;
    if (participant_index < 0 || !sources || !local.valid ||
        sources->capacity < sources->size ||
        static_cast<uint64_t>(participant_index) >= sources->size ||
        !sources->entries) {
        return false;
    }
    // 0x11d5e0 sorts both collections descending by UserImpl::SteamID before
    // it assigns participant indices. The argument10 vector is that final
    // sorted table; the collection-copy snapshot is deliberately pre-sort and
    // must only be used for order-independent local-membership checks.
    void* expected_object = sources->entries[
        static_cast<unsigned>(participant_index)].object;
    if (!expected_object) return false;
    local_collection_index = FindPointerIndex(
        local.objects, local.inspected_count, expected_object);
    if (local_collection_index < 0) {
        controller_index = -1;
        return true;
    }
    controller_index = local.local_controller_indices[
        static_cast<unsigned>(local_collection_index)];
    return controller_index >= 0 && controller_index < 32;
}

[[maybe_unused]] std::string MissionSourceTableRegisteredOrderJson(
    const MissionSourceVector* sources) {
    std::array<int32_t, kMissionSourceAuditCapacity> ordinals{};
    ordinals.fill(-1);
    if (!sources || sources->capacity < sources->size ||
        (sources->size && !sources->entries)) {
        return "[]";
    }
    const unsigned count = static_cast<unsigned>(std::min<uint64_t>(
        sources->size, kMissionSourceAuditCapacity));
    for (unsigned index = 0; index < count; ++index) {
        ordinals[index] = RegisteredUserOrdinal(
            sources->entries[index].object);
    }
    return OrdinalArrayJson(ordinals, count);
}

uint64_t MissionSourceIndexForCall(uint64_t index, uintptr_t caller_rva,
                                   uint64_t table_count,
                                   bool indexed_entry_present) {
    // Only player_create has the proven modulo-four failure. Prefer a native
    // fifth UserImpl when the vector really contains it; otherwise keep the
    // crash-prevention fallback. Later local-vector contexts remain untouched.
    if (MissionSourceContextIndex(caller_rva) == 0 &&
        index >= kNativeMissionSourceCount) {
        if (index < table_count && indexed_entry_present) return index;
        return index % kNativeMissionSourceCount;
    }
    return index;
}

int SelectMissionFallbackSourceIndex(const MissionSourceVector* sources,
                                     uint64_t requested_index) {
    if (!sources || sources->capacity < sources->size ||
        !sources->entries || sources->size == 0) {
        return -1;
    }
    const unsigned candidate_count = static_cast<unsigned>(
        std::min<uint64_t>(sources->size, kNativeMissionSourceCount));
    if (!candidate_count) return -1;
    void* requested_object = requested_index < sources->size
        ? sources->entries[requested_index].object : nullptr;
    const int requested_class =
        FindPlayerInfoObservation(requested_object).selected_class;
    const unsigned start = static_cast<unsigned>(
        requested_index % candidate_count);
    // Prefer a native loadout block belonging to a user whose PlayerInfo has
    // the same actual selected class. UserImpl+0xf8 itself is not a class. If
    // no matching native class has a usable resource, any usable native block
    // is safer than the out-of-range fifth block. The last pass remains for
    // early startup when loadout state was not available to inspect.
    for (unsigned pass = 0; pass < 3; ++pass) {
        for (unsigned offset = 0; offset < candidate_count; ++offset) {
            const unsigned index = (start + offset) % candidate_count;
            void* object = sources->entries[index].object;
            const MissionSourceLoadoutStatus status =
                InspectMissionSourceLoadout(object);
            if (!status.runtime_user) continue;
            const int candidate_class =
                FindPlayerInfoObservation(object).selected_class;
            if (pass == 0 &&
                (requested_class < 0 ||
                 candidate_class != requested_class ||
                 !status.usable)) {
                continue;
            }
            if (pass == 1 && !status.usable) continue;
            return static_cast<int>(index);
        }
    }
    return -1;
}

bool InstallTemporaryExtraMissionLoadout(MissionSourceVector* sources,
                                         uint64_t participant_index,
                                         int& fallback_source_index,
                                         int32_t& original_loadout_index,
                                         int32_t& temporary_loadout_index) {
    fallback_source_index = -1;
    original_loadout_index = -1;
    temporary_loadout_index = -1;
    if (!sources || participant_index < kNativeMissionSourceCount ||
        sources->capacity < sources->size || !sources->entries ||
        participant_index >= sources->size) {
        return false;
    }
    void* requested_object = sources->entries[participant_index].object;
    if (!IsRuntimeUserImpl(requested_object)) return false;
    original_loadout_index = MissionUserLoadoutIndex(requested_object);
    if (original_loadout_index >= 0 && original_loadout_index < 4) {
        return false;
    }
    const MissionLoadoutSelection requested_loadout = SelectMissionLoadout(
        requested_object, original_loadout_index);

    fallback_source_index = SelectMissionFallbackSourceIndex(
        sources, participant_index);
    if (fallback_source_index < 0 ||
        static_cast<uint64_t>(fallback_source_index) >= sources->size) {
        return false;
    }
    void* fallback_object = sources->entries[
        static_cast<unsigned>(fallback_source_index)].object;
    const MissionSourceLoadoutStatus source_status =
        InspectMissionSourceLoadout(fallback_object);
    if (!source_status.runtime_user || source_status.loadout_index < 0 ||
        source_status.loadout_index >= 4) {
        return false;
    }

    temporary_loadout_index = source_status.loadout_index;
    auto* destination = reinterpret_cast<volatile LONG*>(
        static_cast<uint8_t*>(requested_object) +
        kUserMissionLoadoutIndexOffset);
    InterlockedExchange(destination, temporary_loadout_index);
    const PlayerInfoObservation requested_info =
        FindPlayerInfoObservation(requested_object);
    const PlayerInfoObservation fallback_info =
        FindPlayerInfoObservation(fallback_object);
    if (g_mission_player_create_trace.active &&
        participant_index == static_cast<uint64_t>(
            g_mission_player_create_trace.participant_index)) {
        g_mission_player_create_trace.temporary_loadout_object =
            requested_object;
        g_mission_player_create_trace.original_loadout_index =
            original_loadout_index;
        g_mission_player_create_trace.temporary_loadout_index =
            temporary_loadout_index;
        g_mission_player_create_trace.requested_player_info_class =
            requested_info.selected_class;
        g_mission_player_create_trace.fallback_player_info_class =
            fallback_info.selected_class;
    }
    const bool loadout_block_patched = InstallTemporaryMissionLoadoutBlock(
        requested_object, temporary_loadout_index,
        original_loadout_index);

    const uint64_t extra_index =
        participant_index - kNativeMissionSourceCount;
    const uint32_t bit = extra_index < 4
        ? uint32_t{1} << static_cast<unsigned>(extra_index)
        : uint32_t{1} << 31;
    const uint32_t previous_mask =
        g_mission_source_identity_repair_logged_mask.fetch_or(
            bit, std::memory_order_acq_rel);
    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_source_identity", "loadout_temporary",
        participant_index,
        static_cast<uint64_t>(static_cast<int64_t>(
            temporary_loadout_index)));
    if (!(previous_mask & bit)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_source_loadout_fallback_installed",
            capture::Fields()
                .UInt("participant_index", participant_index)
                .Int("registered_order",
                     RegisteredUserOrdinal(requested_object))
                .Int("original_loadout_index", original_loadout_index)
                .Int("temporary_loadout_index", temporary_loadout_index)
                .Int("requested_player_info_class",
                     requested_info.selected_class)
                .Int("fallback_player_info_class",
                     fallback_info.selected_class)
                .Int("fallback_source_index", fallback_source_index)
                .Int("fallback_source_registered_order",
                     RegisteredUserOrdinal(
                         fallback_object))
                .Bool("identity_object_preserved", true)
                .Bool("player_info_class_matched",
                      requested_info.selected_class >= 0 &&
                          requested_info.selected_class ==
                              fallback_info.selected_class)
                .Bool("loadout_block_synthesized",
                      loadout_block_patched)
                .Int("synthesized_class",
                     loadout_block_patched
                         ? requested_loadout.selected_class
                         : -1)
                .Int("synthesized_first_weapon",
                     loadout_block_patched
                         ? ((requested_loadout.weapon_valid_mask & 1)
                                ? requested_loadout.weapons[0] : -1)
                         : -1)
                .UInt("synthesized_weapon_valid_mask",
                      loadout_block_patched
                          ? requested_loadout.weapon_valid_mask : 0)
                .UInt("synthesized_fallback_weapon_mask",
                      loadout_block_patched
                          ? (kMissionLoadoutWeaponMask &
                             ~requested_loadout.weapon_valid_mask) : 0)
                .String("synthesized_loadout_source",
                        loadout_block_patched
                            ? requested_loadout.source
                            : "none")
                .String("strategy",
                        loadout_block_patched
                            ? "temporary_native_block_from_safe_snapshot"
                            : "temporary_native_loadout_by_player_info_class")
                .UInt("loadout_index_offset",
                      kUserMissionLoadoutIndexOffset));
    }
    return MissionUserLoadoutIndex(requested_object) ==
        temporary_loadout_index;
}

SharedProperty* __fastcall MissionSourceLookupHook(
    void* table, SharedProperty* output, uint64_t index) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva =
        return_address >= g_module_base ? return_address - g_module_base : 0;
    auto* sources = static_cast<MissionSourceVector*>(table);
    const bool table_shape_valid = sources &&
        sources->capacity >= sources->size && sources->size <= 64 &&
        (!sources->size || sources->entries);
    const uint64_t table_count = table_shape_valid ? sources->size : 0;
    const bool indexed_entry_present = table_shape_valid &&
        index < table_count && sources->entries[index].object != nullptr;
    const int context = MissionSourceContextIndex(caller_rva);
    void* requested_object = table_shape_valid && index < table_count
        ? sources->entries[index].object : nullptr;
    int fallback_loadout_source_index = -1;
    int32_t original_loadout_index = -1;
    int32_t temporary_loadout_index = -1;
    const bool temporary_loadout_installed = context == 0 &&
        InstallTemporaryExtraMissionLoadout(
            sources, index, fallback_loadout_source_index,
            original_loadout_index, temporary_loadout_index);
    const MissionSourceLoadoutStatus requested_status =
        InspectMissionSourceLoadout(requested_object);
    const bool requested_loadout_index_rejected =
        requested_status.runtime_user &&
        (requested_status.loadout_index < 0 ||
         requested_status.loadout_index >= 4);
    const bool requested_loadout_rejected =
        requested_loadout_index_rejected ||
        (requested_status.selection_inspected && !requested_status.usable);
    const bool direct_entry_usable = indexed_entry_present &&
        !requested_loadout_rejected;
    uint64_t source_index = MissionSourceIndexForCall(
        index, caller_rva, table_count, direct_entry_usable);
    if (context == 0 && index >= kNativeMissionSourceCount &&
        !direct_entry_usable && table_shape_valid) {
        const int selected = SelectMissionFallbackSourceIndex(sources, index);
        if (selected >= 0) source_index = static_cast<uint64_t>(selected);
    }
    const bool source_index_changed = source_index != index;
    const bool fallback_recycled = source_index_changed;
    const void* source_zero_object = table_shape_valid && table_count
        ? sources->entries[0].object : nullptr;
    void* effective_object = table_shape_valid && source_index < table_count
        ? sources->entries[source_index].object : nullptr;
    const MissionSourceLoadoutStatus effective_status =
        InspectMissionSourceLoadout(effective_object);
    const MissionSourceTableAudit table_audit =
        AuditMissionSourceTable(sources);
    if (context == 0 && g_mission_player_create_trace.active &&
        g_mission_player_create_trace.participant_index >= 0 &&
        index == static_cast<uint64_t>(
                     g_mission_player_create_trace.participant_index)) {
        g_mission_player_create_trace.requested_source_index = index;
        g_mission_player_create_trace.effective_source_index = source_index;
        g_mission_player_create_trace.source_fallback = source_index_changed;
    }
    bool first_audit = false;
    if (context >= 0 && index >= kNativeMissionSourceCount) {
        const uint64_t extra_index = index - kNativeMissionSourceCount;
        const uint32_t log_bit = extra_index < 4
            ? uint32_t{1} << (static_cast<unsigned>(context) * 4 +
                              static_cast<unsigned>(extra_index))
            : uint32_t{1} << 31;
        const uint32_t previous =
            g_mission_source_index_audit_logged_mask.fetch_or(
                log_bit, std::memory_order_acq_rel);
        first_audit = !(previous & log_bit);
        EDF5_CRASH_BREADCRUMB("more_players", "mission_source_index",
                                  MissionSourceContextName(context), index,
                                  source_index);
        if (first_audit) {
            EDF5_CAPTURE_EVENT(
                "more_players", "mission_source_index_audit",
                capture::Fields()
                    .String("context", MissionSourceContextName(context))
                    .UInt("participant_index", index)
                    .UInt("effective_index", source_index)
                    .UInt("native_source_count", kNativeMissionSourceCount)
                    .UInt("source_table_count", table_count)
                    .Bool("source_table_shape_valid", table_shape_valid)
                    .Bool("requested_entry_present", indexed_entry_present)
                    .Bool("requested_entry_user_impl",
                          IsRuntimeUserImpl(requested_object))
                    .Int("requested_registered_order",
                         RegisteredUserOrdinal(requested_object))
                    .Int("requested_loadout_index",
                         MissionUserLoadoutIndex(requested_object))
                    .Int("requested_transport_route_index",
                         TransportRouteIndex(requested_object))
                    .Int("requested_player_info_class",
                         FindPlayerInfoObservation(
                             requested_object).selected_class)
                    .Int("requested_loadout_selector",
                         requested_status.selected_loadout)
                    .Int("requested_resource_selector",
                         requested_status.resource_selector)
                    .Bool("requested_loadout_inspected",
                          requested_status.selection_inspected)
                    .Bool("requested_loadout_usable",
                          requested_status.usable)
                    .Bool("requested_loadout_index_rejected",
                          requested_loadout_index_rejected)
                    .Bool("temporary_loadout_installed",
                          temporary_loadout_installed)
                    .Int("original_loadout_index",
                         original_loadout_index)
                    .Int("temporary_loadout_index",
                         temporary_loadout_index)
                    .Int("fallback_loadout_source_index",
                         fallback_loadout_source_index)
                    .Bool("effective_entry_present",
                          effective_object != nullptr)
                    .Bool("effective_entry_user_impl",
                          IsRuntimeUserImpl(effective_object))
                    .Int("effective_registered_order",
                         RegisteredUserOrdinal(effective_object))
                    .Int("effective_loadout_index",
                         MissionUserLoadoutIndex(effective_object))
                    .Int("effective_transport_route_index",
                         TransportRouteIndex(effective_object))
                    .Int("effective_player_info_class",
                         FindPlayerInfoObservation(
                             effective_object).selected_class)
                    .Int("effective_loadout_selector",
                         effective_status.selected_loadout)
                    .Int("effective_resource_selector",
                         effective_status.resource_selector)
                    .Bool("effective_loadout_inspected",
                          effective_status.selection_inspected)
                    .Bool("effective_loadout_usable",
                          effective_status.usable)
                    .Bool("effective_same_as_source_zero",
                          effective_object &&
                              effective_object == source_zero_object)
                    .Bool("direct_entry_usable", direct_entry_usable)
                    .String("source_table_semantics",
                            "post_sort_user_id_descending")
                    .Bool("pre_sort_snapshot_identity_used", false)
                    .Bool("sort_key_complete",
                          table_audit.sort_key_complete)
                    .Bool("sorted_by_user_id_descending",
                          table_audit.sorted_by_user_id_descending)
                    .Bool("sort_keys_unique",
                          table_audit.sort_keys_unique)
                    .Raw("source_table_to_registered_order",
                         MissionSourceTableRegisteredOrderJson(sources))
                    .Raw("source_table_loadout_indices",
                         OrdinalArrayJson(table_audit.loadout_indices,
                                          table_audit.count))
                    .Raw("source_table_transport_route_indices",
                         OrdinalArrayJson(
                             table_audit.transport_route_indices,
                             table_audit.count))
                    .Raw("source_table_loadout_selectors",
                         OrdinalArrayJson(table_audit.selected_loadouts,
                                          table_audit.count))
                    .Raw("source_table_resource_selectors",
                         OrdinalArrayJson(table_audit.resources,
                                          table_audit.count))
                    .UInt("source_table_runtime_user_mask",
                          table_audit.runtime_user_mask)
                    .UInt("source_table_loadout_inspected_mask",
                          table_audit.loadout_inspected_mask)
                    .UInt("source_table_usable_mask",
                          table_audit.usable_mask)
                    .UInt("source_table_local_control_membership_mask",
                          table_audit.local_control_membership_mask)
                    .UInt("source_table_transport_route_index_mask",
                          table_audit.transport_route_index_mask)
                    .UInt(
                        "source_table_duplicate_transport_route_participant_mask",
                        table_audit
                            .duplicate_transport_route_participant_mask)
                    .Bool("source_table_transport_route_indices_complete",
                          table_audit.transport_route_indices_complete)
                    .Bool("source_table_transport_route_indices_unique",
                          table_audit.transport_route_indices_unique)
                    .UInt("lookup_rva", kMissionSourceLookupRva)
                    .UInt("call_rva", caller_rva >= 5 ? caller_rva - 5 : 0)
                    .UInt("caller_rva", caller_rva)
                    .Bool("source_index_changed", source_index_changed)
                    .Bool("fallback_recycled", fallback_recycled)
                    .Bool("recycled", fallback_recycled));
        }
    }
    SharedProperty* result = g_mission_source_lookup(
        table, output, source_index);
    if (first_audit) {
        void* result_object = result ? result->object : nullptr;
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_source_resolution_audit",
            capture::Fields()
                .String("context", MissionSourceContextName(context))
                .UInt("participant_index", index)
                .UInt("effective_index", source_index)
                .Bool("result_present", result_object != nullptr)
                .Bool("result_user_impl", IsRuntimeUserImpl(result_object))
                .Int("result_registered_order",
                     RegisteredUserOrdinal(result_object))
                .Int("result_loadout_index",
                     MissionUserLoadoutIndex(result_object))
                .Int("result_transport_route_index",
                     TransportRouteIndex(result_object))
                .Int("result_player_info_class",
                     FindPlayerInfoObservation(
                         result_object).selected_class)
                .Bool("result_same_as_effective_entry",
                      result_object && result_object == effective_object)
                .Bool("result_same_as_source_zero",
                      result_object && result_object == source_zero_object)
                .Bool("pre_sort_snapshot_identity_used", false)
                .Bool("source_index_changed", source_index_changed)
                .Bool("fallback_recycled", fallback_recycled)
                .Bool("recycled", fallback_recycled));
    }
    if (fallback_recycled) {
        EDF5_CRASH_BREADCRUMB("more_players", "mission_source",
                                  "recycled", index, source_index);
        const uint64_t extra_index = index - kNativeMissionSourceCount;
        const uint32_t log_bit = context >= 0 && extra_index < 4
            ? uint32_t{1} << (static_cast<unsigned>(context) * 4 +
                              static_cast<unsigned>(extra_index))
            : uint32_t{1} << 31;
        const uint32_t previous =
            g_mission_source_recycle_logged_mask.fetch_or(
                log_bit, std::memory_order_acq_rel);
        if (!(previous & log_bit)) {
            EDF5_CAPTURE_EVENT(
                "more_players", "mission_source_recycled",
                capture::Fields().UInt("participant_index", index)
                    .UInt("source_index", source_index)
                    .String("context", MissionSourceContextName(context))
                    .UInt("native_source_count", kNativeMissionSourceCount)
                    .UInt("source_table_count", table_count)
                    .Bool("indexed_entry_present", indexed_entry_present)
                    .UInt("lookup_rva", kMissionSourceLookupRva)
                    .UInt("call_rva", caller_rva >= 5 ? caller_rva - 5 : 0)
                    .UInt("caller_rva", caller_rva)
                    .Bool("source_present",
                          result && result->object != nullptr));
        }
    }
    return result;
}

const char* MissionPlayerCreateContextName(int context);

uint32_t MissionParticipantAuditBit(int context,
                                    int32_t participant_index) {
    if (context >= 0 && context < 2 && participant_index >= 0 &&
        participant_index < 8) {
        return uint32_t{1} <<
            (static_cast<unsigned>(context) * 8 +
             static_cast<unsigned>(participant_index));
    }
    return uint32_t{1} << 31;
}

void* __fastcall MissionSourceConsumerHook(
    const SharedProperty* source, void* spawn_transform) {
    const MissionPlayerCreateTrace initial_trace =
        g_mission_player_create_trace;
    const MissionSourceLoadoutStatus direct_status =
        InspectMissionSourceLoadout(source ? source->object : nullptr);
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_source_consumer", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(
            initial_trace.participant_index)),
        initial_trace.effective_source_index);
    void* result = g_mission_source_consumer
        ? g_mission_source_consumer(source, spawn_transform) : nullptr;
    // 0x11D0EC and 0x11E061 read UserImpl+0xF8 after 0x3123A0 returns and
    // use it as the key of the runtime participant map. Keeping the temporary
    // native 0..3 index until MissionPlayerCreate returns aliases P4+ to an
    // existing player even though character construction itself succeeded.
    // Restore both the scratch block and the unique index at the first safe
    // instruction after the character factory, before those native readers.
    RestoreTemporaryMissionSourceState(
        g_mission_player_create_trace, "after_character_consumer", true);
    const bool direct_result_present = result != nullptr;
    const char* direct_null_stage = MissionSourceConsumerNullStage(
        source, direct_status, direct_result_present);
    unsigned retry_count = 0;
    uint32_t retry_source_mask = 0;
    int successful_retry_source_index = -1;

    const MissionSourceVector* sources = initial_trace.sources;
    const bool table_shape_valid = sources &&
        sources->capacity >= sources->size && sources->size <= 64 &&
        (!sources->size || sources->entries);
    void* requested_object = table_shape_valid &&
            initial_trace.requested_source_index < sources->size
        ? sources->entries[
              initial_trace.requested_source_index].object
        : nullptr;
    const int requested_player_info_class =
        FindPlayerInfoObservation(requested_object).selected_class;
    if (!result && initial_trace.active &&
        initial_trace.participant_index >=
            static_cast<int32_t>(kNativeMissionSourceCount) &&
        table_shape_valid && g_mission_source_lookup &&
        g_mission_source_consumer) {
        const unsigned candidate_count = static_cast<unsigned>(
            std::min<uint64_t>(sources->size,
                               kNativeMissionSourceCount));
        const int requested_class = requested_player_info_class;
        const unsigned start = candidate_count
            ? static_cast<unsigned>(initial_trace.requested_source_index %
                                    candidate_count)
            : 0;
        // A retry is intentionally limited to the four native sources whose
        // character construction was observed to succeed. Same-class sources
        // are attempted first, then the remaining native classes. The
        // trampoline is called directly, so retries do not recurse through
        // this hook.
        for (unsigned pass = 0; pass < 2 && !result; ++pass) {
            for (unsigned offset = 0; offset < candidate_count && !result;
                 ++offset) {
                const unsigned candidate_index =
                    (start + offset) % candidate_count;
                const uint32_t candidate_bit = uint32_t{1} <<
                    candidate_index;
                if ((retry_source_mask & candidate_bit) ||
                    candidate_index ==
                        initial_trace.effective_source_index) {
                    continue;
                }
                void* candidate_object =
                    sources->entries[candidate_index].object;
                const MissionSourceLoadoutStatus candidate_status =
                    InspectMissionSourceLoadout(candidate_object);
                if (!candidate_status.runtime_user) continue;
                const bool same_class = requested_class >= 0 &&
                    FindPlayerInfoObservation(
                        candidate_object).selected_class == requested_class;
                if ((pass == 0 && !same_class) ||
                    (pass == 1 && same_class)) {
                    continue;
                }
                SharedProperty candidate{};
                SharedProperty* copied = g_mission_source_lookup(
                    const_cast<MissionSourceVector*>(sources), &candidate,
                    candidate_index);
                retry_source_mask |= candidate_bit;
                ++retry_count;
                if (copied && copied->object) {
                    result = g_mission_source_consumer(
                        copied, spawn_transform);
                }
                if (g_shared_property_release) {
                    g_shared_property_release(&candidate);
                }
                if (result) {
                    successful_retry_source_index =
                        static_cast<int>(candidate_index);
                    g_mission_player_create_trace.effective_source_index =
                        candidate_index;
                    g_mission_player_create_trace.source_fallback = true;
                }
            }
        }
    }

    const uint32_t log_bit = MissionParticipantAuditBit(
        initial_trace.context, initial_trace.participant_index);
    const uint32_t previous =
        g_mission_source_consumer_audit_logged_mask.fetch_or(
            log_bit, std::memory_order_acq_rel);
    const bool first_audit = !(previous & log_bit);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", result ? 1 : 0,
                            retry_count);
    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_source_consumer_result",
        result ? "character_present" : "character_missing",
        static_cast<uint64_t>(static_cast<int64_t>(
            initial_trace.participant_index)),
        successful_retry_source_index >= 0
            ? static_cast<uint64_t>(successful_retry_source_index)
            : initial_trace.effective_source_index);
    if (first_audit && initial_trace.active) {
        const MissionSourceTableAudit table_audit =
            AuditMissionSourceTable(sources);
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_source_consumer_result",
            capture::Fields()
                .String("context",
                        MissionPlayerCreateContextName(initial_trace.context))
                .Int("participant_index",
                     initial_trace.participant_index)
                .UInt("requested_source_index",
                      initial_trace.requested_source_index)
                .UInt("initial_effective_source_index",
                      initial_trace.effective_source_index)
                .Int("successful_retry_source_index",
                     successful_retry_source_index)
                .UInt("retry_count", retry_count)
                .UInt("retry_source_mask", retry_source_mask)
                .Bool("direct_result_present", direct_result_present)
                .Bool("final_result_present", result != nullptr)
                .String("direct_null_stage", direct_null_stage)
                .Bool("direct_null_stage_statically_inferred",
                      !direct_result_present)
                .Int("direct_loadout_index",
                     direct_status.loadout_index)
                .Int("requested_player_info_class",
                     requested_player_info_class)
                .Int("direct_loadout_selector",
                     direct_status.selected_loadout)
                .Int("direct_resource_selector",
                     direct_status.resource_selector)
                .Bool("direct_loadout_inspected",
                      direct_status.selection_inspected)
                .Bool("direct_loadout_usable", direct_status.usable)
                .UInt("source_table_count",
                      table_shape_valid ? sources->size : 0)
                .Bool("source_table_shape_valid", table_shape_valid)
                .UInt("source_table_runtime_user_mask",
                      table_audit.runtime_user_mask)
                .UInt("source_table_loadout_inspected_mask",
                      table_audit.loadout_inspected_mask)
                .UInt("source_table_usable_mask",
                      table_audit.usable_mask)
                .UInt("source_table_local_control_membership_mask",
                      table_audit.local_control_membership_mask)
                .Raw("source_table_transport_route_indices",
                     OrdinalArrayJson(
                         table_audit.transport_route_indices,
                         table_audit.count))
                .UInt("source_table_transport_route_index_mask",
                      table_audit.transport_route_index_mask)
                .UInt(
                    "source_table_duplicate_transport_route_participant_mask",
                    table_audit
                        .duplicate_transport_route_participant_mask)
                .Bool("source_table_transport_route_indices_complete",
                      table_audit.transport_route_indices_complete)
                .Bool("source_table_transport_route_indices_unique",
                      table_audit.transport_route_indices_unique)
                .Bool("sorted_by_user_id_descending",
                      table_audit.sorted_by_user_id_descending)
                .UInt("consumer_rva", kMissionSourceConsumerRva)
                .UInt("native_fallback_capacity",
                      kNativeMissionSourceCount));
    }
    return result;
}

SharedProperty* __fastcall MissionSharedHandleCopyHook(
    const void* source, SharedProperty* output) {
    // 0x11cf7e performs `lea rcx,[rax+0x10]` without checking the character
    // returned by 0x3123a0. A null character therefore becomes source 0x10
    // and the native helper faults at 0x6e022 while reading [rcx+8]. Restrict
    // the guard to an active mission-player call and that exact sentinel.
    if (g_mission_player_create_trace.active &&
        reinterpret_cast<uintptr_t>(source) == 0x10 && output) {
        output->control = nullptr;
        output->object = nullptr;
        const int32_t participant_index =
            g_mission_player_create_trace.participant_index;
        const uint32_t log_bit = MissionParticipantAuditBit(
            g_mission_player_create_trace.context, participant_index);
        const uint32_t previous =
            g_mission_null_character_guard_logged_mask.fetch_or(
                log_bit, std::memory_order_acq_rel);
        EDF5_CRASH_BREADCRUMB(
            "more_players", "mission_null_character_guarded",
            MissionPlayerCreateContextName(
                g_mission_player_create_trace.context),
            static_cast<uint64_t>(static_cast<int64_t>(participant_index)),
            g_mission_player_create_trace.effective_source_index);
        if (!(previous & log_bit)) {
            EDF5_CAPTURE_EVENT(
                capture::Level::Error, "more_players",
                "mission_null_character_guarded",
                capture::Fields()
                    .String("context", MissionPlayerCreateContextName(
                        g_mission_player_create_trace.context))
                    .Int("participant_index", participant_index)
                    .UInt("requested_source_index",
                          g_mission_player_create_trace
                              .requested_source_index)
                    .UInt("effective_source_index",
                          g_mission_player_create_trace
                              .effective_source_index)
                    .Bool("source_fallback",
                          g_mission_player_create_trace.source_fallback)
                    .UInt("consumer_rva", kMissionSourceConsumerRva)
                    .UInt("guarded_helper_rva",
                          kMissionSharedHandleCopyRva)
                    .UInt("native_fault_instruction_rva", 0x6e022)
                    .String("action",
                            "returned_empty_handle_to_abort_player_create"));
        }
        return output;
    }
    return g_mission_shared_handle_copy
        ? g_mission_shared_handle_copy(source, output) : output;
}

int MissionPlayerCreateContextIndex(uintptr_t caller_rva) {
    if (caller_rva == kMissionPlayerCreatePrimaryReturnRva) return 0;
    if (caller_rva == kMissionPlayerCreateSecondaryReturnRva) return 1;
    return -1;
}

[[maybe_unused]] const char* MissionPlayerCreateContextName(int context) {
    switch (context) {
    case 0: return "mission_entry_primary";
    case 1: return "mission_entry_secondary";
    default: return "unrelated";
    }
}

uint32_t MissionPlayerControlAuditBit(int context,
                                      int32_t participant_index) {
    if (context >= 0 && context < 2 && participant_index >= 0 &&
        participant_index < 8) {
        return uint32_t{1} <<
            (static_cast<unsigned>(context) * 8 +
             static_cast<unsigned>(participant_index));
    }
    return uint32_t{1} << 31;
}

SharedProperty* __fastcall MissionPlayerCreateHook(
    void* owner, SharedProperty* output, void* spawn_transform,
    int32_t participant_index, int32_t local_controller_index,
    int32_t argument6, int32_t argument7, uintptr_t argument8,
    int32_t argument9, void* argument10) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva =
        return_address >= g_module_base ? return_address - g_module_base : 0;
    const int context = MissionPlayerCreateContextIndex(caller_rva);
    const uint32_t log_bit = MissionPlayerControlAuditBit(
        context, participant_index);
    const uint32_t previous =
        g_mission_player_control_audit_logged_mask.fetch_or(
            log_bit, std::memory_order_acq_rel);
    const bool first_audit = !(previous & log_bit);
    const int32_t original_local_controller_index = local_controller_index;
    const auto* final_sources =
        static_cast<const MissionSourceVector*>(argument10);
    void* participant_user = nullptr;
    if (final_sources && final_sources->entries &&
        final_sources->capacity >= final_sources->size &&
        participant_index >= 0 &&
        static_cast<uint64_t>(participant_index) < final_sources->size) {
        participant_user = final_sources->entries[participant_index].object;
    }
    RegisterMissionParticipantUser(participant_index, participant_user);
    const PlayerInfoObservation participant_player_info =
        FindPlayerInfoObservation(participant_user);
    const int participant_registered_order =
        RegisteredUserOrdinal(participant_user);
    const int participant_source_loadout_index =
        MissionUserLoadoutIndex(participant_user);
    const int participant_transport_route_index =
        TransportRouteIndex(participant_user);
    const bool participant_source_identity_matches =
        participant_index >= 0 &&
        participant_source_loadout_index == participant_index;
    int32_t reconstructed_local_controller_index = local_controller_index;
    int local_collection_index = -1;
    const bool local_control_resolved_by_session_object =
        ExpectedMissionLocalController(
            final_sources, participant_index,
            reconstructed_local_controller_index,
            local_collection_index);
    // Native controller values are proven correct for participants 0-3. The
    // primary path overwrites the fifth int with the first spawn transform at
    // 0x11da46; both entry paths can safely reconstruct extras from the final
    // sorted source vector and the order-independent local subset.
    const bool extra_participant = participant_index >=
        static_cast<int32_t>(kNativeMissionSourceCount);
    const bool repair_extra_controller = extra_participant &&
        local_control_resolved_by_session_object;
    const int32_t resolved_local_controller_index = repair_extra_controller
        ? reconstructed_local_controller_index
        : original_local_controller_index;
    const bool control_assignment_corrected =
        resolved_local_controller_index != original_local_controller_index;
    const bool locally_controlled = resolved_local_controller_index >= 0;
    if (locally_controlled && participant_index >= 0 &&
        static_cast<size_t>(participant_index) <
            kReplicationParticipantCapacity) {
        g_mission_local_participant_mask.fetch_or(
            uint32_t{1} << static_cast<unsigned>(participant_index),
            std::memory_order_acq_rel);
    }
    if (final_sources && final_sources->capacity >= final_sources->size) {
        MaybeActivateReplicationParticipantMap(final_sources->size);
    }
    const MissionSourceTableAudit final_table_audit =
        AuditMissionSourceTable(final_sources);

    EDF5_CRASH_BREADCRUMB(
        "more_players", "mission_player_control",
        MissionPlayerCreateContextName(context),
        static_cast<uint64_t>(static_cast<int64_t>(participant_index)),
        static_cast<uint64_t>(
            static_cast<int64_t>(resolved_local_controller_index)));
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_player_create", "before_original",
        static_cast<uint64_t>(static_cast<int64_t>(participant_index)),
        static_cast<uint64_t>(
            static_cast<int64_t>(resolved_local_controller_index)));
    if (first_audit) {
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_player_control_assignment",
            capture::Fields()
                .String("context", MissionPlayerCreateContextName(context))
                .Int("participant_index", participant_index)
                .Int("local_controller_index",
                     resolved_local_controller_index)
                .Int("original_local_controller_index",
                     original_local_controller_index)
                .Int("effective_local_controller_index",
                     resolved_local_controller_index)
                .Int("reconstructed_local_controller_index",
                     reconstructed_local_controller_index)
                .Int("local_collection_index", local_collection_index)
                .Bool("local_control_resolved_by_session_object",
                      local_control_resolved_by_session_object)
                .Bool("control_assignment_corrected",
                      control_assignment_corrected)
                .Bool("native_first_four_preserved",
                      !extra_participant)
                .Bool("native_control_stack_overlap",
                      context == 0 &&
                          participant_index >=
                              static_cast<int32_t>(
                                  kNativeMissionSourceCount))
                .Bool("locally_controlled", locally_controlled)
                .Int("source_registered_order",
                     participant_registered_order)
                .Int("source_mission_loadout_index",
                     participant_source_loadout_index)
                .Int("source_transport_route_index",
                     participant_transport_route_index)
                .Bool("source_identity_index_matches_participant",
                      participant_source_identity_matches)
                .Bool("player_info_display_name_valid",
                      participant_player_info.name_valid)
                .UInt("player_info_display_name_token",
                      participant_player_info.name_token)
                .UInt("player_info_display_name_length",
                      participant_player_info.name_length)
                .Bool("player_info_display_name_text_logged", false)
                .Bool("participant_in_configured_range",
                      participant_index >= 0 &&
                          static_cast<unsigned>(participant_index) <
                              MaxPlayers())
                .Bool("extra_participant",
                      extra_participant)
                .String("source_table_semantics",
                        "post_sort_user_id_descending")
                .Bool("source_table_sort_key_complete",
                      final_table_audit.sort_key_complete)
                .Bool("source_table_sorted_by_user_id_descending",
                      final_table_audit.sorted_by_user_id_descending)
                .Bool("source_table_sort_keys_unique",
                      final_table_audit.sort_keys_unique)
                .UInt("source_table_local_control_membership_mask",
                      final_table_audit.local_control_membership_mask)
                .Raw("source_table_transport_route_indices",
                     OrdinalArrayJson(
                         final_table_audit.transport_route_indices,
                         final_table_audit.count))
                .UInt("source_table_transport_route_index_mask",
                      final_table_audit.transport_route_index_mask)
                .UInt(
                    "source_table_duplicate_transport_route_participant_mask",
                    final_table_audit
                        .duplicate_transport_route_participant_mask)
                .Bool("source_table_transport_route_indices_complete",
                      final_table_audit
                          .transport_route_indices_complete)
                .Bool("source_table_transport_route_indices_unique",
                      final_table_audit.transport_route_indices_unique)
                .Bool("local_controller_index_plausible",
                      resolved_local_controller_index >= -1 &&
                          resolved_local_controller_index < 4)
                .UInt("player_create_rva", kMissionPlayerCreateRva)
                .UInt("call_rva", caller_rva >= 5 ? caller_rva - 5 : 0)
                .UInt("caller_rva", caller_rva)
                .String("phase", "before_original"));
    }

    const MissionPlayerCreateTrace previous_trace =
        g_mission_player_create_trace;
    g_mission_player_create_trace = {};
    g_mission_player_create_trace.active = true;
    g_mission_player_create_trace.context = context;
    g_mission_player_create_trace.participant_index = participant_index;
    g_mission_player_create_trace.requested_source_index =
        participant_index >= 0
            ? static_cast<uint64_t>(participant_index) : 0;
    g_mission_player_create_trace.effective_source_index =
        g_mission_player_create_trace.requested_source_index;
    g_mission_player_create_trace.source_fallback = false;
    g_mission_player_create_trace.sources = final_sources;
    SharedProperty* result = g_mission_player_create
        ? g_mission_player_create(
              owner, output, spawn_transform, participant_index,
              resolved_local_controller_index, argument6, argument7,
              argument8,
              argument9, argument10)
        : output;
    MissionPlayerCreateTrace completed_trace =
        g_mission_player_create_trace;
    // Safety net for a native branch that looked up the source but skipped the
    // character consumer. The normal path has already restored at 0x3123A0's
    // return and therefore performs no work here.
    RestoreTemporaryMissionSourceState(
        completed_trace, "player_create_return_fallback", false);
    g_mission_player_create_trace = previous_trace;
    const bool output_player_present = output && output->object;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", output_player_present ? 1 : 0,
                            result == output ? 1 : 0);
    if (first_audit) {
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_player_create_result",
            capture::Fields()
                .String("context", MissionPlayerCreateContextName(context))
                .Int("participant_index", participant_index)
                .Int("local_controller_index",
                     resolved_local_controller_index)
                .Int("original_local_controller_index",
                     original_local_controller_index)
                .Int("effective_local_controller_index",
                     resolved_local_controller_index)
                .Int("reconstructed_local_controller_index",
                     reconstructed_local_controller_index)
                .Int("local_collection_index", local_collection_index)
                .Bool("local_control_resolved_by_session_object",
                      local_control_resolved_by_session_object)
                .Bool("control_assignment_corrected",
                      control_assignment_corrected)
                .Bool("locally_controlled", locally_controlled)
                .Int("source_registered_order",
                     participant_registered_order)
                .Int("source_mission_loadout_index",
                     participant_source_loadout_index)
                .Int("source_transport_route_index",
                     participant_transport_route_index)
                .Bool("source_identity_index_matches_participant",
                      participant_source_identity_matches)
                .Bool("player_info_display_name_valid",
                      participant_player_info.name_valid)
                .UInt("player_info_display_name_token",
                      participant_player_info.name_token)
                .UInt("player_info_display_name_length",
                      participant_player_info.name_length)
                .Bool("player_info_display_name_text_logged", false)
                .Raw("source_table_transport_route_indices",
                     OrdinalArrayJson(
                         final_table_audit.transport_route_indices,
                         final_table_audit.count))
                .UInt(
                    "source_table_duplicate_transport_route_participant_mask",
                    final_table_audit
                        .duplicate_transport_route_participant_mask)
                .Bool("source_table_transport_route_indices_unique",
                      final_table_audit.transport_route_indices_unique)
                .UInt("requested_source_index",
                      completed_trace.requested_source_index)
                .UInt("effective_source_index",
                      completed_trace.effective_source_index)
                .Bool("source_fallback",
                      completed_trace.source_fallback)
                .Int("original_loadout_index",
                     completed_trace.original_loadout_index)
                .Int("temporary_loadout_index",
                     completed_trace.temporary_loadout_index)
                .Int("observed_loadout_index_before_restore",
                     completed_trace.observed_loadout_index_before_restore)
                .Int("observed_loadout_index_after_restore",
                     completed_trace.observed_loadout_index_after_restore)
                .Int("requested_player_info_class",
                     completed_trace.requested_player_info_class)
                .Int("fallback_player_info_class",
                     completed_trace.fallback_player_info_class)
                .Bool("temporary_loadout_block_patched",
                      completed_trace.temporary_loadout_block_patched)
                .Int("temporary_loadout_block_class",
                     completed_trace.temporary_loadout_block_class)
                .Int("temporary_loadout_block_first_weapon",
                     completed_trace.temporary_loadout_block_first_weapon)
                .UInt("temporary_loadout_block_weapon_valid_mask",
                      completed_trace
                          .temporary_loadout_block_weapon_valid_mask)
                .UInt("temporary_loadout_block_fallback_weapon_mask",
                      completed_trace
                          .temporary_loadout_block_fallback_weapon_mask)
                .Int("temporary_loadout_block_armor",
                     completed_trace.temporary_loadout_block_armor)
                .String("temporary_loadout_block_source",
                        completed_trace.temporary_loadout_block_source)
                .Bool("temporary_loadout_block_restored",
                      completed_trace.temporary_loadout_block_restored)
                .Bool("unique_loadout_index_restored",
                      completed_trace.unique_loadout_index_restored)
                .Bool("loadout_restored_before_post_create_consumers",
                      completed_trace
                          .loadout_restored_before_post_create_consumers)
                .String("loadout_restoration_phase",
                        completed_trace.loadout_restoration_phase)
                .Bool("output_player_present", output_player_present)
                .Bool("result_same_as_output", result == output)
                .String("phase", "original_returned"));
    }
    return result;
}

void* __fastcall UiLayoutCastHook(void* output, void* component) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address =
        reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    void* result = g_ui_layout_cast(output, component);
    if (return_address != g_module_base + kPlayersGroupCastReturnRva) {
        return result;
    }

    auto** shared_layout = static_cast<void**>(result ? result : output);
    void* layout = shared_layout ? shared_layout[0] : nullptr;
    if (layout && *reinterpret_cast<void***>(layout) !=
                      g_runtime_ui_layout_vtable) {
        layout = nullptr;
    }
    g_players_group_layout.store(reinterpret_cast<uintptr_t>(layout),
                                 std::memory_order_release);
    g_players_group_capture_tick.store(layout ? GetTickCount64() : 0,
                                       std::memory_order_release);
    return result;
}

void* __fastcall UiLayoutDestructorHook(void* self, unsigned flags) {
    uintptr_t expected = reinterpret_cast<uintptr_t>(self);
    if (g_players_group_layout.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        g_players_group_capture_tick.store(0, std::memory_order_release);
    }
    return g_ui_layout_destructor(self, flags);
}

bool AdjustRosterScrollModel(uint8_t* model, int detents, float& previous,
                             float& position) {
    if (!model || !detents || model[kUiScrollEnabledOffset] == 0) return false;
    previous = *reinterpret_cast<float*>(
        model + kUiScrollRequestedPositionOffset);
    if (!std::isfinite(previous)) return false;
    position = std::max(0.0f, std::min(
        1.0f, previous - static_cast<float>(detents) * kRosterWheelStep));
    *reinterpret_cast<float*>(model + kUiScrollRequestedPositionOffset) =
        position;
    return true;
}

void ApplyPendingWheelScroll() {
    const int detents = g_pending_wheel_detents.exchange(
        0, std::memory_order_acq_rel);
    if (!detents || !RoomRosterActive() || !g_ui_layout_clamp) return;

    auto* layout = reinterpret_cast<uint8_t*>(
        g_players_group_layout.load(std::memory_order_acquire));
    const uint64_t captured =
        g_players_group_capture_tick.load(std::memory_order_acquire);
    const uint64_t now = GetTickCount64();
    const uint64_t capture_age = captured && now >= captured
        ? now - captured : 0;
    bool layout_valid = layout && captured &&
                        *reinterpret_cast<void***>(layout) ==
                            g_runtime_ui_layout_vtable;
    auto* model = layout_valid
        ? *reinterpret_cast<uint8_t**>(layout + kUiLayoutVerticalScrollOffset)
        : nullptr;
    const bool model_enabled = model && model[kUiScrollEnabledOffset] != 0;
    float previous = 0.0f;
    float position = 0.0f;
    const bool applied = AdjustRosterScrollModel(
        model, detents, previous, position);
    if (applied) g_ui_layout_clamp(layout);
    EDF5_CAPTURE_EVENT("more_players", "room_wheel_scroll_applied",
                   capture::Fields().Int("wheel_detents", detents)
                       .Bool("players_group", layout_valid)
                       .UInt("players_group_capture_age_ms", capture_age)
                       .Bool("scroll_model", model != nullptr)
                       .Bool("scroll_model_enabled", model_enabled)
                       .Int("previous_position_milli",
                            std::isfinite(previous)
                                ? static_cast<int64_t>(std::lround(
                                      previous * 1000.0f))
                                : -1)
                       .Int("new_position_milli",
                            static_cast<int64_t>(std::lround(
                                position * 1000.0f)))
                       .Bool("success", applied)
                       .Bool("cursor_hit_test", false));
}

bool TryReadyBots(uint64_t lobby, bool user_feedback);
void ApplyPendingReadyBots();
void ApplyPendingMissionGroups();
void LogChatBannerWaiting(uint32_t bit, const char* reason);
bool TryPublishChatBannerFromCapturedRoom(bool test_mode);

void CaptureChatRoomInstance(void* room, bool test_mode) {
    bool valid = room != nullptr;
    if (valid && !test_mode) {
        valid = g_runtime_chat_room_vtable &&
            IsReadableMemoryRange(room, sizeof(void*)) &&
            *reinterpret_cast<void***>(room) == g_runtime_chat_room_vtable;
    }
    if (!valid) return;
    g_chat_room_instance.store(reinterpret_cast<uintptr_t>(room),
                               std::memory_order_release);
    const unsigned captures = g_chat_room_capture_count.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    EDF5_CAPTURE_EVENT(
        "more_players", "chat_room_instance_captured",
        capture::Fields()
            .UInt("capture_count", captures)
            .UInt("constructor_rva", kChatRoomConstructorRva)
            .UInt("vtable_rva", kChatRoomVtableRva)
            .Bool("instance_pointer_logged", false));
}

void* __fastcall ChatRoomConstructorHook(void* self) {
    void* result = g_chat_room_constructor
        ? g_chat_room_constructor(self) : nullptr;
    CaptureChatRoomInstance(result, false);
    return result;
}

void* __fastcall HUiRoomUpdateHook(void* self, void* frame) {
    void* result = g_hui_room_update(self, frame);
    const auto layout = g_players_group_layout.load(std::memory_order_acquire);
    if (layout) {
        const uint64_t now = GetTickCount64();
        g_players_group_capture_tick.store(now, std::memory_order_release);
        g_last_room_model_tick.store(now, std::memory_order_release);
    }
    TryPublishChatBannerFromCapturedRoom(false);
    // The result tick is armed by MissionResultApplyHook on every process.
    // Clients can enter Sync_MissionResult without another Mission() update,
    // leaving their diagnostic phase at "mission" even though result 1 is
    // already pending.  HUiRoom itself is the return signal, so requiring a
    // separate phase transition would hide successful client returns.
    if (CompleteMissionResultTransition("room_ui_update")) {
        PublishDiagnosticState("room", true);
    }
    ApplyPendingReadyBots();
    ApplyPendingMissionGroups();
    ObserveLocalMissionHarnessMissionStartSnapshot("HUiRoom::Update");
    ApplyPendingWheelScroll();
    return result;
}

bool __fastcall MissionStartControllerHook() {
    if (!g_mission_start_controller) return false;
    if (!LocalMissionHarnessSessionReady() || !g_module_base) {
        return g_mission_start_controller();
    }

    const unsigned target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    auto* mission_start = reinterpret_cast<uint8_t*>(
        g_module_base + kMissionStartGlobalStateRva);
    int32_t before_state = std::numeric_limits<int32_t>::min();
    if (IsReadableMemoryRange(mission_start, sizeof(before_state))) {
        std::memcpy(&before_state, mission_start, sizeof(before_state));
    }

    void* context = g_mission_start_controller_context
        ? g_mission_start_controller_context() : nullptr;
    bool context_readable = IsReadableMemoryRange(context, sizeof(void*));
    uintptr_t context_vtable = 0;
    if (context_readable) {
        std::memcpy(&context_vtable, context, sizeof(context_vtable));
    }
    const bool supported_vtable = context_readable &&
        context_vtable == g_module_base + kMissionStartControllerVtableRva;
    auto* gate_field = supported_vtable
        ? reinterpret_cast<volatile LONG*>(
              static_cast<uint8_t*>(context) +
              kMissionStartControllerGateValueOffset)
        : nullptr;
    const bool gate_writable = gate_field &&
        IsWritableMemoryRange(
            const_cast<const LONG*>(gate_field), sizeof(LONG));
    int32_t native_gate_value = -1;
    if (gate_writable) {
        std::memcpy(&native_gate_value,
                    const_cast<const LONG*>(gate_field),
                    sizeof(native_gate_value));
    }

    const bool prerequisites =
        LocalMissionHarnessCompletionPrerequisites(target);
    const bool bypass_requested = supported_vtable && gate_writable &&
        ShouldBypassLocalMissionHarnessControllerGate(
            native_gate_value, before_state, target);
    bool bypass_applied = false;
    if (bypass_requested) {
        const LONG previous = InterlockedCompareExchange(gate_field, 1, 0);
        bypass_applied = previous == 0;
    }

    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_start_controller", "call_original",
        static_cast<uint64_t>(before_state), bypass_applied ? 1 : 0);
    const bool result = g_mission_start_controller();
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", result ? 1 : 0,
                            bypass_applied ? 1 : 0);

    bool temporary_value_restored = false;
    if (bypass_applied &&
        IsWritableMemoryRange(
            const_cast<const LONG*>(gate_field), sizeof(LONG))) {
        temporary_value_restored =
            InterlockedCompareExchange(gate_field, 0, 1) == 1;
    }

    int32_t after_state = std::numeric_limits<int32_t>::min();
    if (IsReadableMemoryRange(mission_start, sizeof(after_state))) {
        std::memcpy(&after_state, mission_start, sizeof(after_state));
    }
    const uint64_t call =
        g_local_mission_harness_controller_calls.fetch_add(
            1, std::memory_order_acq_rel) + 1;
    const uint64_t bypass = bypass_applied
        ? g_local_mission_harness_controller_bypasses.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_local_mission_harness_controller_bypasses.load(
              std::memory_order_acquire);
    const int32_t previous_state =
        g_local_mission_harness_last_controller_state.exchange(
            after_state, std::memory_order_acq_rel);
    const bool first = call == 1;
    const bool state_changed = before_state != after_state ||
        (!first && previous_state != after_state);
    const uint64_t now = GetTickCount64();
    const uint64_t last_log_tick =
        g_local_mission_harness_last_controller_log_tick.load(
            std::memory_order_acquire);
    const bool periodic = !last_log_tick || now < last_log_tick ||
        now - last_log_tick >= kMissionStartObservationIntervalMs;
    const bool emit = first || state_changed ||
        (bypass_applied && bypass == 1) || result || periodic;
    if (emit) {
        g_local_mission_harness_last_controller_log_tick.store(
            now, std::memory_order_release);
        EDF5_CRASH_BREADCRUMB(
            "more_players", "mission_start_controller",
            bypass_applied ? "host_only_gate_bypassed" : "observed",
            static_cast<uint64_t>(after_state), bypass);
        EDF5_CAPTURE_EVENT(
            "more_players",
            "local_mission_harness_controller_gate_observed",
            capture::Fields()
                .UInt("call", call)
                .UInt("bypass", bypass)
                .UInt("dummy_count", target)
                .Int("actual_members",
                     g_last_actual_member_count.load(
                         std::memory_order_acquire))
                .Int("native_gate_value", native_gate_value)
                .Int("effective_gate_value",
                     bypass_applied ? 1 : native_gate_value)
                .Int("mission_start_before_state", before_state)
                .Int("mission_start_after_state", after_state)
                .Int("previous_observed_state", previous_state)
                .Bool("context_resolved", context != nullptr)
                .Bool("supported_vtable", supported_vtable)
                .Bool("gate_writable", gate_writable)
                .Bool("completion_prerequisites", prerequisites)
                .Bool("bypass_requested", bypass_requested)
                .Bool("bypass_applied", bypass_applied)
                .Bool("temporary_value_restored",
                      temporary_value_restored)
                .Bool("controller_result", result)
                .Bool("first_observation", first)
                .Bool("state_changed", state_changed)
                .Bool("periodic", periodic)
                .UInt("controller_rva", kMissionStartControllerRva)
                .UInt("controller_context_rva",
                      kMissionStartControllerContextRva)
                .UInt("controller_vtable_rva",
                      kMissionStartControllerVtableRva)
                .UInt("controller_gate_value_offset",
                      kMissionStartControllerGateValueOffset)
                .Bool("native_mission_state_forced", false)
                .Bool("native_context_field_persisted", false));
    }
    return result;
}

void __fastcall MissionStartUpdateHook(void* state, bool publish) {
    const bool is_global = g_module_base &&
        state == reinterpret_cast<void*>(g_module_base +
                                         kMissionStartGlobalStateRva);
    int32_t native_before_state = std::numeric_limits<int32_t>::min();
    if (is_global && IsReadableMemoryRange(state, sizeof(int32_t))) {
        std::memcpy(&native_before_state, state,
                    sizeof(native_before_state));
    }
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "mission_start_update", "call_original",
        is_global ? 1 : 0, publish ? 1 : 0);
    if (g_mission_start_update) g_mission_start_update(state, publish);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", is_global ? 1 : 0, 0);
    ObserveLocalMissionHarnessMissionStart(
        state, is_global, publish, native_before_state,
        "MissionStart::Update", true);
    const bool completed =
        CompleteLocalMissionHarnessMatchingGate(state, false);
    if (completed) {
        EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "local_harness_completed",
                                kMissionStartLocallyAggregatedState,
                                kMissionStartCompletedState);
    }
}

#if EDF5_COMPILE_DIAGNOSTICS
void __fastcall ReportGsFailureHook(uintptr_t observed) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t caller = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t caller = 0;
#endif
    crash_capture::CaptureFastFail(2, caller);
    g_report_gs_failure(observed);
}
#endif

uint64_t ProcessImageRva(const void* address) {
    const uintptr_t value = reinterpret_cast<uintptr_t>(address);
    if (!value || !g_module_base || value < g_module_base ||
        value - g_module_base >= g_module_image_size) {
        return 0;
    }
    return static_cast<uint64_t>(value - g_module_base);
}

void ArmChatBanner(uint64_t lobby, const char* entry_path) {
    if (!Enabled() || !lobby) return;
    g_chat_banner_lobby.store(lobby, std::memory_order_release);
    g_chat_banner_wait_logged_mask.store(0, std::memory_order_release);
    g_chat_banner_pending.store(true, std::memory_order_release);
    EDF5_CAPTURE_EVENT(
        "more_players", "chat_mod_banner_armed",
        capture::Fields()
            .UInt("lobby_steam_id", lobby)
            .String("entry_path", entry_path ? entry_path : "unknown")
            .String("mod_name", mod_info::kName)
            .String("mod_version", mod_info::kVersion)
            .Bool("local_display_only", true)
            .Bool("steam_lobby_chat_send", false)
            .Bool("message_text_logged", false));
}

void LogChatBannerWaiting(uint32_t bit, const char* reason) {
    const uint32_t previous = g_chat_banner_wait_logged_mask.fetch_or(
        bit, std::memory_order_acq_rel);
    if ((previous & bit) != 0) return;
    EDF5_CAPTURE_EVENT(
        capture::Level::Warning, "more_players",
        "chat_mod_banner_waiting",
        capture::Fields()
            .UInt("lobby_steam_id",
                  g_chat_banner_lobby.load(std::memory_order_acquire))
            .String("reason", reason)
            .Bool("identity_logged", false)
            .Bool("instance_pointer_logged", false));
}

bool TryPublishChatBannerFromCapturedRoom(bool test_mode) {
    if (!g_chat_banner_pending.load(std::memory_order_acquire)) return false;
    void* room = reinterpret_cast<void*>(
        g_chat_room_instance.load(std::memory_order_acquire));
    if (!room) {
        LogChatBannerWaiting(1u << 0, "chat_room_not_captured");
        return false;
    }
    if (!test_mode &&
        (!g_runtime_chat_room_vtable ||
         !IsReadableMemoryRange(room, sizeof(void*)) ||
         *reinterpret_cast<void***>(room) != g_runtime_chat_room_vtable)) {
        g_chat_room_instance.store(0, std::memory_order_release);
        LogChatBannerWaiting(1u << 1, "chat_room_instance_invalid");
        return false;
    }
    if (!g_chat_system_message_publish) {
        LogChatBannerWaiting(1u << 2,
                             "system_message_publisher_unavailable");
        return false;
    }

    bool expected = true;
    if (!g_chat_banner_pending.compare_exchange_strong(
            expected, false, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return false;
    }

    const unsigned attempt = g_chat_banner_publish_attempts.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    g_chat_system_message_publish(room, mod_info::kChatBanner);
    g_chat_system_message_publish(room, mod_info::kChatInviteHintLine1);
    g_chat_system_message_publish(room, mod_info::kChatInviteHintLine2);
    const unsigned successes = g_chat_banner_publish_successes.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    EDF5_CAPTURE_EVENT(
        "more_players", "chat_mod_banner_publish",
        capture::Fields()
            .UInt("lobby_steam_id",
                  g_chat_banner_lobby.load(std::memory_order_acquire))
            .UInt("attempt", attempt)
            .UInt("successes", successes)
            .UInt("local_message_count", 3)
            .Int("message_kind", kChatSystemMessageKind)
            .Bool("success", true)
            .Bool("call_completed", true)
            .String("publish_path", "room_update_system_message")
            .UInt("publisher_rva", kChatSystemMessagePublishRva)
            .String("identity_context", "not_required")
            .Bool("identity_value_logged", false)
            .Bool("local_display_only", true)
            .Bool("steam_lobby_chat_send", false)
            .Bool("message_text_logged", false));
    return true;
}

bool __fastcall ChatMessagePublishHook(
    void* self, const uint64_t* room_identity, void* sender_identity,
    const wchar_t* message_text, const void* message_state,
    int32_t message_kind, uint16_t message_subtype) {
    const ChatNameAssociation association = InspectChatNameAssociation(
        static_cast<const uint64_t*>(sender_identity), nullptr);
    const uint64_t message_count = g_chat_name_message_count.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    uint64_t room_id = 0;
    bool room_identity_valid = false;
    if (room_identity &&
        IsReadableMemoryRange(room_identity, sizeof(room_id))) {
        std::memcpy(&room_id, room_identity, sizeof(room_id));
        room_identity_valid = room_id != 0;
    }
    uint64_t sender_id = 0;
    if (sender_identity && IsReadableMemoryRange(
            sender_identity, sizeof(sender_id))) {
        std::memcpy(&sender_id, sender_identity, sizeof(sender_id));
    }
    const uint64_t active_lobby = g_chat_banner_lobby.load(
        std::memory_order_acquire);
    const uint64_t local_steam_id = steam_capture::LocalUserSteamId();
    const bool should_log =
        g_chat_name_unresolved_first_logged.exchange(
            1, std::memory_order_acq_rel) == 0;
    if (should_log) {
        EDF5_CAPTURE_EVENT(
            "more_players", "chat_identity_context",
            capture::Fields()
                .UInt("message_count", message_count)
                .Int("message_kind", message_kind)
                .UInt("message_subtype", message_subtype)
                .Bool("room_identity_valid", room_identity_valid)
                .Bool("room_identity_matches_active_lobby",
                      room_identity_valid && active_lobby != 0 &&
                          room_id == active_lobby)
                .Bool("sender_identity_valid",
                      association.sender_identity_valid)
                .Bool("sender_resolved", association.sender_resolved)
                .Int("sender_registered_order",
                     association.sender_registered_order)
                .Int("sender_participant_index",
                     association.sender_participant_index)
                .Bool("sender_identity_matches_local_user",
                      sender_id != 0 && local_steam_id != 0 &&
                          sender_id == local_steam_id)
                .Bool("identity_pair_distinct",
                      room_identity_valid && sender_id != 0 &&
                          room_id != sender_id)
                .UInt("publisher_rva", kChatMessagePublishRva)
                .Bool("room_identity_logged", false)
                .Bool("sender_identity_logged", false)
                .Bool("message_text_inspected", false)
                .Bool("message_text_logged", false));
    }
    const bool result = g_chat_message_publish
        ? g_chat_message_publish(
              self, room_identity, sender_identity, message_text,
              message_state, message_kind, message_subtype)
        : false;
    return result;
}

struct ReplicationSendTargetAudit {
    uint64_t target_count = 0;
    size_t inspected_count = 0;
    unsigned valid_transport_route_count = 0;
    unsigned unique_transport_route_count = 0;
    uint32_t duplicate_transport_route_target_mask = 0;
    uint32_t duplicate_participant_target_mask = 0;
    uint32_t unresolved_target_mask = 0;
    uint32_t target_participant_mask = 0;
    bool vector_shape_valid = false;
    bool entries_readable = false;
    bool target_transport_routes_unique = false;
    bool target_participants_resolved = false;
};

int MissionParticipantIndexForTransportRoute(int32_t route_index) {
    if (route_index < 0) return -1;
    int result = -1;
    for (size_t participant = 0;
         participant < g_mission_participant_users.size(); ++participant) {
        void* const user = reinterpret_cast<void*>(
            g_mission_participant_users[participant].load(
                std::memory_order_acquire));
        if (!user || TransportRouteIndex(user) != route_index) continue;
        if (result >= 0) return -2;
        result = static_cast<int>(participant);
    }
    return result;
}

ReplicationSendTargetAudit AuditReplicationSendTargets(
    const GameplayReplicationTargetVector* targets) {
    ReplicationSendTargetAudit audit;
    if (!targets || !IsReadableMemoryRange(
                        targets, sizeof(GameplayReplicationTargetVector))) {
        return audit;
    }
    audit.target_count = targets->size;
    audit.vector_shape_valid = targets->capacity >= targets->size &&
        targets->size <= kGameplayReplicationReceiveRouteAuditCapacity &&
        (!targets->size || targets->entries);
    if (!audit.vector_shape_valid) return audit;
    audit.inspected_count = static_cast<size_t>(targets->size);
    audit.entries_readable = audit.inspected_count == 0 ||
        IsReadableMemoryRange(
            targets->entries,
            audit.inspected_count *
                sizeof(GameplayReplicationTargetDescriptor));
    if (!audit.entries_readable) return audit;

    std::array<int32_t, kGameplayReplicationReceiveRouteAuditCapacity>
        unique_routes{};
    unique_routes.fill(-1);
    for (size_t index = 0; index < audit.inspected_count; ++index) {
        const int32_t route_index =
            targets->entries[index].transport_route_index;
        const uint32_t target_bit = index < 32
            ? uint32_t{1} << static_cast<unsigned>(index) : 0;
        if (route_index < 0) {
            audit.unresolved_target_mask |= target_bit;
            continue;
        }
        ++audit.valid_transport_route_count;
        bool duplicate = false;
        for (unsigned prior = 0;
             prior < audit.unique_transport_route_count; ++prior) {
            if (unique_routes[prior] == route_index) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            audit.duplicate_transport_route_target_mask |= target_bit;
        } else {
            unique_routes[audit.unique_transport_route_count++] = route_index;
        }
        const int participant_index =
            MissionParticipantIndexForTransportRoute(route_index);
        if (participant_index < 0 ||
            static_cast<size_t>(participant_index) >=
                kReplicationParticipantCapacity) {
            audit.unresolved_target_mask |= target_bit;
            continue;
        }
        const uint32_t participant_bit = uint32_t{1} <<
            static_cast<unsigned>(participant_index);
        if (audit.target_participant_mask & participant_bit) {
            audit.duplicate_participant_target_mask |= target_bit;
        }
        audit.target_participant_mask |= participant_bit;
    }
    audit.target_transport_routes_unique =
        audit.valid_transport_route_count == audit.target_count &&
        audit.unique_transport_route_count == audit.target_count &&
        audit.duplicate_transport_route_target_mask == 0;
    audit.target_participants_resolved =
        audit.unresolved_target_mask == 0 &&
        audit.duplicate_participant_target_mask == 0;
    return audit;
}

bool __fastcall GameplayReplicationProducerHook(
    void* self, int32_t subtype, const void* payload, uint64_t bytes) {
    uint32_t message_code = 0;
    void* context_user = nullptr;
    if (self) {
        const auto* object = static_cast<const uint8_t*>(self);
        const uint16_t family_selector = static_cast<uint16_t>(
            *reinterpret_cast<const uint32_t*>(
                object + kGameplayReplicationFamilyOffset));
        const uint16_t logical_selector = static_cast<uint16_t>(
            static_cast<uint16_t>(family_selector << 4) |
            static_cast<uint16_t>(subtype & 0x0f));
        message_code = static_cast<uint32_t>(logical_selector) << 8;
        const auto* owner = reinterpret_cast<const SharedProperty*>(
            object + kGameplayReplicationOwnerOffset);
        context_user = owner->object;
    }
    bool local_control_fallback = false;
    if (MissionParticipantIndexForUser(context_user) < 0) {
        const int local_participant = SingleParticipantIndex(
            g_mission_local_participant_mask.load(
                std::memory_order_acquire));
        void* const local_user =
            MissionParticipantUserForIndex(local_participant);
        if (local_user) {
            context_user = local_user;
            local_control_fallback = true;
        }
    }
    RecordReplicationParticipantMessage(
        true, message_code, context_user, local_control_fallback);
    void* const previous_user = g_replication_outgoing_user;
    const bool previous_fallback =
        g_replication_outgoing_local_control_fallback;
    g_replication_outgoing_user = context_user;
    g_replication_outgoing_local_control_fallback =
        local_control_fallback;
    const bool result = g_gameplay_replication_producer
        ? g_gameplay_replication_producer(self, subtype, payload, bytes)
        : false;
    g_replication_outgoing_user = previous_user;
    g_replication_outgoing_local_control_fallback = previous_fallback;
    return result;
}

bool __fastcall GameplayReplicationSerializerHook(
    void* self, int32_t local_lane,
    const GameplayReplicationTargetVector* targets, uint32_t message_header,
    const void* payload, uint64_t bytes) {
    const ReplicationSendTargetAudit audit =
        AuditReplicationSendTargets(targets);
    const bool result = g_gameplay_replication_serializer
        ? g_gameplay_replication_serializer(
              self, local_lane, targets, message_header, payload, bytes)
        : false;

    if (!g_replication_participant_map_ready.load(
            std::memory_order_acquire)) {
        return result;
    }
    const uint32_t message_code = message_header & 0x001fffffU;
    const int family_index = ReplicationFamilyIndex(message_code);
    if (family_index < 0) return result;
    const int participant_index = MissionParticipantIndexForUser(
        g_replication_outgoing_user);
    const size_t participant_bucket = participant_index >= 0
        ? static_cast<size_t>(participant_index)
        : kReplicationUnknownParticipant;
    const uint16_t bit = static_cast<uint16_t>(
        uint16_t{1} << static_cast<unsigned>(participant_bucket));
    const uint16_t previous =
        g_replication_send_fanout_first_logged_masks
            [static_cast<size_t>(family_index)]
                .fetch_or(bit, std::memory_order_acq_rel);
    if (previous & bit) return result;

    const ReplicationParticipantMapAudit participant_map =
        InspectReplicationParticipantMap();
    const uint32_t local_participant_bit = participant_index >= 0 &&
            static_cast<size_t>(participant_index) <
                kReplicationParticipantCapacity
        ? uint32_t{1} << static_cast<unsigned>(participant_index) : 0;
    const uint32_t expected_remote_participant_mask =
        participant_map.participant_mask & ~local_participant_bit;
    const uint32_t missing_remote_participant_mask =
        expected_remote_participant_mask & ~audit.target_participant_mask;
    const uint32_t unexpected_target_participant_mask =
        audit.target_participant_mask & ~expected_remote_participant_mask;
    unsigned expected_remote_participants = 0;
    for (uint32_t remaining = expected_remote_participant_mask; remaining;
         remaining &= remaining - 1) {
        ++expected_remote_participants;
    }
    const bool fanout_complete = participant_index >= 0 &&
        participant_map.unique_users == participant_map.mapped_users &&
        participant_map.duplicate_participant_mask == 0 &&
        audit.vector_shape_valid && audit.entries_readable &&
        audit.target_transport_routes_unique &&
        audit.target_participants_resolved &&
        missing_remote_participant_mask == 0 &&
        unexpected_target_participant_mask == 0 &&
        audit.target_count == expected_remote_participants;
    EDF5_CAPTURE_EVENT(
        result && fanout_complete
            ? capture::Level::Info : capture::Level::Warning,
        "more_players", "replication_send_fanout",
        capture::Fields()
            .UInt("message_family", ReplicationFamilyCode(
                                        static_cast<size_t>(family_index)))
            .UInt("message_code", message_code)
            .Int("participant_index", participant_index)
            .Bool("participant_association_resolved",
                  participant_index >= 0)
            .String("association_boundary",
                    g_replication_outgoing_local_control_fallback
                        ? "mission_local_control"
                        : "producer_owner_user")
            .Bool("local_control_fallback",
                  g_replication_outgoing_local_control_fallback)
            .Int("local_lane", local_lane)
            .UInt("target_count", audit.target_count)
            .UInt("inspected_target_count", audit.inspected_count)
            .UInt("valid_transport_route_count",
                  audit.valid_transport_route_count)
            .UInt("unique_transport_route_count",
                  audit.unique_transport_route_count)
            .UInt("duplicate_transport_route_target_mask",
                  audit.duplicate_transport_route_target_mask)
            .UInt("duplicate_participant_target_mask",
                  audit.duplicate_participant_target_mask)
            .UInt("unresolved_target_mask",
                  audit.unresolved_target_mask)
            .UInt("target_participant_mask",
                  audit.target_participant_mask)
            .UInt("expected_remote_participant_mask",
                  expected_remote_participant_mask)
            .UInt("missing_remote_participant_mask",
                  missing_remote_participant_mask)
            .UInt("unexpected_target_participant_mask",
                  unexpected_target_participant_mask)
            .Bool("target_vector_shape_valid", audit.vector_shape_valid)
            .Bool("target_entries_readable", audit.entries_readable)
            .Bool("target_transport_routes_unique",
                  audit.target_transport_routes_unique)
            .Bool("target_participants_resolved",
                  audit.target_participants_resolved)
            .UInt("mapped_participant_count",
                  participant_map.mapped_users)
            .UInt("expected_remote_participant_count",
                  expected_remote_participants)
            .Bool("matches_expected_participant_fanout",
                  fanout_complete)
            .UInt("target_descriptor_stride",
                  sizeof(GameplayReplicationTargetDescriptor))
            .UInt("target_transport_route_index_offset",
                  offsetof(GameplayReplicationTargetDescriptor,
                           transport_route_index))
            .Bool("serializer_result", result)
            .UInt("serializer_rva",
                  kGameplayReplicationSerializerRva)
            .UInt("serializer_call_rva",
                  kGameplayReplicationSerializerCallRva)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("payload_captured", false)
            .Bool("endpoint_identity_captured", false)
            .Bool("steam_id_logged", false)
            .Bool("pointer_logged", false));
    return result;
}

struct ReplicationReceiveRouteAudit {
    uint64_t route_count = 0;
    size_t inspected_count = 0;
    unsigned runtime_user_count = 0;
    unsigned unique_user_count = 0;
    unsigned unresolved_user_count = 0;
    unsigned empty_slot_count = 0;
    uint32_t local_participant_mask = 0;
    uint32_t expected_participant_mask = 0;
    uint32_t participant_mask = 0;
    uint32_t missing_participant_mask = 0;
    uint32_t unexpected_participant_mask = 0;
    uint32_t duplicate_participant_mask = 0;
    uint32_t duplicate_route_mask = 0;
    uint32_t transport_route_index_mismatch_mask = 0;
    std::array<int32_t, kGameplayReplicationReceiveRouteAuditCapacity>
        route_to_participant{};
    std::array<int32_t, kGameplayReplicationReceiveRouteAuditCapacity>
        route_transport_indices{};
    bool entries_readable = false;
    bool truncated = false;
    bool participant_identity_unique = false;
    bool transport_route_indices_match_slots = false;
    bool route_complete = false;
};

struct ReplicationReceiveRouteOwnerResolution {
    void* user = nullptr;
    bool route_object_present = false;
    bool route_object_readable = false;
    bool user_control_present = false;
    bool user_control_readable = false;
    bool user_present = false;
    bool user_readable = false;
    bool runtime_user = false;
};

ReplicationReceiveRouteOwnerResolution
ResolveReplicationReceiveRouteOwner(void* route_object) {
    ReplicationReceiveRouteOwnerResolution resolution;
    resolution.route_object_present = route_object != nullptr;
    if (!route_object || !IsReadableMemoryRange(
            route_object,
            kGameplayReplicationReceiveRouteUserControlOffset +
                sizeof(void*))) {
        return resolution;
    }
    resolution.route_object_readable = true;
    void* control = nullptr;
    std::memcpy(
        &control,
        static_cast<const uint8_t*>(route_object) +
            kGameplayReplicationReceiveRouteUserControlOffset,
        sizeof(control));
    resolution.user_control_present = control != nullptr;
    if (!control || !IsReadableMemoryRange(
            control, kSharedPropertyControlObjectOffset + sizeof(void*))) {
        return resolution;
    }
    resolution.user_control_readable = true;
    std::memcpy(
        &resolution.user,
        static_cast<const uint8_t*>(control) +
            kSharedPropertyControlObjectOffset,
        sizeof(resolution.user));
    resolution.user_present = resolution.user != nullptr;
    resolution.user_readable = resolution.user &&
        IsReadableMemoryRange(resolution.user, sizeof(void*));
    resolution.runtime_user = resolution.user_readable &&
        IsRuntimeUserImpl(resolution.user);
    if (!resolution.runtime_user) resolution.user = nullptr;
    return resolution;
}

void* ResolveReplicationReceiveParserUser(void* parser) {
    if (!parser || !IsReadableMemoryRange(
            parser,
            kGameplayReplicationReceiveParserRouteOwnerOffset +
                sizeof(void*))) {
        return nullptr;
    }
    void* route_object = nullptr;
    std::memcpy(
        &route_object,
        static_cast<const uint8_t*>(parser) +
            kGameplayReplicationReceiveParserRouteOwnerOffset,
        sizeof(route_object));
    return ResolveReplicationReceiveRouteOwner(route_object).user;
}

ReplicationReceiveRouteAudit AuditGameplayReplicationReceiveEntries(
    const SharedProperty* entries, uint64_t route_count,
    bool entries_readable) {
    ReplicationReceiveRouteAudit audit;
    audit.route_to_participant.fill(-1);
    audit.route_transport_indices.fill(-1);
    audit.route_count = route_count;
    audit.entries_readable = entries_readable;
    audit.truncated = route_count >
        kGameplayReplicationReceiveRouteAuditCapacity;
    audit.inspected_count = static_cast<size_t>(std::min<uint64_t>(
        route_count, kGameplayReplicationReceiveRouteAuditCapacity));
    audit.local_participant_mask = g_mission_local_participant_mask.load(
        std::memory_order_acquire);
    for (size_t participant = 0;
         participant < kReplicationParticipantCapacity;
         ++participant) {
        if (g_mission_participant_users[participant].load(
                std::memory_order_acquire)) {
            audit.expected_participant_mask |=
                uint32_t{1} << static_cast<unsigned>(participant);
        }
    }
    audit.expected_participant_mask &= ~audit.local_participant_mask;
    if (!entries_readable || (audit.inspected_count && !entries)) {
        audit.missing_participant_mask = audit.expected_participant_mask;
        return audit;
    }

    std::array<void*, kGameplayReplicationReceiveRouteAuditCapacity>
        observed_users{};
    unsigned observed_unique_users = 0;
    for (size_t route = 0; route < audit.inspected_count; ++route) {
        const ReplicationReceiveRouteOwnerResolution resolution =
            ResolveReplicationReceiveRouteOwner(entries[route].object);
        void* const user = resolution.user;
        if (!user) {
            if (resolution.route_object_present) {
                ++audit.unresolved_user_count;
            } else {
                ++audit.empty_slot_count;
            }
            continue;
        }
        ++audit.runtime_user_count;
        bool duplicate_user = false;
        for (unsigned previous = 0;
             previous < observed_unique_users;
             ++previous) {
            if (observed_users[previous] == user) {
                duplicate_user = true;
                break;
            }
        }
        if (duplicate_user) {
            if (route < 32) {
                audit.duplicate_route_mask |=
                    uint32_t{1} << static_cast<unsigned>(route);
            }
        } else {
            observed_users[observed_unique_users++] = user;
            ++audit.unique_user_count;
        }

        const int participant = MissionParticipantIndexForUser(user);
        const int transport_route_index = TransportRouteIndex(user);
        audit.route_to_participant[route] = participant;
        audit.route_transport_indices[route] = transport_route_index;
        if (transport_route_index != static_cast<int>(route) &&
            route < 32) {
            audit.transport_route_index_mismatch_mask |=
                uint32_t{1} << static_cast<unsigned>(route);
        }
        if (participant < 0 ||
            participant >= static_cast<int>(
                kReplicationParticipantCapacity)) {
            ++audit.unresolved_user_count;
            continue;
        }
        const uint32_t participant_bit =
            uint32_t{1} << static_cast<unsigned>(participant);
        if (audit.participant_mask & participant_bit) {
            audit.duplicate_participant_mask |= participant_bit;
        }
        audit.participant_mask |= participant_bit;
    }
    audit.missing_participant_mask = audit.expected_participant_mask &
        ~audit.participant_mask;
    audit.unexpected_participant_mask = audit.participant_mask &
        ~audit.expected_participant_mask;
    audit.participant_identity_unique =
        audit.unique_user_count == audit.runtime_user_count &&
        audit.duplicate_route_mask == 0 &&
        audit.duplicate_participant_mask == 0;
    audit.transport_route_indices_match_slots =
        audit.transport_route_index_mismatch_mask == 0;
    audit.route_complete =
        audit.entries_readable && !audit.truncated &&
        audit.unresolved_user_count == 0 &&
        audit.missing_participant_mask == 0 &&
        audit.unexpected_participant_mask == 0 &&
        audit.participant_identity_unique &&
        audit.transport_route_indices_match_slots;
    return audit;
}

uint64_t ReplicationReceiveRouteAuditSignature(
    const ReplicationReceiveRouteAudit& audit) {
    uint64_t signature = 1469598103934665603ULL;
    const auto mix = [&signature](uint64_t value) {
        signature ^= value;
        signature *= 1099511628211ULL;
    };
    mix(audit.route_count);
    mix(audit.inspected_count);
    mix(audit.runtime_user_count);
    mix(audit.unique_user_count);
    mix(audit.unresolved_user_count);
    mix(audit.empty_slot_count);
    mix(audit.local_participant_mask);
    mix(audit.expected_participant_mask);
    mix(audit.participant_mask);
    mix(audit.missing_participant_mask);
    mix(audit.unexpected_participant_mask);
    mix(audit.duplicate_participant_mask);
    mix(audit.duplicate_route_mask);
    mix(audit.transport_route_index_mismatch_mask);
    mix(audit.entries_readable ? 1 : 0);
    mix(audit.truncated ? 1 : 0);
    mix(audit.route_complete ? 1 : 0);
    mix(g_mission_generation.load(std::memory_order_acquire));
    return signature;
}

void InspectAndRecordGameplayReplicationReceiveRoutes(void* self) {
    if (!self ||
        !g_replication_participant_map_ready.load(
            std::memory_order_acquire) ||
        !IsReadableMemoryRange(
            self, kGameplayReplicationReceivePumpCountOffset +
                      sizeof(uint64_t))) {
        return;
    }
    auto* const object = static_cast<uint8_t*>(self);
    auto* const lock = reinterpret_cast<CRITICAL_SECTION*>(
        object + kGameplayReplicationReceivePumpLockOffset);
    if (!TryEnterCriticalSection(lock)) return;

    const uint64_t route_count = *reinterpret_cast<const uint64_t*>(
        object + kGameplayReplicationReceivePumpCountOffset);
    const auto* const entries = *reinterpret_cast<SharedProperty* const*>(
        object + kGameplayReplicationReceivePumpVectorOffset);
    const size_t inspected_count = static_cast<size_t>(std::min<uint64_t>(
        route_count, kGameplayReplicationReceiveRouteAuditCapacity));
    const bool entries_readable = inspected_count == 0 ||
        (entries && IsReadableMemoryRange(
            entries, inspected_count * sizeof(SharedProperty)));
    const ReplicationReceiveRouteAudit audit =
        AuditGameplayReplicationReceiveEntries(
            entries, route_count, entries_readable);
    LeaveCriticalSection(lock);

    const uint64_t signature =
        ReplicationReceiveRouteAuditSignature(audit);
    if (g_replication_receive_route_signature.exchange(
            signature, std::memory_order_acq_rel) == signature) {
        return;
    }
    EDF5_CAPTURE_EVENT(
        "more_players", "replication_receive_route_map",
        capture::Fields()
            .UInt("route_count", audit.route_count)
            .UInt("inspected_count", audit.inspected_count)
            .UInt("runtime_user_count", audit.runtime_user_count)
            .UInt("unique_user_count", audit.unique_user_count)
            .UInt("unresolved_user_count", audit.unresolved_user_count)
            .UInt("empty_slot_count", audit.empty_slot_count)
            .UInt("local_participant_mask",
                  audit.local_participant_mask)
            .UInt("expected_participant_mask",
                  audit.expected_participant_mask)
            .UInt("participant_mask", audit.participant_mask)
            .UInt("missing_participant_mask",
                  audit.missing_participant_mask)
            .UInt("unexpected_participant_mask",
                  audit.unexpected_participant_mask)
            .UInt("duplicate_participant_mask",
                  audit.duplicate_participant_mask)
            .UInt("duplicate_route_mask", audit.duplicate_route_mask)
            .UInt("transport_route_index_mismatch_mask",
                  audit.transport_route_index_mismatch_mask)
            .Raw("route_to_participant",
                 OrdinalArrayJson(audit.route_to_participant,
                                  static_cast<unsigned>(
                                      audit.inspected_count)))
            .Raw("route_transport_indices",
                 OrdinalArrayJson(audit.route_transport_indices,
                                  static_cast<unsigned>(
                                      audit.inspected_count)))
            .Bool("entries_readable", audit.entries_readable)
            .Bool("audit_truncated", audit.truncated)
            .Bool("participant_identity_unique",
                  audit.participant_identity_unique)
            .Bool("transport_route_indices_match_slots",
                  audit.transport_route_indices_match_slots)
            .Bool("route_complete", audit.route_complete)
            .UInt("route_capacity",
                  kGameplayReplicationReceiveRouteAuditCapacity)
            .UInt("participant_capacity",
                  kReplicationParticipantCapacity)
            .UInt("vector_stride", sizeof(SharedProperty))
            .UInt("vector_offset",
                  kGameplayReplicationReceivePumpVectorOffset)
            .UInt("count_offset",
                  kGameplayReplicationReceivePumpCountOffset)
            .UInt("route_user_control_offset",
                  kGameplayReplicationReceiveRouteUserControlOffset)
            .UInt("shared_control_object_offset",
                  kSharedPropertyControlObjectOffset)
            .UInt("user_transport_route_index_offset",
                  kUserTransportRouteIndexOffset)
            .UInt("route_register_rva",
                  kGameplayReplicationReceiveRouteRegisterRva)
            .UInt("route_index_read_rva",
                  kGameplayReplicationReceiveRouteIndexReadRva)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("route_vector_dynamic", true)
            .Bool("payload_captured", false)
            .Bool("endpoint_identity_captured", false)
            .Bool("steam_id_logged", false)
            .Bool("pointer_logged", false));
}

struct ReplicationReceiveRouteLifecycleSnapshot {
    uint64_t route_count = 0;
    uint64_t vector_capacity = 0;
    bool manager_readable = false;
    bool lock_acquired = false;
    bool vector_shape_valid = false;
    bool entries_pointer_present = false;
    bool route_in_range = false;
    bool slot_readable = false;
    bool slot_present = false;
    bool slot_route_object_readable = false;
    bool slot_user_control_readable = false;
    bool slot_user_resolved = false;
    bool slot_matches_user = false;
};

ReplicationReceiveRouteLifecycleSnapshot
SnapshotReplicationReceiveRouteLifecycle(void* manager, void* user,
                                         int32_t route_index) {
    ReplicationReceiveRouteLifecycleSnapshot snapshot;
    if (!manager || !IsReadableMemoryRange(
            manager, kGameplayReplicationReceivePumpCountOffset +
                         sizeof(uint64_t))) {
        return snapshot;
    }
    snapshot.manager_readable = true;
    auto* const object = static_cast<uint8_t*>(manager);
    auto* const lock = reinterpret_cast<CRITICAL_SECTION*>(
        object + kGameplayReplicationReceivePumpLockOffset);
    if (!TryEnterCriticalSection(lock)) return snapshot;
    snapshot.lock_acquired = true;
    std::memcpy(&snapshot.vector_capacity,
                object + kGameplayReplicationReceivePumpCapacityOffset,
                sizeof(snapshot.vector_capacity));
    std::memcpy(&snapshot.route_count,
                object + kGameplayReplicationReceivePumpCountOffset,
                sizeof(snapshot.route_count));
    SharedProperty* entries = nullptr;
    std::memcpy(&entries,
                object + kGameplayReplicationReceivePumpVectorOffset,
                sizeof(entries));
    snapshot.entries_pointer_present = entries != nullptr;
    snapshot.vector_shape_valid =
        snapshot.vector_capacity >= snapshot.route_count &&
        snapshot.route_count <=
            kGameplayReplicationReceiveRouteAuditCapacity;
    snapshot.route_in_range = route_index >= 0 &&
        static_cast<uint64_t>(route_index) < snapshot.route_count &&
        static_cast<uint64_t>(route_index) <
            kGameplayReplicationReceiveRouteAuditCapacity;
    if (snapshot.route_in_range && entries) {
        const uintptr_t entries_address =
            reinterpret_cast<uintptr_t>(entries);
        const uintptr_t offset = static_cast<uintptr_t>(route_index) *
            sizeof(SharedProperty);
        if (entries_address <=
            std::numeric_limits<uintptr_t>::max() - offset) {
            const auto* const slot = reinterpret_cast<const SharedProperty*>(
                entries_address + offset);
            snapshot.slot_readable = IsReadableMemoryRange(
                slot, sizeof(SharedProperty));
            if (snapshot.slot_readable) {
                SharedProperty observed{};
                std::memcpy(&observed, slot, sizeof(observed));
                snapshot.slot_present =
                    observed.control != nullptr || observed.object != nullptr;
                const ReplicationReceiveRouteOwnerResolution resolution =
                    ResolveReplicationReceiveRouteOwner(observed.object);
                snapshot.slot_route_object_readable =
                    resolution.route_object_readable;
                snapshot.slot_user_control_readable =
                    resolution.user_control_readable;
                snapshot.slot_user_resolved =
                    resolution.runtime_user;
                snapshot.slot_matches_user =
                    user != nullptr && resolution.user == user;
            }
        }
    }
    LeaveCriticalSection(lock);
    return snapshot;
}

bool __fastcall GameplayReplicationReceiveRouteLifecycleHook(
    void* manager, const SharedProperty* handle, bool registering) {
#if defined(__clang__) || defined(__GNUC__)
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(
        __builtin_return_address(0));
#else
    const uintptr_t return_address = 0;
#endif
    const uintptr_t caller_rva = ModuleRvaForAddress(return_address);
    const uintptr_t expected_caller_rva = registering
        ? kGameplayReplicationReceiveRouteRegisterReturnRva
        : kGameplayReplicationReceiveRouteUnregisterReturnRva;
    const bool expected_caller = caller_rva == expected_caller_rva;
    const bool handle_readable = handle &&
        IsReadableMemoryRange(handle, sizeof(SharedProperty));
    void* user = nullptr;
    if (handle_readable) {
        std::memcpy(&user, &handle->object, sizeof(user));
    }
    const bool user_readable = user && IsReadableMemoryRange(
        user, kUserLocalControllerIndexOffset + sizeof(int32_t));
    const bool runtime_user = user_readable && IsRuntimeUserImpl(user);
    int32_t route_index = -1;
    int32_t local_controller_index = -1;
    bool route_eligible = false;
    if (runtime_user) {
        std::memcpy(&route_index,
                    static_cast<const uint8_t*>(user) +
                        kUserTransportRouteIndexOffset,
                    sizeof(route_index));
        std::memcpy(&local_controller_index,
                    static_cast<const uint8_t*>(user) +
                        kUserLocalControllerIndexOffset,
                    sizeof(local_controller_index));
        uint8_t eligible = 0;
        std::memcpy(&eligible,
                    static_cast<const uint8_t*>(user) +
                        kUserReceiveRouteEligibleOffset,
                    sizeof(eligible));
        route_eligible = eligible != 0;
    }
    const int registered_order = RegisteredUserOrdinal(user);
    const int participant_index = MissionParticipantIndexForUser(user);
    void* const allocator_owner =
        FindTransportRouteAllocatorOwner(user);
    const bool allocator_owner_observed = allocator_owner != nullptr;
    const bool allocator_owner_matches_receive_manager =
        allocator_owner_observed && allocator_owner == manager;
    const ReplicationReceiveRouteLifecycleSnapshot before =
        SnapshotReplicationReceiveRouteLifecycle(
            manager, user, route_index);
    const uint64_t call = registering
        ? g_replication_receive_route_register_calls.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_replication_receive_route_unregister_calls.fetch_add(
              1, std::memory_order_acq_rel) + 1;
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players",
        registering ? "replication_receive_route_register"
                    : "replication_receive_route_unregister",
        "before_original", call,
        static_cast<uint64_t>(static_cast<int64_t>(route_index)));
    GameplayReplicationReceiveRouteFn original = registering
        ? g_gameplay_replication_receive_route_register
        : g_gameplay_replication_receive_route_unregister;
    const bool native_result = original
        ? original(manager, handle) : false;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned",
                            native_result ? 1 : 0, call);
    const ReplicationReceiveRouteLifecycleSnapshot after =
        SnapshotReplicationReceiveRouteLifecycle(
            manager, user, route_index);
    // Static analysis proves that eligible users with lane zero use the
    // dynamic receive vector. Nonzero local lanes take a separate native
    // branch, so absence from this vector is not an anomaly for them.
    const bool vector_slot_expected = runtime_user && route_eligible &&
        local_controller_index == 0 && route_index >= 0;
    const bool slot_transition_valid = !vector_slot_expected ||
        (registering
             ? after.slot_matches_user
             : before.slot_matches_user && !after.slot_present);
    const bool anomaly = !expected_caller || !handle_readable ||
        !runtime_user || !native_result ||
        (after.lock_acquired && !after.vector_shape_valid) ||
        !slot_transition_valid;
    const uint64_t anomaly_count = anomaly
        ? g_replication_receive_route_lifecycle_anomalies.fetch_add(
              1, std::memory_order_acq_rel) + 1
        : g_replication_receive_route_lifecycle_anomalies.load(
              std::memory_order_acquire);
    EDF5_CAPTURE_EVENT(
        anomaly ? capture::Level::Warning : capture::Level::Info,
        "more_players", "replication_receive_route_lifecycle",
        capture::Fields()
            .UInt("call", call)
            .String("action", registering ? "register" : "unregister")
            .UInt("caller_rva", caller_rva)
            .Bool("expected_caller", expected_caller)
            .Bool("handle_readable", handle_readable)
            .Bool("user_present", user != nullptr)
            .Bool("runtime_user", runtime_user)
            .Int("registered_order", registered_order)
            .Int("participant_index", participant_index)
            .Bool("allocator_owner_observed", allocator_owner_observed)
            .Bool("allocator_owner_matches_receive_manager",
                  allocator_owner_matches_receive_manager)
            .Int("transport_route_index", route_index)
            .Int("local_controller_index", local_controller_index)
            .Bool("route_eligible", route_eligible)
            .Bool("vector_slot_expected", vector_slot_expected)
            .Bool("native_result", native_result)
            .UInt("route_count_before", before.route_count)
            .UInt("route_count_after", after.route_count)
            .UInt("vector_capacity_before", before.vector_capacity)
            .UInt("vector_capacity_after", after.vector_capacity)
            .Bool("manager_readable_before", before.manager_readable)
            .Bool("manager_readable_after", after.manager_readable)
            .Bool("lock_acquired_before", before.lock_acquired)
            .Bool("lock_acquired_after", after.lock_acquired)
            .Bool("vector_shape_valid_before", before.vector_shape_valid)
            .Bool("vector_shape_valid_after", after.vector_shape_valid)
            .Bool("route_in_range_before", before.route_in_range)
            .Bool("route_in_range_after", after.route_in_range)
            .Bool("slot_readable_before", before.slot_readable)
            .Bool("slot_readable_after", after.slot_readable)
            .Bool("slot_present_before", before.slot_present)
            .Bool("slot_present_after", after.slot_present)
            .Bool("slot_route_object_readable_before",
                  before.slot_route_object_readable)
            .Bool("slot_route_object_readable_after",
                  after.slot_route_object_readable)
            .Bool("slot_user_control_readable_before",
                  before.slot_user_control_readable)
            .Bool("slot_user_control_readable_after",
                  after.slot_user_control_readable)
            .Bool("slot_user_resolved_before",
                  before.slot_user_resolved)
            .Bool("slot_user_resolved_after",
                  after.slot_user_resolved)
            .Bool("slot_matches_user_before", before.slot_matches_user)
            .Bool("slot_matches_user_after", after.slot_matches_user)
            .Bool("slot_transition_valid", slot_transition_valid)
            .Bool("anomaly", anomaly)
            .UInt("anomaly_count", anomaly_count)
            .UInt("mission_generation",
                  g_mission_generation.load(std::memory_order_acquire))
            .Bool("payload_logged", false)
            .Bool("endpoint_identity_captured", false)
            .Bool("steam_id_logged", false)
            .Bool("pointer_logged", false));
    InspectAndRecordGameplayReplicationReceiveRoutes(manager);
    return native_result;
}

bool __fastcall GameplayReplicationReceiveRouteRegisterHook(
    void* manager, const SharedProperty* handle) {
    return GameplayReplicationReceiveRouteLifecycleHook(
        manager, handle, true);
}

bool __fastcall GameplayReplicationReceiveRouteUnregisterHook(
    void* manager, const SharedProperty* handle) {
    return GameplayReplicationReceiveRouteLifecycleHook(
        manager, handle, false);
}

bool __fastcall GameplayReplicationReceivePumpHook(
    void* self, uint32_t mode, void* context) {
    const bool result = g_gameplay_replication_receive_pump
        ? g_gameplay_replication_receive_pump(self, mode, context)
        : false;
    InspectAndRecordGameplayReplicationReceiveRoutes(self);
    return result;
}

void __fastcall GameplayReplicationReceiveParserHook(
    void* receive_state, void* handler_vector) {
    void* const previous_user = g_replication_incoming_user;
    void* const candidate_user =
        ResolveReplicationReceiveParserUser(receive_state);
    g_replication_incoming_user = candidate_user;
    if (g_gameplay_replication_receive_parser) {
        g_gameplay_replication_receive_parser(
            receive_state, handler_vector);
    }
    g_replication_incoming_user = previous_user;
}

void __fastcall GameplayMessageEnqueueHook(
    void* builder, const void* message, uint64_t bytes,
    const SharedProperty* context_handle) {
#if defined(__clang__) || defined(__GNUC__)
    const uint64_t producer_rva = ProcessImageRva(
        __builtin_return_address(0));
#else
    const uint64_t producer_rva = 0;
#endif
    uint32_t header = 0;
    const bool header_available = message && bytes >= sizeof(header);
    if (header_available) {
        std::memcpy(&header, message, sizeof(header));
    }
    const uint32_t message_code = header & 0x001fffffU;
    const uint32_t message_family = header & 0x0000ff00U;
    const uint32_t message_flags = (header >> 16) & 0x1fU;
    const uint64_t declared_bytes = static_cast<uint64_t>(header >> 21) + 4;
    const bool header_length_matches = header_available &&
        declared_bytes == bytes;
    // Family 0x1100 is a variable-size container. Its first embedded header
    // may declare only the first item, so a larger total is expected rather
    // than evidence of malformed traffic.
    const bool known_multipart_container = header_available &&
        message_family == 0x1100 && declared_bytes <= bytes;
    const bool context_handle_present = context_handle &&
        (context_handle->control || context_handle->object);
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "game_message_enqueue", "before_original",
        producer_rva, bytes);
    EDF5_CAPTURE_RECORD_GAME_MESSAGE_ROUTE(
        true, message_code, message_family, message_flags,
        context_handle_present, static_cast<size_t>(bytes), producer_rva,
        header_available,
        header_length_matches, known_multipart_container);
    if (g_gameplay_message_enqueue) {
        g_gameplay_message_enqueue(builder, message, bytes, context_handle);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", message_code,
                            context_handle_present ? 1 : 0);
}

uintptr_t __fastcall MissionScriptMessageDispatchHook(
    void* self, void* context, void* payload_cursor, int32_t mode,
    uint32_t message_code) {
    // The dispatcher has already decoded its outer framing. Retain only the
    // logical message selector/mode and context presence; payload size, bytes,
    // cursor address and endpoint identity are deliberately not captured.
    RecordReplicationParticipantMessage(
        false, message_code, g_replication_incoming_user);
    EDF5_CAPTURE_RECORD_GAME_MESSAGE_ROUTE(
        false, message_code, message_code & 0x0000ff00U,
        static_cast<uint32_t>(mode), context != nullptr, 0,
        kMissionScriptMessageDispatchRva, true, true, false, false);
    return g_mission_script_message_dispatch
        ? g_mission_script_message_dispatch(
              self, context, payload_cursor, mode, message_code)
        : 0;
}

bool __fastcall GameplayP2PSendHook(void* self, uint64_t recipient,
                                    const void* data, uint64_t bytes) {
#if defined(__clang__) || defined(__GNUC__)
    const uint64_t producer_rva = ProcessImageRva(
        __builtin_return_address(0));
#else
    const uint64_t producer_rva = 0;
#endif
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "game_packet_send", "before_original",
        producer_rva, bytes);
    EDF5_CAPTURE_RECORD_GAME_PACKET_ROUTE(true, 0, static_cast<size_t>(bytes),
                                   producer_rva, 0, 0);
    const bool result = g_gameplay_p2p_send
        ? g_gameplay_p2p_send(self, recipient, data, bytes) : false;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", result ? 1 : 0, bytes);
    return result;
}

struct ReceiveRoute {
    uint64_t handler_rva = 0;
    uint64_t vtable_rva = 0;
};

size_t InspectGameplayReceiveRoutes(void* self,
                                    std::array<ReceiveRoute, 32>& routes,
                                    bool& inspected) {
    inspected = false;
    if (!self || !g_module_base) return 0;
    auto* object = static_cast<uint8_t*>(self);
    auto* lock = reinterpret_cast<CRITICAL_SECTION*>(
        object + kGameplayP2PDispatchLockOffset);
    // Telemetry must not introduce a new wait into the game's receive path.
    // A contested list is simply sampled on a later packet.
    if (!TryEnterCriticalSection(lock)) return 0;
    inspected = true;
    size_t count = 0;
    void* sentinel = *reinterpret_cast<void**>(
        object + kGameplayP2PDispatchListOffset);
    void* node = sentinel ? *reinterpret_cast<void**>(sentinel) : nullptr;
    for (unsigned visited = 0;
         node && node != sentinel && visited < 64;
         ++visited) {
        void* holder = *reinterpret_cast<void**>(
            static_cast<uint8_t*>(node) +
            kGameplayP2PDispatchCallbackOffset);
        if (holder && count < routes.size()) {
            auto** vtable = *reinterpret_cast<void***>(holder);
            void* handler = nullptr;
            if (vtable == reinterpret_cast<void**>(
                              g_module_base +
                              kGameplayP2PDispatchSpecialVtableRva)) {
                handler = reinterpret_cast<void*>(
                    g_module_base + kGameplayP2PDispatchSpecialTargetRva);
            } else if (vtable) {
                handler = vtable[1];
            }
            routes[count++] = {
                ProcessImageRva(handler), ProcessImageRva(vtable)};
        }
        node = *reinterpret_cast<void**>(node);
    }
    LeaveCriticalSection(lock);
    return count;
}

void __fastcall GameplayP2PDispatchHook(void* self, void* packet,
                                        void* source, uint64_t bytes,
                                        int32_t channel) {
#if defined(__clang__) || defined(__GNUC__)
    const uint64_t dispatcher_caller_rva = ProcessImageRva(
        __builtin_return_address(0));
#else
    const uint64_t dispatcher_caller_rva = 0;
#endif
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "game_packet_dispatch", "inspect_callbacks",
        dispatcher_caller_rva, bytes);
    std::array<ReceiveRoute, 32> routes{};
    bool inspected = false;
    const size_t route_count = InspectGameplayReceiveRoutes(
        self, routes, inspected);
    for (size_t index = 0; index < route_count; ++index) {
        EDF5_CAPTURE_RECORD_GAME_PACKET_ROUTE(
            false, channel, static_cast<size_t>(bytes), 0,
            routes[index].handler_rva, routes[index].vtable_rva);
    }
    if (inspected && route_count == 0) {
        EDF5_CAPTURE_RECORD_GAME_PACKET_ROUTE(false, channel,
                                       static_cast<size_t>(bytes), 0, 0, 0);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "call_original", route_count,
                            static_cast<uint64_t>(
                                static_cast<uint32_t>(channel)));
    if (g_gameplay_p2p_dispatch) {
        g_gameplay_p2p_dispatch(self, packet, source, bytes, channel);
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "original_returned", route_count, bytes);
}

bool TryBotIndex(uint64_t peer, unsigned& index);
bool AppliesToLobby(uint64_t lobby);

bool MarkSyntheticUserReady(void* object, bool test_mode, unsigned& index,
                            uint64_t& user_id, bool& transport_ready,
                            bool& cm_ready, bool& ds_ready) {
    if (!object) return false;
    auto** vtable = *reinterpret_cast<void***>(object);
    if (!vtable || (!test_mode && vtable != g_runtime_user_vtable) ||
        !vtable[10]) {
        return false;
    }
    const auto get_user_id = reinterpret_cast<UserIdGetterFn>(vtable[10]);
    user_id = get_user_id(object);
    const unsigned requested = g_bot_count.load(std::memory_order_acquire);
    if (!TryBotIndex(user_id, index) || index >= requested) return false;
    WriteReadyFlag(object, test_mode);
    transport_ready = ReadReadyFlag(object, test_mode);
    cm_ready = SetSyntheticUserProperty(object, "cm", "c1", test_mode);
    ds_ready = SetSyntheticUserProperty(object, "ds", "ds", test_mode);
    return true;
}

struct MissionGroupMirrorStats {
    uint64_t source_user = 0;
    unsigned source_candidates = 0;
    unsigned requested = 0;
    uint32_t expected_mask = 0;
    uint32_t matched_mask = 0;
    uint32_t l1_ready_mask = 0;
    uint32_t l2_ready_mask = 0;
    size_t l1_length = 0;
    size_t l2_length = 0;
    bool source_found = false;
};

bool IsMissionGroupList(const std::string& value) {
    if (value.empty() || value.size() > 4096 ||
        value.find(':') == std::string::npos) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || ch == ':' || ch == ',' || ch == '-';
    });
}

uint64_t HashMissionGroup(const std::string& l1, const std::string& l2,
                          const MissionGroupMirrorStats& stats) {
    uint64_t hash = 1469598103934665603ULL;
    const auto mix = [&hash](uint8_t byte) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    };
    for (unsigned shift = 0; shift < 64; shift += 8) {
        mix(static_cast<uint8_t>(stats.source_user >> shift));
    }
    for (char ch : l1) mix(static_cast<uint8_t>(ch));
    mix(0xff);
    for (char ch : l2) mix(static_cast<uint8_t>(ch));
    for (uint32_t mask : {stats.matched_mask, stats.l1_ready_mask,
                          stats.l2_ready_mask}) {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            mix(static_cast<uint8_t>(mask >> shift));
        }
    }
    return hash;
}

bool MirrorMissionGroups(uint64_t lobby, bool test_mode,
                         MissionGroupMirrorStats& stats) {
    stats = {};
    stats.requested = g_bot_count.load(std::memory_order_acquire);
    if (!stats.requested || stats.requested >= 32 || !AppliesToLobby(lobby)) {
        return false;
    }
    stats.expected_mask = (uint32_t{1} << stats.requested) - 1;

    std::string source_l1;
    std::string source_l2;
    AcquireSRWLockShared(&g_ready_user_lock);
    for (void* object : g_ready_users) {
        if (!object) continue;
        auto** vtable = *reinterpret_cast<void***>(object);
        if (!vtable || (!test_mode && vtable != g_runtime_user_vtable) ||
            !vtable[10]) {
            continue;
        }
        const auto get_user_id = reinterpret_cast<UserIdGetterFn>(vtable[10]);
        const uint64_t user_id = get_user_id(object);
        unsigned synthetic_index = 0;
        if (TryBotIndex(user_id, synthetic_index)) continue;
        ++stats.source_candidates;

        std::string candidate_l2;
        if (!ReadUserProperty(object, "l2", candidate_l2, test_mode) ||
            !IsMissionGroupList(candidate_l2)) {
            continue;
        }
        std::string candidate_l1;
        if (!ReadUserProperty(object, "l1", candidate_l1, test_mode) ||
            !IsMissionGroupList(candidate_l1)) {
            candidate_l1 = candidate_l2;
        }
        stats.source_user = user_id;
        stats.source_found = true;
        source_l1 = std::move(candidate_l1);
        source_l2 = std::move(candidate_l2);
        break;
    }

    if (stats.source_found) {
        for (void* object : g_ready_users) {
            if (!object) continue;
            auto** vtable = *reinterpret_cast<void***>(object);
            if (!vtable || (!test_mode && vtable != g_runtime_user_vtable) ||
                !vtable[10]) {
                continue;
            }
            const auto get_user_id = reinterpret_cast<UserIdGetterFn>(vtable[10]);
            const uint64_t user_id = get_user_id(object);
            unsigned index = 0;
            if (!TryBotIndex(user_id, index) || index >= stats.requested) continue;
            const uint32_t bit = uint32_t{1} << index;
            stats.matched_mask |= bit;

            std::string current;
            const bool l1_ready =
                (ReadUserProperty(object, "l1", current, test_mode) &&
                 current == source_l1) ||
                SetSyntheticUserProperty(object, "l1", source_l1.c_str(),
                                         test_mode);
            current.clear();
            const bool l2_ready =
                (ReadUserProperty(object, "l2", current, test_mode) &&
                 current == source_l2) ||
                SetSyntheticUserProperty(object, "l2", source_l2.c_str(),
                                         test_mode);
            if (l1_ready) stats.l1_ready_mask |= bit;
            if (l2_ready) stats.l2_ready_mask |= bit;
        }
    }
    ReleaseSRWLockShared(&g_ready_user_lock);

    stats.l1_length = source_l1.size();
    stats.l2_length = source_l2.size();
    const bool success = stats.source_found &&
                         stats.matched_mask == stats.expected_mask &&
                         stats.l1_ready_mask == stats.expected_mask &&
                         stats.l2_ready_mask == stats.expected_mask;
    if (success) {
        const uint32_t ready = stats.l1_ready_mask & stats.l2_ready_mask;
        g_diagnostic_mission_group_mask.store(ready,
                                              std::memory_order_release);
        EDF5_CRASH_BREADCRUMB("more_players", "mission_groups",
                                  "synchronized", ready,
                                  stats.expected_mask);
        PublishDiagnosticState(nullptr, true);
    }
    if (stats.source_found) {
        const uint64_t signature = HashMissionGroup(source_l1, source_l2, stats);
        const bool changed = g_last_mission_group_log_signature.exchange(
            signature, std::memory_order_acq_rel) != signature;
        if (changed) {
            EDF5_CAPTURE_EVENT("more_players", "bot_mission_groups_mirrored",
                           capture::Fields().UInt("lobby_steam_id", lobby)
                               .UInt("source_user_steam_id", stats.source_user)
                               .UInt("source_candidates", stats.source_candidates)
                               .UInt("synthetic_members", stats.requested)
                               .UInt("expected_mask", stats.expected_mask)
                               .UInt("matched_mask", stats.matched_mask)
                               .UInt("l1_ready_mask", stats.l1_ready_mask)
                               .UInt("l2_ready_mask", stats.l2_ready_mask)
                               .UInt("l1_bytes", stats.l1_length)
                               .UInt("l2_bytes", stats.l2_length)
                               .String("trigger", "first_gameplay_channel_send")
                               .String("execution_thread", "HUiRoom::Update")
                               .Bool("success", success));
        }
    }
    return success;
}

void ApplyPendingMissionGroups() {
    if (!g_mission_groups_pending.load(std::memory_order_acquire) ||
        g_mission_groups_synchronized.load(std::memory_order_acquire)) {
        return;
    }
    const uint64_t lobby = g_owned_lobby.load(std::memory_order_acquire);
    MissionGroupMirrorStats stats;
    const bool test_mode =
        g_ready_user_test_mode.load(std::memory_order_acquire);
    if (!MirrorMissionGroups(lobby, test_mode, stats)) return;
    g_mission_groups_synchronized.store(true, std::memory_order_release);
    g_mission_groups_pending.store(false, std::memory_order_release);
}

void* __fastcall UserConstructorHook(void* self, void* context, void* source) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "user_constructor", "call_original",
        reinterpret_cast<uintptr_t>(self),
        reinterpret_cast<uintptr_t>(source));
    void* user = g_user_constructor(self, context, source);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "register", reinterpret_cast<uintptr_t>(user), 0);
    RegisterReadyUser(user);
    RecordTransportRouteAllocatorOwner(user, context);
    const bool user_readable = user && IsReadableMemoryRange(
        user, kUserLocalControllerIndexOffset + sizeof(int32_t));
    const bool runtime_user = user_readable && IsRuntimeUserImpl(user);
    int32_t transport_route_index = -1;
    int32_t local_controller_index = -1;
    bool receive_route_eligible = false;
    if (runtime_user) {
        std::memcpy(
            &transport_route_index,
            static_cast<const uint8_t*>(user) +
                kUserTransportRouteIndexOffset,
            sizeof(transport_route_index));
        std::memcpy(
            &local_controller_index,
            static_cast<const uint8_t*>(user) +
                kUserLocalControllerIndexOffset,
            sizeof(local_controller_index));
        uint8_t eligible = 0;
        std::memcpy(
            &eligible,
            static_cast<const uint8_t*>(user) +
                kUserReceiveRouteEligibleOffset,
            sizeof(eligible));
        receive_route_eligible = eligible != 0;
    }
    const int registered_order = RegisteredUserOrdinal(user);
    EDF5_CAPTURE_EVENT(
        "more_players", "user_transport_route_assignment",
        capture::Fields()
            .Int("registered_order", registered_order)
            .Bool("runtime_user", runtime_user)
            .Int("transport_route_index", transport_route_index)
            .Int("local_controller_index", local_controller_index)
            .Bool("receive_route_eligible", receive_route_eligible)
            .Bool("route_index_nonnegative", transport_route_index >= 0)
            .Bool("route_index_matches_registered_order",
                  transport_route_index == registered_order)
            .UInt("route_index_initializer_rva",
                  kUserTransportRouteIndexInitializerRva)
            .UInt("route_slot_allocator_rva",
                  kUserTransportRouteSlotAllocatorRva)
            .UInt("allocator_scan_stride", sizeof(void*))
            .UInt("receive_vector_stride", sizeof(SharedProperty))
            .Bool("allocator_owner_observed", context != nullptr)
            .Bool("allocator_owner_equals_receive_manager_proven", false)
            .Bool("endpoint_identity_captured", false)
            .Bool("steam_id_logged", false)
            .Bool("pointer_logged", false));
    unsigned index = 0;
    uint64_t user_id = 0;
    bool transport_ready = false;
    bool cm_ready = false;
    bool ds_ready = false;
    if (MarkSyntheticUserReady(user, false, index, user_id, transport_ready,
                               cm_ready, ds_ready)) {
        ResetMissionGroupSync();
        EDF5_CAPTURE_EVENT("more_players", "bot_ready_on_spawn",
                       capture::Fields().UInt("bot_steam_id", user_id)
                           .UInt("bot_number", index + 1)
                           .Bool("transport_ready", transport_ready)
                           .Bool("cm_ready", cm_ready)
                           .Bool("ds_ready", ds_ready)
                           .UInt("transport_flag_offset",
                                 kUserReadyFlagOffset)
                           .UInt("property_object_offset",
                                 kUserPropertyObjectOffset));
    }
    return user;
}

void* __fastcall UserDestructorHook(void* self, unsigned flags) {
    UnregisterMissionParticipantUser(self);
    UnregisterReadyUser(self);
    return g_user_destructor(self, flags);
}

bool AppliesToLobby(uint64_t lobby) {
    return Enabled() && lobby != 0 &&
           g_owned_lobby.load(std::memory_order_acquire) == lobby;
}

uint8_t* __fastcall PlayerInfoFromUserHook(
    uint8_t* destination, const SharedProperty* source) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "player_info_from_user", "call_original",
        reinterpret_cast<uintptr_t>(destination),
        reinterpret_cast<uintptr_t>(source ? source->object : nullptr));
    uint8_t* const result = g_player_info_from_user
        ? g_player_info_from_user(destination, source) : destination;
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "observe", reinterpret_cast<uintptr_t>(result),
                            reinterpret_cast<uintptr_t>(destination));
    RecordPlayerInfoObservation(
        source ? source->object : nullptr, destination);
    const bool return_matches_destination = result == destination;
    const unsigned mismatch_count = return_matches_destination
        ? g_player_info_return_mismatch_count.load(std::memory_order_acquire)
        : g_player_info_return_mismatch_count.fetch_add(
              1, std::memory_order_acq_rel) + 1;
    const bool first_contract_observation =
        !g_player_info_return_contract_logged.exchange(
            true, std::memory_order_acq_rel);
    if (first_contract_observation || !return_matches_destination) {
        EDF5_CAPTURE_EVENT(
            return_matches_destination ? capture::Level::Info
                                       : capture::Level::Error,
            "more_players", "player_info_return_contract",
            capture::Fields()
                .Bool("return_matches_destination",
                      return_matches_destination)
                .UInt("return_mismatch_count", mismatch_count)
                .UInt("converter_rva", kPlayerInfoFromUserRva)
                .UInt("native_return_rva", kPlayerInfoFromUserReturnRva)
                .Bool("destination_pointer_logged", false)
                .Bool("return_pointer_logged", false));
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "return_preserved",
                            return_matches_destination ? 1 : 0,
                            mismatch_count);
    return result;
}

int __fastcall PlayerInfoBuilderHook(void* context, PlayerInfoVector* players) {
    const unsigned requested_before =
        g_bot_count.load(std::memory_order_acquire);
    if (!requested_before) return g_player_info_builder(context, players);
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "player_info_builder", "call_original",
        requested_before, reinterpret_cast<uintptr_t>(players));
    const int result = g_player_info_builder(context, players);
    const uint64_t lobby = g_owned_lobby.load(std::memory_order_acquire);
    const unsigned requested = g_bot_count.load(std::memory_order_acquire);
    if (result != 0 || !requested || !AppliesToLobby(lobby)) return result;
    g_last_room_model_tick.store(GetTickCount64(), std::memory_order_release);

    LoadoutCloneStats stats;
    const int observed_actual =
        g_last_actual_member_count.load(std::memory_order_acquire);
    const unsigned actual_members = observed_actual > 0
        ? static_cast<unsigned>(observed_actual) : 0;
    const bool success = CloneHostLoadout(players, requested, actual_members,
                                          stats);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "clone_complete", stats.copied,
                            players ? players->size : 0);
    uint64_t signature = lobby ^ (static_cast<uint64_t>(requested) << 56) ^
                         (static_cast<uint64_t>(stats.recognized_mask) << 24) ^
                         (static_cast<uint64_t>(stats.copied) << 16) ^
                         static_cast<uint32_t>(stats.host_class);
    signature ^= static_cast<uint64_t>(
        static_cast<uint32_t>(stats.host_first_weapon)) << 32;
    const bool changed = g_last_loadout_log_signature.exchange(
        signature, std::memory_order_acq_rel) != signature;
    if (changed) {
        EDF5_CAPTURE_EVENT("more_players", "bot_loadout_clone",
                       capture::Fields().UInt("lobby_steam_id", lobby)
                           .UInt("synthetic_members", requested)
                           .UInt("player_info_count", players ? players->size : 0)
                           .UInt("actual_members", actual_members)
                           .UInt("recognized_bots", stats.recognized)
                           .UInt("recognized_mask", stats.recognized_mask)
                           .UInt("copied_bots", stats.copied)
                           .Int("host_class", stats.host_class)
                           .Int("host_first_weapon", stats.host_first_weapon)
                           .Int("host_position", stats.host_position)
                           .Bool("single_real_fallback",
                                 stats.used_single_real_fallback)
                           .Bool("success", success));
        // Ready can be cleared while the room rejects an entry whose class or
        // equipment is incomplete. Reapply it only after the first successful
        // loadout clone for this roster shape.
        if (success) TryReadyBots(lobby, false);
    }
    return result;
}

bool TryBotIndex(uint64_t peer, unsigned& index) {
    if (!Enabled() || !peer) return false;
    const unsigned possible = MaxPlayers() > 0 ? MaxPlayers() - 1 : 0;
    for (unsigned candidate = 0; candidate < possible; ++candidate) {
        if (BotSteamId(candidate) == peer) {
            index = candidate;
            return true;
        }
    }
    return false;
}

void QueueMembershipChangeLocked(uint64_t lobby, uint64_t user, uint32_t state) {
    if (g_membership_changes.size() >= 128) g_membership_changes.pop_front();
    g_membership_changes.push_back({lobby, user, state});
}

void ClearPeerTransportLocked(uint64_t peer) {
    g_packets.erase(
        std::remove_if(g_packets.begin(), g_packets.end(),
                       [peer](const SyntheticPacket& packet) {
                           return packet.peer == peer;
                       }),
        g_packets.end());
    g_auth_validations.erase(
        std::remove(g_auth_validations.begin(), g_auth_validations.end(), peer),
        g_auth_validations.end());
}

void ClearSyntheticState(bool reset_template) {
    AcquireSRWLockExclusive(&g_state_lock);
    g_local_mission_harness_target.store(0, std::memory_order_release);
    g_local_mission_harness_result_sync_logged_mask.store(
        0, std::memory_order_release);
    ResetLocalMissionHarnessMatchingTelemetry();
    g_bot_count.store(0, std::memory_order_release);
    g_gameplay_contact_mask.store(0, std::memory_order_release);
    g_all_gameplay_contact_reported.store(false, std::memory_order_release);
    g_room_full_reported.store(false, std::memory_order_release);
    g_last_room_model_tick.store(0, std::memory_order_release);
    g_single_real_host_position.store(-1, std::memory_order_release);
    g_pending_wheel_detents.store(0, std::memory_order_release);
    g_pending_ready_lobby.store(0, std::memory_order_release);
    g_pending_ready_feedback.store(false, std::memory_order_release);
    g_diagnostic_ready_mask.store(0, std::memory_order_release);
    g_diagnostic_mission_group_mask.store(0, std::memory_order_release);
    for (auto& peer : g_diagnostic_real_gameplay_peer_ids) {
        peer.store(0, std::memory_order_release);
    }
    g_diagnostic_real_gameplay_peers.store(0, std::memory_order_release);
    g_players_group_layout.store(0, std::memory_order_release);
    g_players_group_capture_tick.store(0, std::memory_order_release);
    ResetMissionGroupSync();
    g_packets.clear();
    g_membership_changes.clear();
    g_auth_validations.clear();
    if (reset_template) g_member_template = kFallbackMemberData;
    ReleaseSRWLockExclusive(&g_state_lock);
}

void DisarmLocalMissionHarness(const char* reason, uint64_t lobby) {
    const unsigned previous = g_local_mission_harness_target.exchange(
        0, std::memory_order_acq_rel);
    if (!previous) return;
    g_local_mission_harness_result_sync_logged_mask.store(
        0, std::memory_order_release);
    ResetLocalMissionHarnessMatchingTelemetry();
    ResetMissionGroupSync();
    EDF5_CAPTURE_EVENT(
        capture::Level::Warning, "more_players",
        "local_mission_harness_disarmed",
        capture::Fields()
            .String("reason", reason ? reason : "unknown")
            .UInt("lobby_steam_id", lobby)
            .UInt("previous_dummy_target", previous)
            .UInt("remaining_synthetic_members",
                  g_bot_count.load(std::memory_order_acquire))
            .Int("actual_members",
                 g_last_actual_member_count.load(std::memory_order_acquire)));
}

void RejectHotkey(const char* reason, uint64_t lobby, unsigned hotkey,
                  bool user_feedback) {
    EDF5_CAPTURE_EVENT("more_players", "hotkey_rejected",
                   capture::Fields().String("reason", reason)
                       .UInt("lobby_steam_id", lobby).UInt("hotkey_vk", hotkey)
                       .Int("actual_members",
                            g_last_actual_member_count.load(std::memory_order_acquire))
                       .UInt("synthetic_members",
                             g_bot_count.load(std::memory_order_acquire))
                       .UInt("max_players", MaxPlayers()));
    if (user_feedback) MessageBeep(MB_ICONWARNING);
}

bool TryAddBot(uint64_t lobby, bool user_feedback,
               bool local_harness_action = false) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "add_bot", "validate", lobby,
        g_bot_count.load(std::memory_order_acquire));
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby,
                     capture::GetConfig().bot_hotkey_vk, user_feedback);
        return false;
    }
    if (!local_harness_action) {
        DisarmLocalMissionHarness("manual filler add", lobby);
    }

    const int observed = g_last_actual_member_count.load(std::memory_order_acquire);
    const unsigned actual = observed >= 0 ? static_cast<unsigned>(observed) : 1U;
    unsigned index = 0;
    uint64_t user = 0;
    AcquireSRWLockExclusive(&g_state_lock);
    index = g_bot_count.load(std::memory_order_relaxed);
    if (actual >= MaxPlayers() || index >= MaxPlayers() - 1 ||
        index >= MaxPlayers() - actual) {
        ReleaseSRWLockExclusive(&g_state_lock);
        RejectHotkey("lobby has no free slot", lobby,
                     capture::GetConfig().bot_hotkey_vk, user_feedback);
        return false;
    }
    user = BotSteamId(index);
    g_bot_count.store(index + 1, std::memory_order_release);
    ResetMissionGroupSync();
    g_all_gameplay_contact_reported.store(false, std::memory_order_release);
    g_room_full_reported.store(false, std::memory_order_release);
    QueueMembershipChangeLocked(lobby, user, kMemberEntered);
    ReleaseSRWLockExclusive(&g_state_lock);

    EDF5_CAPTURE_EVENT("more_players", "bot_added",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("bot_steam_id", user).UInt("bot_number", index + 1)
                       .UInt("synthetic_members", index + 1)
                       .UInt("max_players", MaxPlayers()));
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "published", user, index + 1);
    PublishDiagnosticState(nullptr, true);
    if (user_feedback) MessageBeep(MB_OK);
    return true;
}

bool TryOpenInviteDialog(uint64_t lobby, bool user_feedback) {
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby,
                     capture::GetConfig().invite_hotkey_vk, user_feedback);
        return false;
    }
    const bool success = steam_capture::OpenLobbyInviteDialog(lobby);
    EDF5_CAPTURE_EVENT(success ? capture::Level::Info : capture::Level::Warning,
                   "more_players", "invite_dialog_requested",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("hotkey_vk",
                             capture::GetConfig().invite_hotkey_vk)
                       .UInt("max_players", MaxPlayers())
                       .Bool("success", success));
    if (user_feedback) MessageBeep(success ? MB_OK : MB_ICONWARNING);
    return success;
}

bool TryRemoveBot(uint64_t lobby, bool user_feedback,
                  bool local_harness_action = false) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "remove_bot", "validate", lobby,
        g_bot_count.load(std::memory_order_acquire));
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby,
                     capture::GetConfig().bot_remove_hotkey_vk, user_feedback);
        return false;
    }
    if (!local_harness_action) {
        DisarmLocalMissionHarness("manual filler remove", lobby);
    }

    unsigned previous = 0;
    uint64_t user = 0;
    AcquireSRWLockExclusive(&g_state_lock);
    previous = g_bot_count.load(std::memory_order_relaxed);
    if (!previous) {
        ReleaseSRWLockExclusive(&g_state_lock);
        RejectHotkey("no synthetic member to remove", lobby,
                     capture::GetConfig().bot_remove_hotkey_vk, user_feedback);
        return false;
    }
    const unsigned index = previous - 1;
    user = BotSteamId(index);
    g_bot_count.store(index, std::memory_order_release);
    ResetMissionGroupSync();
    g_gameplay_contact_mask.fetch_and(~(uint32_t{1} << index),
                                      std::memory_order_acq_rel);
    g_all_gameplay_contact_reported.store(false, std::memory_order_release);
    g_room_full_reported.store(false, std::memory_order_release);
    ClearPeerTransportLocked(user);
    QueueMembershipChangeLocked(lobby, user, kMemberLeft);
    ReleaseSRWLockExclusive(&g_state_lock);

    EDF5_CAPTURE_EVENT("more_players", "bot_removed",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("bot_steam_id", user).UInt("bot_number", previous)
                       .UInt("synthetic_members", previous - 1)
                       .UInt("max_players", MaxPlayers()));
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "published", user, previous - 1);
    PublishDiagnosticState(nullptr, true);
    if (user_feedback) MessageBeep(MB_ICONASTERISK);
    return true;
}

bool TryReadyBots(uint64_t lobby, bool user_feedback) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "ready_bots", "validate", lobby,
        g_bot_count.load(std::memory_order_acquire));
    const unsigned ready_hotkey = capture::GetConfig().bot_ready_hotkey_vk;
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby, ready_hotkey,
                     user_feedback);
        return false;
    }

    const unsigned requested = g_bot_count.load(std::memory_order_acquire);
    if (!requested) {
        RejectHotkey("no synthetic member to ready", lobby, ready_hotkey,
                     user_feedback);
        return false;
    }

    // A Ready request starts a fresh MissionStart synchronization cycle. The
    // first channel-0 send will arm l1/l2 mirroring after the host has built
    // its authoritative participant list.
    ResetMissionGroupSync();

    uint32_t matched_mask = 0;
    uint32_t transport_ready_mask = 0;
    uint32_t cm_ready_mask = 0;
    uint32_t ds_ready_mask = 0;
    unsigned user_writes = 0;
    const bool test_mode = g_ready_user_test_mode.load(std::memory_order_acquire);
    AcquireSRWLockShared(&g_ready_user_lock);
    for (void* object : g_ready_users) {
        unsigned index = 0;
        uint64_t user_id = 0;
        bool transport_ready = false;
        bool cm_ready = false;
        bool ds_ready = false;
        if (!MarkSyntheticUserReady(object, test_mode, index, user_id,
                                    transport_ready, cm_ready, ds_ready)) {
            continue;
        }
        const uint32_t bit = uint32_t{1} << index;
        matched_mask |= bit;
        ++user_writes;
        if (transport_ready) transport_ready_mask |= bit;
        if (cm_ready) cm_ready_mask |= bit;
        if (ds_ready) ds_ready_mask |= bit;
    }
    ReleaseSRWLockShared(&g_ready_user_lock);

    const uint32_t expected_mask = (uint32_t{1} << requested) - 1;
    const bool success = matched_mask == expected_mask &&
                         transport_ready_mask == expected_mask &&
                         cm_ready_mask == expected_mask &&
                         ds_ready_mask == expected_mask;
    g_diagnostic_ready_mask.store(transport_ready_mask & cm_ready_mask &
                                      ds_ready_mask,
                                  std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "bots_ready_requested",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("synthetic_members", requested)
                       .UInt("expected_mask", expected_mask)
                       .UInt("matched_mask", matched_mask)
                       .UInt("transport_ready_mask", transport_ready_mask)
                       .UInt("cm_ready_mask", cm_ready_mask)
                       .UInt("ds_ready_mask", ds_ready_mask)
                       .UInt("user_writes", user_writes)
                       .UInt("transport_flag_offset", kUserReadyFlagOffset)
                       .UInt("property_object_offset",
                             kUserPropertyObjectOffset)
                       .String("cm_value", "c1")
                       .String("ds_value", "ds")
                       .Bool("success", success));
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, success ? "ready" : "incomplete", matched_mask,
                            expected_mask);
    PublishDiagnosticState(success ? "ready" : nullptr, true);
    if (user_feedback) MessageBeep(success ? MB_OK : MB_ICONWARNING);
    return success;
}

bool RequestReadyBots(uint64_t lobby, bool user_feedback) {
    if (g_ready_user_test_mode.load(std::memory_order_acquire)) {
        return TryReadyBots(lobby, user_feedback);
    }
    const unsigned ready_hotkey = capture::GetConfig().bot_ready_hotkey_vk;
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby, ready_hotkey,
                     user_feedback);
        return false;
    }
    if (!g_bot_count.load(std::memory_order_acquire)) {
        RejectHotkey("no synthetic member to ready", lobby, ready_hotkey,
                     user_feedback);
        return false;
    }

    g_pending_ready_feedback.store(user_feedback, std::memory_order_release);
    g_pending_ready_lobby.store(lobby, std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "bots_ready_queued",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("synthetic_members",
                             g_bot_count.load(std::memory_order_acquire))
                       .String("execution_thread", "HUiRoom::Update")
                       .Bool("success", true));
    return true;
}

void ApplyPendingReadyBots() {
    const uint64_t lobby = g_pending_ready_lobby.exchange(
        0, std::memory_order_acq_rel);
    if (!lobby) return;
    const bool feedback = g_pending_ready_feedback.exchange(
        false, std::memory_order_acq_rel);
    TryReadyBots(lobby, feedback);
}

unsigned NextLocalMissionHarnessTarget(unsigned current) {
    if (current == 0) return kLocalMissionHarnessBaselineDummies;
    if (current == kLocalMissionHarnessBaselineDummies) {
        return kLocalMissionHarnessProbeDummies;
    }
    return 0;
}

bool TryCycleLocalMissionHarness(uint64_t lobby, bool user_feedback) {
    const auto& config = capture::GetConfig();
    const unsigned hotkey = config.local_mission_harness_hotkey_vk;
    if (!config.local_mission_harness_enabled) {
        RejectHotkey("local mission harness disabled", lobby, hotkey,
                     user_feedback);
        return false;
    }
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby, hotkey,
                     user_feedback);
        return false;
    }
    const bool test_mode =
        g_ready_user_test_mode.load(std::memory_order_acquire);
    if (!test_mode && !RoomRosterActive()) {
        RejectHotkey("room roster is not active", lobby, hotkey,
                     user_feedback);
        return false;
    }
    const int actual =
        g_last_actual_member_count.load(std::memory_order_acquire);
    if (actual != 1) {
        RejectHotkey("local harness requires exactly one real host", lobby,
                     hotkey, user_feedback);
        return false;
    }

    const unsigned previous_target =
        g_local_mission_harness_target.load(std::memory_order_acquire);
    const unsigned current_bots =
        g_bot_count.load(std::memory_order_acquire);
    if ((previous_target == 0 && current_bots != 0) ||
        (previous_target != 0 && current_bots != previous_target)) {
        RejectHotkey("local harness state differs from filler roster", lobby,
                     hotkey, user_feedback);
        return false;
    }
    const unsigned target = NextLocalMissionHarnessTarget(previous_target);
    if (target >= MaxPlayers()) {
        RejectHotkey("MaxPlayers is below requested harness size", lobby,
                     hotkey, user_feedback);
        return false;
    }

    bool adjusted = true;
    unsigned bots = current_bots;
    while (adjusted && bots < target) {
        adjusted = TryAddBot(lobby, false, true);
        if (adjusted) ++bots;
    }
    while (adjusted && bots > target) {
        adjusted = TryRemoveBot(lobby, false, true);
        if (adjusted) --bots;
    }
    if (!adjusted || bots != target) {
        DisarmLocalMissionHarness("dummy roster adjustment failed", lobby);
        RejectHotkey("local harness could not build dummy roster", lobby,
                     hotkey, user_feedback);
        return false;
    }

    g_local_mission_harness_target.store(target,
                                         std::memory_order_release);
    g_local_mission_harness_result_sync_logged_mask.store(
        0, std::memory_order_release);
    ResetLocalMissionHarnessMatchingTelemetry();
    ResetMissionGroupSync();
    const bool ready_queued = target == 0 ||
        RequestReadyBots(lobby, false);
    EDF5_CAPTURE_EVENT(
        ready_queued ? capture::Level::Info : capture::Level::Warning,
        "more_players", "local_mission_harness_target_changed",
        capture::Fields()
            .UInt("lobby_steam_id", lobby)
            .UInt("previous_dummy_target", previous_target)
            .UInt("dummy_target", target)
            .UInt("total_mission_participants", target + 1)
            .String("mode", target == 0 ? "off" :
                    (target == kLocalMissionHarnessBaselineDummies
                         ? "native_baseline" : "p4_capacity_probe"))
            .Bool("ready_queued", ready_queued)
            .Bool("loadout_copies_host", target != 0)
            .Bool("dummy_control_mode_remote", target != 0)
            .Bool("gameplay_ai_present", false)
            .Bool("real_steam_connections", false)
            .Bool("success", ready_queued));
    PublishDiagnosticState(target ? "local_harness" : "room", true);
    if (user_feedback) {
        MessageBeep(target ? (ready_queued ? MB_OK : MB_ICONWARNING)
                           : MB_ICONASTERISK);
    }
    return ready_queued;
}

bool TryScrollRoster(uint64_t lobby, int detents) {
    if (!AppliesToLobby(lobby)) {
        RejectHotkey("no locally-created lobby", lobby, 0, false);
        return false;
    }
    if (!g_bot_count.load(std::memory_order_acquire)) {
        RejectHotkey("no synthetic member to scroll", lobby, 0, false);
        return false;
    }
    if (!detents) return false;

    const bool test_mode = g_scroll_test_mode.load(std::memory_order_acquire);
    if (!test_mode) {
        const uint64_t last_tick =
            g_last_room_model_tick.load(std::memory_order_acquire);
        const uint64_t now = GetTickCount64();
        if (!last_tick || now - last_tick > 2000) {
            RejectHotkey("room roster is not active", lobby, 0, false);
            return false;
        }
    }

    if (test_mode) {
        g_scroll_test_calls.fetch_add(1, std::memory_order_acq_rel);
    } else {
        QueueWheelDetents(detents);
    }
    EDF5_CAPTURE_EVENT("more_players", "room_scroll_requested",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .Int("wheel_detents", detents)
                       .String("direction", detents > 0 ? "up" : "down")
                       .String("input", "physical_mouse_wheel")
                       .Bool("cursor_hit_test", false)
                       .Bool("test_mode", test_mode)
                       .Bool("success", true));
    return true;
}

bool ReadHotkeyState(std::atomic<int>& override_state, unsigned virtual_key) {
    const int state = override_state.load(std::memory_order_acquire);
    return state >= 0 ? state != 0
                      : (GetAsyncKeyState(static_cast<int>(virtual_key)) & 0x8000) != 0;
}

DWORD WINAPI HotkeyMain(void*) {
    bool was_add_down = false;
    bool was_remove_down = false;
    bool was_ready_down = false;
    bool was_invite_down = false;
    bool was_local_mission_harness_down = false;
    bool was_debug_stage_win_down = false;
    bool was_scroll_test_down = false;
    while (g_running.load(std::memory_order_acquire)) {
        InstallGameWindowProc();
        game_patches::PollMissionRelayTelemetry();
        PollMissionResultTelemetry();
        PollReplicationParticipantTelemetry();
        const bool add_down = ReadHotkeyState(
            g_add_hotkey_test_override, capture::GetConfig().bot_hotkey_vk);
        const bool remove_down = ReadHotkeyState(
            g_remove_hotkey_test_override, capture::GetConfig().bot_remove_hotkey_vk);
        const bool ready_down = ReadHotkeyState(
            g_ready_hotkey_test_override, capture::GetConfig().bot_ready_hotkey_vk);
        const bool invite_down = ReadHotkeyState(
            g_invite_hotkey_test_override,
            capture::GetConfig().invite_hotkey_vk);
        const bool local_mission_harness_down =
            capture::GetConfig().local_mission_harness_enabled &&
            ReadHotkeyState(
                g_local_mission_harness_hotkey_test_override,
                capture::GetConfig().local_mission_harness_hotkey_vk);
        const bool debug_stage_win_down =
            capture::GetConfig().debug_stage_win_enabled && ReadHotkeyState(
                g_debug_stage_win_hotkey_test_override,
                capture::GetConfig().debug_stage_win_hotkey_vk);
        const int scroll_override =
            g_scroll_hotkey_test_override.load(std::memory_order_acquire);
        const bool scroll_test_down = scroll_override > 0;
        const bool feedback = !g_suppress_hotkey_feedback.load(std::memory_order_acquire);
        const uint64_t lobby = g_owned_lobby.load(std::memory_order_acquire);
        if (add_down && !was_add_down) TryAddBot(lobby, feedback);
        if (remove_down && !was_remove_down) TryRemoveBot(lobby, feedback);
        if (ready_down && !was_ready_down) RequestReadyBots(lobby, feedback);
        if (invite_down && !was_invite_down) {
            TryOpenInviteDialog(lobby, feedback);
        }
        if (local_mission_harness_down &&
            !was_local_mission_harness_down) {
            TryCycleLocalMissionHarness(lobby, feedback);
        }
        if (debug_stage_win_down && !was_debug_stage_win_down) {
            QueueDebugStageWin(feedback);
        }
        if (scroll_test_down && !was_scroll_test_down) {
            TryScrollRoster(lobby, -1);
        }
        was_add_down = add_down;
        was_remove_down = remove_down;
        was_ready_down = ready_down;
        was_invite_down = invite_down;
        was_local_mission_harness_down = local_mission_harness_down;
        was_debug_stage_win_down = debug_stage_win_down;
        was_scroll_test_down = scroll_test_down;
        Sleep(40);
    }
    return 0;
}

bool StartsWith(const char* value, const char* prefix) {
    if (!value || !prefix) return false;
    return std::strncmp(value, prefix, std::strlen(prefix)) == 0;
}

void PatchSteamId(std::vector<uint8_t>& packet, uint64_t from, uint64_t to) {
    if (!from || from == to || packet.size() < sizeof(uint64_t)) return;
    for (size_t i = 0; i + sizeof(uint64_t) <= packet.size(); ++i) {
        uint64_t value = 0;
        std::memcpy(&value, packet.data() + i, sizeof(value));
        if (value == from) {
            std::memcpy(packet.data() + i, &to, sizeof(to));
            i += sizeof(uint64_t) - 1;
        }
    }
}

bool BuildHandshakeReply(const void* data, uint32_t size, uint64_t bot_steam_id,
                         unsigned max_players, std::vector<uint8_t>& reply) {
    if (!data || size == 0 || size > 1024 * 1024) return false;
    reply.assign(static_cast<const uint8_t*>(data),
                 static_cast<const uint8_t*>(data) + size);
    if (reply.size() >= 20) {
        uint64_t local_id = 0;
        std::memcpy(&local_id, reply.data() + 12, sizeof(local_id));
        PatchSteamId(reply, local_id, bot_steam_id);
    }
    if (reply.size() >= 64) {
        uint32_t advertised_limit = 0;
        std::memcpy(&advertised_limit, reply.data() + 60, sizeof(advertised_limit));
        if (advertised_limit == 4) {
            advertised_limit = max_players;
            std::memcpy(reply.data() + 60, &advertised_limit,
                        sizeof(advertised_limit));
        }
    }
    return true;
}

void QueueHandshakeReply(uint64_t peer, const void* data, uint32_t size,
                         int channel) {
    SyntheticPacket packet;
    packet.peer = peer;
    packet.channel = channel;
    if (!BuildHandshakeReply(data, size, peer, MaxPlayers(), packet.bytes)) return;
    AcquireSRWLockExclusive(&g_state_lock);
    if (g_packets.size() >= 128) g_packets.pop_front();
    g_packets.emplace_back(std::move(packet));
    ReleaseSRWLockExclusive(&g_state_lock);
}

}  // namespace

bool InstallGameHooks() {
    if (!Enabled() || !IsEdf5Process()) {
        EDF5_CAPTURE_EVENT("more_players", "ready_hooks_skipped",
                       capture::Fields().String(
                           "reason", Enabled() ? "process is not EDF5.exe"
                                               : "MorePlayers disabled"));
        return true;
    }

    auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    size_t image_size = 0;
    if (!ValidatePeImage(base, image_size) ||
        !ValidateUserReadyLayout(base, image_size) ||
        !ValidateGameplayP2PLayout(base, image_size) ||
        !ValidateEnemySpawnLayout(base, image_size) ||
        !ValidateDebugStageWinLayout(base, image_size)) {
        EDF5_CAPTURE_EVENT("more_players", "ready_hooks_signature_mismatch",
                       capture::Fields().UInt("constructor_rva", kUserConstructorRva)
                           .UInt("destructor_rva", kUserDestructorRva)
                           .UInt("vtable_rva", kUserVtableRva)
                           .UInt("player_info_builder_rva",
                                 kPlayerInfoBuilderRva)
                           .UInt("mission_loadout_parser_rva",
                                 kMissionLoadoutParserRva)
                           .UInt("mission_start_update_rva",
                                 kMissionStartUpdateRva)
                           .UInt("mission_start_global_state_rva",
                                 kMissionStartGlobalStateRva)
                           .UInt("mission_participant_class_resolver_rva",
                                 kMissionParticipantClassResolverRva)
                           .UInt("mission_participant_visual_table_index_rva",
                                 kMissionParticipantVisualTableIndexRva)
                           .UInt("mission_participant_class_text_table_index_rva",
                                 kMissionParticipantClassTextTableIndexRva)
                           .UInt("mission_text_measure_invalid_read_rva",
                                 kMissionTextMeasureInvalidReadRva)
                           .UInt("shared_render_property_ref_read_rva",
                                 kSharedRenderPropertyRefReadRva)
                           .UInt("game_packet_send_rva",
                                 kGameplayP2PSendRva)
                            .UInt("game_packet_dispatch_rva",
                                  kGameplayP2PDispatchRva)
                            .UInt("game_replication_producer_rva",
                                  kGameplayReplicationProducerRva)
                            .UInt("game_replication_receive_pump_rva",
                                  kGameplayReplicationReceivePumpRva)
                            .UInt("game_replication_receive_parser_rva",
                                  kGameplayReplicationReceiveParserRva)
                            .UInt("game_replication_receive_route_object_constructor_rva",
                                  kGameplayReplicationReceiveRouteObjectConstructorRva)
                            .UInt("game_replication_receive_parser_owner_store_rva",
                                  kGameplayReplicationReceiveParserOwnerStoreRva)
                            .UInt("game_replication_route_register_rva",
                                  kGameplayReplicationReceiveRouteRegisterRva)
                            .UInt("game_replication_route_unregister_rva",
                                  kGameplayReplicationReceiveRouteUnregisterRva)
                            .UInt("game_replication_route_register_call_rva",
                                  kGameplayReplicationReceiveRouteRegisterCallRva)
                            .UInt("game_replication_route_unregister_call_rva",
                                  kGameplayReplicationReceiveRouteUnregisterCallRva)
                            .UInt("user_transport_route_index_offset",
                                  kUserTransportRouteIndexOffset)
                            .UInt("chat_message_publish_rva",
                                  kChatMessagePublishRva)
                            .UInt("chat_system_message_publish_rva",
                                  kChatSystemMessagePublishRva)
                            .UInt("chat_room_constructor_rva",
                                  kChatRoomConstructorRva)
                           .Bool("debug_stage_win_enabled",
                                 capture::GetConfig().debug_stage_win_enabled)
                           .UInt("mission_update_rva", kMissionUpdateRva)
                           .UInt("mission_result_setter_rva",
                                 kMissionResultSetterRva)
                            .UInt("mission_result_event_publish_rva",
                                  kMissionResultEventPublishRva)
                            .UInt("mission_result_ui_event_dispatch_rva",
                                  kMissionResultUiEventDispatchRva)
                           .UInt("mission_result_exec_begin_rva",
                                 kMissionResultExecBeginRva)
                           .UInt("mission_result_exec_begin_script_wrapper_rva",
                                 kMissionResultExecBeginScriptWrapperRva)
                           .UInt("mission_result_exec_update_rva",
                                 kMissionResultExecUpdateRva)
                           .UInt("mission_result_exec_update_script_wrapper_rva",
                                 kMissionResultExecUpdateScriptWrapperRva)
                           .UInt("mission_result_exec_finally_rva",
                                 kMissionResultExecFinallyRva)
                           .UInt("mission_result_exec_finally_script_wrapper_rva",
                                 kMissionResultExecFinallyScriptWrapperRva)
                           .UInt("enemy_spawn_rva", kEnemySpawnRva)
                           .UInt("generator_poll_update_rva",
                                 kGeneratorPollUpdateRva)
                           .UInt("generator_poll_spawn_rva",
                                 kGeneratorPollSpawnRva)
                           .UInt("generator_poll_gate_rva",
                                 kGeneratorPollGateRva)
                           .UInt("generator_poll_gate_state_offset",
                                 kGeneratorPollGateStateOffset)
                           .UInt("generator_poll_gate_cooldown_threshold",
                                 kGeneratorPollGateCooldownThreshold)
                           .UInt("mission_result_item_sink_rva",
                                 kMissionResultItemSinkRva)
                           .UInt("mission_result_item_apply_filter_rva",
                                 kMissionResultItemApplyFilterRva)
                           .UInt("mission_named_sync_begin_rva",
                                 kMissionNamedSyncBeginRva)
                           .UInt("mission_named_sync_poll_rva",
                                 kMissionNamedSyncPollRva)
                           .UInt("mission_reward_resolve_rva",
                                 kMissionRewardResolveRva)
                           .UInt("mission_reward_apply_rva",
                                 kMissionRewardApplyRva));
        return false;
    }

    g_module_base = reinterpret_cast<uintptr_t>(base);
    g_module_image_size = image_size;
    g_runtime_user_vtable = reinterpret_cast<void**>(base + kUserVtableRva);
    g_user_property_getter = reinterpret_cast<UserPropertyGetterFn>(
        base + kUserPropertyGetterRva);
    g_user_property_setter = reinterpret_cast<UserPropertySetterFn>(
        base + kUserPropertySetterRva);
    g_shared_property_release = reinterpret_cast<SharedPropertyReleaseFn>(
        base + kSharedPropertyReleaseRva);
    g_mission_start_controller_context =
        reinterpret_cast<MissionStartControllerContextFn>(
            base + kMissionStartControllerContextRva);
    g_mission_loadout_state_slot = reinterpret_cast<void**>(
        base + kMissionLoadoutStateSlotRva);
    g_runtime_ui_layout_vtable = reinterpret_cast<void**>(
        base + kUiLayoutVtableRva);
    g_runtime_chat_room_vtable = reinterpret_cast<void**>(
        base + kChatRoomVtableRva);
    g_chat_system_message_publish =
        reinterpret_cast<ChatSystemMessagePublishFn>(
            base + kChatSystemMessagePublishRva);
    g_ui_layout_clamp = reinterpret_cast<UiLayoutClampFn>(
        base + kUiLayoutClampRva);
    g_mission_manager_slot = reinterpret_cast<void**>(
        base + kMissionManagerSlotRva);
    g_mission_result_event_publisher_slot = reinterpret_cast<void**>(
        base + kMissionResultEventPublisherSlotRva);
    if (!hooks::Address(base + kUserDestructorRva,
                        reinterpret_cast<void*>(&UserDestructorHook),
                        reinterpret_cast<void**>(&g_user_destructor),
                        "net::UserImpl scalar destructor", true) ||
        !hooks::Address(base + kUserConstructorRva,
                        reinterpret_cast<void*>(&UserConstructorHook),
                        reinterpret_cast<void**>(&g_user_constructor),
                        "net::UserImpl constructor", true) ||
        !hooks::Address(base + kPlayerInfoBuilderRva,
                        reinterpret_cast<void*>(&PlayerInfoBuilderHook),
                        reinterpret_cast<void**>(&g_player_info_builder),
                        "room PlayerInfo vector builder", true) ||
        !hooks::Address(base + kPlayerInfoFromUserRva,
                        reinterpret_cast<void*>(&PlayerInfoFromUserHook),
                        reinterpret_cast<void**>(&g_player_info_from_user),
                        "room UserImpl to PlayerInfo converter", true) ||
        !hooks::Address(
            base + kMissionLoadoutParserRva,
            reinterpret_cast<void*>(&MissionLoadoutParserHook),
            reinterpret_cast<void**>(&g_mission_loadout_parser),
            "mission loadout parser extra-block rollback", true) ||
        !hooks::Address(
            base + kMissionParticipantClassResolverRva,
            reinterpret_cast<void*>(
                &MissionParticipantClassResolverHook),
            reinterpret_cast<void**>(
                &g_mission_participant_class_resolver),
            "mission participant class sidecar resolver", true) ||
        !hooks::Address(base + kUiLayoutCastRva,
                        reinterpret_cast<void*>(&UiLayoutCastHook),
                        reinterpret_cast<void**>(&g_ui_layout_cast),
                        "PlayersGroup ui::Layout cast", true) ||
        !hooks::Address(base + kUiLayoutDestructorRva,
                        reinterpret_cast<void*>(&UiLayoutDestructorHook),
                        reinterpret_cast<void**>(&g_ui_layout_destructor),
                        "ui::Layout scalar destructor", true) ||
        !hooks::Address(base + kHUiRoomUpdateRva,
                        reinterpret_cast<void*>(&HUiRoomUpdateHook),
                        reinterpret_cast<void**>(&g_hui_room_update),
                        "HUiRoom update", true) ||
        !hooks::Address(
            base + kMissionStartUpdateRva,
            reinterpret_cast<void*>(&MissionStartUpdateHook),
            reinterpret_cast<void**>(&g_mission_start_update),
            "MissionStart host-only harness completion", true) ||
        !hooks::Address(
            base + kMissionStartControllerRva,
            reinterpret_cast<void*>(&MissionStartControllerHook),
            reinterpret_cast<void**>(&g_mission_start_controller),
            "MissionStart host-only controller gate", true) ||
        !hooks::Address(base + kMissionSourceLookupRva,
                        reinterpret_cast<void*>(&MissionSourceLookupHook),
                        reinterpret_cast<void**>(&g_mission_source_lookup),
                        "mission participant source lookup", true) ||
        !hooks::Address(base + kMissionSourceConsumerRva,
                        reinterpret_cast<void*>(&MissionSourceConsumerHook),
                        reinterpret_cast<void**>(&g_mission_source_consumer),
                        "mission character source consumer", true) ||
        !hooks::Address(base + kMissionSharedHandleCopyRva,
                        reinterpret_cast<void*>(&MissionSharedHandleCopyHook),
                        reinterpret_cast<void**>(
                            &g_mission_shared_handle_copy),
                        "mission null character handle guard", true) ||
        !hooks::Address(
            base + kMissionSourceCollectionCopyRva,
            reinterpret_cast<void*>(&MissionSourceCollectionCopyHook),
            reinterpret_cast<void**>(&g_mission_source_collection_copy),
            "mission UserImpl collection copy", true) ||
        !hooks::Address(base + kMissionPlayerCreateRva,
                        reinterpret_cast<void*>(&MissionPlayerCreateHook),
                        reinterpret_cast<void**>(&g_mission_player_create),
                        "mission player control assignment", true) ||
#if EDF5_COMPILE_DIAGNOSTICS
        !hooks::Address(base + kReportGsFailureRva,
                        reinterpret_cast<void*>(&ReportGsFailureHook),
                        reinterpret_cast<void**>(&g_report_gs_failure),
                        "MSVC report_gsfailure", true) ||
#endif
         !hooks::Address(base + kGameplayP2PSendRva,
                        reinterpret_cast<void*>(&GameplayP2PSendHook),
                         reinterpret_cast<void**>(&g_gameplay_p2p_send),
                         "EDF5 high-level P2P send", true) ||
         !hooks::Address(
             base + kGameplayReplicationProducerRva,
             reinterpret_cast<void*>(&GameplayReplicationProducerHook),
             reinterpret_cast<void**>(&g_gameplay_replication_producer),
             "EDF5 participant replication producer", true) ||
         !hooks::Address(
             base + kGameplayReplicationSerializerRva,
             reinterpret_cast<void*>(&GameplayReplicationSerializerHook),
             reinterpret_cast<void**>(&g_gameplay_replication_serializer),
             "EDF5 participant replication send fan-out", true) ||
         !hooks::Address(
             base + kGameplayReplicationReceivePumpRva,
             reinterpret_cast<void*>(
                 &GameplayReplicationReceivePumpHook),
             reinterpret_cast<void**>(
                 &g_gameplay_replication_receive_pump),
             "EDF5 participant replication receive pump", true) ||
         !hooks::Address(
             base + kGameplayReplicationReceiveParserRva,
             reinterpret_cast<void*>(
                 &GameplayReplicationReceiveParserHook),
             reinterpret_cast<void**>(
                 &g_gameplay_replication_receive_parser),
             "EDF5 participant replication receive parser", true) ||
         !hooks::Address(
             base + kGameplayReplicationReceiveRouteRegisterRva,
             reinterpret_cast<void*>(
                 &GameplayReplicationReceiveRouteRegisterHook),
             reinterpret_cast<void**>(
                 &g_gameplay_replication_receive_route_register),
             "EDF5 replication receive route register", true) ||
         !hooks::Address(
             base + kGameplayReplicationReceiveRouteUnregisterRva,
             reinterpret_cast<void*>(
                 &GameplayReplicationReceiveRouteUnregisterHook),
             reinterpret_cast<void**>(
                 &g_gameplay_replication_receive_route_unregister),
             "EDF5 replication receive route unregister", true) ||
         !hooks::Address(
             base + kChatRoomConstructorRva,
             reinterpret_cast<void*>(&ChatRoomConstructorHook),
             reinterpret_cast<void**>(&g_chat_room_constructor),
             "net::Chat_Room constructor capture", true) ||
         !hooks::Address(
             base + kChatMessagePublishRva,
             reinterpret_cast<void*>(&ChatMessagePublishHook),
             reinterpret_cast<void**>(&g_chat_message_publish),
             "Chat_Room room/sender identity audit", true) ||
         !hooks::Address(base + kGameplayMessageEnqueueRva,
                        reinterpret_cast<void*>(&GameplayMessageEnqueueHook),
                        reinterpret_cast<void**>(
                            &g_gameplay_message_enqueue),
                        "EDF5 outgoing logical message enqueue", true) ||
        !hooks::Address(
            base + kMissionScriptMessageDispatchRva,
            reinterpret_cast<void*>(&MissionScriptMessageDispatchHook),
            reinterpret_cast<void**>(
                &g_mission_script_message_dispatch),
            "MissionScript decoded message dispatcher", true) ||
        !hooks::Address(base + kGameplayP2PDispatchRva,
                        reinterpret_cast<void*>(&GameplayP2PDispatchHook),
                        reinterpret_cast<void**>(&g_gameplay_p2p_dispatch),
                        "EDF5 P2P receive dispatcher", true)) {
        return false;
    }
    if (!hooks::Address(base + kMissionResultApplyRva,
                        reinterpret_cast<void*>(&MissionResultApplyHook),
                        reinterpret_cast<void**>(&g_mission_result_apply),
                        "Mission result UI apply", true) ||
        !hooks::Address(
            base + kGeneratorPollUpdateRva,
            reinterpret_cast<void*>(&GeneratorPollUpdateHook),
            reinterpret_cast<void**>(&g_generator_poll_update),
            "GeneratorPoll update-to-gate path telemetry", true) ||
        !hooks::Address(
            base + kGeneratorPollGateRva,
            reinterpret_cast<void*>(&GeneratorPollGateHook),
            reinterpret_cast<void**>(&g_generator_poll_gate),
            "GeneratorPoll native gate outcome telemetry", true) ||
        !hooks::Address(
            base + kGeneratorPollSpawnRva,
            reinterpret_cast<void*>(&GeneratorPollSpawnHook),
            reinterpret_cast<void**>(&g_generator_poll_spawn),
            "GeneratorPoll pre-boundary spawn path telemetry", true) ||
        !hooks::Address(
            base + kEnemySpawnRva,
            reinterpret_cast<void*>(&EnemySpawnHook),
            reinterpret_cast<void**>(&g_enemy_spawn),
            "confirmed enemy spawn quantity/scale", true) ||
        !hooks::Address(
            base + kMissionResultEventPublishRva,
            reinterpret_cast<void*>(&MissionResultEventPublishHook),
            reinterpret_cast<void**>(&g_mission_result_event_publish),
            "Mission result UI close event publish audit", true) ||
        !hooks::Address(
            base + kMissionResultUiEventDispatchRva,
            reinterpret_cast<void*>(&MissionResultUiEventDispatchHook),
            reinterpret_cast<void**>(&g_mission_result_ui_event_dispatch),
            "Mission result UI close target dispatch audit", true) ||
        !hooks::Address(
            base + kMissionResultExecBeginRva,
            reinterpret_cast<void*>(&MissionResultExecBeginHook),
            reinterpret_cast<void**>(&g_mission_result_exec_begin),
            "net::MissionResult Exec_Begin", true) ||
        !hooks::Address(
            base + kMissionResultExecUpdateRva,
            reinterpret_cast<void*>(&MissionResultExecUpdateHook),
            reinterpret_cast<void**>(&g_mission_result_exec_update),
            "net::MissionResult ResultSync_Update", true) ||
        !hooks::Address(
            base + kMissionResultExecFinallyRva,
            reinterpret_cast<void*>(&MissionResultExecFinallyHook),
            reinterpret_cast<void**>(&g_mission_result_exec_finally),
            "net::MissionResult ResultSync_Finally", true) ||
        !hooks::Address(
            base + kMissionResultItemSinkRva,
            reinterpret_cast<void*>(&MissionResultItemSinkHook),
            reinterpret_cast<void**>(&g_mission_result_item_sink),
            "NetGameStatus extra participant Item fold", true) ||
        !hooks::Address(
            base + kMissionNamedSyncBeginRva,
            reinterpret_cast<void*>(&MissionNamedSyncBeginHook),
            reinterpret_cast<void**>(&g_mission_named_sync_begin),
            "named sync begin audit", true) ||
        !hooks::Address(
            base + kMissionNamedSyncPollRva,
            reinterpret_cast<void*>(&MissionNamedSyncPollHook),
            reinterpret_cast<void**>(&g_mission_named_sync_poll),
            "named sync poll audit", true) ||
        !hooks::Address(
            base + kMissionRewardResolveRva,
            reinterpret_cast<void*>(&MissionRewardResolveHook),
            reinterpret_cast<void**>(&g_mission_reward_resolve),
            "Mission ResolveResult reward audit", true) ||
        !hooks::Address(
            base + kMissionRewardApplyRva,
            reinterpret_cast<void*>(&MissionRewardApplyHook),
            reinterpret_cast<void**>(&g_mission_reward_apply),
            "Mission ApplyResult reward audit", true) ||
        !hooks::Address(base + kMissionResultSetterRva,
                        reinterpret_cast<void*>(&MissionResultSetterHook),
                        reinterpret_cast<void**>(&g_mission_result_setter),
                        "Mission result setter", true) ||
        !hooks::Address(base + kMissionUpdateRva,
                        reinterpret_cast<void*>(&MissionUpdateHook),
                        reinterpret_cast<void**>(&g_mission_update),
                        "Mission script update", true)) {
        return false;
    }

    EDF5_CAPTURE_EVENT("more_players", "ready_hooks_installed",
                   capture::Fields().UInt("constructor_rva", kUserConstructorRva)
                       .UInt("destructor_rva", kUserDestructorRva)
                       .UInt("state_flags_initializer_rva",
                             kUserStateFlagsInitializerRva)
                       .UInt("user_ready_state_reader_rva",
                             kUserReadyStateReaderRva)
                       .UInt("state_lock_offset", kUserStateLockOffset)
                       .UInt("transport_flag_offset", kUserReadyFlagOffset)
                       .UInt("property_object_offset",
                             kUserPropertyObjectOffset)
                       .UInt("property_object_initializer_rva",
                             kUserPropertyObjectInitializerRva)
                       .UInt("property_getter_rva", kUserPropertyGetterRva)
                       .UInt("property_setter_rva", kUserPropertySetterRva)
                       .UInt("property_release_rva",
                             kSharedPropertyReleaseRva)
                       .String("ready_cm_value", "c1")
                       .String("ready_ds_value", "ds")
                       .String("mission_group_properties", "l1,l2")
                       .UInt("player_info_builder_rva", kPlayerInfoBuilderRva)
                       .UInt("player_info_from_user_rva",
                             kPlayerInfoFromUserRva)
                       .UInt("player_info_from_user_return_rva",
                             kPlayerInfoFromUserReturnRva)
                       .Bool("player_info_return_preserved", true)
                       .UInt("player_info_size", kPlayerInfoSize)
                       .UInt("room_update_rva", kHUiRoomUpdateRva)
                       .UInt("mission_start_update_rva",
                             kMissionStartUpdateRva)
                       .UInt("mission_start_global_state_rva",
                             kMissionStartGlobalStateRva)
                       .UInt("mission_start_controller_rva",
                             kMissionStartControllerRva)
                       .UInt("mission_start_controller_call_rva",
                             kMissionStartControllerCallRva)
                       .UInt("mission_start_controller_completed_read_rva",
                             kMissionStartControllerCompletedReadRva)
                       .UInt("mission_start_controller_context_rva",
                             kMissionStartControllerContextRva)
                       .UInt("mission_start_controller_vtable_rva",
                             kMissionStartControllerVtableRva)
                       .UInt("mission_start_controller_gate_getter_rva",
                             kMissionStartControllerGateGetterRva)
                       .UInt("mission_start_controller_gate_request_offset",
                             kMissionStartControllerGateRequestOffset)
                       .UInt("mission_start_controller_gate_value_offset",
                             kMissionStartControllerGateValueOffset)
                       .Int("mission_start_local_aggregate_state",
                            kMissionStartLocallyAggregatedState)
                       .Int("mission_start_completed_state",
                            kMissionStartCompletedState)
                       .Bool("local_mission_harness_matching_bypass",
                             true)
                       .Bool("local_mission_harness_mission_start_observation",
                             true)
                       .Bool("local_mission_harness_controller_gate_bypass",
                             true)
                       .Bool("local_mission_harness_controller_gate_temporary",
                             true)
                       .UInt("mission_start_observation_interval_ms",
                             kMissionStartObservationIntervalMs)
                       .String("mission_start_observation_points",
                               "MissionStart::Update,HUiRoom::Update")
                       .Bool("local_mission_harness_intermediate_state_forcing",
                             false)
                       .Bool("local_mission_harness_gameplay_packet_fabrication",
                             false)
                       .UInt("players_group_cast_rva", kUiLayoutCastRva)
                       .UInt("players_group_cast_return_rva",
                             kPlayersGroupCastReturnRva)
                       .UInt("layout_vertical_scroll_offset",
                             kUiLayoutVerticalScrollOffset)
                       .UInt("scroll_position_offset",
                             kUiScrollRequestedPositionOffset)
                       .UInt("report_gsfailure_rva",
                             kReportGsFailureRva)
                       .UInt("game_packet_send_rva",
                             kGameplayP2PSendRva)
                       .UInt("game_packet_send_target_rva",
                             kGameplayP2PSendTargetRva)
                       .UInt("game_packet_dispatch_rva",
                             kGameplayP2PDispatchRva)
                       .UInt("game_packet_dispatch_special_vtable_rva",
                             kGameplayP2PDispatchSpecialVtableRva)
                       .UInt("game_packet_dispatch_special_target_rva",
                             kGameplayP2PDispatchSpecialTargetRva)
                       .UInt("game_packet_route_slot_capacity", 128)
                       .UInt("game_message_enqueue_rva",
                             kGameplayMessageEnqueueRva)
                       .UInt("game_replication_producer_rva",
                             kGameplayReplicationProducerRva)
                       .UInt("game_replication_serializer_rva",
                             kGameplayReplicationSerializerRva)
                       .UInt("game_replication_serializer_call_rva",
                             kGameplayReplicationSerializerCallRva)
                       .UInt("game_replication_target_builder_rva",
                             kGameplayReplicationTargetBuilderRva)
                       .UInt("game_replication_target_resolve_rva",
                             kGameplayReplicationTargetResolveRva)
                       .UInt("game_replication_target_descriptor_stride",
                             sizeof(GameplayReplicationTargetDescriptor))
                       .UInt(
                           "game_replication_target_route_index_offset",
                           offsetof(GameplayReplicationTargetDescriptor,
                                    transport_route_index))
                       .Bool("game_replication_send_fanout_audit", true)
                       .UInt("game_replication_receive_pump_rva",
                             kGameplayReplicationReceivePumpRva)
                       .UInt("game_replication_receive_vector_offset",
                             kGameplayReplicationReceivePumpVectorOffset)
                       .UInt("game_replication_receive_capacity_offset",
                             kGameplayReplicationReceivePumpCapacityOffset)
                       .UInt("game_replication_receive_count_offset",
                             kGameplayReplicationReceivePumpCountOffset)
                       .UInt("game_replication_route_register_rva",
                             kGameplayReplicationReceiveRouteRegisterRva)
                       .UInt("game_replication_route_unregister_rva",
                             kGameplayReplicationReceiveRouteUnregisterRva)
                       .UInt("game_replication_route_register_call_rva",
                             kGameplayReplicationReceiveRouteRegisterCallRva)
                       .UInt("game_replication_route_unregister_call_rva",
                             kGameplayReplicationReceiveRouteUnregisterCallRva)
                       .Bool("game_replication_route_lifecycle_audit", true)
                       .UInt("user_transport_route_index_offset",
                             kUserTransportRouteIndexOffset)
                       .UInt("user_transport_route_index_initializer_rva",
                             kUserTransportRouteIndexInitializerRva)
                       .UInt("user_transport_route_slot_allocator_rva",
                             kUserTransportRouteSlotAllocatorRva)
                       .UInt("game_replication_receive_vector_stride",
                             sizeof(SharedProperty))
                       .Bool("game_replication_receive_vector_dynamic",
                             true)
                       .UInt("game_replication_receive_parser_rva",
                             kGameplayReplicationReceiveParserRva)
                       .UInt("game_replication_receive_route_object_constructor_rva",
                             kGameplayReplicationReceiveRouteObjectConstructorRva)
                       .UInt("game_replication_receive_route_user_control_offset",
                             kGameplayReplicationReceiveRouteUserControlOffset)
                       .UInt("game_replication_receive_route_parser_offset",
                             kGameplayReplicationReceiveRouteParserOffset)
                       .UInt("game_replication_receive_parser_constructor_rva",
                             kGameplayReplicationReceiveParserConstructorRva)
                       .UInt("game_replication_receive_parser_route_owner_offset",
                             kGameplayReplicationReceiveParserRouteOwnerOffset)
                       .UInt("shared_property_control_object_offset",
                             kSharedPropertyControlObjectOffset)
                       .UInt("chat_message_publish_rva",
                             kChatMessagePublishRva)
                       .UInt("chat_system_message_publish_rva",
                             kChatSystemMessagePublishRva)
                       .UInt("chat_room_constructor_rva",
                             kChatRoomConstructorRva)
                       .UInt("chat_room_vtable_assignment_rva",
                             kChatRoomVtableAssignmentRva)
                       .UInt("chat_room_vtable_rva",
                             kChatRoomVtableRva)
                       .String("chat_mod_banner_name", mod_info::kName)
                       .String("chat_mod_banner_version",
                               mod_info::kVersion)
                       .Bool("chat_mod_banner_once_per_room", true)
                       .Bool("chat_mod_banner_direct_room_update", true)
                       .Bool("chat_mod_banner_system_message_path", true)
                       .Bool("chat_mod_banner_identity_required", false)
                       .Bool("chat_mod_banner_local_display_only", true)
                       .Bool("chat_mod_banner_steam_send", false)
                       .Bool("chat_sender_name_association_audit", false)
                       .Bool("chat_room_sender_identity_audit", true)
                       .Bool("chat_sender_identity_captured", false)
                       .Bool("chat_display_name_text_captured", false)
                       .Bool("chat_message_text_inspected", false)
                       .Bool("chat_message_text_captured", false)
                       .String("game_replication_receive_user_resolution_chain",
                               "parser+0x498->route+0x58->control+0x08")
                       .Bool("game_replication_receive_legacy_minus_0x88_used",
                             false)
                       .String("game_replication_families",
                               "0x3300,0x3400")
                       .UInt("game_replication_participant_capacity",
                             kReplicationParticipantCapacity)
                       .UInt("game_replication_summary_interval_ms",
                             kReplicationSummaryIntervalMs)
                       .Bool("game_replication_participant_audit", true)
                       .Bool("game_replication_payload_captured", false)
                       .Bool("game_replication_identity_captured", false)
                       .UInt("mission_script_message_dispatch_rva",
                             kMissionScriptMessageDispatchRva)
                       .UInt("game_message_route_slot_capacity", 256)
                       .Bool("game_message_header_captured", true)
                       .Bool("game_message_context_handle_presence", true)
                       .Bool("incoming_game_message_route", true)
                       .Bool("incoming_game_message_size_captured", false)
                       .Bool("game_message_multipart_classification", true)
                       .Bool("game_message_payload_captured", false)
                       .Bool("game_message_endpoint_captured", false)
                       .Bool("game_packet_payload_captured", false)
                       .Bool("game_packet_endpoint_captured", false)
                       .Bool("local_mission_harness_enabled",
                             capture::GetConfig()
                                 .local_mission_harness_enabled)
                       .UInt("local_mission_harness_hotkey_vk",
                             capture::GetConfig()
                                 .local_mission_harness_hotkey_vk)
                       .UInt("local_mission_harness_baseline_dummies",
                             kLocalMissionHarnessBaselineDummies)
                       .UInt("local_mission_harness_probe_dummies",
                             kLocalMissionHarnessProbeDummies)
                       .Bool("local_mission_harness_real_connections",
                             false)
                       .Bool("local_mission_harness_gameplay_ai", false)
                       .Bool("debug_stage_win_enabled",
                             capture::GetConfig().debug_stage_win_enabled)
                       .UInt("debug_stage_win_hotkey_vk",
                             capture::GetConfig().debug_stage_win_hotkey_vk)
                       .UInt("mission_update_rva", kMissionUpdateRva)
                       .UInt("mission_result_setter_rva",
                             kMissionResultSetterRva)
                       .UInt("mission_result_apply_rva",
                             kMissionResultApplyRva)
                       .UInt("mission_result_event_publish_rva",
                             kMissionResultEventPublishRva)
                       .UInt("mission_result_event_publisher_slot_rva",
                             kMissionResultEventPublisherSlotRva)
                       .UInt("mission_result_ui_event_dispatch_rva",
                             kMissionResultUiEventDispatchRva)
                       .UInt("mission_result_ui_object_id_offset",
                             kUiObjectEventIdOffset)
                       .UInt("mission_result_ui_object_flags_offset",
                             kUiObjectEventFlagsOffset)
                       .Int("mission_result_event_type",
                            kMissionResultEventType)
                       .Int("mission_result_event_payload",
                            kMissionResultEventPayload)
                       .UInt("mission_result_exec_begin_rva",
                             kMissionResultExecBeginRva)
                       .UInt("mission_result_exec_begin_native_caller_rva",
                             kMissionResultExecBeginNativeCallerRva)
                       .UInt("mission_result_exec_begin_script_wrapper_rva",
                             kMissionResultExecBeginScriptWrapperRva)
                       .UInt("mission_result_exec_begin_direct_callers", 2)
                       .String("mission_result_exec_begin_script_wrapper_name",
                               "ResultSync_Begin")
                       .UInt("mission_result_exec_update_rva",
                             kMissionResultExecUpdateRva)
                       .UInt("mission_result_exec_update_script_wrapper_rva",
                             kMissionResultExecUpdateScriptWrapperRva)
                       .UInt("mission_result_exec_update_native_caller_rva",
                             kMissionResultExecUpdateNativeCallerRva)
                       .UInt("mission_result_exec_update_direct_callers", 2)
                       .String("mission_result_exec_update_script_wrapper_name",
                               "ResultSync_Update")
                       .Bool("mission_result_exec_update_result_semantics_assumed",
                             false)
                       .UInt("mission_result_exec_finally_rva",
                             kMissionResultExecFinallyRva)
                       .UInt("mission_result_exec_finally_script_wrapper_rva",
                             kMissionResultExecFinallyScriptWrapperRva)
                       .UInt("mission_result_exec_finally_direct_callers", 2)
                       .String("mission_result_exec_finally_script_wrapper_name",
                               "ResultSync_Finally")
                       .Bool("mission_result_exec_pipeline_telemetry_only",
                             true)
                       .Int("mission_result_exec_recovery_argument",
                            mission_result_recovery::kExecBeginArgument)
                       .UInt("mission_result_exec_recovery_grace_ms",
                             mission_result_recovery::kExecBeginGraceMs)
                       .Bool("mission_result_exec_recovery_host_only",
                             false)
                       .Bool("mission_result_exec_recovery_harness_enabled",
                             false)
                       .UInt("enemy_spawn_rva", kEnemySpawnRva)
                       .UInt("generator_poll_update_rva",
                             kGeneratorPollUpdateRva)
                       .UInt("generator_poll_spawn_rva",
                             kGeneratorPollSpawnRva)
                       .UInt("generator_poll_vtable_rva",
                             kGeneratorPollVtableRva)
                       .UInt("generator_poll_vtable_update_offset",
                             kGeneratorPollVirtualUpdateOffset)
                       .UInt("generator_poll_vtable_spawn_offset",
                             kGeneratorPollVirtualSpawnOffset)
                       .UInt("generator_poll_base_update_rva",
                             kGeneratorPollBaseUpdateRva)
                       .UInt("generator_poll_gate_rva",
                             kGeneratorPollGateRva)
                       .UInt("generator_poll_gate_state_offset",
                             kGeneratorPollGateStateOffset)
                       .UInt("generator_poll_gate_cooldown_threshold",
                             kGeneratorPollGateCooldownThreshold)
                       .Bool("generator_poll_gate_outcome_telemetry", true)
                       .UInt("generator_poll_manager_offset",
                             kGeneratorPollManagerOffset)
                       .Bool("generator_poll_telemetry_only", true)
                       .UInt("enemy_spawn_confirmed_callers",
                             mission_spawn::kConfirmedEnemySpawnCallRvas.size())
                       .UInt("enemy_spawn_multiplier",
                             capture::GetConfig().enemy_spawn_multiplier)
                       .Bool("experimental_enemy_spawn_multiplier",
                             capture::GetConfig()
                                 .experimental_enemy_spawn_multiplier)
                       .UInt("enemy_spawn_native_capacity",
                             mission_spawn::kNativeEnemyCapacity)
                       .UInt("enemy_spawn_scale_numerator_offset",
                             kEnemySpawnScaleNumeratorOffset)
                       .UInt("enemy_spawn_scale_denominator_offset",
                             kEnemySpawnScaleDenominatorOffset)
                       .UInt("enemy_spawn_source_offset",
                             kEnemySpawnSourceOffset)
                       .Bool("enemy_spawn_zero_scale_repair", true)
                       .Bool("enemy_spawn_actor_pointer_logged", false)
                       .Bool("enemy_spawn_payload_logged", false)
                       .UInt("mission_result_item_sink_rva",
                             kMissionResultItemSinkRva)
                       .UInt("mission_result_item_initialize_limit_rva",
                             kMissionResultItemInitializeLimitRva)
                       .UInt("mission_result_item_apply_filter_rva",
                             kMissionResultItemApplyFilterRva)
                       .UInt("mission_result_native_item_capacity",
                             kMissionResultNativeItemCount)
                       .Bool("mission_result_extra_item_fold", true)
                       .UInt("mission_named_sync_begin_rva",
                             kMissionNamedSyncBeginRva)
                       .UInt("mission_named_sync_poll_rva",
                             kMissionNamedSyncPollRva)
                       .UInt("mission_result_script_sync_begin_call_rva",
                             kMissionResultScriptSyncBeginCallRva)
                       .UInt("mission_result_script_sync_poll_call_rva",
                             kMissionResultScriptSyncPollCallRva)
                       .UInt("mission_result_net_sync_begin_call_rva",
                             kMissionResultNetSyncBeginCallRva)
                       .UInt("mission_result_net_sync_poll_call_rva",
                             kMissionResultNetSyncPollCallRva)
                       .UInt("mission_reward_resolve_rva",
                             kMissionRewardResolveRva)
                       .UInt("mission_reward_apply_rva",
                             kMissionRewardApplyRva)
                       .UInt("mission_reward_local_profile_capacity",
                             kMissionRewardLocalProfileCapacity)
                       .Bool("mission_result_flow_audit",
                             true)
                       .Bool("mission_result_sync_reward_audit", true)
                       .Bool("mission_reward_contents_logged", false)
                       .Bool("mission_reward_online_player_count_used",
                             false)
                       .Bool("mission_result_host_recovery", true)
                       .UInt("mission_result_recovery_grace_ms",
                             kMissionResultRecoveryGraceMs)
                       .UInt("mission_manager_slot_rva",
                             kMissionManagerSlotRva)
                       .UInt("mission_source_lookup_rva",
                             kMissionSourceLookupRva)
                       .UInt("mission_source_lookup_caller_rva",
                             kMissionSourceLookupCallRva)
                       .UInt("mission_source_transfer_caller_rva",
                             kMissionSourceTransferCallRva)
                       .UInt("mission_source_append_caller_rva",
                             kMissionSourceAppendCallRva)
                       .UInt("mission_source_consumer_rva",
                             kMissionSourceConsumerRva)
                       .UInt("mission_null_character_guard_rva",
                             kMissionSharedHandleCopyRva)
                       .UInt("mission_loadout_state_slot_rva",
                             kMissionLoadoutStateSlotRva)
                       .UInt("mission_loadout_parser_rva",
                             kMissionLoadoutParserRva)
                       .UInt("mission_participant_class_resolver_rva",
                             kMissionParticipantClassResolverRva)
                       .UInt("mission_participant_native_class_read_rva",
                             kMissionParticipantNativeClassReadRva)
                       .UInt("mission_participant_class_text_table_index_rva",
                             kMissionParticipantClassTextTableIndexRva)
                       .UInt("mission_participant_class_text_select_rva",
                             kMissionParticipantClassTextSelectRva)
                       .UInt("mission_text_measure_invalid_read_rva",
                             kMissionTextMeasureInvalidReadRva)
                       .UInt("mission_participant_visual_table_index_rva",
                             kMissionParticipantVisualTableIndexRva)
                       .UInt("mission_participant_visual_submit_call_rva",
                             kMissionParticipantVisualSubmitCallRva)
                       .UInt("shared_render_property_copy_rva",
                             kSharedRenderPropertyCopyRva)
                       .UInt("shared_render_property_ref_read_rva",
                             kSharedRenderPropertyRefReadRva)
                       .UInt("mission_participant_visual_slot_count",
                             kNativeMissionSourceCount)
                       .Bool("mission_participant_visual_slot_remap", true)
                       .Bool("mission_participant_class_output_bounded", true)
                       .Bool("mission_loadout_parser_sidecar", true)
                       .UInt("mission_loadout_extra_block_begin_offset",
                             kMissionExtraLoadoutBeginOffset)
                       .UInt("mission_loadout_extra_block_span",
                             kMissionExtraLoadoutSpan)
                       .UInt("mission_result_participant_count_offset",
                             kMissionResultParticipantCountOffset)
                       .Bool("mission_loadout_extra_block_rollback", true)
                       .Bool("mission_participant_class_sidecar", true)
                       .UInt("mission_user_sort_key_offset",
                             kUserMissionSortKeyOffset)
                       .UInt("mission_source_collection_copy_rva",
                             kMissionSourceCollectionCopyRva)
                       .UInt("mission_source_primary_copy_caller_rva",
                             kMissionSourcePrimaryCopyCallRva)
                       .UInt("mission_source_reference_copy_caller_rva",
                             kMissionSourceReferenceCopyCallRva)
                       .UInt("mission_player_create_rva",
                             kMissionPlayerCreateRva)
                       .UInt("mission_player_create_primary_call_rva",
                             kMissionPlayerCreatePrimaryCallRva)
                       .UInt("mission_player_create_secondary_call_rva",
                             kMissionPlayerCreateSecondaryCallRva)
                       .UInt("mission_source_context_count", 3)
                       .UInt("mission_source_native_count",
                             kNativeMissionSourceCount)
                       .UInt("mission_source_dynamic_player_index", 4)
                       .Bool("mission_source_modulo_fallback", true)
                       .Bool("mission_source_temporary_loadout_fallback",
                             true)
                       .Bool("mission_source_unique_loadout_restored", true)
                       .Bool("mission_source_player_info_class_match", true)
                       .Bool("mission_source_post_sort_identity", true)
                       .Bool("mission_source_pre_sort_remap", false)
                       .Bool("mission_source_consumer_retry", true)
                       .Bool("mission_null_character_guard", true)
                       .Bool("mission_user_sort_key_value_logged", false)
                       .Bool("mission_source_registered_order_audit", true)
                       .Bool("mission_source_local_control_order_audit", true)
                       .Bool("mission_source_resolution_audit", true)
                       .Bool("mission_player_control_assignment_audit", true)
                       .Int("mission_clear_result", kMissionResultClear)
                       .UInt("identity_getter_rva", kUserIdGetterRva));
    return true;
}

bool Start() {
    if (!Enabled()) return true;
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true,
                                           std::memory_order_acq_rel)) return true;
    g_running.store(true, std::memory_order_release);
    g_hotkey_thread_id = 0;
    g_hotkey_thread = CreateThread(nullptr, 0, HotkeyMain, nullptr, 0,
                                   &g_hotkey_thread_id);
    if (!g_hotkey_thread) {
        g_running.store(false, std::memory_order_release);
        g_started.store(false, std::memory_order_release);
        EDF5_CAPTURE_EVENT("more_players", "hotkey_thread_failed",
                       capture::Fields().UInt("win32_error", GetLastError()));
        return false;
    }
    EDF5_CAPTURE_EVENT("more_players", "started",
                   capture::Fields().UInt("max_players", MaxPlayers())
                       .UInt("enemy_spawn_multiplier",
                             capture::GetConfig().enemy_spawn_multiplier)
                       .Bool("experimental_enemy_spawn_multiplier",
                             capture::GetConfig()
                                 .experimental_enemy_spawn_multiplier)
                       .UInt("bot_add_hotkey_vk", capture::GetConfig().bot_hotkey_vk)
                        .UInt("bot_remove_hotkey_vk",
                              capture::GetConfig().bot_remove_hotkey_vk)
                        .UInt("bot_ready_hotkey_vk",
                              capture::GetConfig().bot_ready_hotkey_vk)
                        .UInt("invite_hotkey_vk",
                              capture::GetConfig().invite_hotkey_vk)
                        .Bool("local_mission_harness_enabled",
                              capture::GetConfig()
                                  .local_mission_harness_enabled)
                        .UInt("local_mission_harness_hotkey_vk",
                              capture::GetConfig()
                                  .local_mission_harness_hotkey_vk)
                        .UInt("local_mission_harness_baseline_dummies",
                              kLocalMissionHarnessBaselineDummies)
                        .UInt("local_mission_harness_probe_dummies",
                              kLocalMissionHarnessProbeDummies)
                        .Bool("debug_stage_win_enabled",
                              capture::GetConfig().debug_stage_win_enabled)
                        .UInt("debug_stage_win_hotkey_vk",
                              capture::GetConfig().debug_stage_win_hotkey_vk)
                        .String("roster_scroll_input", "physical_mouse_wheel")
                        .Bool("roster_scroll_requires_hover", false)
                        .UInt("first_bot_steam_id", BotSteamId()));
    return true;
}

void RequestStop() {
    g_running.store(false, std::memory_order_release);
}

void Stop() {
    RequestStop();
    HANDLE thread = g_hotkey_thread;
    if (thread) {
        const bool self_stop = g_hotkey_thread_id != 0 &&
            g_hotkey_thread_id == GetCurrentThreadId();
        if (self_stop || !win32_handle::ThreadStopped(thread, 2000)) {
            EDF5_CAPTURE_EVENT(
                capture::Level::Warning, "more_players",
                "hotkey_thread_stop_deferred",
                capture::Fields()
                    .Bool("called_from_hotkey_thread", self_stop)
                    .Bool("resources_retained", true)
                    .UInt("wait_timeout_ms", self_stop ? 0 : 2000));
            return;
        }
        win32_handle::CloseNullable(g_hotkey_thread);
        g_hotkey_thread_id = 0;
    }
    RestoreGameWindowProc();
    g_started.store(false, std::memory_order_release);
    g_create_pending.store(false, std::memory_order_release);
    g_owned_lobby.store(0, std::memory_order_release);
    g_join_lobby_pending.store(0, std::memory_order_release);
    g_chat_banner_lobby.store(0, std::memory_order_release);
    g_chat_banner_pending.store(false, std::memory_order_release);
    g_chat_banner_publish_attempts.store(0, std::memory_order_release);
    g_chat_banner_publish_successes.store(0, std::memory_order_release);
    g_chat_banner_wait_logged_mask.store(0, std::memory_order_release);
    g_chat_room_capture_count.store(0, std::memory_order_release);
    g_chat_room_instance.store(0, std::memory_order_release);
    g_chat_system_message_publish = nullptr;
    g_last_actual_member_count.store(-1, std::memory_order_release);
    g_add_hotkey_test_override.store(-1, std::memory_order_release);
    g_remove_hotkey_test_override.store(-1, std::memory_order_release);
    g_ready_hotkey_test_override.store(-1, std::memory_order_release);
    g_invite_hotkey_test_override.store(-1, std::memory_order_release);
    g_local_mission_harness_hotkey_test_override.store(
        -1, std::memory_order_release);
    g_debug_stage_win_hotkey_test_override.store(-1,
                                                  std::memory_order_release);
    g_scroll_hotkey_test_override.store(-1, std::memory_order_release);
    g_ready_user_test_mode.store(false, std::memory_order_release);
    g_scroll_test_mode.store(false, std::memory_order_release);
    g_scroll_test_calls.store(0, std::memory_order_release);
    g_suppress_hotkey_feedback.store(false, std::memory_order_release);
    g_last_loadout_log_signature.store(0, std::memory_order_release);
    g_last_room_model_tick.store(0, std::memory_order_release);
    g_player_info_return_contract_logged.store(false,
                                                std::memory_order_release);
    g_player_info_return_mismatch_count.store(0,
                                               std::memory_order_release);
    g_single_real_host_position.store(-1, std::memory_order_release);
    g_pending_wheel_detents.store(0, std::memory_order_release);
    g_players_group_layout.store(0, std::memory_order_release);
    g_players_group_capture_tick.store(0, std::memory_order_release);
    g_mission_source_recycle_logged_mask.store(0,
                                                std::memory_order_release);
    g_mission_source_identity_repair_logged_mask.store(
        0, std::memory_order_release);
    g_mission_source_index_audit_logged_mask.store(
        0, std::memory_order_release);
    g_mission_source_consumer_audit_logged_mask.store(
        0, std::memory_order_release);
    g_mission_null_character_guard_logged_mask.store(
        0, std::memory_order_release);
    g_mission_player_control_audit_logged_mask.store(
        0, std::memory_order_release);
    g_mission_class_correction_logged_mask.store(
        0, std::memory_order_release);
    g_mission_visual_slot_remap_logged_mask.store(
        0, std::memory_order_release);
    g_mission_loadout_parser_calls.store(0,
                                          std::memory_order_release);
    g_mission_loadout_parser_protected_calls.store(
        0, std::memory_order_release);
    g_mission_loadout_parser_oob_calls.store(
        0, std::memory_order_release);
    g_mission_source_primary_snapshot = {};
    g_mission_source_local_snapshot = {};
    g_mission_player_create_trace = {};
    ResetReplicationParticipantTelemetry();
    ResetMissionRuntimeState();
    ClearSyntheticState(false);
    ClearReadyUsers();
}

bool AddBotFromApi() {
    return TryAddBot(g_owned_lobby.load(std::memory_order_acquire), false);
}

bool RemoveBotFromApi() {
    return TryRemoveBot(g_owned_lobby.load(std::memory_order_acquire), false);
}

bool ReadyBotsFromApi() {
    return RequestReadyBots(g_owned_lobby.load(std::memory_order_acquire), false);
}

bool OpenInviteDialogFromApi() {
    return TryOpenInviteDialog(
        g_owned_lobby.load(std::memory_order_acquire), false);
}

bool ToggleBotFromApi() {
    return g_bot_count.load(std::memory_order_acquire) == 0
        ? AddBotFromApi() : RemoveBotFromApi();
}

bool Enabled() {
    return capture::GetConfig().more_players;
}

unsigned MaxPlayers() {
    return capture::GetConfig().max_players;
}

uint64_t BotSteamId(unsigned index) {
    const uint64_t base = capture::GetConfig().bot_steam_id;
    const uint64_t prefix = base & 0xffffffff00000000ULL;
    const uint32_t account = static_cast<uint32_t>(base);
    const uint32_t derived = account >= index ? account - index : account + index;
    return prefix | derived;
}

bool TryGetBotName(uint64_t user, std::string& name) {
    unsigned index = 0;
    if (!TryBotIndex(user, index) ||
        index >= g_bot_count.load(std::memory_order_acquire)) return false;
    const unsigned harness_target = g_local_mission_harness_target.load(
        std::memory_order_acquire);
    name = (harness_target && index < harness_target
                ? "Harness Dummy " : "EDF Bot ") +
        std::to_string(index + 1);
    return true;
}

int EffectiveCreateLimit(int requested) {
    if (!Enabled()) return requested;
    return std::max(requested, static_cast<int>(MaxPlayers()));
}

int EffectiveMemberLimit(uint64_t lobby, int requested) {
    if (!Enabled() || lobby != g_owned_lobby.load(std::memory_order_acquire)) {
        return requested;
    }
    return std::max(requested, static_cast<int>(MaxPlayers()));
}

void NotifyCreateLobby(int requested, int effective) {
    if (!Enabled()) return;
    const uint64_t flow_id = EDF5_CAPTURE_NEXT_FLOW_ID();
    g_diagnostic_flow_id.store(flow_id, std::memory_order_release);
    g_create_pending.store(true, std::memory_order_release);
    g_owned_lobby.store(0, std::memory_order_release);
    g_join_lobby_pending.store(0, std::memory_order_release);
    g_chat_banner_lobby.store(0, std::memory_order_release);
    g_chat_banner_pending.store(false, std::memory_order_release);
    g_last_actual_member_count.store(-1, std::memory_order_release);
    g_mission_source_identity_repair_logged_mask.store(
        0, std::memory_order_release);
    g_mission_class_correction_logged_mask.store(
        0, std::memory_order_release);
    g_mission_visual_slot_remap_logged_mask.store(
        0, std::memory_order_release);
    g_mission_loadout_parser_calls.store(0,
                                          std::memory_order_release);
    g_mission_loadout_parser_protected_calls.store(
        0, std::memory_order_release);
    g_mission_loadout_parser_oob_calls.store(
        0, std::memory_order_release);
    ClearMissionExtraLoadoutSidecars();
    ResetReplicationParticipantTelemetry();
    ResetMissionRuntimeState();
    ClearSyntheticState(false);
    EDF5_CAPTURE_EVENT("more_players", "create_lobby_limit",
                   capture::Fields().UInt("flow_id", flow_id)
                       .Int("requested", requested)
                       .Int("effective", effective));
    PublishDiagnosticState("creating", true);
}

void NotifyJoinLobby(uint64_t lobby) {
    if (!Enabled() || !lobby) return;
    ClearMissionExtraLoadoutSidecars();
    g_create_pending.store(false, std::memory_order_release);
    g_join_lobby_pending.store(lobby, std::memory_order_release);
    g_chat_banner_lobby.store(0, std::memory_order_release);
    g_chat_banner_pending.store(false, std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "join_lobby_banner_pending",
                   capture::Fields()
                       .UInt("lobby_steam_id", lobby)
                       .Bool("waits_for_member_count", true)
                       .Bool("message_text_logged", false));
}

void ObserveLobbyDataWrite(uint64_t lobby, const char* key) {
    if (!Enabled() || !lobby || !key) return;
    if (std::strcmp(key, "public_slot") == 0 &&
        g_create_pending.exchange(false, std::memory_order_acq_rel)) {
        g_owned_lobby.store(lobby, std::memory_order_release);
        EDF5_CAPTURE_EVENT("more_players", "owned_lobby_detected",
                       capture::Fields().UInt("lobby_steam_id", lobby)
                           .UInt("max_players", MaxPlayers()));
        ArmChatBanner(lobby, "created");
        PublishDiagnosticState("room", true);
    }
}

void ObserveLeaveLobby(uint64_t lobby) {
    if (!lobby) return;
    uint64_t expected_join = lobby;
    g_join_lobby_pending.compare_exchange_strong(
        expected_join, 0, std::memory_order_acq_rel,
        std::memory_order_acquire);
    if (g_chat_banner_lobby.load(std::memory_order_acquire) == lobby) {
        g_chat_banner_pending.store(false, std::memory_order_release);
        g_chat_banner_lobby.store(0, std::memory_order_release);
    }
    if (g_owned_lobby.load(std::memory_order_acquire) != lobby) return;
    PublishDiagnosticState("leaving", true);
    CompleteMissionResultTransition("leave_lobby");
    g_owned_lobby.store(0, std::memory_order_release);
    g_last_actual_member_count.store(-1, std::memory_order_release);
    ResetReplicationParticipantTelemetry();
    ClearSyntheticState(false);
    g_diagnostic_flow_id.store(0, std::memory_order_release);
    PublishDiagnosticState("idle", true);
}

bool RewriteLobbyData(uint64_t lobby, const char* key, const char* value,
                      std::string& rewritten) {
    if (!Enabled() || !key || !value ||
        lobby != g_owned_lobby.load(std::memory_order_acquire)) return false;
    if (std::strcmp(key, "public_slot") == 0) {
        char* end = nullptr;
        long slots = std::strtol(value, &end, 10);
        if (!end || *end != '\0') return false;
        const long max_players = static_cast<long>(MaxPlayers());
        slots += max_players - 4;
        slots = std::max<long>(0, std::min(max_players, slots));
        rewritten = std::to_string(slots);
        return rewritten != value;
    }
    if (std::strcmp(key, "open_public") == 0) {
        char* end = nullptr;
        long slots = std::strtol(value, &end, 10);
        if (!end || *end != '\0') return false;
        const long max_players = static_cast<long>(MaxPlayers());
        slots += max_players - 4;
        slots = std::max<long>(0, std::min(max_players, slots));
        rewritten = std::to_string(slots);
        return rewritten != value;
    }
    return false;
}

int AdjustMemberCount(uint64_t lobby, int actual_count) {
    if (!AppliesToLobby(lobby) || actual_count < 0) return actual_count;
    const unsigned bots = g_bot_count.load(std::memory_order_acquire);
    if (!bots || actual_count >= static_cast<int>(MaxPlayers())) return actual_count;
    const int total = std::min<int>(static_cast<int>(MaxPlayers()),
                                    actual_count + static_cast<int>(bots));
    if (total == static_cast<int>(MaxPlayers())) {
        bool expected = false;
        if (g_room_full_reported.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            EDF5_CAPTURE_EVENT("more_players", "synthetic_room_full",
                           capture::Fields().UInt("lobby_steam_id", lobby)
                               .Int("actual_members", actual_count)
                               .UInt("synthetic_members", bots)
                               .Int("total_members", total)
                               .UInt("max_players", MaxPlayers()));
        }
    } else {
        g_room_full_reported.store(false, std::memory_order_release);
    }
    return total;
}

void ObserveMemberCount(uint64_t lobby, int actual_count) {
    if (Enabled() && lobby && actual_count > 0) {
        uint64_t expected_join = lobby;
        if (g_join_lobby_pending.compare_exchange_strong(
                expected_join, 0, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            ArmChatBanner(lobby, "joined");
        }
    }
    if (!Enabled() || actual_count < 0 ||
        lobby != g_owned_lobby.load(std::memory_order_acquire)) return;
    const int previous_actual = g_last_actual_member_count.exchange(
        actual_count, std::memory_order_acq_rel);
    std::vector<uint64_t> evicted;
    const unsigned harness_target =
        g_local_mission_harness_target.load(std::memory_order_acquire);
    const bool harness_conflict = harness_target != 0 && actual_count != 1;
    AcquireSRWLockExclusive(&g_state_lock);
    unsigned count = g_bot_count.load(std::memory_order_relaxed);
    const unsigned allowed = harness_conflict ||
            actual_count >= static_cast<int>(MaxPlayers())
        ? 0U : MaxPlayers() - static_cast<unsigned>(actual_count);
    while (count > allowed) {
        const uint64_t user = BotSteamId(count - 1);
        --count;
        ClearPeerTransportLocked(user);
        QueueMembershipChangeLocked(lobby, user, kMemberLeft);
        evicted.push_back(user);
    }
    g_bot_count.store(count, std::memory_order_release);
    const uint32_t active_mask = count ? ((uint32_t{1} << count) - 1) : 0;
    g_gameplay_contact_mask.fetch_and(active_mask, std::memory_order_acq_rel);
    if (!evicted.empty()) {
        ResetMissionGroupSync();
        g_all_gameplay_contact_reported.store(false, std::memory_order_release);
        g_room_full_reported.store(false, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    if (harness_conflict) {
        DisarmLocalMissionHarness("real player joined host-only harness",
                                  lobby);
    }
    for (uint64_t user : evicted) {
        EDF5_CAPTURE_EVENT("more_players", "bot_evicted_for_real_member",
                       capture::Fields().UInt("lobby_steam_id", lobby)
                           .Int("actual_members", actual_count)
                           .UInt("synthetic_members", count)
                           .UInt("max_players", MaxPlayers())
                           .UInt("bot_steam_id", user));
    }
    PublishDiagnosticState(nullptr,
                           previous_actual != actual_count || !evicted.empty());
}

bool TryGetSyntheticMember(uint64_t lobby, int actual_count, int index,
                           uint64_t& user) {
    if (!AppliesToLobby(lobby) || actual_count < 0 || index < actual_count) return false;
    const unsigned synthetic_index = static_cast<unsigned>(index - actual_count);
    const unsigned count = g_bot_count.load(std::memory_order_acquire);
    if (synthetic_index >= count || index >= static_cast<int>(MaxPlayers())) return false;
    user = BotSteamId(synthetic_index);
    return true;
}

bool TryGetMemberData(uint64_t lobby, uint64_t user, const char* key,
                      std::string& value) {
    unsigned index = 0;
    if (!AppliesToLobby(lobby) || !key || !TryBotIndex(user, index) ||
        index >= g_bot_count.load(std::memory_order_acquire)) return false;
    AcquireSRWLockShared(&g_state_lock);
    if (StartsWith(key, "usr")) value = g_member_template;
    else value.clear();
    ReleaseSRWLockShared(&g_state_lock);
    return true;
}

void CaptureLocalMemberData(const char* key, const char* value) {
    if (!Enabled() || !StartsWith(key, "usr") || !value || !*value) return;
    AcquireSRWLockExclusive(&g_state_lock);
    g_member_template = value;
    ReleaseSRWLockExclusive(&g_state_lock);
}

bool ConsumeMembershipChange(uint64_t& lobby, uint64_t& user,
                             uint32_t& state_change) {
    AcquireSRWLockShared(&g_state_lock);
    if (g_membership_changes.empty()) {
        ReleaseSRWLockShared(&g_state_lock);
        return false;
    }
    const MembershipChange change = g_membership_changes.front();
    ReleaseSRWLockShared(&g_state_lock);
    lobby = change.lobby;
    user = change.user;
    state_change = change.state;
    return true;
}

void MembershipChangeDelivered(uint64_t lobby, uint64_t user,
                               uint32_t state_change) {
    AcquireSRWLockExclusive(&g_state_lock);
    if (!g_membership_changes.empty()) {
        const MembershipChange& change = g_membership_changes.front();
        if (change.lobby == lobby && change.user == user &&
            change.state == state_change) g_membership_changes.pop_front();
    }
    ReleaseSRWLockExclusive(&g_state_lock);
}

bool IsSyntheticPeer(uint64_t peer) {
    unsigned index = 0;
    return TryBotIndex(peer, index) &&
           index < g_bot_count.load(std::memory_order_acquire);
}

bool IsSyntheticIdentity(uint64_t peer) {
    unsigned index = 0;
    return TryBotIndex(peer, index);
}

void ObserveRealP2PSend(uint64_t peer, int channel, size_t bytes, bool success) {
    if (!Enabled() || !success || !peer || channel != 0 ||
        !g_owned_lobby.load(std::memory_order_acquire)) {
        return;
    }
    const char* phase = g_diagnostic_phase.load(std::memory_order_acquire);
    if (!phase || (std::strcmp(phase, "room") != 0 &&
                   std::strcmp(phase, "ready") != 0 &&
                   std::strcmp(phase, "matching") != 0)) {
        return;
    }
    for (auto& slot : g_diagnostic_real_gameplay_peer_ids) {
        uint64_t observed = slot.load(std::memory_order_acquire);
        if (observed == peer) return;
        if (!observed && slot.compare_exchange_strong(
                             observed, peer, std::memory_order_acq_rel,
                             std::memory_order_acquire)) {
            const unsigned count =
                g_diagnostic_real_gameplay_peers.fetch_add(
                    1, std::memory_order_acq_rel) + 1;
            EDF5_CRASH_BREADCRUMB("flow", "real_gameplay_channel",
                                      "first_contact", peer, count);
            EDF5_CAPTURE_EVENT(
                "flow", "real_gameplay_peer_contacted",
                capture::Fields()
                    .UInt("peer_steam_id", peer)
                    .UInt("real_gameplay_peers", count)
                    .UInt("bytes", bytes)
                    .UInt("lobby_steam_id",
                          g_owned_lobby.load(std::memory_order_acquire)));
            PublishDiagnosticState("matching", true);
            return;
        }
        if (observed == peer) return;
    }
}

bool HandleSyntheticSend(uint64_t peer, const void* data, uint32_t size,
                         int send_type, int channel) {
    if (!IsSyntheticPeer(peer)) return false;
    EDF5_CAPTURE_EVENT("more_players", "bot_p2p_send",
                   capture::Fields().UInt("peer_steam_id", peer)
                       .Int("channel", channel).Int("send_type", send_type)
                       .UInt("bytes", size), data, size);
    if (channel == 0) {
        if (!g_mission_groups_synchronized.load(std::memory_order_acquire)) {
            g_mission_groups_pending.store(true, std::memory_order_release);
        }
        unsigned index = 0;
        if (TryBotIndex(peer, index) && index < 32) {
            const uint32_t bit = uint32_t{1} << index;
            const uint32_t previous = g_gameplay_contact_mask.fetch_or(
                bit, std::memory_order_acq_rel);
            const uint32_t contacted = previous | bit;
            if (!(previous & bit)) {
                EDF5_CRASH_BREADCRUMB("more_players", "gameplay_channel",
                                          "first_contact", peer, index + 1);
                EDF5_CAPTURE_EVENT("more_players", "bot_gameplay_channel_contacted",
                               capture::Fields().UInt("peer_steam_id", peer)
                                   .UInt("bot_number", index + 1)
                                   .UInt("contacted_mask", contacted)
                                   .UInt("bytes", size));
                PublishDiagnosticState("matching", true);
            }
            const unsigned count = g_bot_count.load(std::memory_order_acquire);
            const uint32_t active_mask = count ? ((uint32_t{1} << count) - 1) : 0;
            if (active_mask && (contacted & active_mask) == active_mask) {
                bool expected = false;
                if (g_all_gameplay_contact_reported.compare_exchange_strong(
                        expected, true, std::memory_order_acq_rel)) {
                    EDF5_CAPTURE_EVENT("more_players", "all_fillers_gameplay_contacted",
                                   capture::Fields().UInt(
                                       "lobby_steam_id",
                                       g_owned_lobby.load(std::memory_order_acquire))
                                       .UInt("synthetic_members", count)
                                       .UInt("contacted_mask", contacted));
                }
            }
        }
    }
    if (channel == 2) QueueHandshakeReply(peer, data, size, channel);
    return true;
}

bool PeekSyntheticPacket(int channel, uint32_t* size) {
    AcquireSRWLockShared(&g_state_lock);
    const auto found = std::find_if(
        g_packets.begin(), g_packets.end(),
        [channel](const SyntheticPacket& item) { return item.channel == channel; });
    const bool present = found != g_packets.end();
    if (present && size) *size = static_cast<uint32_t>(found->bytes.size());
    ReleaseSRWLockShared(&g_state_lock);
    return present;
}

bool ReadSyntheticPacket(void* destination, uint32_t capacity,
                         uint32_t* message_size, uint64_t* peer, int channel) {
    SyntheticPacket packet;
    bool found_packet = false;
    AcquireSRWLockExclusive(&g_state_lock);
    const auto found = std::find_if(
        g_packets.begin(), g_packets.end(),
        [channel](const SyntheticPacket& item) { return item.channel == channel; });
    if (found != g_packets.end()) {
        if (message_size) *message_size = static_cast<uint32_t>(found->bytes.size());
        if (destination && capacity >= found->bytes.size()) {
            packet = std::move(*found);
            g_packets.erase(found);
            found_packet = true;
        }
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    if (!found_packet) return false;
    std::memcpy(destination, packet.bytes.data(), packet.bytes.size());
    if (message_size) *message_size = static_cast<uint32_t>(packet.bytes.size());
    if (peer) *peer = packet.peer;
    EDF5_CAPTURE_EVENT("more_players", "bot_p2p_read",
                   capture::Fields().UInt("peer_steam_id", packet.peer)
                       .Int("channel", channel).UInt("bytes", packet.bytes.size()),
                   packet.bytes.data(), packet.bytes.size());
    return true;
}

void CloseSyntheticPeer(uint64_t peer) {
    if (!IsSyntheticIdentity(peer)) return;
    AcquireSRWLockExclusive(&g_state_lock);
    ClearPeerTransportLocked(peer);
    ReleaseSRWLockExclusive(&g_state_lock);
}

void QueueSyntheticAuthValidation(uint64_t user) {
    if (!IsSyntheticPeer(user)) return;
    AcquireSRWLockExclusive(&g_state_lock);
    if (g_auth_validations.size() >= 128) g_auth_validations.pop_front();
    g_auth_validations.push_back(user);
    ReleaseSRWLockExclusive(&g_state_lock);
}

bool ConsumeSyntheticAuthValidation(uint64_t& user) {
    AcquireSRWLockShared(&g_state_lock);
    if (g_auth_validations.empty()) {
        ReleaseSRWLockShared(&g_state_lock);
        return false;
    }
    user = g_auth_validations.front();
    ReleaseSRWLockShared(&g_state_lock);
    return true;
}

void SyntheticAuthValidationDelivered(uint64_t user) {
    AcquireSRWLockExclusive(&g_state_lock);
    if (!g_auth_validations.empty() && g_auth_validations.front() == user) {
        g_auth_validations.pop_front();
    }
    ReleaseSRWLockExclusive(&g_state_lock);
}

bool SelfTest(std::string& report) {
    constexpr uint64_t local_id = 76561198000000001ULL;
    constexpr uint64_t test_lobby = 109775241799999998ULL;
    if (g_started.load(std::memory_order_acquire) ||
        g_owned_lobby.load(std::memory_order_acquire) != 0) {
        report = "self-test refused during an active Steam session";
        return false;
    }
    if (!Enabled() || MaxPlayers() < 5) {
        report = "MorePlayers must be enabled with MaxPlayers >= 5";
        return false;
    }
    if (!mission_spawn::SelfTest(report)) return false;
    if (!mission_result_recovery::SelfTest(report)) return false;

    auto reset_state = [] {
        if (g_mission_loadout_block_patch.active) {
            RestoreTemporaryMissionLoadoutBlock();
        }
        g_running.store(false, std::memory_order_release);
        g_started.store(false, std::memory_order_release);
        g_create_pending.store(false, std::memory_order_release);
        g_owned_lobby.store(0, std::memory_order_release);
        g_join_lobby_pending.store(0, std::memory_order_release);
        g_chat_banner_lobby.store(0, std::memory_order_release);
        g_chat_banner_pending.store(false, std::memory_order_release);
        g_chat_banner_publish_attempts.store(
            0, std::memory_order_release);
        g_chat_banner_publish_successes.store(
            0, std::memory_order_release);
        g_chat_banner_wait_logged_mask.store(
            0, std::memory_order_release);
        g_chat_room_capture_count.store(0, std::memory_order_release);
        g_chat_room_instance.store(0, std::memory_order_release);
        g_last_actual_member_count.store(-1, std::memory_order_release);
        g_add_hotkey_test_override.store(-1, std::memory_order_release);
        g_remove_hotkey_test_override.store(-1, std::memory_order_release);
        g_ready_hotkey_test_override.store(-1, std::memory_order_release);
        g_invite_hotkey_test_override.store(-1, std::memory_order_release);
        g_local_mission_harness_hotkey_test_override.store(
            -1, std::memory_order_release);
        g_debug_stage_win_hotkey_test_override.store(
            -1, std::memory_order_release);
        g_scroll_hotkey_test_override.store(-1, std::memory_order_release);
        g_ready_user_test_mode.store(false, std::memory_order_release);
        g_scroll_test_mode.store(false, std::memory_order_release);
        g_scroll_test_calls.store(0, std::memory_order_release);
        g_suppress_hotkey_feedback.store(false, std::memory_order_release);
        g_last_loadout_log_signature.store(0, std::memory_order_release);
        g_last_room_model_tick.store(0, std::memory_order_release);
        g_player_info_return_contract_logged.store(
            false, std::memory_order_release);
        g_player_info_return_mismatch_count.store(
            0, std::memory_order_release);
        g_single_real_host_position.store(-1, std::memory_order_release);
        g_pending_wheel_detents.store(0, std::memory_order_release);
        g_pending_ready_lobby.store(0, std::memory_order_release);
        g_pending_ready_feedback.store(false, std::memory_order_release);
        g_debug_stage_win_test_set_calls.store(0,
                                               std::memory_order_release);
        g_mission_source_recycle_logged_mask.store(
            0, std::memory_order_release);
        g_mission_source_identity_repair_logged_mask.store(
            0, std::memory_order_release);
        g_mission_source_index_audit_logged_mask.store(
            0, std::memory_order_release);
        g_mission_source_consumer_audit_logged_mask.store(
            0, std::memory_order_release);
        g_mission_null_character_guard_logged_mask.store(
            0, std::memory_order_release);
        g_mission_player_control_audit_logged_mask.store(
            0, std::memory_order_release);
        g_mission_class_correction_logged_mask.store(
            0, std::memory_order_release);
        g_mission_visual_slot_remap_logged_mask.store(
            0, std::memory_order_release);
        g_mission_loadout_parser_calls.store(
            0, std::memory_order_release);
        g_mission_loadout_parser_protected_calls.store(
            0, std::memory_order_release);
        g_mission_loadout_parser_oob_calls.store(
            0, std::memory_order_release);
        g_mission_source_primary_snapshot = {};
        g_mission_source_local_snapshot = {};
        g_mission_player_create_trace = {};
        g_mission_loadout_parser_protection.active = false;
        g_mission_loadout_parser_protection.state = nullptr;
        g_mission_loadout_parser_protection.bytes = 0;
        ResetReplicationParticipantTelemetry();
        g_diagnostic_flow_id.store(0, std::memory_order_release);
        g_diagnostic_progress_tick.store(0, std::memory_order_release);
        g_diagnostic_ready_mask.store(0, std::memory_order_release);
        g_diagnostic_mission_group_mask.store(0,
                                              std::memory_order_release);
        g_diagnostic_phase.store("idle", std::memory_order_release);
        ResetMissionRuntimeState();
        g_mission_update = nullptr;
        g_mission_loadout_parser = nullptr;
        g_mission_participant_class_resolver = nullptr;
        g_mission_result_setter = nullptr;
        g_mission_result_apply = nullptr;
        g_mission_result_event_publish = nullptr;
        g_mission_result_ui_event_dispatch = nullptr;
        g_mission_result_exec_begin = nullptr;
        g_mission_result_exec_update = nullptr;
        g_mission_result_exec_finally = nullptr;
        g_enemy_spawn = nullptr;
        g_generator_poll_update = nullptr;
        g_generator_poll_gate = nullptr;
        g_generator_poll_spawn = nullptr;
        g_mission_result_item_sink = nullptr;
        g_mission_named_sync_begin = nullptr;
        g_mission_named_sync_poll = nullptr;
        g_mission_reward_resolve = nullptr;
        g_mission_reward_apply = nullptr;
        g_fake_mission_result_exec_begin_calls.store(
            0, std::memory_order_release);
        g_fake_mission_result_exec_begin_argument.store(
            0, std::memory_order_release);
        g_fake_mission_result_exec_update_calls.store(
            0, std::memory_order_release);
        g_fake_mission_result_exec_update_argument.store(
            0, std::memory_order_release);
        g_fake_mission_result_exec_update_result.store(
            false, std::memory_order_release);
        g_fake_mission_result_exec_finally_calls.store(
            0, std::memory_order_release);
        g_fake_mission_result_exec_finally_argument.store(
            0, std::memory_order_release);
        g_fake_replication_route_register_calls.store(
            0, std::memory_order_release);
        g_fake_replication_route_unregister_calls.store(
            0, std::memory_order_release);
        g_fake_enemy_spawn_calls.store(0, std::memory_order_release);
        g_fake_enemy_spawn_requested_count.store(
            0, std::memory_order_release);
        g_fake_enemy_spawn_numerator_seen.store(
            0, std::memory_order_release);
        g_fake_generator_poll_spawn_calls.store(
            0, std::memory_order_release);
        g_fake_generator_poll_update_calls.store(
            0, std::memory_order_release);
        g_fake_generator_poll_gate_calls.store(
            0, std::memory_order_release);
        g_fake_generator_poll_spawn_result.store(
            0, std::memory_order_release);
        g_fake_generator_poll_spawn_owner = nullptr;
        g_fake_mission_result_item_sink_calls.store(
            0, std::memory_order_release);
        g_fake_mission_result_event_publish_calls.store(
            0, std::memory_order_release);
        g_fake_mission_result_event_type.store(
            0, std::memory_order_release);
        g_fake_mission_result_event_payload.store(
            0, std::memory_order_release);
        g_fake_mission_result_ui_dispatch_calls.store(
            0, std::memory_order_release);
        g_fake_mission_sync_begin_calls.store(
            0, std::memory_order_release);
        g_fake_mission_sync_poll_calls.store(
            0, std::memory_order_release);
        g_fake_mission_reward_resolve_calls.store(
            0, std::memory_order_release);
        g_fake_mission_reward_apply_calls.store(
            0, std::memory_order_release);
        g_fake_mission_source_consumer_loadout_index.store(
            -1, std::memory_order_release);
        g_fake_mission_update_override.store(
            -1, std::memory_order_release);
        g_fake_mission_loadout_parser_calls.store(
            0, std::memory_order_release);
        g_fake_mission_class_resolver_calls.store(
            0, std::memory_order_release);
        g_fake_mission_class_resolver_index.store(
            4, std::memory_order_release);
        g_fake_mission_class_resolver_class.store(
            0, std::memory_order_release);
        g_fake_player_info_from_user_calls.store(
            0, std::memory_order_release);
        g_fake_chat_system_publish_calls.store(
            0, std::memory_order_release);
        g_fake_chat_system_publish_valid.store(
            true, std::memory_order_release);
        g_fake_chat_expected_room_instance.store(
            0, std::memory_order_release);
        g_mission_manager_slot = nullptr;
        g_mission_loadout_state_slot = nullptr;
        g_mission_result_event_publisher_slot = nullptr;
        g_fake_mission_result_ui_object = nullptr;
        g_mission_source_consumer = nullptr;
        g_player_info_from_user = nullptr;
        g_gameplay_replication_producer = nullptr;
        g_gameplay_replication_receive_pump = nullptr;
        g_gameplay_replication_receive_parser = nullptr;
        g_gameplay_replication_receive_route_register = nullptr;
        g_gameplay_replication_receive_route_unregister = nullptr;
        g_chat_room_constructor = nullptr;
        g_chat_message_publish = nullptr;
        g_chat_system_message_publish = nullptr;
        g_mission_script_message_dispatch = nullptr;
        ClearSyntheticState(true);
        ClearReadyUsers();
    };
    reset_state();
    auto fail = [&report, &reset_state](const char* message) {
        report = message;
        if (g_started.load(std::memory_order_acquire)) Stop();
        reset_state();
        return false;
    };

    {
        std::array<uint8_t, kPlayerInfoSize> destination{};
        g_player_info_from_user = &FakePlayerInfoFromUser;
        uint8_t* const returned = PlayerInfoFromUserHook(
            destination.data(), nullptr);
        if (returned != destination.data() ||
            g_fake_player_info_from_user_calls.load(
                std::memory_order_acquire) != 1 ||
            g_player_info_return_mismatch_count.load(
                std::memory_order_acquire) != 0) {
            return fail("PlayerInfo hook did not preserve the native return value in RAX");
        }
        g_player_info_from_user = nullptr;
    }

    {
        g_gameplay_replication_receive_route_register =
            &FakeReplicationReceiveRouteRegister;
        g_gameplay_replication_receive_route_unregister =
            &FakeReplicationReceiveRouteUnregister;
        const bool registered = GameplayReplicationReceiveRouteRegisterHook(
            nullptr, nullptr);
        const bool unregistered =
            GameplayReplicationReceiveRouteUnregisterHook(
                nullptr, nullptr);
        if (!registered || unregistered ||
            g_fake_replication_route_register_calls.load(
                std::memory_order_acquire) != 1 ||
            g_fake_replication_route_unregister_calls.load(
                std::memory_order_acquire) != 1 ||
            g_replication_receive_route_register_calls.load(
                std::memory_order_acquire) != 1 ||
            g_replication_receive_route_unregister_calls.load(
                std::memory_order_acquire) != 1) {
            return fail(
                "route lifecycle hooks did not preserve native bool/ABI");
        }
        g_gameplay_replication_receive_route_register = nullptr;
        g_gameplay_replication_receive_route_unregister = nullptr;
        ResetReplicationParticipantTelemetry();
    }

    {
        g_mission_result_exec_update = &FakeMissionResultExecUpdate;
        g_mission_result_exec_finally = &FakeMissionResultExecFinally;
        g_fake_mission_result_exec_update_result.store(
            false, std::memory_order_release);
        const bool first_update = MissionResultExecUpdateHook(101, nullptr);
        g_fake_mission_result_exec_update_result.store(
            true, std::memory_order_release);
        const bool second_update = MissionResultExecUpdateHook(202, nullptr);
        MissionResultExecFinallyHook(303);
        if (first_update || !second_update ||
            g_fake_mission_result_exec_update_calls.load(
                std::memory_order_acquire) != 2 ||
            g_fake_mission_result_exec_update_argument.load(
                std::memory_order_acquire) != 202 ||
            g_fake_mission_result_exec_finally_calls.load(
                std::memory_order_acquire) != 1 ||
            g_fake_mission_result_exec_finally_argument.load(
                std::memory_order_acquire) != 303 ||
            g_mission_result_exec_update_calls.load(
                std::memory_order_acquire) != 2 ||
            g_mission_result_exec_update_true_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_result_exec_update_false_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_result_exec_finally_calls.load(
                std::memory_order_acquire) != 1 ||
            MissionResultExecUpdateOriginForCaller(
                kMissionResultExecUpdateScriptReturnRva) !=
                MissionResultExecCallerOrigin::ResultSyncWrapper ||
            MissionResultExecUpdateOriginForCaller(
                kMissionResultExecUpdateNativeReturnRva) !=
                MissionResultExecCallerOrigin::NativeMission ||
            MissionResultExecFinallyOriginForCaller(
                kMissionResultExecFinallyScriptReturnRva) !=
                MissionResultExecCallerOrigin::ResultSyncWrapper ||
            MissionResultExecFinallyOriginForCaller(
                kMissionResultExecFinallyNativeReturnRva) !=
                MissionResultExecCallerOrigin::NativeMission) {
            return fail(
                "ResultSync_Update/Finally hooks did not preserve ABI/origin");
        }
        g_mission_result_exec_update = nullptr;
        g_mission_result_exec_finally = nullptr;
        ResetMissionResultExecPipelineTelemetry();
    }

    {
        constexpr uint64_t joined_lobby = test_lobby + 20;
        constexpr uint64_t created_lobby = test_lobby + 21;
        void* const fake_room =
            reinterpret_cast<void*>(uintptr_t{1});
        g_fake_chat_expected_room_instance.store(
            reinterpret_cast<uintptr_t>(fake_room),
            std::memory_order_release);
        g_chat_system_message_publish =
            &FakeChatSystemMessagePublish;

        NotifyJoinLobby(joined_lobby);
        if (g_chat_banner_pending.load(std::memory_order_acquire)) {
            return fail("join chat banner was armed before confirmed entry");
        }
        ObserveMemberCount(joined_lobby, 1);
        if (!g_chat_banner_pending.load(std::memory_order_acquire) ||
            g_chat_banner_lobby.load(std::memory_order_acquire) !=
                joined_lobby) {
            return fail("join chat banner was not armed after confirmed entry");
        }
        if (TryPublishChatBannerFromCapturedRoom(true) ||
            !g_chat_banner_pending.load(std::memory_order_acquire) ||
            g_fake_chat_system_publish_calls.load(
                std::memory_order_acquire) != 0) {
            return fail("local banner did not wait for Chat_Room");
        }
        CaptureChatRoomInstance(fake_room, true);
        if (!TryPublishChatBannerFromCapturedRoom(true) ||
            g_fake_chat_system_publish_calls.load(
                std::memory_order_acquire) != 3 ||
            !g_fake_chat_system_publish_valid.load(
                std::memory_order_acquire) ||
            g_chat_banner_pending.load(std::memory_order_acquire) ||
            g_chat_banner_publish_attempts.load(
                std::memory_order_acquire) != 1 ||
            g_chat_banner_publish_successes.load(
                std::memory_order_acquire) != 1) {
            return fail("local mod banner was not published on room entry");
        }
        if (TryPublishChatBannerFromCapturedRoom(true) ||
            g_fake_chat_system_publish_calls.load(
                std::memory_order_acquire) != 3) {
            return fail("local mod banner was duplicated in the same room");
        }
        ObserveLeaveLobby(joined_lobby);

        NotifyCreateLobby(4, static_cast<int>(MaxPlayers()));
        ObserveLobbyDataWrite(created_lobby, "public_slot");
        if (!g_chat_banner_pending.load(std::memory_order_acquire) ||
            g_chat_banner_lobby.load(std::memory_order_acquire) !=
                created_lobby ||
            !TryPublishChatBannerFromCapturedRoom(true) ||
            g_fake_chat_system_publish_calls.load(
                std::memory_order_acquire) != 6 ||
            g_chat_banner_publish_successes.load(
                std::memory_order_acquire) != 2) {
            return fail("local mod banner was not published on room creation");
        }
        ObserveLeaveLobby(created_lobby);
        g_chat_room_instance.store(0, std::memory_order_release);
        g_chat_system_message_publish = nullptr;
        g_fake_chat_expected_room_instance.store(
            0, std::memory_order_release);
    }

    {
        for (uint64_t index = 0; index < 4; ++index) {
            if (MissionSourceIndexForCall(index,
                                          kMissionSourceLookupReturnRva,
                                          4, true) !=
                index) {
                return fail("source lookup changed one of the four native players");
            }
        }
        if (MissionSourceIndexForCall(4, kMissionSourceLookupReturnRva,
                                      4, false) != 0 ||
            MissionSourceIndexForCall(4,
                                      kMissionSourceLookupReturnRva + 1,
                                      4, false) != 4 ||
            MissionSourceIndexForCall(5,
                                      kMissionSourceLookupReturnRva,
                                      4, false) != 1 ||
            MissionSourceIndexForCall(6,
                                      kMissionSourceLookupReturnRva,
                                      4, false) != 2 ||
            MissionSourceIndexForCall(7,
                                      kMissionSourceLookupReturnRva,
                                      4, false) != 3 ||
            MissionSourceIndexForCall(4,
                                      kMissionSourceLookupReturnRva,
                                      5, true) != 4 ||
            MissionSourceIndexForCall(5,
                                      kMissionSourceLookupReturnRva,
                                      6, true) != 5 ||
            MissionSourceIndexForCall(4,
                                      kMissionSourceLookupReturnRva,
                                      5, false) != 0 ||
            MissionSourceIndexForCall(4,
                                      kMissionSourceTransferReturnRva,
                                      4, false) != 4 ||
            MissionSourceIndexForCall(7,
                                      kMissionSourceTransferReturnRva,
                                      4, false) != 7 ||
            MissionSourceIndexForCall(4,
                                      kMissionSourceAppendReturnRva,
                                      4, false) != 4 ||
            MissionSourceIndexForCall(7,
                                      kMissionSourceAppendReturnRva,
                                      4, false) != 7) {
            return fail("dynamic/fallback source lookup produced an incorrect index");
        }
        if (MissionPlayerCreateContextIndex(
                kMissionPlayerCreatePrimaryReturnRva) != 0 ||
            MissionPlayerCreateContextIndex(
                kMissionPlayerCreateSecondaryReturnRva) != 1 ||
            MissionPlayerCreateContextIndex(
                kMissionPlayerCreatePrimaryReturnRva + 1) != -1 ||
            MissionPlayerControlAuditBit(0, 0) != 0x00000001U ||
            MissionPlayerControlAuditBit(0, 7) != 0x00000080U ||
            MissionPlayerControlAuditBit(1, 0) != 0x00000100U ||
            MissionPlayerControlAuditBit(1, 7) != 0x00008000U ||
            MissionPlayerControlAuditBit(1, 8) != 0x80000000U ||
            MissionPlayerControlAuditBit(-1, 0) != 0x80000000U) {
            return fail("mission control assignment classification failed");
        }
    }

    {
        struct FakeMissionSourceUser {
            void** vtable = nullptr;
            std::array<uint8_t,
                       kUserLocalControllerIndexOffset - sizeof(void*)>
                padding{};
            int32_t local_controller_index = -1;
        };
        static_assert(offsetof(FakeMissionSourceUser,
                               local_controller_index) ==
                          kUserLocalControllerIndexOffset,
                      "UserImpl fixture lost the local control offset");
        std::array<void*, 11> fake_vtable{};
        fake_vtable[10] = reinterpret_cast<void*>(
            &FakeRuntimeUserIdGetter);
        std::array<FakeMissionSourceUser, 5> users{};
        std::array<unsigned, 5> controls{};
        std::array<unsigned, 5> allocator_owners{};
        std::array<SharedProperty, 5> entries{};
        struct FakeSharedPropertyControl {
            int32_t strong_refs = 1;
            int32_t weak_refs = 1;
            void* object = nullptr;
        };
        static_assert(offsetof(FakeSharedPropertyControl, object) ==
                          kSharedPropertyControlObjectOffset,
                      "fixture lost the control block pointer");
        std::array<FakeSharedPropertyControl, 5> receive_user_controls{};
        std::array<std::array<uint8_t,
                              kGameplayReplicationReceiveRouteUserControlOffset +
                                  sizeof(void*)>, 5>
            receive_route_objects{};
        std::array<SharedProperty, 5> receive_entries{};
        g_runtime_user_vtable = fake_vtable.data();
        for (unsigned index = 0; index < users.size(); ++index) {
            users[index].vtable = fake_vtable.data();
            users[index].local_controller_index = 0;
            const uint64_t user_id = 10000 + index;
            std::memcpy(reinterpret_cast<uint8_t*>(&users[index]) +
                            kUserMissionSortKeyOffset,
                        &user_id, sizeof(user_id));
            const int32_t loadout_index = static_cast<int32_t>(index);
            std::memcpy(reinterpret_cast<uint8_t*>(&users[index]) +
                            kUserMissionLoadoutIndexOffset,
                        &loadout_index, sizeof(loadout_index));
            const int32_t transport_route_index =
                static_cast<int32_t>(index);
            std::memcpy(reinterpret_cast<uint8_t*>(&users[index]) +
                            kUserTransportRouteIndexOffset,
                        &transport_route_index,
                        sizeof(transport_route_index));
            controls[index] = index + 1;
            entries[index].control = &controls[index];
            entries[index].object = &users[index];
            receive_user_controls[index].object = &users[index];
            void* const receive_user_control =
                &receive_user_controls[index];
            std::memcpy(
                receive_route_objects[index].data() +
                    kGameplayReplicationReceiveRouteUserControlOffset,
                &receive_user_control, sizeof(receive_user_control));
            receive_entries[index].control = &controls[index];
            receive_entries[index].object =
                receive_route_objects[index].data();
            RegisterReadyUser(&users[index]);
            allocator_owners[index] = 100 + index;
            RecordTransportRouteAllocatorOwner(
                &users[index], &allocator_owners[index]);
        }
        MissionSourceVector primary{};
        primary.entries = entries.data();
        primary.capacity = entries.size();
        primary.size = entries.size();
        std::array<std::array<uint8_t, kPlayerInfoSize>, 5>
            observed_player_info{};
        const std::array<int32_t, 5> selected_classes = {0, 2, 3, 0, 1};
        const std::array<const wchar_t*, 5> display_names = {
            L"Host", L"Ranger", L"Fencer", L"Raider", L"Wing",
        };
        for (unsigned index = 0; index < users.size(); ++index) {
            const uint64_t name_length = std::wcslen(display_names[index]);
            const uint64_t name_capacity = kPlayerInfoNameInlineCapacity;
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoNameStorageOffset,
                        display_names[index],
                        static_cast<size_t>(name_length) * sizeof(wchar_t));
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoNameLengthOffset,
                        &name_length, sizeof(name_length));
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoNameCapacityOffset,
                        &name_capacity, sizeof(name_capacity));
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoClassOffset,
                        &selected_classes[index], sizeof(int32_t));
            std::array<int32_t, kMissionLoadoutWeaponCount> weapons{};
            for (unsigned weapon = 0; weapon < weapons.size(); ++weapon) {
                weapons[weapon] = static_cast<int32_t>(
                    1000 + index * 10 + weapon);
            }
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoWeaponsOffset,
                        weapons.data(), sizeof(weapons));
            const float armor = index == 4
                ? 456.0f
                : 100.0f + static_cast<float>(index);
            std::memcpy(observed_player_info[index].data() +
                            kPlayerInfoArmorOffset,
                        &armor, sizeof(armor));
            RecordPlayerInfoObservation(
                &users[index], observed_player_info[index].data());
        }
        std::array<uint32_t, 5> observed_name_tokens{};
        for (unsigned index = 0; index < users.size(); ++index) {
            const PlayerInfoObservation observation =
                FindPlayerInfoObservation(&users[index]);
            if (!observation.name_valid || !observation.name_token ||
                observation.name_length !=
                    std::wcslen(display_names[index]) ||
                observation.shared_name_user_count != 1 ||
                observation.source_mission_loadout_index !=
                    static_cast<int32_t>(index) ||
                observation.shared_loadout_index_user_count != 1 ||
                observation.transport_route_index !=
                    static_cast<int32_t>(index) ||
                observation.shared_transport_route_index_user_count != 1 ||
                std::find(observed_name_tokens.begin(),
                          observed_name_tokens.begin() + index,
                          observation.name_token) !=
                    observed_name_tokens.begin() + index) {
                return fail(
                    "duplicate or invalid private PlayerInfo name token");
            }
            observed_name_tokens[index] = observation.name_token;
        }
        ResetReplicationParticipantTelemetry();
        for (unsigned index = 0; index < users.size(); ++index) {
            RegisterMissionParticipantUser(
                static_cast<int32_t>(index), &users[index]);
        }
        const uint64_t fifth_chat_sender_id = 10004;
        const ChatNameAssociation correct_chat_name =
            InspectChatNameAssociation(
                &fifth_chat_sender_id, display_names[4]);
        const ChatNameAssociation collided_chat_name =
            InspectChatNameAssociation(
                &fifth_chat_sender_id, display_names[0]);
        if (!correct_chat_name.sender_resolved ||
            correct_chat_name.sender_registered_order != 4 ||
            !correct_chat_name.display_name_resolved ||
            !correct_chat_name.name_matches_sender ||
            correct_chat_name.sender_participant_index != 4 ||
            correct_chat_name.display_name_owner_participant_index != 4 ||
            correct_chat_name.expected_name_token !=
                observed_name_tokens[4] ||
            correct_chat_name.display_name_token !=
                observed_name_tokens[4] ||
            !collided_chat_name.sender_resolved ||
            collided_chat_name.name_matches_sender ||
            collided_chat_name.sender_participant_index != 4 ||
            collided_chat_name.display_name_owner_participant_index != 0 ||
            collided_chat_name.display_name_owner_registered_order != 0 ||
            collided_chat_name.expected_name_token !=
                observed_name_tokens[4] ||
            collided_chat_name.display_name_token !=
                observed_name_tokens[0]) {
            return fail(
                "private chat sender/name audit did not detect a collision");
        }
        const ReplicationParticipantMapAudit unique_replication_map =
            InspectReplicationParticipantMap();
        RegisterMissionParticipantUser(4, &users[0]);
        const ReplicationParticipantMapAudit collided_replication_map =
            InspectReplicationParticipantMap();
        RegisterMissionParticipantUser(4, &users[4]);
        if (ReplicationFamilyIndex(0x3300) != 0 ||
            ReplicationFamilyIndex(0x33ff) != 0 ||
            ReplicationFamilyIndex(0x3400) != 1 ||
            ReplicationFamilyIndex(0x34ff) != 1 ||
            ReplicationFamilyIndex(0x3500) != -1 ||
            MissionParticipantIndexForUser(&users[0]) != 0 ||
            MissionParticipantIndexForUser(&users[4]) != 4 ||
            unique_replication_map.mapped_users != users.size() ||
            unique_replication_map.unique_users != users.size() ||
            unique_replication_map.duplicate_participant_mask != 0 ||
            collided_replication_map.mapped_users != users.size() ||
            collided_replication_map.unique_users != users.size() - 1 ||
            collided_replication_map.duplicate_participant_mask !=
                (uint32_t{1} << 4)) {
            return fail(
                "private replication family association failed");
        }
        UnregisterMissionParticipantUser(&users[4]);
        if (MissionParticipantIndexForUser(&users[4]) != -1) {
            return fail(
                "replication association survived user destruction");
        }
        RegisterMissionParticipantUser(4, &users[4]);
        g_mission_local_participant_mask.store(
            uint32_t{1}, std::memory_order_release);
        void* const first_receive_route_object =
            receive_entries[0].object;
        receive_entries[0].object = nullptr;
        const ReplicationReceiveRouteAudit complete_receive_routes =
            AuditGameplayReplicationReceiveEntries(
                receive_entries.data(), receive_entries.size(), true);
        void* const second_receive_user_control =
            &receive_user_controls[1];
        std::memcpy(
            receive_route_objects[4].data() +
                kGameplayReplicationReceiveRouteUserControlOffset,
            &second_receive_user_control,
            sizeof(second_receive_user_control));
        const ReplicationReceiveRouteAudit duplicate_receive_routes =
            AuditGameplayReplicationReceiveEntries(
                receive_entries.data(), receive_entries.size(), true);
        void* const fifth_receive_user_control =
            &receive_user_controls[4];
        std::memcpy(
            receive_route_objects[4].data() +
                kGameplayReplicationReceiveRouteUserControlOffset,
            &fifth_receive_user_control,
            sizeof(fifth_receive_user_control));
        void* const second_receive_route_object =
            receive_entries[1].object;
        receive_entries[1].object = nullptr;
        const ReplicationReceiveRouteAudit missing_remote_receive_routes =
            AuditGameplayReplicationReceiveEntries(
                receive_entries.data(), receive_entries.size(), true);
        receive_entries[1].object = second_receive_route_object;
        receive_entries[0].object = first_receive_route_object;
        std::array<uint8_t,
                   kGameplayReplicationReceiveParserRouteOwnerOffset +
                       sizeof(void*)>
            receive_parser{};
        void* const fifth_route_object =
            receive_route_objects[4].data();
        std::memcpy(
            receive_parser.data() +
                kGameplayReplicationReceiveParserRouteOwnerOffset,
            &fifth_route_object, sizeof(fifth_route_object));
        void* const parser_resolved_user =
            ResolveReplicationReceiveParserUser(receive_parser.data());
        if (complete_receive_routes.route_count != users.size() ||
            complete_receive_routes.runtime_user_count != users.size() - 1 ||
            complete_receive_routes.unique_user_count != users.size() - 1 ||
            complete_receive_routes.empty_slot_count != 1 ||
            complete_receive_routes.local_participant_mask != 0x01U ||
            complete_receive_routes.expected_participant_mask != 0x1eU ||
            complete_receive_routes.participant_mask != 0x1eU ||
            complete_receive_routes.missing_participant_mask != 0 ||
            complete_receive_routes.unexpected_participant_mask != 0 ||
            complete_receive_routes.duplicate_participant_mask != 0 ||
            complete_receive_routes.duplicate_route_mask != 0 ||
            complete_receive_routes.transport_route_index_mismatch_mask != 0 ||
            !complete_receive_routes.participant_identity_unique ||
            !complete_receive_routes.transport_route_indices_match_slots ||
            complete_receive_routes.route_to_participant[0] != -1 ||
            complete_receive_routes.route_to_participant[4] != 4 ||
            complete_receive_routes.route_transport_indices[0] != -1 ||
            complete_receive_routes.route_transport_indices[4] != 4 ||
            !complete_receive_routes.route_complete ||
            duplicate_receive_routes.unique_user_count != users.size() - 2 ||
            duplicate_receive_routes.participant_mask != 0x0eU ||
            duplicate_receive_routes.missing_participant_mask != 0x10U ||
            duplicate_receive_routes.unexpected_participant_mask != 0 ||
            duplicate_receive_routes.duplicate_participant_mask != 0x02U ||
            duplicate_receive_routes.duplicate_route_mask != 0x10U ||
            duplicate_receive_routes.transport_route_index_mismatch_mask !=
                0x10U ||
            duplicate_receive_routes.transport_route_indices_match_slots ||
            duplicate_receive_routes.participant_identity_unique ||
            duplicate_receive_routes.route_complete ||
            missing_remote_receive_routes.empty_slot_count != 2 ||
            missing_remote_receive_routes.participant_mask != 0x1cU ||
            missing_remote_receive_routes.missing_participant_mask != 0x02U ||
            missing_remote_receive_routes.unexpected_participant_mask != 0 ||
            missing_remote_receive_routes.duplicate_participant_mask != 0 ||
            missing_remote_receive_routes.duplicate_route_mask != 0 ||
            missing_remote_receive_routes.transport_route_index_mismatch_mask !=
                0 ||
            !missing_remote_receive_routes.transport_route_indices_match_slots ||
            missing_remote_receive_routes.route_complete ||
            parser_resolved_user != &users[4] ||
            FindTransportRouteAllocatorOwner(&users[4]) !=
                &allocator_owners[4]) {
            return fail(
                "dynamic receive table audit did not detect a missing/duplicate route");
        }
        const int32_t collided_transport_route_index = 0;
        std::memcpy(reinterpret_cast<uint8_t*>(&users[4]) +
                        kUserTransportRouteIndexOffset,
                    &collided_transport_route_index,
                    sizeof(collided_transport_route_index));
        const MissionSourceTableAudit collided_transport_routes =
            AuditMissionSourceTable(&primary);
        const int32_t restored_transport_route_index = 4;
        std::memcpy(reinterpret_cast<uint8_t*>(&users[4]) +
                        kUserTransportRouteIndexOffset,
                    &restored_transport_route_index,
                    sizeof(restored_transport_route_index));
        if (!collided_transport_routes.transport_route_indices_complete ||
            collided_transport_routes.transport_route_indices_unique ||
            collided_transport_routes.transport_route_index_mask != 0x0fU ||
            collided_transport_routes
                    .duplicate_transport_route_participant_mask != 0x11U) {
            return fail(
                "source audit did not detect a transport route index collision");
        }
        std::array<GameplayReplicationTargetDescriptor, 4>
            send_target_descriptors{};
        for (size_t target = 0; target < send_target_descriptors.size();
             ++target) {
            send_target_descriptors[target].opaque_route_key =
                static_cast<uint32_t>(100 + target);
            send_target_descriptors[target].transport_route_index =
                static_cast<int32_t>(target + 1);
        }
        GameplayReplicationTargetVector send_targets{};
        send_targets.entries = send_target_descriptors.data();
        send_targets.capacity = 4;
        send_targets.size = 4;
        const ReplicationSendTargetAudit complete_send_targets =
            AuditReplicationSendTargets(&send_targets);
        send_target_descriptors[3].transport_route_index = 1;
        const ReplicationSendTargetAudit duplicate_send_targets =
            AuditReplicationSendTargets(&send_targets);
        send_target_descriptors[3].transport_route_index = 4;
        if (!complete_send_targets.vector_shape_valid ||
            !complete_send_targets.entries_readable ||
            complete_send_targets.target_count != 4 ||
            complete_send_targets.valid_transport_route_count != 4 ||
            complete_send_targets.unique_transport_route_count != 4 ||
            complete_send_targets.duplicate_transport_route_target_mask != 0 ||
            complete_send_targets.duplicate_participant_target_mask != 0 ||
            complete_send_targets.unresolved_target_mask != 0 ||
            complete_send_targets.target_participant_mask != 0x1eU ||
            !complete_send_targets.target_transport_routes_unique ||
            !complete_send_targets.target_participants_resolved ||
            duplicate_send_targets.unique_transport_route_count != 3 ||
            duplicate_send_targets.duplicate_transport_route_target_mask !=
                0x08U ||
            duplicate_send_targets.duplicate_participant_target_mask !=
                0x08U ||
            duplicate_send_targets.target_participant_mask != 0x0eU ||
            duplicate_send_targets.target_transport_routes_unique ||
            duplicate_send_targets.target_participants_resolved ||
            MissionParticipantIndexForTransportRoute(0) != 0 ||
            MissionParticipantIndexForTransportRoute(4) != 4 ||
            MissionParticipantIndexForTransportRoute(7) != -1) {
            return fail(
                "fan-out audit did not detect a missing/duplicate target");
        }
        MaybeActivateReplicationParticipantMap(users.size());
        RecordReplicationParticipantMessage(true, 0x3300, &users[0]);
        RecordReplicationParticipantMessage(false, 0x3400, &users[4]);
        if (!g_replication_participant_map_ready.load(
                std::memory_order_acquire) ||
            g_replication_message_counts[0][0][0].load(
                std::memory_order_acquire) != 1 ||
            g_replication_message_counts[1][1][4].load(
                std::memory_order_acquire) != 1 ||
            g_replication_message_counts[0][0]
                                        [kReplicationUnknownParticipant]
                .load(std::memory_order_acquire) != 0 ||
            g_replication_message_counts[1][1]
                                        [kReplicationUnknownParticipant]
                .load(std::memory_order_acquire) != 0) {
            return fail(
                "private per-participant replication count failed");
        }

        g_mission_participant_class_resolver =
            &FakeMissionParticipantClassResolver;
        g_fake_mission_class_resolver_index.store(
            4, std::memory_order_release);
        g_fake_mission_class_resolver_class.store(
            0, std::memory_order_release);
        int32_t resolved_participant_index = -1;
        int32_t resolved_participant_class = -1;
        uint8_t resolved_participant = 0;
        MissionParticipantClassResolverHook(
            nullptr, &resolved_participant_index,
            &resolved_participant_class, nullptr,
            &resolved_participant);
        if (resolved_participant_index != 0 ||
            resolved_participant_class != selected_classes[4] ||
            !resolved_participant ||
            g_fake_mission_class_resolver_calls.load(
                std::memory_order_acquire) != 1 ||
            !(g_mission_class_correction_logged_mask.load(
                  std::memory_order_acquire) & (uint32_t{1} << 4)) ||
            !(g_mission_visual_slot_remap_logged_mask.load(
                  std::memory_order_acquire) & (uint32_t{1} << 4))) {
            return fail(
                "side resolver did not preserve the class or remap P4 visuals");
        }
        g_mission_participant_class_resolver = nullptr;

        std::vector<uint8_t> fake_loadout_state(
            kMissionExtraLoadoutBeginOffset +
                kMissionExtraLoadoutSpan,
            0);
        for (unsigned index = 0; index < kNativeMissionSourceCount;
             ++index) {
            const size_t base = index * kMissionClassLoadoutStride;
            const int32_t selected = 0;
            const int32_t resource = 100 + static_cast<int32_t>(index);
            std::memcpy(fake_loadout_state.data() + base +
                            kMissionSelectedLoadoutOffset,
                        &selected, sizeof(selected));
            std::memcpy(fake_loadout_state.data() + base +
                            kMissionLoadoutRecordOffset,
                        &resource, sizeof(resource));
        }
        void* fake_loadout_state_pointer = fake_loadout_state.data();
        g_mission_loadout_state_slot = &fake_loadout_state_pointer;
        const int32_t local_profile_count_before_parser = 1;
        const int32_t participant_count_before_parser = 4;
        std::memcpy(fake_loadout_state.data() +
                        kMissionRewardLocalProfileCountOffset,
                    &local_profile_count_before_parser,
                    sizeof(local_profile_count_before_parser));
        std::memcpy(fake_loadout_state.data() +
                        kMissionResultParticipantCountOffset,
                    &participant_count_before_parser,
                    sizeof(participant_count_before_parser));
        std::array<uint8_t, kMissionExtraLoadoutSpan>
            extra_loadout_before{};
        std::memcpy(extra_loadout_before.data(),
                    fake_loadout_state.data() +
                        kMissionExtraLoadoutBeginOffset,
                    extra_loadout_before.size());
        g_mission_loadout_parser = &FakeMissionLoadoutParser;
        bool fake_parser_failed = true;
        const bool fake_parser_result = MissionLoadoutParserHook(
            123, &fake_parser_failed);
        int32_t local_profile_count_after_parser = -1;
        int32_t participant_count_after_parser = -1;
        std::memcpy(&local_profile_count_after_parser,
                    fake_loadout_state.data() +
                        kMissionRewardLocalProfileCountOffset,
                    sizeof(local_profile_count_after_parser));
        std::memcpy(&participant_count_after_parser,
                    fake_loadout_state.data() +
                        kMissionResultParticipantCountOffset,
                    sizeof(participant_count_after_parser));
        std::array<uint8_t, kMissionExtraLoadoutSpan>
            extra_loadout_expected = extra_loadout_before;
        std::memcpy(extra_loadout_expected.data() +
                        (kMissionResultParticipantCountOffset -
                         kMissionExtraLoadoutBeginOffset),
                    &participant_count_after_parser,
                    sizeof(participant_count_after_parser));
        if (fake_parser_result || fake_parser_failed ||
            local_profile_count_after_parser !=
                local_profile_count_before_parser ||
            participant_count_after_parser != 5 ||
            std::memcmp(
                fake_loadout_state.data() +
                    kMissionExtraLoadoutBeginOffset,
                extra_loadout_expected.data(),
                extra_loadout_expected.size()) != 0 ||
            g_fake_mission_loadout_parser_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_loadout_parser_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_loadout_parser_protected_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_loadout_parser_oob_calls.load(
                std::memory_order_acquire) != 1 ||
            g_mission_loadout_parser_protection.active) {
            return fail(
                "parser rollback did not protect P4 loadout and rewards");
        }
        g_mission_loadout_parser = nullptr;
        const MissionExtraLoadoutSidecar fifth_sidecar =
            FindMissionExtraLoadoutSidecar(4);
        const std::array<int32_t, kMissionLoadoutWeaponCount>
            expected_fifth_sidecar_weapons = {
                1040, 1041, 1042, 1043, 5, 1045,
            };
        if (!fifth_sidecar.valid || fifth_sidecar.logical_index != 4 ||
            fifth_sidecar.selected_class != 1 ||
            fifth_sidecar.weapons != expected_fifth_sidecar_weapons ||
            fifth_sidecar.weapon_valid_mask != 0x2f ||
            fifth_sidecar.armor != 456 || fifth_sidecar.parser_call != 1) {
            return fail(
                "sidecar did not capture P4 loadout before rollback");
        }

        // Real 0.6.24 reports had no PlayerInfo observation for P4.  Exercise
        // that exact condition and the invalid native class (256/257) that
        // reached the HUD's fixed four-class text table.
        RemovePlayerInfoObservation(&users[4]);
        g_mission_participant_class_resolver =
            &FakeMissionParticipantClassResolver;
        g_fake_mission_class_resolver_index.store(
            4, std::memory_order_release);
        g_fake_mission_class_resolver_class.store(
            257, std::memory_order_release);
        resolved_participant_index = -1;
        resolved_participant_class = -1;
        resolved_participant = 0;
        MissionParticipantClassResolverHook(
            nullptr, &resolved_participant_index,
            &resolved_participant_class, nullptr,
            &resolved_participant);
        if (resolved_participant_index != 0 ||
            resolved_participant_class != 1 || !resolved_participant ||
            g_fake_mission_class_resolver_calls.load(
                std::memory_order_acquire) != 2) {
            return fail(
                "resolver did not replace native class 257 with the P4 sidecar");
        }
        g_mission_participant_class_resolver = nullptr;
        const uint8_t* native_block = fake_loadout_state.data() +
            kMissionSelectedLoadoutOffset;
        std::array<uint8_t, kMissionClassLoadoutStride>
            native_block_before{};
        std::memcpy(native_block_before.data(), native_block,
                    native_block_before.size());
        void* fifth_identity_before = primary.entries[4].object;
        int fallback_source_index = -1;
        int32_t original_fifth_loadout_index = -1;
        int32_t temporary_fifth_loadout_index = -1;
        g_mission_player_create_trace = {};
        g_mission_player_create_trace.active = true;
        g_mission_player_create_trace.participant_index = 4;
        if (!InstallTemporaryExtraMissionLoadout(
                &primary, 4, fallback_source_index,
                original_fifth_loadout_index,
                temporary_fifth_loadout_index) ||
            primary.entries[4].object != fifth_identity_before ||
            fallback_source_index != 0 ||
            original_fifth_loadout_index != 4 ||
            temporary_fifth_loadout_index != 0 ||
            MissionUserLoadoutIndex(primary.entries[4].object) != 0 ||
            !g_mission_loadout_block_patch.active) {
            return fail(
                "temporary fallback did not preserve the fifth player identity");
        }
        int32_t synthesized_class = -1;
        int32_t synthesized_armor = -1;
        std::array<int32_t, kMissionLoadoutWeaponCount>
            synthesized_weapons{};
        std::memcpy(&synthesized_class, native_block,
                    sizeof(synthesized_class));
        std::memcpy(synthesized_weapons.data(),
                    native_block +
                        (kMissionLoadoutRecordOffset -
                         kMissionSelectedLoadoutOffset) +
                        kMissionLoadoutRecordStride,
                    sizeof(synthesized_weapons));
        std::memcpy(&synthesized_armor,
                    native_block + kMissionLoadoutArmorOffset,
                    sizeof(synthesized_armor));
        const std::array<int32_t, kMissionLoadoutWeaponCount>
            expected_synthesized_weapons = {
                1040, 1041, 1042, 1043, 0, 1045,
            };
        if (synthesized_class != 1 || synthesized_armor != 456 ||
            synthesized_weapons != expected_synthesized_weapons ||
            g_mission_player_create_trace
                    .temporary_loadout_block_weapon_valid_mask != 0x2f ||
            g_mission_player_create_trace
                    .temporary_loadout_block_fallback_weapon_mask != 0x10 ||
            std::strcmp(
                g_mission_player_create_trace
                    .temporary_loadout_block_source,
                "parser_sidecar") != 0 ||
            !RestoreTemporaryMissionLoadoutBlock() ||
            std::memcmp(native_block, native_block_before.data(),
                        native_block_before.size()) != 0 ||
            g_mission_loadout_block_patch.active) {
            return fail(
                "temporary block did not synthesize/restore the fifth player class, weapons and armor");
        }
        auto* fifth_loadout_field = reinterpret_cast<volatile LONG*>(
            reinterpret_cast<uint8_t*>(&users[4]) +
            kUserMissionLoadoutIndexOffset);
        InterlockedExchange(fifth_loadout_field,
                            original_fifth_loadout_index);
        if (MissionUserLoadoutIndex(primary.entries[4].object) != 4) {
            return fail(
                "fifth player unique index was not restored");
        }
        g_mission_player_create_trace = {};
        g_mission_player_create_trace.active = true;
        g_mission_player_create_trace.context = 0;
        g_mission_player_create_trace.participant_index = 4;
        g_mission_player_create_trace.requested_source_index = 4;
        g_mission_player_create_trace.effective_source_index = 4;
        g_mission_player_create_trace.sources = &primary;
        fallback_source_index = -1;
        original_fifth_loadout_index = -1;
        temporary_fifth_loadout_index = -1;
        if (!InstallTemporaryExtraMissionLoadout(
                &primary, 4, fallback_source_index,
                original_fifth_loadout_index,
                temporary_fifth_loadout_index)) {
            return fail(
                "fixture did not reinstall fifth player creation scratch");
        }
        g_fake_mission_source_consumer_loadout_index.store(
            -1, std::memory_order_release);
        g_mission_source_consumer = &FakeMissionSourceConsumer;
        void* early_restore_result = MissionSourceConsumerHook(
            &entries[4], nullptr);
        const MissionPlayerCreateTrace early_restore_trace =
            g_mission_player_create_trace;
        g_mission_source_consumer = nullptr;
        g_mission_player_create_trace = {};
        if (early_restore_result != &users[4] ||
            g_fake_mission_source_consumer_loadout_index.load(
                std::memory_order_acquire) != 0 ||
            MissionUserLoadoutIndex(primary.entries[4].object) != 4 ||
            g_mission_loadout_block_patch.active ||
            std::memcmp(native_block, native_block_before.data(),
                        native_block_before.size()) != 0 ||
            !early_restore_trace.temporary_loadout_block_restored ||
            !early_restore_trace.unique_loadout_index_restored ||
            !early_restore_trace
                 .loadout_restored_before_post_create_consumers ||
            early_restore_trace.observed_loadout_index_before_restore != 0 ||
            early_restore_trace.observed_loadout_index_after_restore != 4 ||
            std::strcmp(early_restore_trace.loadout_restoration_phase,
                        "after_character_consumer") != 0) {
            return fail(
                "P4 index was not restored immediately after the consumer");
        }
        std::array<SharedProperty, 1> local_entries = {entries[3]};
        MissionSourceVector reference{};
        reference.entries = local_entries.data();
        reference.capacity = local_entries.size();
        reference.size = local_entries.size();
        const MissionSourceCollectionSnapshot primary_snapshot =
            SnapshotMissionSourceCollection(&primary);
        const MissionSourceCollectionSnapshot reference_snapshot =
            SnapshotMissionSourceCollection(&reference);
        const auto all_to_local = ObjectOrderMap(primary_snapshot,
                                                 reference_snapshot);
        const auto local_to_all = ObjectOrderMap(reference_snapshot,
                                                 primary_snapshot);
        const auto all_to_local_control = ControlOrderMap(
            primary_snapshot, reference_snapshot);
        const auto local_to_all_control = ControlOrderMap(
            reference_snapshot, primary_snapshot);
        std::array<SharedProperty, 5> reordered_entries = {
            entries[0], entries[1], entries[4], entries[3], entries[2]};
        auto set_sort_key = [](FakeMissionSourceUser& user, uint64_t value) {
            std::memcpy(reinterpret_cast<uint8_t*>(&user) +
                            kUserMissionSortKeyOffset,
                        &value, sizeof(value));
        };
        set_sort_key(users[0], 500);
        set_sort_key(users[1], 400);
        set_sort_key(users[4], 300);
        set_sort_key(users[3], 200);
        set_sort_key(users[2], 100);
        MissionSourceVector reordered{};
        reordered.entries = reordered_entries.data();
        reordered.capacity = reordered_entries.size();
        reordered.size = reordered_entries.size();
        g_mission_source_primary_snapshot = primary_snapshot;
        g_mission_source_local_snapshot = reference_snapshot;
        const MissionSourceTableAudit final_table_audit =
            AuditMissionSourceTable(&reordered);
        int32_t local_controller_p3 = -7;
        int local_collection_p3 = -7;
        const bool resolved_local_p3 = ExpectedMissionLocalController(
            &reordered, 3, local_controller_p3, local_collection_p3);
        int32_t local_controller_p4 = -7;
        int local_collection_p4 = -7;
        const bool resolved_remote_p4 = ExpectedMissionLocalController(
            &reordered, 4, local_controller_p4, local_collection_p4);
        const bool source_audit_ok = primary_snapshot.valid &&
            primary_snapshot.source_count == 5 &&
            primary_snapshot.unique_objects == 5 &&
            primary_snapshot.unique_controls == 5 &&
            primary_snapshot.recognized_users == 5 &&
            primary_snapshot.registered_users == 5 &&
            primary_snapshot.matched_registered_users == 5 &&
            primary_snapshot.registered_order_matches == 5 &&
            primary_snapshot.registered_order_mismatches == 0 &&
            primary_snapshot.registered_order_unknown == 0 &&
            primary_snapshot.registered_ordinals[4] == 4 &&
            primary_snapshot.local_controller_index_mask == 0x01 &&
            primary_snapshot.duplicate_local_controller_indices == 4 &&
            primary_snapshot.maximum_local_controller_index == 0 &&
            reference_snapshot.source_count == 1 &&
            reference_snapshot.local_controller_index_mask == 0x01 &&
            reference_snapshot.matched_registered_users == 1 &&
            reference_snapshot.registered_ordinals[0] == 3 &&
            primary_snapshot.local_controller_indices[4] == 0 &&
            reference_snapshot.local_controller_indices[0] == 0 &&
            ObjectMembershipMask(primary_snapshot, reference_snapshot) ==
                0x08 &&
            ObjectMembershipMask(reference_snapshot, primary_snapshot) ==
                0x01 &&
            all_to_local[0] == -1 && all_to_local[3] == 0 &&
            all_to_local[4] == -1 && local_to_all[0] == 3 &&
            all_to_local_control[0] == -1 &&
            all_to_local_control[3] == 0 &&
            all_to_local_control[4] == -1 &&
            local_to_all_control[0] == 3 &&
            final_table_audit.count == 5 &&
            final_table_audit.runtime_user_mask == 0x1f &&
            final_table_audit.loadout_inspected_mask == 0x1b &&
            final_table_audit.usable_mask == 0x1b &&
            final_table_audit.local_control_membership_mask == 0x08 &&
            final_table_audit.transport_route_index_mask == 0x1f &&
            final_table_audit.duplicate_transport_route_participant_mask == 0 &&
            final_table_audit.transport_route_indices_complete &&
            final_table_audit.transport_route_indices_unique &&
            final_table_audit.sort_key_complete &&
            final_table_audit.sorted_by_user_id_descending &&
            final_table_audit.sort_keys_unique &&
            resolved_local_p3 && local_controller_p3 == 0 &&
            local_collection_p3 == 0 && resolved_remote_p4 &&
            local_controller_p4 == -1 && local_collection_p4 == -1 &&
            CountObjectsMissingFrom(primary_snapshot,
                                    reference_snapshot) == 4 &&
            CountObjectsMissingFrom(reference_snapshot,
                                    primary_snapshot) == 0;
        g_mission_source_primary_snapshot = {};
        g_mission_source_local_snapshot = {};
        g_mission_source_identity_repair_logged_mask.store(
            0, std::memory_order_release);
        ClearMissionExtraLoadoutSidecars();
        g_mission_participant_class_resolver =
            &FakeMissionParticipantClassResolver;
        g_fake_mission_class_resolver_index.store(
            4, std::memory_order_release);
        g_fake_mission_class_resolver_class.store(
            257, std::memory_order_release);
        resolved_participant_index = -1;
        resolved_participant_class = -1;
        resolved_participant = 0;
        MissionParticipantClassResolverHook(
            nullptr, &resolved_participant_index,
            &resolved_participant_class, nullptr,
            &resolved_participant);
        g_mission_participant_class_resolver = nullptr;
        if (resolved_participant_index != 0 ||
            resolved_participant_class != 0 || !resolved_participant ||
            g_fake_mission_class_resolver_calls.load(
                std::memory_order_acquire) != 3) {
            return fail(
                "resolver did not clamp an invalid class to visual fallback 0..3");
        }
        g_mission_loadout_state_slot = nullptr;
        ClearReadyUsers();
        g_runtime_user_vtable = nullptr;
        if (!source_audit_ok) {
            return fail("primary/reference UserImpl collection audit failed");
        }
    }

    {
        std::array<uint8_t, 0x10> scroll_model{};
        scroll_model[kUiScrollEnabledOffset] = 1;
        float initial = 0.5f;
        std::memcpy(scroll_model.data() + kUiScrollRequestedPositionOffset,
                    &initial, sizeof(initial));
        float previous = 0.0f;
        float position = 0.0f;
        if (!AdjustRosterScrollModel(scroll_model.data(), -1, previous,
                                     position) ||
            std::fabs(previous - 0.5f) > 0.0001f ||
            std::fabs(position - 0.75f) > 0.0001f ||
            !AdjustRosterScrollModel(scroll_model.data(), 4, previous,
                                     position) ||
            std::fabs(position) > 0.0001f) {
            return fail("PlayersGroup normalized scrolling model failed");
        }
        scroll_model[kUiScrollEnabledOffset] = 0;
        if (AdjustRosterScrollModel(scroll_model.data(), -1, previous,
                                    position)) {
            return fail("scrolling accepted a disabled model");
        }
    }

    std::vector<uint8_t> source(246, 0xa5);
    const uint32_t packet_type = 20;
    const uint32_t original_limit = 4;
    std::memcpy(source.data(), &packet_type, sizeof(packet_type));
    std::memcpy(source.data() + 12, &local_id, sizeof(local_id));
    std::memcpy(source.data() + 60, &original_limit, sizeof(original_limit));
    std::memcpy(source.data() + 64, &local_id, sizeof(local_id));
    std::memcpy(source.data() + 104, &local_id, sizeof(local_id));
    std::vector<uint8_t> pure_reply;
    if (!BuildHandshakeReply(source.data(), static_cast<uint32_t>(source.size()),
                             BotSteamId(0), MaxPlayers(), pure_reply)) {
        return fail("failed to build synthetic handshake");
    }
    uint64_t patched_id = 0;
    uint32_t patched_limit = 0;
    std::memcpy(&patched_id, pure_reply.data() + 12, sizeof(patched_id));
    std::memcpy(&patched_limit, pure_reply.data() + 60, sizeof(patched_limit));
    if (patched_id != BotSteamId(0) || patched_limit != MaxPlayers()) {
        return fail("synthetic handshake did not apply identity/limit");
    }

    const unsigned desired_bots = MaxPlayers() - 1;
    {
        std::array<std::array<uint8_t, kPlayerInfoSize>, 16> objects{};
        std::array<std::array<wchar_t, 16>, 16> names{};
        std::array<PlayerInfoEntry, 16> entries{};
        auto assign_name = [&objects, &names](unsigned position,
                                              const wchar_t* value) {
            std::wcsncpy(names[position].data(), value,
                         names[position].size() - 1);
            const uint64_t length = std::wcslen(names[position].data());
            const wchar_t* pointer = names[position].data();
            std::memcpy(objects[position].data() + kPlayerInfoNameStorageOffset,
                        &pointer, sizeof(pointer));
            std::memcpy(objects[position].data() + kPlayerInfoNameLengthOffset,
                        &length, sizeof(length));
            const uint64_t capacity = names[position].size() - 1;
            std::memcpy(objects[position].data() + kPlayerInfoNameCapacityOffset,
                        &capacity, sizeof(capacity));
        };
        assign_name(0, L"Host");
        const int host_class = 2;
        const int host_secondary = 41;
        const float host_armor = 555.5f;
        std::memcpy(objects[0].data() + kPlayerInfoClassOffset,
                    &host_class, sizeof(host_class));
        std::memcpy(objects[0].data() + kPlayerInfoSecondaryLoadoutOffset,
                    &host_secondary, sizeof(host_secondary));
        for (unsigned slot = 0; slot < 6; ++slot) {
            const int weapon = 1000 + static_cast<int>(slot);
            std::memcpy(objects[0].data() + kPlayerInfoWeaponsOffset +
                            slot * sizeof(int),
                        &weapon, sizeof(weapon));
            objects[0][kPlayerInfoWeaponValidityOffset + slot] = 1;
        }
        std::memcpy(objects[0].data() + kPlayerInfoArmorOffset,
                    &host_armor, sizeof(host_armor));
        for (unsigned index = 0; index < desired_bots; ++index) {
            wchar_t bot_name[16]{};
            std::swprintf(bot_name, _countof(bot_name), L"EDF Bot %u", index + 1);
            assign_name(index + 1, bot_name);
            const int preserved_voice = 700 + static_cast<int>(index);
            const int preserved_status = 800 + static_cast<int>(index);
            std::memcpy(objects[index + 1].data() + 0x50,
                        &preserved_voice, sizeof(preserved_voice));
            std::memcpy(objects[index + 1].data() + 0x58,
                        &preserved_status, sizeof(preserved_status));
        }
        for (unsigned position = 0; position <= desired_bots; ++position) {
            entries[position].object = objects[position].data();
        }
        PlayerInfoVector players{0, entries.data(), entries.size(),
                                 desired_bots + 1};
        LoadoutCloneStats stats;
        if (!CloneHostLoadout(&players, desired_bots, 1, stats) ||
            stats.copied != desired_bots ||
            stats.host_class != host_class) {
            return fail("copying host loadout to fillers failed");
        }
        for (unsigned index = 0; index < desired_bots; ++index) {
            const uint8_t* bot = objects[index + 1].data();
            if (std::memcmp(bot + kPlayerInfoClassOffset,
                            objects[0].data() + kPlayerInfoClassOffset,
                            2 * sizeof(int)) != 0 ||
                std::memcmp(bot + kPlayerInfoWeaponsOffset,
                            objects[0].data() + kPlayerInfoWeaponsOffset,
                            6 * sizeof(int)) != 0 ||
                std::memcmp(bot + kPlayerInfoWeaponValidityOffset,
                            objects[0].data() + kPlayerInfoWeaponValidityOffset,
                            6) != 0 ||
                *reinterpret_cast<const int*>(bot + 0x50) !=
                    700 + static_cast<int>(index) ||
                *reinterpret_cast<const int*>(bot + 0x58) !=
                    800 + static_cast<int>(index)) {
                return fail("loadout copy changed name/status or lost equipment");
            }
        }

        // The live EDF5 PlayerInfo display string is not the persona name.
        // Verify the one-real-member fallback without relying on bot names or
        // on a particular vector position.
        for (unsigned index = 0; index < desired_bots; ++index) {
            assign_name(index + 1, L"Unknown");
            const int missing = -1;
            std::memcpy(objects[index + 1].data() + kPlayerInfoClassOffset,
                        &missing, sizeof(missing));
            for (unsigned slot = 0; slot < 6; ++slot) {
                std::memcpy(objects[index + 1].data() +
                                kPlayerInfoWeaponsOffset + slot * sizeof(int),
                            &missing, sizeof(missing));
            }
        }
        // Put the only equipped real entry last to prove the fallback does
        // not assume a particular position. The second pass proves it keeps
        // the same source after every filler has received a valid loadout.
        const PlayerInfoEntry real_entry = entries[0];
        for (unsigned position = 0; position < desired_bots; ++position) {
            entries[position] = entries[position + 1];
        }
        entries[desired_bots] = real_entry;
        g_single_real_host_position.store(-1, std::memory_order_release);
        if (!CloneHostLoadout(&players, desired_bots, 1, stats) ||
            !stats.used_single_real_fallback ||
            stats.copied != desired_bots ||
            stats.host_position != static_cast<int>(desired_bots) ||
            !CloneHostLoadout(&players, desired_bots, 1, stats) ||
            stats.host_position != static_cast<int>(desired_bots)) {
            return fail("loadout fallback for one real player failed");
        }
    }

    NotifyCreateLobby(4, static_cast<int>(MaxPlayers()));
    ObserveLobbyDataWrite(test_lobby, "public_slot");
    ObserveMemberCount(test_lobby, 1);
    CaptureLocalMemberData("usr76561198000000001", "selftest-member-data");
    for (unsigned i = 0; i < desired_bots; ++i) {
        if (!TryAddBot(test_lobby, false)) return fail("sequential addition rejected");
        uint64_t changed_lobby = 0;
        uint64_t changed_user = 0;
        uint32_t state = 0;
        if (!ConsumeMembershipChange(changed_lobby, changed_user, state) ||
            changed_lobby != test_lobby || changed_user != BotSteamId(i) ||
            state != kMemberEntered) {
            return fail("invalid sequential entry callback");
        }
        MembershipChangeDelivered(changed_lobby, changed_user, state);
    }
    if (AdjustMemberCount(test_lobby, 1) != static_cast<int>(MaxPlayers()) ||
        !g_room_full_reported.load(std::memory_order_acquire) ||
        TryAddBot(test_lobby, false)) {
        return fail("synthetic room did not stop exactly at the limit");
    }
    for (unsigned i = 0; i < desired_bots; ++i) {
        uint64_t user = 0;
        std::string data;
        std::string name;
        if (!TryGetSyntheticMember(test_lobby, 1, static_cast<int>(i + 1), user) ||
            user != BotSteamId(i) || !TryGetMemberData(
                test_lobby, user, ("usr" + std::to_string(user)).c_str(), data) ||
            data != "selftest-member-data" || !TryGetBotName(user, name) ||
            name != "EDF Bot " + std::to_string(i + 1)) {
            return fail("invalid multiple-filler synthetic roster");
        }
    }

    {
        std::array<void*, 11> fake_vtable{};
        fake_vtable[10] = reinterpret_cast<void*>(&FakeUserIdGetter);
        std::array<FakeReadyUser, 16> ready_users{};
        ready_users[0].vtable = fake_vtable.data();
        ready_users[0].steam_id = local_id;
        RegisterReadyUser(&ready_users[0]);
        for (unsigned i = 0; i < desired_bots; ++i) {
            ready_users[i + 1].vtable = fake_vtable.data();
            ready_users[i + 1].steam_id = BotSteamId(i);
            RegisterReadyUser(&ready_users[i + 1]);
        }
        g_ready_user_test_mode.store(true, std::memory_order_release);
        for (unsigned i = 0; i < desired_bots; ++i) {
            unsigned marked_index = 0;
            uint64_t marked_user = 0;
            bool transport_ready = false;
            bool cm_ready = false;
            bool ds_ready = false;
            if (!MarkSyntheticUserReady(&ready_users[i + 1], true, marked_index,
                                        marked_user, transport_ready,
                                        cm_ready, ds_ready) ||
                marked_index != i || marked_user != BotSteamId(i)) {
                return fail("automatic Ready on filler creation failed");
            }
            if (!transport_ready || !cm_ready || !ds_ready) {
                return fail("automatic Ready did not mark transport, cm and ds");
            }
        }
        if (!TryReadyBots(test_lobby, false) ||
            ready_users[0].ready.load(std::memory_order_acquire) != 0 ||
            ready_users[0].write_calls.load(std::memory_order_acquire) != 0 ||
            ready_users[0].cm_write_calls.load(
                std::memory_order_acquire) != 0 ||
            ready_users[0].ds_write_calls.load(
                std::memory_order_acquire) != 0) {
            return fail("Ready action changed the host or rejected valid fillers");
        }
        for (unsigned i = 0; i < desired_bots; ++i) {
            if (ready_users[i + 1].ready.load(std::memory_order_acquire) != 1 ||
                !ready_users[i + 1].cm_ready.load(std::memory_order_acquire) ||
                !ready_users[i + 1].ds_ready.load(std::memory_order_acquire) ||
                ready_users[i + 1].write_calls.load(
                    std::memory_order_acquire) != 2 ||
                ready_users[i + 1].cm_write_calls.load(
                    std::memory_order_acquire) != 2 ||
                ready_users[i + 1].ds_write_calls.load(
                    std::memory_order_acquire) != 2) {
                return fail("automatic Ready/F6 did not mark transport, cm and ds");
            }
        }

        // MissionStart state 4 consumes each participant's l2 list. A real
        // client publishes the same authoritative token list to l1 and l2;
        // inert fillers must mirror it after the first gameplay-channel send.
        if (!HandleSyntheticSend(BotSteamId(0), source.data(),
                                 static_cast<uint32_t>(source.size()), 0, 0) ||
            !g_mission_groups_pending.load(std::memory_order_acquire)) {
            return fail("gameplay channel did not arm l1/l2 synchronization");
        }
        ApplyPendingMissionGroups();
        if (!g_mission_groups_pending.load(std::memory_order_acquire) ||
            g_mission_groups_synchronized.load(std::memory_order_acquire)) {
            return fail("l1/l2 synchronization accepted an empty source");
        }

        std::string mission_group = std::to_string(local_id) + ":0";
        for (unsigned i = 0; i < desired_bots; ++i) {
            mission_group += "," + std::to_string(BotSteamId(i)) + ":" +
                             std::to_string(i + 1);
        }
        ready_users[0].l1 = mission_group;
        ready_users[0].l2 = mission_group;
        ApplyPendingMissionGroups();
        if (g_mission_groups_pending.load(std::memory_order_acquire) ||
            !g_mission_groups_synchronized.load(std::memory_order_acquire) ||
            ready_users[0].l1_write_calls.load(std::memory_order_acquire) != 0 ||
            ready_users[0].l2_write_calls.load(std::memory_order_acquire) != 0) {
            return fail("l1/l2 mirroring changed the host or did not complete");
        }
        for (unsigned i = 0; i < desired_bots; ++i) {
            if (ready_users[i + 1].l1 != mission_group ||
                ready_users[i + 1].l2 != mission_group ||
                ready_users[i + 1].l1_write_calls.load(
                    std::memory_order_acquire) != 1 ||
                ready_users[i + 1].l2_write_calls.load(
                    std::memory_order_acquire) != 1) {
                return fail("filler did not mirror the l1/l2 mission list");
            }
        }
        uint32_t fabricated_gameplay_size = 0;
        if (PeekSyntheticPacket(0, &fabricated_gameplay_size)) {
            return fail("l1/l2 mirroring fabricated a gameplay packet");
        }
        for (unsigned i = 0; i <= desired_bots; ++i) {
            UnregisterReadyUser(&ready_users[i]);
        }
        g_ready_user_test_mode.store(false, std::memory_order_release);
    }

    const uint64_t first_bot = BotSteamId(0);
    const uint64_t last_bot = BotSteamId(desired_bots - 1);
    if (!HandleSyntheticSend(first_bot, source.data(),
                             static_cast<uint32_t>(source.size()), 2, 2) ||
        !HandleSyntheticSend(last_bot, source.data(),
                             static_cast<uint32_t>(source.size()), 2, 2)) {
        return fail("P2P send to multiple fillers failed");
    }
    for (uint64_t expected_peer : {first_bot, last_bot}) {
        uint32_t queued_size = 0;
        if (!PeekSyntheticPacket(2, &queued_size) || queued_size != source.size()) {
            return fail("synthetic P2P packet did not become available");
        }
        uint8_t small[8]{};
        uint32_t reported_size = 0;
        if (ReadSyntheticPacket(small, sizeof(small), &reported_size, nullptr, 2) ||
            reported_size != source.size()) {
            return fail("small P2P buffer was not handled correctly");
        }
        std::vector<uint8_t> reply(source.size());
        uint64_t peer = 0;
        if (!ReadSyntheticPacket(reply.data(), static_cast<uint32_t>(reply.size()),
                                 &reported_size, &peer, 2) || peer != expected_peer) {
            return fail("P2P queue lost filler identity");
        }
        std::memcpy(&patched_id, reply.data() + 12, sizeof(patched_id));
        if (patched_id != expected_peer) return fail("incorrect P2P SteamID");
    }

    QueueSyntheticAuthValidation(first_bot);
    QueueSyntheticAuthValidation(last_bot);
    for (uint64_t expected_user : {first_bot, last_bot}) {
        uint64_t auth_user = 0;
        if (!ConsumeSyntheticAuthValidation(auth_user) || auth_user != expected_user) {
            return fail("invalid multiple-authentication queue");
        }
        SyntheticAuthValidationDelivered(auth_user);
    }
    for (unsigned i = 0; i < desired_bots; ++i) {
        if (!HandleSyntheticSend(BotSteamId(i), source.data(),
                                 static_cast<uint32_t>(source.size()), 0, 0)) {
            return fail("gameplay channel contact was rejected");
        }
    }
    const uint32_t expected_contact_mask =
        (uint32_t{1} << desired_bots) - 1;
    if (g_gameplay_contact_mask.load(std::memory_order_acquire) !=
            expected_contact_mask ||
        !g_all_gameplay_contact_reported.load(std::memory_order_acquire)) {
        return fail("all-fillers-contacted milestone was not reached");
    }

    if (!TryRemoveBot(test_lobby, false)) return fail("removing the last filler failed");
    uint64_t changed_lobby = 0;
    uint64_t changed_user = 0;
    uint32_t state = 0;
    if (!ConsumeMembershipChange(changed_lobby, changed_user, state) ||
        changed_user != last_bot || state != kMemberLeft ||
        AdjustMemberCount(test_lobby, 1) != static_cast<int>(MaxPlayers() - 1)) {
        return fail("invalid last-filler exit callback");
    }
    MembershipChangeDelivered(changed_lobby, changed_user, state);
    if (!TryAddBot(test_lobby, false) ||
        !ConsumeMembershipChange(changed_lobby, changed_user, state)) {
        return fail("reentry before collision test failed");
    }
    MembershipChangeDelivered(changed_lobby, changed_user, state);
    ObserveMemberCount(test_lobby, 2);
    if (IsSyntheticPeer(last_bot) ||
        !ConsumeMembershipChange(changed_lobby, changed_user, state) ||
        changed_user != last_bot || state != kMemberLeft ||
        AdjustMemberCount(test_lobby, 2) != static_cast<int>(MaxPlayers())) {
        return fail("filler did not yield its slot to the real player");
    }
    MembershipChangeDelivered(changed_lobby, changed_user, state);
    ObserveLeaveLobby(test_lobby);
    reset_state();

    constexpr uint64_t hotkey_lobby = test_lobby + 1;
    NotifyCreateLobby(4, static_cast<int>(MaxPlayers()));
    ObserveLobbyDataWrite(hotkey_lobby, "public_slot");
    ObserveMemberCount(hotkey_lobby, 1);
    g_suppress_hotkey_feedback.store(true, std::memory_order_release);
    g_add_hotkey_test_override.store(0, std::memory_order_release);
    g_remove_hotkey_test_override.store(0, std::memory_order_release);
    g_ready_hotkey_test_override.store(0, std::memory_order_release);
    g_local_mission_harness_hotkey_test_override.store(
        0, std::memory_order_release);
    g_debug_stage_win_hotkey_test_override.store(0,
                                                  std::memory_order_release);
    g_scroll_hotkey_test_override.store(0, std::memory_order_release);
    g_scroll_test_mode.store(true, std::memory_order_release);
    FakeMissionUi fake_mission_ui{};
    FakeMissionManager fake_mission_manager{};
    FakeMissionResultUiObject fake_mission_result_ui_object{};
    fake_mission_manager.ui = &fake_mission_ui;
    void* fake_mission_manager_slot = &fake_mission_manager;
    g_mission_manager_slot = &fake_mission_manager_slot;
    void* fake_result_event_publisher_owner = &fake_mission_manager;
    g_mission_result_event_publisher_slot =
        &fake_result_event_publisher_owner;
    g_mission_result_setter = &FakeMissionResultSetter;
    g_mission_result_event_publish = &FakeMissionResultEventPublish;
    g_mission_result_ui_event_dispatch =
        &FakeMissionResultUiEventDispatch;
    g_fake_mission_result_ui_object = &fake_mission_result_ui_object;
    g_mission_update = &FakeMissionUpdate;
    std::array<void*, 11> hotkey_ready_vtable{};
    hotkey_ready_vtable[10] = reinterpret_cast<void*>(&FakeUserIdGetter);
    std::array<FakeReadyUser, 5> hotkey_ready_users{};
    hotkey_ready_users[0].vtable = hotkey_ready_vtable.data();
    hotkey_ready_users[0].steam_id = local_id;
    for (unsigned i = 0; i < 4; ++i) {
        hotkey_ready_users[i + 1].vtable = hotkey_ready_vtable.data();
        hotkey_ready_users[i + 1].steam_id = BotSteamId(i);
    }
    g_ready_user_test_mode.store(true, std::memory_order_release);
    for (auto& user : hotkey_ready_users) RegisterReadyUser(&user);
    if (!Start()) return fail("hotkey thread did not start");
    auto wait_for_count = [](unsigned expected) {
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            if (g_bot_count.load(std::memory_order_acquire) == expected) return true;
            Sleep(10);
        }
        return false;
    };
    g_add_hotkey_test_override.store(1, std::memory_order_release);
    if (!wait_for_count(1)) return fail("simulated F8 did not add a filler");
    Sleep(120);
    if (g_bot_count.load(std::memory_order_acquire) != 1) {
        return fail("F8 repeated while held");
    }
    g_add_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    g_add_hotkey_test_override.store(1, std::memory_order_release);
    if (!wait_for_count(2)) return fail("second F8 did not add another filler");
    g_add_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    g_ready_hotkey_test_override.store(1, std::memory_order_release);
    auto wait_for_ready = [&hotkey_ready_users] {
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            if (hotkey_ready_users[1].ready.load(std::memory_order_acquire) == 1 &&
                hotkey_ready_users[2].ready.load(std::memory_order_acquire) == 1 &&
                hotkey_ready_users[1].cm_ready.load(std::memory_order_acquire) &&
                hotkey_ready_users[2].cm_ready.load(std::memory_order_acquire) &&
                hotkey_ready_users[1].ds_ready.load(std::memory_order_acquire) &&
                hotkey_ready_users[2].ds_ready.load(std::memory_order_acquire)) {
                return true;
            }
            Sleep(10);
        }
        return false;
    };
    if (!wait_for_ready() ||
        hotkey_ready_users[0].ready.load(std::memory_order_acquire) != 0 ||
        hotkey_ready_users[0].cm_ready.load(std::memory_order_acquire) ||
        hotkey_ready_users[0].ds_ready.load(std::memory_order_acquire)) {
        return fail("simulated F6 did not mark only active fillers");
    }
    Sleep(120);
    if (hotkey_ready_users[1].write_calls.load(std::memory_order_acquire) != 1 ||
        hotkey_ready_users[2].write_calls.load(std::memory_order_acquire) != 1 ||
        hotkey_ready_users[1].cm_write_calls.load(
            std::memory_order_acquire) != 1 ||
        hotkey_ready_users[2].cm_write_calls.load(
            std::memory_order_acquire) != 1 ||
        hotkey_ready_users[1].ds_write_calls.load(
            std::memory_order_acquire) != 1 ||
        hotkey_ready_users[2].ds_write_calls.load(
            std::memory_order_acquire) != 1) {
        return fail("F6 repeated while held");
    }
    g_ready_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    g_scroll_hotkey_test_override.store(1, std::memory_order_release);
    for (unsigned attempt = 0; attempt < 100 &&
         g_scroll_test_calls.load(std::memory_order_acquire) == 0; ++attempt) {
        Sleep(10);
    }
    if (g_scroll_test_calls.load(std::memory_order_acquire) != 1) {
        return fail("simulated mouse wheel did not scroll");
    }
    Sleep(120);
    if (g_scroll_test_calls.load(std::memory_order_acquire) != 1) {
        return fail("mouse wheel repeated while held");
    }
    g_scroll_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    const uint64_t mission_now = GetTickCount64();
    fake_mission_ui.state = kMissionUiStateRunning;
    fake_mission_ui.result = 0;
    fake_mission_manager.active_result = 0;
    g_mission_generation.store(1, std::memory_order_release);
    g_mission_first_update_tick.store(mission_now - kMissionWarmupMs - 1,
                                      std::memory_order_release);
    g_mission_update_tick.store(mission_now, std::memory_order_release);
    g_mission_ui_state.store(kMissionUiStateRunning,
                             std::memory_order_release);
    g_debug_stage_win_active.store(true, std::memory_order_release);
    g_debug_stage_win_hotkey_test_override.store(1,
                                                  std::memory_order_release);
    for (unsigned attempt = 0; attempt < 100 &&
         !g_debug_stage_win_pending.load(std::memory_order_acquire); ++attempt) {
        Sleep(10);
    }
    if (!g_debug_stage_win_pending.load(std::memory_order_acquire)) {
        return fail("simulated F5 did not queue mission victory");
    }
    const int debug_result = MissionUpdateHook();
    if (debug_result != kMissionResultClear ||
        fake_mission_ui.state != kMissionUiStateFinished ||
        fake_mission_ui.result != kMissionResultClear ||
        fake_mission_manager.active_result != kMissionResultClear ||
        g_debug_stage_win_test_set_calls.load(std::memory_order_acquire) != 1 ||
        g_mission_result_setter_calls.load(std::memory_order_acquire) != 1 ||
        g_mission_result_event_publish_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_expected_event_publish_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_ui_dispatch_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_ui_target_match_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_result_ui_dispatch_calls.load(
            std::memory_order_acquire) != 1 ||
        (fake_mission_result_ui_object.flags & kUiObjectClosingFlag) == 0 ||
        g_fake_mission_result_event_publish_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_result_event_type.load(
            std::memory_order_acquire) != kMissionResultEventType ||
        g_fake_mission_result_event_payload.load(
            std::memory_order_acquire) != kMissionResultEventPayload ||
        g_mission_result_last_value.load(std::memory_order_acquire) !=
            kMissionResultClear ||
        g_mission_result_last_ui_state.load(std::memory_order_acquire) !=
            kMissionUiStateFinished ||
        !g_mission_result_tick.load(std::memory_order_acquire)) {
        return fail("simulated F5 did not return the native victory result");
    }
    Sleep(120);
    if (g_debug_stage_win_test_set_calls.load(std::memory_order_acquire) != 1 ||
        g_debug_stage_win_pending.load(std::memory_order_acquire)) {
        return fail("F5 repeated while held");
    }
    g_debug_stage_win_hotkey_test_override.store(0,
                                                  std::memory_order_release);
    Sleep(100);
    fake_mission_ui.state = kMissionUiStateFinished;
    fake_mission_ui.result = kMissionResultClear;
    fake_mission_manager.active_result = 0;
    fake_mission_result_ui_object.flags = 0;
    g_last_actual_member_count.store(5, std::memory_order_release);
    g_mission_generation.store(2, std::memory_order_release);
    const uint64_t recovery_now = GetTickCount64();
    ArmMissionResultRecovery(kMissionScriptClearApplyReturnRva + 1,
                             recovery_now, kMissionResultClear,
                             fake_mission_ui.state,
                             fake_mission_ui.result);
    if (g_mission_result_recovery_pending.load(
            std::memory_order_acquire)) {
        return fail("result recovery accepted an incorrect caller");
    }
    ArmMissionResultRecovery(kMissionScriptClearApplyReturnRva,
                             recovery_now, kMissionResultClear,
                             fake_mission_ui.state,
                             fake_mission_ui.result);
    g_mission_result_recovery_tick.store(
        recovery_now - kMissionResultRecoveryGraceMs - 1,
        std::memory_order_release);
    // Reproduce the native ordering: Mission() has already selected stale
    // zero before the recovery setter is invoked by the hook.
    g_fake_mission_update_override.store(0,
                                          std::memory_order_release);
    const int recovery_result = MissionUpdateHook();
    g_fake_mission_update_override.store(-1,
                                          std::memory_order_release);
    if (recovery_result != kMissionResultClear ||
        g_mission_result_recovery_pending.load(
            std::memory_order_acquire) ||
        g_mission_result_recovery_attempts.load(
            std::memory_order_acquire) != 1 ||
        g_debug_stage_win_test_set_calls.load(
            std::memory_order_acquire) != 2 ||
        fake_mission_manager.active_result != kMissionResultClear ||
        g_mission_result_last_setter_generation.load(
            std::memory_order_acquire) != 2 ||
        g_mission_result_event_publish_calls.load(
            std::memory_order_acquire) != 2 ||
        g_mission_result_expected_event_publish_calls.load(
            std::memory_order_acquire) != 2 ||
        g_mission_result_ui_dispatch_calls.load(
            std::memory_order_acquire) != 2 ||
        g_mission_result_ui_target_match_calls.load(
            std::memory_order_acquire) != 2 ||
        g_fake_mission_result_ui_dispatch_calls.load(
            std::memory_order_acquire) != 2 ||
        (fake_mission_result_ui_object.flags & kUiObjectClosingFlag) == 0 ||
        g_fake_mission_result_event_publish_calls.load(
            std::memory_order_acquire) != 2) {
        return fail(
            "host-only recovery did not return the effective mission result");
    }
    if (MissionResultSyncOriginForCaller(
            kMissionResultScriptSyncBeginReturnRva, true) !=
            MissionResultSyncOrigin::Script ||
        MissionResultSyncOriginForCaller(
            kMissionResultNetSyncBeginReturnRva, true) !=
            MissionResultSyncOrigin::Network ||
        MissionResultSyncOriginForCaller(
            kMissionResultScriptSyncPollReturnRva, false) !=
            MissionResultSyncOrigin::Script ||
        MissionResultSyncOriginForCaller(
            kMissionResultNetSyncPollReturnRva, false) !=
            MissionResultSyncOrigin::Network ||
        MissionResultSyncOriginForCaller(
            kMissionResultNetSyncPollReturnRva + 1, false) !=
            MissionResultSyncOrigin::Unknown) {
        return fail(
            "Sync_MissionResult caller classification failed");
    }
    std::vector<uint8_t> fake_reward_state(
        kMissionResultParticipantCountOffset + sizeof(int32_t), 0);
    const int32_t fake_local_profiles = 1;
    const int32_t fake_participant_count = 5;
    std::memcpy(fake_reward_state.data() +
                    kMissionRewardLocalProfileCountOffset,
                &fake_local_profiles, sizeof(fake_local_profiles));
    std::memcpy(fake_reward_state.data() +
                    kMissionResultParticipantCountOffset,
                &fake_participant_count, sizeof(fake_participant_count));
    void* fake_reward_state_pointer = fake_reward_state.data();
    g_mission_loadout_state_slot = &fake_reward_state_pointer;
    std::vector<uint8_t> fake_spawn_owner(
        kEnemySpawnSourceOffset + sizeof(void*), 0);
    const uint32_t fake_spawn_denominator = 4;
    void* fake_spawn_source = fake_spawn_owner.data();
    std::memcpy(fake_spawn_owner.data() +
                    kEnemySpawnScaleDenominatorOffset,
                &fake_spawn_denominator,
                sizeof(fake_spawn_denominator));
    std::memcpy(fake_spawn_owner.data() + kEnemySpawnSourceOffset,
                &fake_spawn_source, sizeof(fake_spawn_source));
    g_enemy_spawn = &FakeEnemySpawn;
    ResetEnemySpawnTelemetry();
    DispatchEnemySpawn(
        fake_spawn_owner.data(), nullptr, 10,
        mission_spawn::kConfirmedEnemySpawnCallRvas.front() + 5, 2, true);
    uint32_t fake_spawn_numerator_after = 1;
    std::memcpy(&fake_spawn_numerator_after,
                fake_spawn_owner.data() +
                    kEnemySpawnScaleNumeratorOffset,
                sizeof(fake_spawn_numerator_after));
    volatile LONG concurrent_spawn_numerator = 7;
    const bool overwrote_concurrent_spawn_scale =
        RestoreEnemySpawnScale(&concurrent_spawn_numerator, 4, 0, 0,
                               false);
    if (g_fake_enemy_spawn_calls.load(std::memory_order_acquire) != 1 ||
        g_fake_enemy_spawn_requested_count.load(
            std::memory_order_acquire) != 20 ||
        g_fake_enemy_spawn_numerator_seen.load(
            std::memory_order_acquire) != fake_spawn_denominator ||
        fake_spawn_numerator_after != 0 ||
        g_enemy_spawn_calls.load(std::memory_order_acquire) != 1 ||
        g_enemy_spawn_confirmed_calls.load(
            std::memory_order_acquire) != 1 ||
        g_enemy_spawn_requested_total.load(
            std::memory_order_acquire) != 10 ||
        g_enemy_spawn_effective_total.load(
            std::memory_order_acquire) != 20 ||
        g_enemy_spawn_scale_repairs.load(
            std::memory_order_acquire) != 1 ||
        g_enemy_spawn_scale_restore_failures.load(
            std::memory_order_acquire) != 0 ||
        overwrote_concurrent_spawn_scale || concurrent_spawn_numerator != 7) {
        return fail(
            "spawn hook did not multiply/repair/restore with safe CAS");
    }
    g_fake_enemy_spawn_calls.store(0, std::memory_order_release);
    g_fake_enemy_spawn_requested_count.store(0,
                                              std::memory_order_release);
    g_fake_enemy_spawn_numerator_seen.store(0,
                                             std::memory_order_release);
    g_fake_generator_poll_spawn_calls.store(
        0, std::memory_order_release);
    g_fake_generator_poll_update_calls.store(
        0, std::memory_order_release);
    g_fake_generator_poll_gate_calls.store(
        0, std::memory_order_release);
    g_fake_generator_poll_spawn_result.store(
        0, std::memory_order_release);
    ResetEnemySpawnTelemetry();
    std::vector<uint8_t> fake_generator(
        kGeneratorPollManagerOffset + sizeof(void*), 0);
    void* fake_generator_vtable = reinterpret_cast<void*>(
        g_module_base + kGeneratorPollVtableRva);
    std::memcpy(fake_generator.data(), &fake_generator_vtable,
                sizeof(fake_generator_vtable));
    auto set_fake_gate_state = [&fake_generator](int32_t remaining,
                                                 int32_t cooldown) {
        std::memcpy(fake_generator.data() +
                        kGeneratorPollGateStateOffset +
                        kGeneratorPollGateRemainingOffset,
                    &remaining, sizeof(remaining));
        std::memcpy(fake_generator.data() +
                        kGeneratorPollGateStateOffset +
                        kGeneratorPollGateCooldownOffset,
                    &cooldown, sizeof(cooldown));
    };
    set_fake_gate_state(1, 0);
    void* fake_generator_manager = fake_generator.data();
    std::memcpy(fake_generator.data() + kGeneratorPollManagerOffset,
                &fake_generator_manager, sizeof(fake_generator_manager));
    g_fake_generator_poll_spawn_owner = fake_spawn_owner.data();
    g_generator_poll_update = &FakeGeneratorPollUpdate;
    g_generator_poll_gate = &FakeGeneratorPollGate;
    g_generator_poll_spawn = &FakeGeneratorPollSpawn;
    GeneratorPollUpdateHook(fake_generator.data(), nullptr);
    if (g_fake_generator_poll_spawn_result.load(
            std::memory_order_acquire) != static_cast<uintptr_t>(0x101) ||
        g_fake_generator_poll_update_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_generator_poll_gate_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_generator_poll_spawn_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_enemy_spawn_calls.load(std::memory_order_acquire) != 1 ||
        g_fake_enemy_spawn_requested_count.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_spawn_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_manager_readable_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_manager_present_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_methods_reaching_common_spawn.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_common_spawn_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_gate_true_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_gate_false_calls.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_update_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_update_completed_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_updates_reaching_spawn_method.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_spawn_method_calls_in_updates.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_completed_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_cooldown_blocks.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_quota_blocks.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_spawn_false.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_spawn_accepted.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_unknown.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_update_scope_depth != 0 ||
        g_generator_poll_native_gate_scope_depth != 0 ||
        g_generator_poll_spawn_scope_depth != 0) {
        return fail(
            "GeneratorPoll telemetry did not preserve update/return/path");
    }

    ResetEnemySpawnTelemetry();
    g_generator_poll_gate = &FakeGeneratorPollGateNoSpawn;
    set_fake_gate_state(1, kGeneratorPollGateCooldownThreshold + 1);
    GeneratorPollGateHook(
        fake_generator.data() + kGeneratorPollGateStateOffset,
        fake_generator.data());
    if (g_generator_poll_native_gate_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_completed_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_cooldown_blocks.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_quota_blocks.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_spawn_false.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_spawn_accepted.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_unknown.load(
            std::memory_order_acquire) != 0) {
        return fail("GeneratorPoll gate did not classify native cooldown");
    }

    ResetEnemySpawnTelemetry();
    set_fake_gate_state(0, 0);
    GeneratorPollGateHook(
        fake_generator.data() + kGeneratorPollGateStateOffset,
        fake_generator.data());
    if (g_generator_poll_native_gate_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_quota_blocks.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_cooldown_blocks.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_unknown.load(
            std::memory_order_acquire) != 0) {
        return fail("GeneratorPoll gate did not classify native quota");
    }

    ResetEnemySpawnTelemetry();
    g_generator_poll_gate = &FakeGeneratorPollGate;
    g_generator_poll_spawn = &FakeGeneratorPollSpawnFalse;
    set_fake_gate_state(1, 0);
    GeneratorPollGateHook(
        fake_generator.data() + kGeneratorPollGateStateOffset,
        fake_generator.data());
    if (g_generator_poll_native_gate_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_spawn_false.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_spawn_accepted.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_spawn_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_gate_false_calls.load(
            std::memory_order_acquire) != 1 ||
        g_generator_poll_native_gate_unknown.load(
            std::memory_order_acquire) != 0 ||
        g_generator_poll_native_gate_scope_depth != 0) {
        return fail("GeneratorPoll gate did not classify a false return");
    }
    g_generator_poll_update = nullptr;
    g_generator_poll_gate = nullptr;
    g_generator_poll_spawn = nullptr;
    g_fake_generator_poll_spawn_owner = nullptr;
    g_enemy_spawn = nullptr;
    ResetEnemySpawnTelemetry();
    g_mission_result_exec_begin = &FakeMissionResultExecBegin;
    g_mission_result_item_sink = &FakeMissionResultItemSink;
    g_mission_named_sync_begin = &FakeMissionNamedSyncBegin;
    g_mission_named_sync_poll = &FakeMissionNamedSyncPoll;
    g_mission_reward_resolve = &FakeMissionRewardResolve;
    g_mission_reward_apply = &FakeMissionRewardApply;
    g_mission_expected_local_profile_count.store(
        fake_local_profiles, std::memory_order_release);
    g_mission_result_sync_test_origin.store(
        static_cast<int>(MissionResultSyncOrigin::Script),
        std::memory_order_release);
    FakeMissionResultSyncState fake_sync_state{};
    for (int32_t participant = 0;
         participant <
             static_cast<int32_t>(kMissionResultNativeItemCount);
         ++participant) {
        const std::array<uint32_t, 2> fields = {
            static_cast<uint32_t>(participant + 1),
            static_cast<uint32_t>((participant + 1) * 10),
        };
        uint64_t item = 0;
        std::memcpy(&item, fields.data(), sizeof(item));
        MissionResultItemSinkHook(nullptr, &participant, &item);
    }
    int32_t extra_participant = 4;
    const std::array<uint32_t, 2> extra_fields = {5, 50};
    uint64_t extra_item = 0;
    std::memcpy(&extra_item, extra_fields.data(), sizeof(extra_item));
    MissionResultItemSinkHook(nullptr, &extra_participant, &extra_item);
    std::array<uint32_t, 2> folded_fields{};
    std::memcpy(folded_fields.data(),
                fake_reward_state.data() +
                    kMissionResultItemArrayOffset,
                sizeof(folded_fields));
    g_mission_generation.store(4, std::memory_order_release);
    const bool fake_exec_queued = QueueMissionResultExecRecovery(
        MissionResultSyncOrigin::Script, true, 0, 0);
    // Deterministic synthetic clock avoids unsigned underflow when the DLL's
    // SelfTest happens to run within the first second after Windows boot.
    constexpr uint64_t kFakeExecRecoveryQueuedTick = 1;
    constexpr uint64_t kFakeExecRecoveryApplyTick =
        kFakeExecRecoveryQueuedTick +
        mission_result_recovery::kExecBeginGraceMs + 1;
    g_mission_result_exec_recovery_tick.store(
        kFakeExecRecoveryQueuedTick, std::memory_order_release);
    const bool fake_exec_accepted =
        ApplyPendingMissionResultExecRecovery(kFakeExecRecoveryApplyTick);
    MissionNamedSyncBeginHook(&fake_sync_state, nullptr);
    MissionNamedSyncPollHook(&fake_sync_state);
    MissionRewardResolveHook();
    // Reproduce the exact destructive overlap from the fifth 0x3e90 parser
    // block after its normal rollback.  ApplyResult must recover the count
    // from the independently captured local-control collection.
    const int32_t corrupted_local_profiles = 0;
    std::memcpy(fake_reward_state.data() +
                    kMissionRewardLocalProfileCountOffset,
                &corrupted_local_profiles,
                sizeof(corrupted_local_profiles));
    const bool fake_reward_native_result = MissionRewardApplyHook(true);
    g_mission_result_sync_test_origin.store(-1,
                                             std::memory_order_release);
    if (!fake_exec_queued || !fake_exec_accepted ||
        fake_reward_native_result ||
        folded_fields[0] != 6 || folded_fields[1] != 60 ||
        g_fake_mission_result_item_sink_calls.load(
            std::memory_order_acquire) !=
                kMissionResultNativeItemCount ||
        g_mission_result_extra_item_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_extra_item_aggregated_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_extra_item_mask.load(
            std::memory_order_acquire) != (uint32_t{1} << 4) ||
        g_mission_result_item_mask.load(
            std::memory_order_acquire) != 0x1fU ||
        fake_sync_state.phase != 1 || fake_sync_state.result != 0 ||
        ReadMissionRewardLocalProfileCount() != 1 ||
        g_mission_reward_profile_count_repairs.load(
            std::memory_order_acquire) != 1 ||
        ReadMissionResultParticipantCount() != 5 ||
        ExpectedMissionResultExtraItemMask(4) != 0 ||
        ExpectedMissionResultExtraItemMask(5) !=
            (uint32_t{1} << 4) ||
        ExpectedMissionResultItemMask(0) != 0 ||
        ExpectedMissionResultItemMask(5) != 0x1fU ||
        (MaxPlayers() >= 8 &&
         (ExpectedMissionResultExtraItemMask(8) != 0xf0U ||
          ExpectedMissionResultItemMask(8) != 0xffU)) ||
        g_fake_mission_result_exec_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_result_exec_begin_argument.load(
            std::memory_order_acquire) !=
                kMissionResultSelfTestArgument ||
        g_fake_mission_sync_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_sync_poll_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_reward_resolve_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_reward_apply_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_exec_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_exec_recovery_pending.load(
            std::memory_order_acquire) ||
        g_mission_result_exec_recovery_attempts.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_sync_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_sync_poll_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_sync_complete_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_sync_last_state.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_sync_last_result.load(
            std::memory_order_acquire) != 0 ||
        g_mission_reward_resolve_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_reward_apply_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_reward_apply_completed_calls.load(
            std::memory_order_acquire) != 1) {
        return fail(
            "audited Item P4+/Exec_Begin/Sync/ResolveResult/ApplyResult pipeline failed");
    }

    // Exercise the opposite race deterministically: the native script path
    // arrives inside the grace period. It must consume the queued fallback,
    // block subsequent re-queues and leave no work for the Mission() poll.
    ResetMissionResultExecRecoveryState();
    g_fake_mission_result_exec_begin_calls.store(
        0, std::memory_order_release);
    g_fake_mission_result_exec_begin_argument.store(
        0, std::memory_order_release);

    const bool native_cancel_queued = QueueMissionResultExecRecovery(
        MissionResultSyncOrigin::Script, true, 0, 0);
    const bool native_exec_accepted = MissionResultExecBeginHook(
        mission_result_recovery::kExecBeginArgument);
    const bool requeued_after_native = QueueMissionResultExecRecovery(
        MissionResultSyncOrigin::Script, true, 0, 0);
    const bool duplicate_recovery_applied =
        ApplyPendingMissionResultExecRecovery(
            GetTickCount64() +
            mission_result_recovery::kExecBeginGraceMs + 1);
    if (!native_cancel_queued || !native_exec_accepted ||
        requeued_after_native || duplicate_recovery_applied ||
        g_mission_result_exec_recovery_pending.load(
            std::memory_order_acquire) ||
        g_mission_result_exec_recovery_tick.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_recovery_generation.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_mission_result_exec_recovery_attempts.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_recovery_native_cancels.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_result_exec_begin_calls.load(
            std::memory_order_acquire) != 1 ||
        g_fake_mission_result_exec_begin_argument.load(
            std::memory_order_acquire) !=
                mission_result_recovery::kExecBeginArgument) {
        return fail(
            "native Exec_Begin did not cancel recovery without duplicate finalization");
    }

    // A room can start another stage without recreating its lobby. Reproduce
    // that generation gap with a stale queued fallback and verify the normal
    // mission observer discards every generation-scoped field atomically.
    AcquireSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    g_mission_result_exec_recovery_tick.store(123,
                                               std::memory_order_release);
    g_mission_result_exec_recovery_generation.store(
        4, std::memory_order_release);
    g_mission_result_exec_recovery_pending.store(
        true, std::memory_order_release);
    g_mission_result_exec_begin_calls.store(3, std::memory_order_release);
    g_mission_result_exec_recovery_attempts.store(
        2, std::memory_order_release);
    g_mission_result_exec_recovery_native_cancels.store(
        1, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_mission_result_exec_recovery_lock);
    g_mission_generation.store(4, std::memory_order_release);
    g_mission_update_tick.store(1, std::memory_order_release);
    ObserveMissionUpdate(kMissionGenerationGapMs + 2,
                         kMissionUiStateRunning);
    if (g_mission_generation.load(std::memory_order_acquire) != 5 ||
        g_mission_result_exec_recovery_pending.load(
            std::memory_order_acquire) ||
        g_mission_result_exec_recovery_tick.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_recovery_generation.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_begin_calls.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_recovery_attempts.load(
            std::memory_order_acquire) != 0 ||
        g_mission_result_exec_recovery_native_cancels.load(
            std::memory_order_acquire) != 0) {
        return fail(
            "new mission did not discard the previous generation Exec_Begin state");
    }
    g_mission_update_tick.store(0, std::memory_order_release);
    g_debug_stage_win_active.store(false, std::memory_order_release);
    g_debug_stage_win_consumed.store(false, std::memory_order_release);
    g_debug_stage_win_hotkey_test_override.store(1,
                                                  std::memory_order_release);
    Sleep(120);
    if (g_debug_stage_win_pending.load(std::memory_order_acquire) ||
        g_debug_stage_win_test_set_calls.load(std::memory_order_acquire) != 2) {
        return fail("F5 outside an active mission was not rejected");
    }
    g_debug_stage_win_hotkey_test_override.store(0,
                                                  std::memory_order_release);
    Sleep(100);
    g_remove_hotkey_test_override.store(1, std::memory_order_release);
    if (!wait_for_count(1)) return fail("simulated F7 did not remove the last filler");
    g_remove_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    g_remove_hotkey_test_override.store(1, std::memory_order_release);
    if (!wait_for_count(0)) {
        return fail("second simulated F7 did not remove all fillers");
    }
    g_remove_hotkey_test_override.store(0, std::memory_order_release);
    Sleep(100);
    g_last_actual_member_count.store(1, std::memory_order_release);
    auto wait_for_harness = [](unsigned expected) {
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            if (g_local_mission_harness_target.load(
                    std::memory_order_acquire) == expected &&
                g_bot_count.load(std::memory_order_acquire) == expected) {
                return true;
            }
            Sleep(10);
        }
        return false;
    };
    g_local_mission_harness_hotkey_test_override.store(
        1, std::memory_order_release);
    if (!wait_for_harness(kLocalMissionHarnessBaselineDummies)) {
        return fail("F3 did not create the local host+3 baseline");
    }
    if (!g_mission_groups_pending.load(std::memory_order_acquire) ||
        !LocalMissionHarnessSessionReady() ||
        hotkey_ready_users[3].ready.load(std::memory_order_acquire) != 1 ||
        !hotkey_ready_users[3].cm_ready.load(std::memory_order_acquire) ||
        !hotkey_ready_users[3].ds_ready.load(std::memory_order_acquire)) {
        return fail("host+3 baseline did not arm local Ready and l1/l2");
    }
    int32_t fake_matching_state = kMissionStartLocallyAggregatedState;
    if (CompleteLocalMissionHarnessMatchingGate(&fake_matching_state, false) ||
        fake_matching_state != kMissionStartLocallyAggregatedState ||
        CompleteLocalMissionHarnessMatchingGate(&fake_matching_state, true)) {
        return fail("harness Matching gate did not fail closed without masks");
    }
    constexpr uint32_t baseline_harness_mask =
        (uint32_t{1} << kLocalMissionHarnessBaselineDummies) - 1;
    g_diagnostic_ready_mask.store(baseline_harness_mask,
                                  std::memory_order_release);
    g_diagnostic_mission_group_mask.store(baseline_harness_mask,
                                          std::memory_order_release);
    g_gameplay_contact_mask.store(baseline_harness_mask,
                                  std::memory_order_release);
    g_mission_groups_synchronized.store(true, std::memory_order_release);
    g_diagnostic_real_gameplay_peers.store(1, std::memory_order_release);
    if (ShouldBypassLocalMissionHarnessControllerGate(
            0, 1, kLocalMissionHarnessBaselineDummies)) {
        return fail("preceding controller gate accepted a real peer");
    }
    if (CompleteLocalMissionHarnessMatchingGate(&fake_matching_state, true) ||
        fake_matching_state != kMissionStartLocallyAggregatedState) {
        return fail("Matching gate accepted a real peer in the host-only harness");
    }
    g_diagnostic_real_gameplay_peers.store(0, std::memory_order_release);
    if (ShouldBypassLocalMissionHarnessControllerGate(
            0, 0, kLocalMissionHarnessBaselineDummies) ||
        ShouldBypassLocalMissionHarnessControllerGate(
            1, 1, kLocalMissionHarnessBaselineDummies) ||
        !ShouldBypassLocalMissionHarnessControllerGate(
            0, 1, kLocalMissionHarnessBaselineDummies) ||
        !ShouldBypassLocalMissionHarnessControllerGate(
            0, kMissionStartLocallyAggregatedState,
            kLocalMissionHarnessBaselineDummies) ||
        !ShouldBypassLocalMissionHarnessControllerGate(
            0, kMissionStartCompletedState,
            kLocalMissionHarnessBaselineDummies) ||
        ShouldBypassLocalMissionHarnessControllerGate(
            0, kMissionStartCompletedState + 1,
            kLocalMissionHarnessBaselineDummies)) {
        return fail("preceding controller gate was not limited to states 1..5");
    }
    if (!CompleteLocalMissionHarnessMatchingGate(&fake_matching_state, true) ||
        fake_matching_state != kMissionStartCompletedState ||
        g_local_mission_harness_matching_completions.load(
            std::memory_order_acquire) != 1 ||
        CompleteLocalMissionHarnessMatchingGate(&fake_matching_state, true)) {
        return fail("Matching gate did not complete exactly one 4->5 transition");
    }
    g_mission_generation.store(3, std::memory_order_release);
    g_mission_result_last_setter_generation.store(
        2, std::memory_order_release);
    ArmMissionResultRecovery(kMissionScriptClearApplyReturnRva,
                             GetTickCount64(), kMissionResultClear,
                             kMissionUiStateFinished,
                             kMissionResultClear);
    if (!g_mission_result_recovery_pending.exchange(
            false, std::memory_order_acq_rel)) {
        return fail("host-only harness did not arm result recovery");
    }
    g_mission_result_recovery_tick.store(0, std::memory_order_release);
    g_mission_result_recovery_generation.store(
        0, std::memory_order_release);
    Sleep(120);
    if (!wait_for_harness(kLocalMissionHarnessBaselineDummies)) {
        return fail("F3 repeated while held");
    }
    FakeMissionResultSyncState harness_sync_state{};
    harness_sync_state.phase = 0;
    harness_sync_state.result = 1;
    g_mission_result_sync_test_origin.store(
        static_cast<int>(MissionResultSyncOrigin::Script),
        std::memory_order_release);
    MissionNamedSyncBeginHook(&harness_sync_state, nullptr);
    g_mission_result_sync_test_origin.store(-1,
                                             std::memory_order_release);
    if (harness_sync_state.phase != 1 || harness_sync_state.result != 0) {
        return fail("harness did not complete Sync_MissionResult locally");
    }
    g_local_mission_harness_hotkey_test_override.store(
        0, std::memory_order_release);
    Sleep(100);
    g_local_mission_harness_hotkey_test_override.store(
        1, std::memory_order_release);
    if (!wait_for_harness(kLocalMissionHarnessProbeDummies) ||
        hotkey_ready_users[4].ready.load(std::memory_order_acquire) != 1 ||
        !hotkey_ready_users[4].cm_ready.load(std::memory_order_acquire) ||
        !hotkey_ready_users[4].ds_ready.load(std::memory_order_acquire)) {
        return fail("F3 did not create the local host+4/P4 probe");
    }
    std::string harness_name;
    if (!TryGetBotName(BotSteamId(3), harness_name) ||
        harness_name != "Harness Dummy 4") {
        return fail("P4 dummy did not receive an isolated harness name");
    }
    g_local_mission_harness_hotkey_test_override.store(
        0, std::memory_order_release);
    Sleep(100);
    g_local_mission_harness_hotkey_test_override.store(
        1, std::memory_order_release);
    if (!wait_for_harness(0) ||
        g_mission_groups_pending.load(std::memory_order_acquire)) {
        return fail("third F3 did not disable and empty the harness");
    }
    g_local_mission_harness_hotkey_test_override.store(
        0, std::memory_order_release);
    for (auto& user : hotkey_ready_users) UnregisterReadyUser(&user);
    g_ready_user_test_mode.store(false, std::memory_order_release);
    Stop();
    reset_state();
    report = "ok: dynamic room up to 8/8; one native local EDF5_MultiSlotMod/version banner per create/join without identity or Steam send; PlayerInfo RAX preserved; P4-P7 parser safely captures sidecars, accepts valid count despite false return, masks overlapping weapon and restores out-of-range blocks without losing participants/rewards; extra class uses PlayerInfo/sidecar within 0..3; direct/fallback UserImpl source; fifth-player scratch synthesizes/restores class-weapons-armor and restores the unique index before map consumers; private distinct PlayerInfo name tokens/source indices; isolated per-participant sender/owner correlation without real chat text; registered order/local subset and participant-control assignment; replication detects duplicate UserImpl; dynamic receive table detects missing/duplicate P0 route and per-participant 0x3300/0x3400; runtime spawn multiplies 10->20, repairs 0/4 during call, restores zero and preserves concurrent mutation; GeneratorPoll preserves Update and RAX/AL, correlates update/base/gate/spawn/boundary and classifies cooldown/quota/false/accepted returns; native host-only recovery publishes UI event 1/2, closes object id 2 and returns effective result 1; independent Exec_Begin/Sync_MissionResult/ResolveResult/ApplyResult pipeline checks extra Items mask, defensively restores local count 0->1 before rewards, proves native Exec_Begin cancels the queue without requeue/duplication and new generations discard all previous mission state; Local Mission Harness F3 cycles host+3/host+4/off with distinct UserImpl, Ready, early l1/l2, preceding controller gate limited to states 1..5 and zero real peers, fail-closed global Matching 4->5 without fabricated packets and local result sync; loadout, PlayersGroup, callbacks, P2P, authentication and F8/F7/F6/F5/wheel validated";
    return true;
}

}  // namespace more_players
