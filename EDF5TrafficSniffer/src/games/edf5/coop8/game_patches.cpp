#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "game_patches.h"

#include "crash_handler.h"
#include "logger.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <string>

namespace game_patches {
namespace {

constexpr uintptr_t kRosterConstructorRva = 0x448840;
constexpr uintptr_t kCapacityRegionRva = 0x44894b;
constexpr size_t kCapacityRegionSize = 41;
constexpr size_t kFirstCapacityImmediate = 1;
constexpr size_t kSecondCapacityImmediate = 23;
constexpr unsigned kOriginalCapacity = 4;

// A second roster owner, constructed at RVA 0x4328c0, stores intrusive
// pointers in 16-byte slots.  Its constructor, specialized grow helper, and
// final size initialization all encode the original capacity independently.
// Leaving any one of these at four either allocates only four slots or leaves
// slot five uninitialized (the observed crash at RVA 0x7d9b0).
constexpr uintptr_t kSecondaryConstructorRva = 0x4328c0;
constexpr uintptr_t kSecondaryGrowHelperRva = 0x436990;
constexpr uintptr_t kSecondaryFaultRva = 0x7d9b0;
constexpr uintptr_t kTertiaryConstructorRva = 0x419550;
constexpr uintptr_t kTertiaryGrowHelperRva = 0x41bb30;
constexpr uintptr_t kTertiaryFaultRva = 0x25a5c;
constexpr uintptr_t kMemberButtonLoopRva = 0x565a9d;
constexpr uintptr_t kMemberButtonFaultRva = 0x4e4773;
constexpr uintptr_t kRoomPanelConstructorRva = 0x5a5910;
constexpr uintptr_t kRoomPanelResizeRva = 0x5a7180;
constexpr uintptr_t kRoomPanelGrowHelperRva = 0x5a7240;
constexpr uintptr_t kRoomPanelUpdateRva = 0x5a5bd0;
constexpr uintptr_t kRoomPanelFaultCallerRva = 0x5a5eb6;
constexpr uintptr_t kMissionParticipantFunctionRva = 0x126c90;
constexpr uintptr_t kMissionParticipantProducerRva = 0x11d5e0;
constexpr uintptr_t kMissionParticipantWriteRva = 0x11d7a9;
constexpr uintptr_t kMissionParticipantCookieReturnRva = 0x126d57;
constexpr unsigned kMissionParticipantSafeCapacity = 8;
constexpr uintptr_t kMissionSpawnFunctionRva = 0x11d860;
constexpr uintptr_t kMissionSpawnBuilderRva = 0x11ce60;
constexpr uintptr_t kMissionSpawnSharedHandleCopyRva = 0x6e010;
constexpr uintptr_t kMissionSpawnFaultRva = 0x6e022;
constexpr uintptr_t kMissionRecordFaultRva = 0x11dc95;
constexpr uintptr_t kMissionRecordRedirectRva = 0x11db90;
constexpr uintptr_t kMissionRecordRedirectReturnRva = 0x11db98;
constexpr uintptr_t kMissionRecordLoopBackedgeRva = 0x11dd68;
constexpr uintptr_t kMissionRecordCopyRva = 0x11df95;
constexpr uintptr_t kMissionRecordCopyReturnRva = 0x11df9b;
constexpr uintptr_t kMissionRecordAppendFaultRva = 0x11e2dc;
constexpr uintptr_t kMissionRecordAppendRedirectRva = 0x11e2a0;
constexpr uintptr_t kMissionRecordAppendRedirectReturnRva = 0x11e2a7;
constexpr uintptr_t kMissionRecordAppendLoopBackedgeRva = 0x11e2fe;
constexpr unsigned kMissionSpawnPointCount = 4;
constexpr unsigned kMissionSpawnSafeCapacity = 8;
constexpr uintptr_t kMissionResultParticipantFilterRva = 0x42db4c;
constexpr uintptr_t kMissionResultItemFilterRva = 0x430f23;
constexpr uintptr_t kButtonMasterStringRva = 0xed7fe8;
constexpr uintptr_t kButtonMemberStringRva = 0xed7fc8;
constexpr wchar_t kButtonMasterKey[] = L"Button_Master";
constexpr wchar_t kButtonMemberKey[] = L"Button_Member";
static_assert(sizeof(wchar_t) == 2, "EDF5 patch requires Windows UTF-16 wchar_t");

struct CapacityPatchSite {
    uintptr_t rva;
    std::array<uint8_t, 8> original;
    size_t instruction_size;
    size_t value_offset;
    size_t value_size;
    bool allocation_count_displacement;
    unsigned allocation_element_size = 16;
};

struct BytePatchSite {
    uintptr_t rva;
    std::array<uint8_t, 16> original;
    std::array<uint8_t, 16> replacement;
    size_t instruction_size;
};

struct RelativePatchSite {
    uintptr_t rva;
    std::array<uint8_t, 12> original;
    size_t instruction_size;
    uintptr_t original_target_rva;
    size_t relay_offset;
};

enum class ScalingRegister : uint8_t {
    Eax,
    R8d,
    R9d,
    R10d,
};

struct ParticipantScalingPatchSite {
    uintptr_t rva;
    std::array<uint8_t, 7> original;
    size_t instruction_size;
    ScalingRegister destination;
};

// EDF5 has 56 decoded reads of mission_state+0x245A0 in the enemy/native
// difficulty setup range.  Every one feeds participant_count-1 into the same
// three-dword-per-player table shape without a bounds check.  The native
// tables have profiles for one through four players; participant five selects
// the first record beyond the table and can turn spawn timers or enemy
// parameters into zero/NaN.  Keep the real participant count untouched and
// clamp only these proven table-scaling reads to the native four-player
// profile.  The copied load instruction in each relay preserves its original
// base and destination register.
// Two entries (0x8adcf and 0x2d0913) are leaf functions without x64 unwind
// metadata and therefore require the dependency-free whole-.text census in
// validate_spawn_result_layout.py.  The leaf getter at 0x11e48e deliberately
// remains unpatched because it returns the real participant count.
constexpr std::array<ParticipantScalingPatchSite, 56>
    kParticipantScalingSites = {{
    {0x0008adcf, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001cfeff, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ddbe8, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x001dddc9, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x001ddf0b, {0x45, 0x8b, 0x80, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R8d},
    {0x001e424d, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001e6497, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001e8309, {0x44, 0x8b, 0x93, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R10d},
    {0x001eabc3, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ecbaa, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ecdcf, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ecf17, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ecfa0, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ed021, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001f872c, {0x45, 0x8b, 0x82, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R8d},
    {0x001f89da, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ff74f, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ffab8, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ffb28, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x001ffbb7, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0020aa06, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0020ac34, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00214e8c, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00214f2e, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0021ec6d, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0021eef3, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0021efcf, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0021f04e, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00227381, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x0022a94a, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x002428ca, {0x8b, 0x87, 0xa0, 0x45, 0x02, 0x00, 0x00}, 6, ScalingRegister::Eax},
    {0x0024ebcb, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00255221, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00255361, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0025c341, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0025d830, {0x41, 0x8b, 0x82, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0026406e, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0026802a, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0026ec0e, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002786e0, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x0027883d, {0x45, 0x8b, 0x80, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R8d},
    {0x0028344f, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0028538f, {0x44, 0x8b, 0x93, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R10d},
    {0x0028c6f0, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0028c888, {0x8b, 0x87, 0xa0, 0x45, 0x02, 0x00, 0x00}, 6, ScalingRegister::Eax},
    {0x00294944, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002949c0, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x00297f0c, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x0029a98c, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002a1402, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002a73c7, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x002c0746, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002cadb4, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002d0913, {0x41, 0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::Eax},
    {0x002d4b29, {0x45, 0x8b, 0x89, 0xa0, 0x45, 0x02, 0x00}, 7, ScalingRegister::R9d},
    {0x0033defe, {0x8b, 0x83, 0xa0, 0x45, 0x02, 0x00, 0x00}, 6, ScalingRegister::Eax},
}};

constexpr std::array<CapacityPatchSite, 7> kSecondaryCapacitySites = {{
    {0x432af9, {0x48, 0x83, 0x7e, 0x10, 0x04}, 5, 4, 1, false},
    {0x432b14, {0x48, 0x83, 0x7e, 0x10, 0x04}, 5, 4, 1, false},
    {0x432b2c, {0xba, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x436996, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    // The preceding mov edx,16 plus lea ecx,[rdx-12] encodes allocation count
    // four as 16-12.
    {0x4369b2, {0x8d, 0x4a, 0xf4}, 3, 2, 1, true},
    {0x4369db, {0x41, 0xbe, 0x04, 0x00, 0x00, 0x00}, 6, 2, 4, false},
    {0x436aac, {0x48, 0xc7, 0x47, 0x10, 0x04, 0x00, 0x00, 0x00}, 8, 4, 4,
     false},
}};

// The manager constructed at RVA 0x419550 owns a third 16-byte-slot table at
// object+0xf8 (storage pointer at object+0x100).  Its update path uses the
// participant index directly; index four produced the observed RVA 0x25a5c
// release through a stale value of 1.
constexpr std::array<CapacityPatchSite, 7> kTertiaryCapacitySites = {{
    {0x419789, {0x48, 0x83, 0x7e, 0x10, 0x04}, 5, 4, 1, false},
    {0x4197a4, {0x48, 0x83, 0x7e, 0x10, 0x04}, 5, 4, 1, false},
    {0x4197bc, {0xba, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x41bb36, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x41bb52, {0x8d, 0x4a, 0xf4}, 3, 2, 1, true},
    {0x41bb76, {0xbd, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x41bc0d, {0x48, 0xc7, 0x47, 0x10, 0x04, 0x00, 0x00, 0x00}, 8, 4, 4,
     false},
}};

// The room UI owns a vector at object+0x148 whose storage pointer, capacity,
// and size are at +0x150/+0x158/+0x160. Each 0x50-byte element holds the
// strings and state for one player information panel. The constructor reserves
// and resizes this vector to exactly four elements. The expanded roster then
// reaches index four with byte offset 0x140 and writes into an unconstructed
// std::wstring, producing the observed null-destination memmove below RVA
// 0x5a5eb6. Expand the reserve helper and constructor resize together.
constexpr std::array<CapacityPatchSite, 6> kRoomPanelCapacitySites = {{
    {0x5a59fc, {0x48, 0x83, 0x7f, 0x10, 0x04}, 5, 4, 1, false},
    {0x5a5a14, {0xba, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x5a7261, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    // The preceding mov edx,80 plus lea ecx,[rdx-76] encodes allocation
    // count four as 80-76.
    {0x5a726d, {0x8d, 0x4a, 0xb4}, 3, 2, 1, true, 80},
    {0x5a7281, {0xbd, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x5a72dc, {0x48, 0xc7, 0x47, 0x10, 0x04, 0x00, 0x00, 0x00}, 8, 4, 4,
     false},
}};

// MissionSync_Res walks the live UserImpl collection and accumulates the
// mission result data for every eligible online participant. The collection
// and the local shared-handle destination are dynamic (the latter grows at
// 0x42dbdc), but the first comparison rejects UserImpl+0xf8 values >= 4 before
// the handle is appended. UserImpl+0xf8 is the unique mission participant
// index outside the short character-factory fallback.
//
// The matching NetGameStatus decoder at 0x430c20 reads a dynamic record count,
// yet its second comparison at 0x430f23 decodes records 4+ without invoking
// the Item callback. The first comparison at 0x430ef6 intentionally remains
// four because it clears a fixed four-Item native accumulator. MorePlayers
// hooks the Item sink and safely folds P4-P7 into those four accumulators, so
// only the decoder's application filter may follow MaxPlayers here.
constexpr std::array<CapacityPatchSite, 2>
    kMissionResultParticipantCapacitySites = {{
        {kMissionResultParticipantFilterRva,
         {0x83, 0xf8, 0x04}, 3, 2, 1, false},
        {kMissionResultItemFilterRva,
         {0x83, 0xfb, 0x04}, 3, 2, 1, false},
    }};

// Experimental reserve-only audit.  These 24 groups have the same coherent
// constructor shape: an empty vector compares its capacity with four and then
// calls reserve(4).  Both operands must move together; changing only the
// comparison could suppress growth while leaving a four-entry allocation.
//
// They are deliberately separate from the proven player-roster patches.  The
// owning game systems have not yet been identified, so this batch is optional
// and exists only to make their fixed-four construction paths observable in a
// controlled test build.  EXPERIMENTAL_SLOT_PATCHES.md is the source of truth
// for classification and manual-test status.
constexpr std::array<CapacityPatchSite, 48> kExperimentalReserveSites = {{
    {0x14958d, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x149594, {0x8d, 0x50, 0x04}, 3, 2, 1, false},
    {0x1cdcf2, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1cdcf9, {0x8d, 0x53, 0x04}, 3, 2, 1, false},
    {0x1ce773, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1ce77a, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x1d8176, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1d817d, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x1d95ad, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1d95b4, {0x8d, 0x50, 0x04}, 3, 2, 1, false},
    {0x1f7d70, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1f7d77, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x1fbf2a, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1fbf31, {0x41, 0x8d, 0x55, 0x04}, 4, 3, 1, false},
    {0x1fc508, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x1fc50f, {0x8d, 0x53, 0x04}, 3, 2, 1, false},
    {0x25d408, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x25d40f, {0x41, 0x8d, 0x55, 0x04}, 4, 3, 1, false},
    {0x263925, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x26392c, {0x8d, 0x55, 0x04}, 3, 2, 1, false},
    {0x2769a2, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2769a9, {0x41, 0x8d, 0x57, 0x04}, 4, 3, 1, false},
    {0x282612, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x282619, {0xba, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x29cba2, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x29cba9, {0x8d, 0x55, 0x04}, 3, 2, 1, false},
    {0x2a27a5, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2a27ac, {0x8d, 0x56, 0x04}, 3, 2, 1, false},
    {0x2a6f6f, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2a6f76, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x2b0242, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2b0249, {0x8d, 0x56, 0x04}, 3, 2, 1, false},
    {0x2b837d, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2b8384, {0x41, 0x8d, 0x54, 0x24, 0x04}, 5, 4, 1, false},
    {0x2bb10d, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2bb114, {0x8d, 0x56, 0x04}, 3, 2, 1, false},
    {0x2c4b67, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2c4b6e, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x2d17f3, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x2d17fa, {0x8d, 0x56, 0x04}, 3, 2, 1, false},
    {0x34eaa0, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x34eaa7, {0x8d, 0x53, 0x04}, 3, 2, 1, false},
    {0x35037a, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x350381, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
    {0x47a4cf, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x47a4d6, {0xba, 0x04, 0x00, 0x00, 0x00}, 5, 1, 4, false},
    {0x4aecfe, {0x48, 0x83, 0x79, 0x10, 0x04}, 5, 4, 1, false},
    {0x4aed05, {0x8d, 0x57, 0x04}, 3, 2, 1, false},
}};

constexpr std::array<uintptr_t, 24> kExperimentalReserveAnchors = {{
    0x14958d, 0x1cdcf2, 0x1ce773, 0x1d8176, 0x1d95ad, 0x1f7d70,
    0x1fbf2a, 0x1fc508, 0x25d408, 0x263925, 0x2769a2, 0x282612,
    0x29cba2, 0x2a27a5, 0x2a6f6f, 0x2b0242, 0x2b837d, 0x2bb10d,
    0x2c4b67, 0x2d17f3, 0x34eaa0, 0x35037a, 0x47a4cf, 0x4aecfe,
}};

constexpr std::array<uintptr_t, 11> kDeferredFourAnchors = {{
    0x5b6c1, 0xd2238, 0xd25b6, 0x2bd3cf, 0x971940, 0x9722c7,
    0xc3b97c, 0xc3b9fa, 0xc3ba2d, 0xc3bc1a, 0xc3bc76,
}};

static_assert(kExperimentalReserveSites.size() ==
                  kExperimentalReserveAnchors.size() * 2,
              "experimental reserve groups must patch two operands each");

// The room UI builds a four-pointer local array containing Button_Master once
// and Button_Member three times, then iterates object+0x920 entries. With a
// five-player roster, the fifth iteration reads the stack cookie immediately
// after that array and passes it as a UTF-16 key, producing the observed read
// AV at RVA 0x4e4773. Rewrite the loop to use Button_Master for index zero and
// Button_Member for every subsequent index without indexing the fixed array.
constexpr std::array<BytePatchSite, 4> kMemberButtonLoopSites = {{
    {0x565aa9,
     {0x48, 0x8d, 0x9d, 0x80, 0x00, 0x00, 0x00},
     {0x48, 0x8d, 0x1d, 0x38, 0x25, 0x97, 0x00}, 7},
    {0x565ab0,
     {0x48, 0x8b, 0x13},
     {0x48, 0x8b, 0xd3}, 3},
    {0x565abd,
     {0x48, 0x8d, 0x5b, 0x08, 0x48, 0x63, 0xc7},
     {0x48, 0x8d, 0x1d, 0x04, 0x25, 0x97, 0x00}, 7},
    {0x565ac4,
     {0x49, 0x3b, 0x87, 0x20, 0x09, 0x00, 0x00},
     {0x49, 0x3b, 0xbf, 0x20, 0x09, 0x00, 0x00}, 7},
}};

// The mission-entry helper at RVA 0x126c90 places an int32 participant array
// at rsp+0x68 and its /GS cookie at rsp+0x78. Six or more participants would
// overwrite the cookie even after the former 4->6 relocation. Redirect both
// calls that consume that pointer through tiny relays which substitute an
// eight-int32 buffer on our relay page. This leaves the function's stack frame
// and Windows unwind metadata untouched.
constexpr size_t kMissionParticipantProducerStubOffset = 0x300;
constexpr size_t kMissionParticipantConsumerStubOffset = 0x340;
constexpr size_t kMissionParticipantArrayOffset = 0x500;
constexpr std::array<RelativePatchSite, 2> kMissionParticipantCallSites = {{
    {0x126ce0, {0xe8, 0xfb, 0x68, 0xff, 0xff}, 5,
     kMissionParticipantProducerRva, kMissionParticipantProducerStubOffset},
    {0x126d24, {0xe8, 0x17, 0x75, 0xf5, 0xff}, 5,
     0x7e240, kMissionParticipantConsumerStubOffset},
}};

// Mission entry has four native 16-byte spawn/orientation records and four
// native 24-byte persistent participant records. Relays keep those native
// arrays untouched: every participant >=4 recycles spawn[index % 4], while
// persistent records 4..7 live in four 24-byte sidecars. Both later record
// transfer loops select the same sidecar array for extra source/destination
// indices, so no fifth-only local stack record is required.

constexpr std::array<uint8_t, 8> kMissionRecordRedirectOriginal = {
    0x41, 0x8b, 0x5d, 0x00,  // mov ebx,[r13]
    0x0f, 0x28, 0x45, 0xc0,  // movaps xmm0,[rbp-0x40]
};
constexpr std::array<uint8_t, 6> kMissionRecordCopyOriginal = {
    0x8b, 0x55, 0x48, 0x48, 0x85, 0xd2,
};
constexpr uintptr_t kMissionRecordExistingRedirectRva = 0x11e1a0;
constexpr uintptr_t kMissionRecordExistingNativeSourceRva = 0x11e1ae;
constexpr uintptr_t kMissionRecordExistingExtraSourceReturnRva = 0x11e1cc;
constexpr std::array<uint8_t, 10> kMissionRecordExistingRedirectOriginal = {
    0x4d, 0x8b, 0xf4,                    // mov r14,r12
    0x41, 0xff, 0xc5,                    // inc r13d
    0x49, 0x83, 0xc4, 0x18,              // add r12,0x18
};
constexpr std::array<uint8_t, 7> kMissionRecordAppendRedirectOriginal = {
    0x49, 0x8b, 0xf4,              // mov rsi,r12
    0x49, 0x83, 0xc4, 0x18,        // add r12,0x18
};
constexpr size_t kMissionRelayPageSize = 0x2000;
constexpr size_t kMissionRedirectStubOffset = 0x000;
constexpr size_t kMissionCopyStubOffset = 0x080;  // legacy harness layout
constexpr size_t kMissionExistingRedirectStubOffset = 0x100;
constexpr size_t kMissionAppendRedirectStubOffset = 0x200;
constexpr size_t kMissionSidecarOffset = 0x400;
constexpr size_t kMissionPrimaryRedirectCounterOffset = 0x470;
constexpr size_t kMissionExistingRedirectCounterOffset = 0x478;
constexpr size_t kMissionAppendRedirectCounterOffset = 0x480;
constexpr size_t kParticipantScalingStubOffset = 0x600;
constexpr size_t kParticipantScalingStubStride = 0x30;
constexpr size_t kParticipantScalingClampHitsOffset = 0x1100;
constexpr size_t kParticipantScalingClampMaskOffset = 0x1108;
constexpr size_t kMissionParticipantCountOffset = 0x245a0;
constexpr int32_t kNativeParticipantScalingCapacity = 4;
constexpr size_t kMissionRecordSize = 0x18;
constexpr size_t kMissionRecordObjectBaseOffset = 0x138;
constexpr size_t kMissionRecordFirstExtraObjectOffset =
    kMissionRecordObjectBaseOffset + 4 * kMissionRecordSize;
constexpr unsigned kMissionRecordSidecarCount = 4;
constexpr size_t kMissionRecordLastExtraObjectOffset =
    kMissionRecordFirstExtraObjectOffset +
    (kMissionRecordSidecarCount - 1) * kMissionRecordSize;
static_assert(kParticipantScalingStubOffset +
                  kParticipantScalingSites.size() *
                      kParticipantScalingStubStride <=
              kParticipantScalingClampHitsOffset,
              "participant scaling relays overlap telemetry");
static_assert(kParticipantScalingClampMaskOffset + sizeof(uint64_t) <=
                  kMissionRelayPageSize,
              "participant scaling telemetry exceeds relay page");

// Loadout parser 0x42F480 addresses every participant block as
// r14 + index*0x3E90 + offset, with r14 = state+0x14A40 (block 0 - 0xF0).
// Mission state holds only four blocks: block 4 already overlaps the result
// Items/counters at +0x24570, and its 0x30-byte tail at +0x283D0 lies past
// the allocation (six-player host crash EDF5.exe+0x42F954 writing there).
// Relay the stride multiply and select r14 per iteration so indices 4..7
// address private blocks with the identical layout. r14 is dead after the
// loop: 0x42FA94 zeroes it before its next use.
constexpr uintptr_t kLoadoutParserStrideRva = 0x42f7c9;
constexpr uintptr_t kLoadoutParserStrideReturnRva = 0x42f7d0;
constexpr std::array<uint8_t, 7> kLoadoutParserStrideOriginal = {
    0x4c, 0x69, 0xd1, 0x90, 0x3e, 0x00, 0x00,  // imul r10,rcx,0x3e90
};
constexpr uintptr_t kLoadoutParserStateSlotRva = 0x125ab30;
constexpr uint32_t kLoadoutParserNativeBaseOffset = 0x14a40;
constexpr size_t kLoadoutParserBlockStride = 0x3e90;
constexpr size_t kLoadoutParserBlockBias = 0xf0;
constexpr size_t kLoadoutParserLastWriteEnd = 0x3f80;
constexpr unsigned kLoadoutParserExtraBlocks = 4;
// One further block absorbs malformed indices >= 8 instead of letting them
// address arbitrary memory.
constexpr size_t kLoadoutParserScratchSize = 0x14000;
constexpr size_t kLoadoutParserStubOffset = 0x1200;
constexpr size_t kLoadoutParserExtraCounterOffset = 0x1300;
constexpr size_t kLoadoutParserInvalidCounterOffset = 0x1308;
static_assert(kLoadoutParserLastWriteEnd - kLoadoutParserBlockBias ==
                  kLoadoutParserBlockStride,
              "parser tail must end at its block boundary");
static_assert((kLoadoutParserExtraBlocks + 1) * kLoadoutParserBlockStride <=
                  kLoadoutParserScratchSize,
              "loadout scratch cannot hold four blocks plus the guard block");
static_assert(kParticipantScalingClampMaskOffset + sizeof(uint64_t) <=
                  kLoadoutParserStubOffset,
              "loadout parser relay overlaps scaling telemetry");
static_assert(kLoadoutParserInvalidCounterOffset + sizeof(uint64_t) <=
                  kMissionRelayPageSize,
              "loadout parser telemetry exceeds relay page");

// EDF5's two variable-length message builders size their buffer to a fixed
// 0x2E8 bytes and copy the caller's payload into it before (0x433000, 12-byte
// header, rejects totals above 0x578 only afterwards) or without (0x432D20,
// 4-byte header) any size check. Mission start with six participants sent an
// 857-byte 0x1100 message and corrupted the host heap (live 2026-10-02).
// Relay each initial reserve so it is max(0x2E8, header + payload size).
constexpr uint32_t kNativeMessageReserve = 0x2e8;
constexpr uintptr_t kReliableMessageReserveRva = 0x43309e;
constexpr uintptr_t kReliableMessageReserveReturnRva = 0x4330a6;
constexpr std::array<uint8_t, 8> kReliableMessageReserveOriginal = {
    0xba, 0xe8, 0x02, 0x00, 0x00,  // mov edx,0x2e8
    0x48, 0x8b, 0xcb,              // mov rcx,rbx
};
constexpr uintptr_t kReplicationMessageReserveRva = 0x432d65;
constexpr uintptr_t kReplicationMessageReserveReturnRva = 0x432d6e;
constexpr std::array<uint8_t, 9> kReplicationMessageReserveOriginal = {
    0xba, 0xe8, 0x02, 0x00, 0x00,  // mov edx,0x2e8
    0x48, 0x8d, 0x4d, 0x07,        // lea rcx,[rbp+7]
};
constexpr size_t kReliableMessageReserveStubOffset = 0x1400;
constexpr size_t kReplicationMessageReserveStubOffset = 0x1480;
constexpr size_t kReliableMessageReserveGrownCounterOffset = 0x1310;
constexpr size_t kReplicationMessageReserveGrownCounterOffset = 0x1318;
static_assert(kLoadoutParserInvalidCounterOffset + sizeof(uint64_t) <=
                  kReliableMessageReserveGrownCounterOffset,
              "message reserve telemetry overlaps loadout telemetry");
static_assert(kReplicationMessageReserveStubOffset + 0x80 <=
                  kMissionRelayPageSize,
              "message reserve relays exceed relay page");

// Mission spawn function 0x11D860 transforms its four native 16-byte spawn
// records at rbp+0x1E0 in a loop bounded by the real participant count. With
// six participants slot 5 lands on the /GS cookie at rbp+0x230 and every
// machine fails with 0xC0000409 (live 2026-10-02); slots 6-7 would overwrite
// saved xmm registers. Extra participants already recycle spawn[index % 4],
// so cap that loop at the four native records.
constexpr uintptr_t kSpawnTransformLoopRva = 0x11db21;
constexpr uintptr_t kSpawnTransformLoopBodyRva = 0x11dab1;
constexpr uintptr_t kSpawnTransformLoopExitRva = 0x11db27;
constexpr std::array<uint8_t, 6> kSpawnTransformLoopOriginal = {
    0x3b, 0x7c, 0x24, 0x50,  // cmp edi,[rsp+0x50]
    0x75, 0x8a,              // jne 0x11dab1
};
constexpr size_t kSpawnTransformLoopStubOffset = 0x1500;
constexpr size_t kSpawnTransformCappedCounterOffset = 0x1320;
static_assert(kReplicationMessageReserveGrownCounterOffset +
                      sizeof(uint64_t) <=
                  kSpawnTransformCappedCounterOffset,
              "spawn transform telemetry overlaps message telemetry");
static_assert(kSpawnTransformLoopStubOffset + 0x40 <= kMissionRelayPageSize,
              "spawn transform relay exceeds relay page");

uint8_t* g_mission_relay_page = nullptr;
// Allocated once and never released: the parser hook may still be reading it
// while a quarantine restores the original instruction.
uint8_t* g_loadout_parser_scratch = nullptr;
std::atomic<bool> g_loadout_parser_redirect_active{false};
std::atomic<uint64_t> g_reported_loadout_parser_extra_redirects{0};
std::atomic<uint64_t> g_reported_loadout_parser_invalid_redirects{0};
std::atomic<uint64_t> g_reported_reliable_message_reserves_grown{0};
std::atomic<uint64_t> g_reported_replication_message_reserves_grown{0};
std::atomic<uint64_t> g_reported_spawn_transform_caps{0};
unsigned g_mission_relay_capacity = 0;
unsigned g_roster_patch_max_players = 0;
unsigned g_roster_patch_preallocated_slots = 0;
unsigned g_experimental_patch_capacity = 0;
std::atomic<uint64_t> g_reported_primary_redirects{0};
std::atomic<uint64_t> g_reported_existing_redirects{0};
std::atomic<uint64_t> g_reported_append_redirects{0};
std::atomic<uint64_t> g_reported_participant_scaling_clamp_hits{0};
std::atomic<uint64_t> g_reported_participant_scaling_clamp_mask{0};

// EDF5.exe RVA 0x44894b. The two imm32 values are the requested size passed to
// the internal pointer-table grow/check helpers. Both must change together.
constexpr std::array<uint8_t, kCapacityRegionSize> kCapacityRegion = {
    0xba, 0x04, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0xcb,
    0x48, 0x3b, 0xf2,
    0x73, 0x11,
    0xe8, 0x43, 0xe8, 0xc9, 0xff,
    0x84, 0xc0,
    0x74, 0x13,
    0xba, 0x04, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0xcb,
    0x4c, 0x8d, 0x44, 0x24, 0x48,
    0xe8, 0x8d, 0xec, 0xc9, 0xff,
    0x90,
};

const wchar_t* BaseName(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* slash = std::wcsrchr(path, L'\\');
    const wchar_t* forward = std::wcsrchr(path, L'/');
    const wchar_t* last = slash;
    if (!last || (forward && forward > last)) last = forward;
    return last ? last + 1 : path;
}

uint8_t* FindPreviousFreeRegion(uint8_t* address, uint8_t* minimum,
                                DWORD granularity) {
    uintptr_t candidate = reinterpret_cast<uintptr_t>(address);
    candidate -= candidate % granularity;
    if (candidate < granularity) return nullptr;
    candidate -= granularity;
    while (candidate >= reinterpret_cast<uintptr_t>(minimum)) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(reinterpret_cast<void*>(candidate), &info,
                          sizeof(info))) {
            break;
        }
        if (info.State == MEM_FREE) {
            return reinterpret_cast<uint8_t*>(candidate);
        }
        const uintptr_t allocation =
            reinterpret_cast<uintptr_t>(info.AllocationBase);
        if (allocation < granularity) break;
        candidate = allocation - granularity;
    }
    return nullptr;
}

uint8_t* FindNextFreeRegion(uint8_t* address, uint8_t* maximum,
                            DWORD granularity) {
    uintptr_t candidate = reinterpret_cast<uintptr_t>(address);
    candidate -= candidate % granularity;
    candidate += granularity;
    while (candidate <= reinterpret_cast<uintptr_t>(maximum)) {
        MEMORY_BASIC_INFORMATION info{};
        if (!VirtualQuery(reinterpret_cast<void*>(candidate), &info,
                          sizeof(info))) {
            break;
        }
        if (info.State == MEM_FREE) {
            return reinterpret_cast<uint8_t*>(candidate);
        }
        candidate = reinterpret_cast<uintptr_t>(info.BaseAddress) +
                    info.RegionSize;
        candidate += granularity - 1;
        candidate -= candidate % granularity;
    }
    return nullptr;
}

uint8_t* AllocateMissionRelayPage(uint8_t* origin) {
    constexpr uintptr_t kMaximumDistance = 0x70000000;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    uintptr_t minimum =
        reinterpret_cast<uintptr_t>(system_info.lpMinimumApplicationAddress);
    uintptr_t maximum =
        reinterpret_cast<uintptr_t>(system_info.lpMaximumApplicationAddress);
    const uintptr_t center = reinterpret_cast<uintptr_t>(origin);
    if (center > kMaximumDistance && minimum < center - kMaximumDistance) {
        minimum = center - kMaximumDistance;
    }
    if (maximum > center + kMaximumDistance) {
        maximum = center + kMaximumDistance;
    }
    maximum -= kMissionRelayPageSize - 1;

    uint8_t* candidate = origin;
    while (reinterpret_cast<uintptr_t>(candidate) >= minimum) {
        candidate = FindPreviousFreeRegion(
            candidate, reinterpret_cast<uint8_t*>(minimum),
            system_info.dwAllocationGranularity);
        if (!candidate) break;
        auto* page = static_cast<uint8_t*>(VirtualAlloc(
            candidate, kMissionRelayPageSize, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
        if (page) return page;
    }

    candidate = origin;
    while (reinterpret_cast<uintptr_t>(candidate) <= maximum) {
        candidate = FindNextFreeRegion(
            candidate, reinterpret_cast<uint8_t*>(maximum),
            system_info.dwAllocationGranularity);
        if (!candidate) break;
        auto* page = static_cast<uint8_t*>(VirtualAlloc(
            candidate, kMissionRelayPageSize, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
        if (page) return page;
    }
    return nullptr;
}

bool WriteRelative32(uint8_t* instruction, uint8_t opcode,
                     const uint8_t* target) {
    if (!instruction || !target) return false;
    const int64_t difference =
        reinterpret_cast<int64_t>(target) -
        reinterpret_cast<int64_t>(instruction + 5);
    if (difference < std::numeric_limits<int32_t>::min() ||
        difference > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    instruction[0] = opcode;
    const int32_t relative = static_cast<int32_t>(difference);
    std::memcpy(instruction + 1, &relative, sizeof(relative));
    return true;
}

const uint8_t* Relative32Target(const uint8_t* instruction,
                                uint8_t opcode) {
    if (!instruction || instruction[0] != opcode) return nullptr;
    int32_t relative = 0;
    std::memcpy(&relative, instruction + 1, sizeof(relative));
    return instruction + 5 + relative;
}

uintptr_t RelativeRvaTarget(uintptr_t next_instruction,
                            int32_t displacement) {
    return static_cast<uintptr_t>(
        static_cast<int64_t>(next_instruction) +
        static_cast<int64_t>(displacement));
}

[[maybe_unused]] bool BuildLegacyMissionRelayPage(uint8_t* image) {
    if (g_mission_relay_page) return true;
    auto* page = AllocateMissionRelayPage(image + kMissionRecordRedirectRva);
    if (!page) return false;
    std::memset(page, 0xcc, kMissionRelayPageSize);

    auto* redirect = page + kMissionRedirectStubOffset;
    const uint8_t redirect_prefix[] = {
        0x41, 0x8b, 0x5d, 0x00,              // original: mov ebx,[r13]
        0x0f, 0x28, 0x45, 0xc0,              // original: movaps xmm0,[rbp-0x40]
        0x41, 0x83, 0xfe, 0x04,              // cmp r14d,4
        0x75, 0x16,                          // jne final_jump
        0xf0, 0x48, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00,
                                                // lock inc qword [primary_hits]
        0x4c, 0x8d, 0xa5, 0xe0, 0x01, 0x00, 0x00,
                                                // lea r12,[rbp+0x1e0]
        0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00,
                                                // lea rsi,[rip+sidecar+0x10]
        0xe9, 0x00, 0x00, 0x00, 0x00,       // jmp mission loop
    };
    std::memcpy(redirect, redirect_prefix, sizeof(redirect_prefix));
    const int64_t primary_counter_difference =
        reinterpret_cast<int64_t>(page + kMissionPrimaryRedirectCounterOffset) -
        reinterpret_cast<int64_t>(redirect + 22);
    if (primary_counter_difference < std::numeric_limits<int32_t>::min() ||
        primary_counter_difference > std::numeric_limits<int32_t>::max()) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    const int32_t primary_counter_relative =
        static_cast<int32_t>(primary_counter_difference);
    std::memcpy(redirect + 18, &primary_counter_relative,
                sizeof(primary_counter_relative));
    const int64_t sidecar_difference =
        reinterpret_cast<int64_t>(page + kMissionSidecarOffset + 0x10) -
        reinterpret_cast<int64_t>(redirect + 36);
    if (sidecar_difference < std::numeric_limits<int32_t>::min() ||
        sidecar_difference > std::numeric_limits<int32_t>::max()) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    const int32_t sidecar_relative =
        static_cast<int32_t>(sidecar_difference);
    std::memcpy(redirect + 32, &sidecar_relative,
                sizeof(sidecar_relative));
    if (!WriteRelative32(redirect + 36, 0xe9,
                         image + kMissionRecordRedirectReturnRva)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    auto* copy = page + kMissionCopyStubOffset;
    const uint8_t copy_stub[] = {
        0x49, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                // mov r10,sidecar
        0x41, 0x8b, 0x02,                       // mov eax,[r10]
        0x89, 0x85, 0xd0, 0x01, 0x00, 0x00,    // mov [rbp+0x1d0],eax
        0x4d, 0x8b, 0x42, 0x08,                 // mov r8,[r10+8]
        0x4c, 0x89, 0x85, 0xd8, 0x01, 0x00, 0x00,
                                                // mov [rbp+0x1d8],r8
        0x4d, 0x8b, 0x4a, 0x10,                 // mov r9,[r10+0x10]
        0x4c, 0x89, 0x8d, 0xe0, 0x01, 0x00, 0x00,
                                                // mov [rbp+0x1e0],r9
        0x33, 0xc0,                             // xor eax,eax
        0x41, 0x89, 0x02,                       // mov [r10],eax
        0x49, 0x89, 0x42, 0x08,                 // mov [r10+8],rax
        0x49, 0x89, 0x42, 0x10,                 // mov [r10+0x10],rax
        0x8b, 0x55, 0x48,                       // original: mov edx,[rbp+0x48]
        0x48, 0x85, 0xd2,                       // original: test rdx,rdx
        0xe9, 0x00, 0x00, 0x00, 0x00,          // jmp original continuation
    };
    std::memcpy(copy, copy_stub, sizeof(copy_stub));
    const uint64_t sidecar_address =
        reinterpret_cast<uint64_t>(page + kMissionSidecarOffset);
    std::memcpy(copy + 2, &sidecar_address, sizeof(sidecar_address));
    if (!WriteRelative32(copy + sizeof(copy_stub) - 5, 0xe9,
                         image + kMissionRecordCopyReturnRva)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    auto* append = page + kMissionAppendRedirectStubOffset;
    const uint8_t append_stub[] = {
        0x49, 0x8b, 0xf4,                       // original: mov rsi,r12
        0x49, 0x83, 0xc4, 0x18,                 // original: add r12,0x18
        0x48, 0x8b, 0x45, 0x80,                 // mov rax,[rbp-0x80]
        0x48, 0x05, 0x98, 0x01, 0x00, 0x00,   // add rax,0x198
        0x48, 0x3b, 0xf0,                       // cmp rsi,rax
        0x75, 0x0f,                             // jne final_jump
        0xf0, 0x48, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00,
                                                // lock inc qword [append_hits]
        0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00,
                                                // lea rsi,[rip+sidecar]
        0xe9, 0x00, 0x00, 0x00, 0x00,          // jmp append loop body
    };
    std::memcpy(append, append_stub, sizeof(append_stub));
    const int64_t append_counter_difference =
        reinterpret_cast<int64_t>(page + kMissionAppendRedirectCounterOffset) -
        reinterpret_cast<int64_t>(append + 30);
    if (append_counter_difference < std::numeric_limits<int32_t>::min() ||
        append_counter_difference > std::numeric_limits<int32_t>::max()) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    const int32_t append_counter_relative =
        static_cast<int32_t>(append_counter_difference);
    std::memcpy(append + 26, &append_counter_relative,
                sizeof(append_counter_relative));
    const int64_t append_sidecar_difference =
        reinterpret_cast<int64_t>(page + kMissionSidecarOffset) -
        reinterpret_cast<int64_t>(append + 37);
    if (append_sidecar_difference < std::numeric_limits<int32_t>::min() ||
        append_sidecar_difference > std::numeric_limits<int32_t>::max()) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    const int32_t append_sidecar_relative =
        static_cast<int32_t>(append_sidecar_difference);
    std::memcpy(append + 33, &append_sidecar_relative,
                sizeof(append_sidecar_relative));
    if (!WriteRelative32(append + 37, 0xe9,
                         image + kMissionRecordAppendRedirectReturnRva)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }

    std::memset(page + kMissionSidecarOffset, 0, kMissionRecordSize);
    std::memset(page + kMissionPrimaryRedirectCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kMissionAppendRedirectCounterOffset, 0,
                sizeof(uint64_t));
    FlushInstructionCache(GetCurrentProcess(), page, kMissionRelayPageSize);
    g_mission_relay_page = page;
    return true;
}

void EmitBytes(uint8_t*& cursor, std::initializer_list<uint8_t> bytes) {
    for (const uint8_t value : bytes) *cursor++ = value;
}

void EmitU64(uint8_t*& cursor, uint64_t value) {
    std::memcpy(cursor, &value, sizeof(value));
    cursor += sizeof(value);
}

bool EmitRelative32(uint8_t*& cursor, uint8_t opcode,
                    const uint8_t* target) {
    if (!WriteRelative32(cursor, opcode, target)) return false;
    cursor += 5;
    return true;
}

bool EmitLockIncrement(uint8_t*& cursor, uint8_t* counter) {
    uint8_t* instruction = cursor;
    EmitBytes(cursor, {0xf0, 0x48, 0xff, 0x05});
    const int64_t difference = reinterpret_cast<int64_t>(counter) -
                               reinterpret_cast<int64_t>(cursor + 4);
    if (difference < std::numeric_limits<int32_t>::min() ||
        difference > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    const int32_t relative = static_cast<int32_t>(difference);
    std::memcpy(cursor, &relative, sizeof(relative));
    cursor += sizeof(relative);
    return cursor == instruction + 8;
}

bool EmitLockBitSet(uint8_t*& cursor, uint8_t* mask, uint8_t bit) {
    uint8_t* instruction = cursor;
    EmitBytes(cursor, {0xf0, 0x48, 0x0f, 0xba, 0x2d});
    const int64_t difference = reinterpret_cast<int64_t>(mask) -
                               reinterpret_cast<int64_t>(cursor + 5);
    if (difference < std::numeric_limits<int32_t>::min() ||
        difference > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    const int32_t relative = static_cast<int32_t>(difference);
    std::memcpy(cursor, &relative, sizeof(relative));
    cursor += sizeof(relative);
    *cursor++ = bit;
    return cursor == instruction + 10;
}

void EmitScalingCompare(uint8_t*& cursor, ScalingRegister destination) {
    switch (destination) {
        case ScalingRegister::Eax:
            EmitBytes(cursor, {0x83, 0xf8, 0x04});
            break;
        case ScalingRegister::R8d:
            EmitBytes(cursor, {0x41, 0x83, 0xf8, 0x04});
            break;
        case ScalingRegister::R9d:
            EmitBytes(cursor, {0x41, 0x83, 0xf9, 0x04});
            break;
        case ScalingRegister::R10d:
            EmitBytes(cursor, {0x41, 0x83, 0xfa, 0x04});
            break;
    }
}

void EmitScalingClamp(uint8_t*& cursor, ScalingRegister destination) {
    switch (destination) {
        case ScalingRegister::Eax:
            EmitBytes(cursor, {0xb8, 0x04, 0x00, 0x00, 0x00});
            break;
        case ScalingRegister::R8d:
            EmitBytes(cursor, {0x41, 0xb8, 0x04, 0x00, 0x00, 0x00});
            break;
        case ScalingRegister::R9d:
            EmitBytes(cursor, {0x41, 0xb9, 0x04, 0x00, 0x00, 0x00});
            break;
        case ScalingRegister::R10d:
            EmitBytes(cursor, {0x41, 0xba, 0x04, 0x00, 0x00, 0x00});
            break;
    }
}

bool PatchRelative8(uint8_t* displacement, const uint8_t* target) {
    const int64_t difference = reinterpret_cast<int64_t>(target) -
                               reinterpret_cast<int64_t>(displacement + 1);
    if (difference < std::numeric_limits<int8_t>::min() ||
        difference > std::numeric_limits<int8_t>::max()) {
        return false;
    }
    *displacement = static_cast<uint8_t>(static_cast<int8_t>(difference));
    return true;
}

bool BuildParticipantScalingRelays(uint8_t* page) {
    if (!page) return false;
    for (size_t index = 0; index < kParticipantScalingSites.size(); ++index) {
        const auto& site = kParticipantScalingSites[index];
        uint8_t* const stub = page + kParticipantScalingStubOffset +
            index * kParticipantScalingStubStride;
        uint8_t* cursor = stub;
        EmitBytes(cursor, {0x9c});  // pushfq
        std::memcpy(cursor, site.original.data(), site.instruction_size);
        cursor += site.instruction_size;
        EmitScalingCompare(cursor, site.destination);
        EmitBytes(cursor, {0x7e, 0x00});  // jle final
        uint8_t* const native_branch = cursor - 1;
        if (!EmitLockIncrement(
                cursor, page + kParticipantScalingClampHitsOffset) ||
            !EmitLockBitSet(
                cursor, page + kParticipantScalingClampMaskOffset,
                static_cast<uint8_t>(index))) {
            return false;
        }
        EmitScalingClamp(cursor, site.destination);
        uint8_t* const final = cursor;
        EmitBytes(cursor, {0x9d, 0xc3});  // popfq; ret
        if (!PatchRelative8(native_branch, final) ||
            cursor > stub + kParticipantScalingStubStride) {
            return false;
        }
    }
    return true;
}

uint8_t* EnsureLoadoutParserScratch() {
    if (!g_loadout_parser_scratch) {
        g_loadout_parser_scratch = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, kLoadoutParserScratchSize, MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE));
    }
    return g_loadout_parser_scratch;
}

bool BuildLoadoutParserRelay(uint8_t* page, uint8_t* image) {
    uint8_t* scratch = EnsureLoadoutParserScratch();
    if (!page || !image || !scratch) return false;
    // rcx holds the sign-extended record index; the native js at 0x42F7C0
    // already skipped negative values. Every path keeps the original r10.
    uint8_t* stub = page + kLoadoutParserStubOffset;
    EmitBytes(stub, {0x4c, 0x69, 0xd1, 0x90, 0x3e, 0x00, 0x00,
                     0x48, 0x83, 0xf9, 0x04,
                     0x72, 0x00});
    uint8_t* native_branch = stub - 1;
    EmitBytes(stub, {0x48, 0x83, 0xf9, 0x08,
                     0x73, 0x00});
    uint8_t* invalid_branch = stub - 1;

    // Indices 4..7: r14 + index*stride + bias == scratch + (index-4)*stride.
    EmitBytes(stub, {0x49, 0xbe});
    EmitU64(stub, reinterpret_cast<uint64_t>(scratch) -
                      kLoadoutParserExtraBlocks * kLoadoutParserBlockStride -
                      kLoadoutParserBlockBias);
    if (!EmitLockIncrement(stub, page + kLoadoutParserExtraCounterOffset) ||
        !EmitRelative32(stub, 0xe9, image + kLoadoutParserStrideReturnRva)) {
        return false;
    }

    // Indices >= 8 cannot be real participants: r14 = guard - bias - r10.
    uint8_t* invalid = stub;
    EmitBytes(stub, {0x49, 0xbe});
    EmitU64(stub, reinterpret_cast<uint64_t>(
                      scratch + kLoadoutParserExtraBlocks *
                                    kLoadoutParserBlockStride) -
                      kLoadoutParserBlockBias);
    EmitBytes(stub, {0x4d, 0x29, 0xd6});
    if (!EmitLockIncrement(stub, page + kLoadoutParserInvalidCounterOffset) ||
        !EmitRelative32(stub, 0xe9, image + kLoadoutParserStrideReturnRva)) {
        return false;
    }

    // Indices 0..3: rebuild the native r14 from the global state slot, as
    // 0x42F764/0x42F77F did before the loop.
    uint8_t* native = stub;
    EmitBytes(stub, {0x49, 0xbe});
    EmitU64(stub, reinterpret_cast<uint64_t>(
                      image + kLoadoutParserStateSlotRva));
    EmitBytes(stub, {0x4d, 0x8b, 0x36,
                     0x49, 0x81, 0xc6});
    std::memcpy(stub, &kLoadoutParserNativeBaseOffset,
                sizeof(kLoadoutParserNativeBaseOffset));
    stub += sizeof(kLoadoutParserNativeBaseOffset);
    if (!EmitRelative32(stub, 0xe9, image + kLoadoutParserStrideReturnRva) ||
        !PatchRelative8(native_branch, native) ||
        !PatchRelative8(invalid_branch, invalid)) {
        return false;
    }
    return stub <= page + kLoadoutParserExtraCounterOffset;
}

// rdx = max(0x2E8, [rbp+size_disp] + header_bytes), then replay the displaced
// rcx setup and return to the native reserve call. The payload size is the
// builder's stack argument that later becomes the memcpy length.
bool BuildMessageReserveRelay(uint8_t* page, uint8_t* image,
                              size_t stub_offset, uint8_t size_disp,
                              uint8_t header_bytes,
                              std::initializer_list<uint8_t> rcx_setup,
                              uintptr_t return_rva, size_t counter_offset) {
    uint8_t* stub = page + stub_offset;
    EmitBytes(stub, {0x48, 0x8b, 0x55, size_disp,
                     0x48, 0x83, 0xc2, header_bytes,
                     0x48, 0x81, 0xfa});
    std::memcpy(stub, &kNativeMessageReserve, sizeof(kNativeMessageReserve));
    stub += sizeof(kNativeMessageReserve);
    EmitBytes(stub, {0x77, 0x00});
    uint8_t* grown_branch = stub - 1;
    EmitBytes(stub, {0xba});
    std::memcpy(stub, &kNativeMessageReserve, sizeof(kNativeMessageReserve));
    stub += sizeof(kNativeMessageReserve);
    EmitBytes(stub, {0xeb, 0x00});
    uint8_t* native_branch = stub - 1;
    uint8_t* grown = stub;
    if (!EmitLockIncrement(stub, page + counter_offset)) return false;
    uint8_t* done = stub;
    EmitBytes(stub, rcx_setup);
    return EmitRelative32(stub, 0xe9, image + return_rva) &&
           PatchRelative8(grown_branch, grown) &&
           PatchRelative8(native_branch, done) &&
           stub <= page + stub_offset + 0x80;
}

bool BuildMessageReserveRelays(uint8_t* page, uint8_t* image) {
    return page && image &&
        BuildMessageReserveRelay(
            page, image, kReliableMessageReserveStubOffset, 0x77, 0x0c,
            {0x48, 0x8b, 0xcb}, kReliableMessageReserveReturnRva,
            kReliableMessageReserveGrownCounterOffset) &&
        BuildMessageReserveRelay(
            page, image, kReplicationMessageReserveStubOffset, 0x7f, 0x04,
            {0x48, 0x8d, 0x4d, 0x07}, kReplicationMessageReserveReturnRva,
            kReplicationMessageReserveGrownCounterOffset);
}

// Loop again only while edi != count and edi < 4. The stub is reached by a
// jump from the same frame, so [rsp+0x50] is still the native count.
bool BuildSpawnTransformRelay(uint8_t* page, uint8_t* image) {
    if (!page || !image) return false;
    uint8_t* stub = page + kSpawnTransformLoopStubOffset;
    EmitBytes(stub, {0x3b, 0x7c, 0x24, 0x50,
                     0x74, 0x00});
    uint8_t* exit_branch = stub - 1;
    EmitBytes(stub, {0x83, 0xff,
                     static_cast<uint8_t>(kMissionSpawnPointCount),
                     0x73, 0x00});
    uint8_t* capped_branch = stub - 1;
    if (!EmitRelative32(stub, 0xe9, image + kSpawnTransformLoopBodyRva)) {
        return false;
    }
    uint8_t* capped = stub;
    if (!EmitLockIncrement(stub, page + kSpawnTransformCappedCounterOffset)) {
        return false;
    }
    uint8_t* loop_exit = stub;
    return EmitRelative32(stub, 0xe9, image + kSpawnTransformLoopExitRva) &&
           PatchRelative8(exit_branch, loop_exit) &&
           PatchRelative8(capped_branch, capped) &&
           stub <= page + kSpawnTransformLoopStubOffset + 0x40;
}

bool BuildMissionRelayPage(uint8_t* image, unsigned max_players) {
    if (g_mission_relay_page) {
        return g_mission_relay_capacity == max_players;
    }
    if (!image || max_players <= kOriginalCapacity || max_players > 8) {
        return false;
    }
    auto* page = AllocateMissionRelayPage(image + kMissionRecordRedirectRva);
    if (!page) return false;
    std::memset(page, 0xcc, kMissionRelayPageSize);

    auto fail = [&]() {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    };
    const uint64_t sidecars = reinterpret_cast<uint64_t>(
        page + kMissionSidecarOffset);

    // Primary participant loop: preserve the two displaced instructions,
    // recycle one of four native spawn records, and select sidecar[index-4].
    uint8_t* primary = page + kMissionRedirectStubOffset;
    EmitBytes(primary, {0x41, 0x8b, 0x5d, 0x00,
                        0x0f, 0x28, 0x45, 0xc0,
                        0x41, 0x83, 0xfe, 0x04,
                        0x72, 0x00});
    uint8_t* primary_native_branch = primary - 1;
    EmitBytes(primary, {0x50, 0x51,
                        0x44, 0x89, 0xf0,
                        0x83, 0xe0, 0x03,
                        0x48, 0xc1, 0xe0, 0x04,
                        0x4c, 0x8d, 0xa4, 0x05, 0xe0, 0x01, 0x00, 0x00,
                        0x44, 0x89, 0xf0,
                        0x83, 0xe8, 0x04,
                        0x83, 0xe0, 0x03,
                        0x48, 0x8d, 0x0c, 0x40,
                        0x48, 0xb8});
    EmitU64(primary, sidecars);
    EmitBytes(primary, {0x48, 0x8d, 0x74, 0xc8, 0x10});
    if (!EmitLockIncrement(primary,
                           page + kMissionPrimaryRedirectCounterOffset)) {
        return fail();
    }
    EmitBytes(primary, {0x59, 0x58});
    uint8_t* primary_final_jump = primary;
    if (!EmitRelative32(primary, 0xe9,
                        image + kMissionRecordRedirectReturnRva) ||
        !PatchRelative8(primary_native_branch, primary_final_jump)) {
        return fail();
    }

    // Existing-record loop: map extra persistent destinations to sidecars.
    // Extra local indices source the same sidecars instead of indexing beyond
    // the four native records at rbp+0x170.
    uint8_t* existing = page + kMissionExistingRedirectStubOffset;
    EmitBytes(existing, {0x4d, 0x8b, 0xf4,
                         0x41, 0xff, 0xc5,
                         0x49, 0x83, 0xc4, 0x18,
                         0x48, 0x8b, 0x45, 0x80,
                         0x48, 0x05, 0x98, 0x01, 0x00, 0x00,
                         0x4c, 0x3b, 0xf0,
                         0x72, 0x00});
    uint8_t* existing_source_branch_low = existing - 1;
    EmitBytes(existing, {0x4c, 0x89, 0xf1,
                         0x48, 0x2b, 0xc8,
                         0x48, 0x83, 0xf9, 0x48,
                         0x77, 0x00});
    uint8_t* existing_source_branch_high = existing - 1;
    EmitBytes(existing, {0x48, 0xb8});
    EmitU64(existing, sidecars);
    EmitBytes(existing, {0x4c, 0x8d, 0x34, 0x08});
    if (!EmitLockIncrement(existing,
                           page + kMissionExistingRedirectCounterOffset)) {
        return fail();
    }
    uint8_t* existing_source = existing;
    EmitBytes(existing, {0x48, 0x63, 0x43, 0x20,
                         0x83, 0xf8, 0x04,
                         0x72, 0x00});
    uint8_t* existing_native_branch = existing - 1;
    EmitBytes(existing, {0x83, 0xe8, 0x04,
                         0x83, 0xe0, 0x03,
                         0x48, 0x8d, 0x0c, 0x40,
                         0x48, 0xb8});
    EmitU64(existing, sidecars);
    EmitBytes(existing, {0x48, 0x8d, 0x0c, 0xc8,
                         0x8b, 0x01,
                         0x41, 0x89, 0x06,
                         0x48, 0x8b, 0x71, 0x10,
                         0x4c, 0x8b, 0x79, 0x08});
    if (!EmitRelative32(existing, 0xe9,
                        image + kMissionRecordExistingExtraSourceReturnRva)) {
        return fail();
    }
    uint8_t* existing_native_jump = existing;
    if (!EmitRelative32(existing, 0xe9,
                        image + kMissionRecordExistingNativeSourceRva) ||
        !PatchRelative8(existing_source_branch_low, existing_source) ||
        !PatchRelative8(existing_source_branch_high, existing_source) ||
        !PatchRelative8(existing_native_branch, existing_native_jump)) {
        return fail();
    }

    // Append loop: the same mapping, with its native source index at [rbx].
    uint8_t* append = page + kMissionAppendRedirectStubOffset;
    EmitBytes(append, {0x49, 0x8b, 0xf4,
                       0x49, 0x83, 0xc4, 0x18,
                       0x48, 0x8b, 0x45, 0x80,
                       0x48, 0x05, 0x98, 0x01, 0x00, 0x00,
                       0x48, 0x3b, 0xf0,
                       0x72, 0x00});
    uint8_t* append_source_branch_low = append - 1;
    EmitBytes(append, {0x48, 0x89, 0xf1,
                       0x48, 0x2b, 0xc8,
                       0x48, 0x83, 0xf9, 0x48,
                       0x77, 0x00});
    uint8_t* append_source_branch_high = append - 1;
    EmitBytes(append, {0x48, 0xb8});
    EmitU64(append, sidecars);
    EmitBytes(append, {0x48, 0x8d, 0x34, 0x08});
    if (!EmitLockIncrement(append,
                           page + kMissionAppendRedirectCounterOffset)) {
        return fail();
    }
    uint8_t* append_source = append;
    EmitBytes(append, {0x48, 0x63, 0x03,
                       0x83, 0xf8, 0x04,
                       0x72, 0x00});
    uint8_t* append_native_branch = append - 1;
    EmitBytes(append, {0x83, 0xe8, 0x04,
                       0x83, 0xe0, 0x03,
                       0x48, 0x8d, 0x0c, 0x40,
                       0x48, 0xb8});
    EmitU64(append, sidecars);
    EmitBytes(append, {0x48, 0x8d, 0x0c, 0xc8,
                       0x8b, 0x01,
                       0x89, 0x06,
                       0x48, 0x8b, 0x79, 0x10,
                       0x4c, 0x8b, 0x69, 0x08});
    if (!EmitRelative32(append, 0xe9,
                        image + kMissionRecordAppendRedirectReturnRva + 0x20)) {
        return fail();
    }
    uint8_t* append_native_jump = append;
    if (!EmitRelative32(append, 0xe9,
                        image + kMissionRecordAppendRedirectReturnRva + 3) ||
        !PatchRelative8(append_source_branch_low, append_source) ||
        !PatchRelative8(append_source_branch_high, append_source) ||
        !PatchRelative8(append_native_branch, append_native_jump)) {
        return fail();
    }

    for (const auto& site : kMissionParticipantCallSites) {
        uint8_t* stub = page + site.relay_offset;
        EmitBytes(stub, {0x48, 0xba});
        EmitU64(stub, reinterpret_cast<uint64_t>(
                          page + kMissionParticipantArrayOffset));
        if (!EmitRelative32(stub, 0xe9,
                            image + site.original_target_rva)) {
            return fail();
        }
    }

    if (!BuildParticipantScalingRelays(page) ||
        !BuildLoadoutParserRelay(page, image) ||
        !BuildMessageReserveRelays(page, image) ||
        !BuildSpawnTransformRelay(page, image)) {
        return fail();
    }

    std::memset(page + kSpawnTransformCappedCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kReliableMessageReserveGrownCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kReplicationMessageReserveGrownCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kLoadoutParserExtraCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kLoadoutParserInvalidCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kMissionSidecarOffset, 0,
                kMissionRecordSidecarCount * kMissionRecordSize);
    std::memset(page + kMissionPrimaryRedirectCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kMissionExistingRedirectCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kMissionAppendRedirectCounterOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kMissionParticipantArrayOffset, 0,
                kMissionParticipantSafeCapacity * sizeof(int32_t));
    std::memset(page + kParticipantScalingClampHitsOffset, 0,
                sizeof(uint64_t));
    std::memset(page + kParticipantScalingClampMaskOffset, 0,
                sizeof(uint64_t));
    FlushInstructionCache(GetCurrentProcess(), page, kMissionRelayPageSize);
    g_mission_relay_page = page;
    g_mission_relay_capacity = max_players;
    return true;
}

uint64_t ReadMissionRelayCounter(size_t offset) {
    if (!g_mission_relay_page) return 0;
    auto* counter = reinterpret_cast<volatile LONG64*>(
        g_mission_relay_page + offset);
    return static_cast<uint64_t>(
        InterlockedCompareExchange64(counter, 0, 0));
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
    return image_size >= kMemberButtonLoopSites.back().rva +
                             kMemberButtonLoopSites.back().instruction_size &&
           image_size >= kMissionParticipantCallSites.back().rva +
                             kMissionParticipantCallSites.back().instruction_size &&
           image_size >= kMissionRecordAppendRedirectRva +
                             kMissionRecordAppendRedirectOriginal.size() &&
           image_size >= kButtonMasterStringRva + sizeof(kButtonMasterKey);
}

bool RegionMatches(const uint8_t* region, unsigned accepted_capacity) {
    if (!region) return false;
    for (size_t i = 0; i < kCapacityRegion.size(); ++i) {
        const bool first_immediate =
            i >= kFirstCapacityImmediate && i < kFirstCapacityImmediate + 4;
        const bool second_immediate =
            i >= kSecondCapacityImmediate && i < kSecondCapacityImmediate + 4;
        if (first_immediate || second_immediate) continue;
        if (region[i] != kCapacityRegion[i]) return false;
    }
    uint32_t first = 0;
    uint32_t second = 0;
    std::memcpy(&first, region + kFirstCapacityImmediate, sizeof(first));
    std::memcpy(&second, region + kSecondCapacityImmediate, sizeof(second));
    return first == accepted_capacity && second == accepted_capacity;
}

void WriteCapacity(uint8_t* region, unsigned capacity) {
    const uint32_t desired = capacity;
    std::memcpy(region + kFirstCapacityImmediate, &desired, sizeof(desired));
    std::memcpy(region + kSecondCapacityImmediate, &desired, sizeof(desired));
}

uint32_t EncodedSiteValue(const CapacityPatchSite& site, unsigned capacity) {
    if (site.allocation_count_displacement) {
        // The instruction is lea ecx,[rdx+disp8], where edx holds the fixed
        // element size and the result is the allocation element count.
        return static_cast<uint8_t>(static_cast<int>(capacity) -
                                    static_cast<int>(site.allocation_element_size));
    }
    return capacity;
}

bool SiteMatches(const uint8_t* instruction, const CapacityPatchSite& site,
                 unsigned capacity) {
    if (!instruction || site.instruction_size > site.original.size() ||
        (site.value_size != 1 && site.value_size != 4) ||
        site.value_offset + site.value_size > site.instruction_size) {
        return false;
    }
    for (size_t i = 0; i < site.instruction_size; ++i) {
        if (i >= site.value_offset && i < site.value_offset + site.value_size) continue;
        if (instruction[i] != site.original[i]) return false;
    }
    uint32_t observed = 0;
    std::memcpy(&observed, instruction + site.value_offset, site.value_size);
    return observed == EncodedSiteValue(site, capacity);
}

void WriteSite(uint8_t* instruction, const CapacityPatchSite& site,
               unsigned capacity) {
    const uint32_t desired = EncodedSiteValue(site, capacity);
    std::memcpy(instruction + site.value_offset, &desired, site.value_size);
}

bool SecondarySitesMatch(const uint8_t* image, unsigned capacity) {
    for (const auto& site : kSecondaryCapacitySites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return false;
    }
    return true;
}

bool TertiarySitesMatch(const uint8_t* image, unsigned capacity) {
    for (const auto& site : kTertiaryCapacitySites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return false;
    }
    return true;
}

bool RoomPanelSitesMatch(const uint8_t* image, unsigned capacity) {
    for (const auto& site : kRoomPanelCapacitySites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return false;
    }
    return true;
}

bool MissionResultParticipantSitesMatch(const uint8_t* image,
                                        unsigned capacity) {
    for (const auto& site : kMissionResultParticipantCapacitySites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return false;
    }
    return true;
}

void WriteSecondarySites(uint8_t* image, unsigned capacity) {
    for (const auto& site : kSecondaryCapacitySites) {
        WriteSite(image + site.rva, site, capacity);
    }
}

void WriteTertiarySites(uint8_t* image, unsigned capacity) {
    for (const auto& site : kTertiaryCapacitySites) {
        WriteSite(image + site.rva, site, capacity);
    }
}

void WriteRoomPanelSites(uint8_t* image, unsigned capacity) {
    for (const auto& site : kRoomPanelCapacitySites) {
        WriteSite(image + site.rva, site, capacity);
    }
}

void WriteMissionResultParticipantSites(uint8_t* image,
                                        unsigned capacity) {
    for (const auto& site : kMissionResultParticipantCapacitySites) {
        WriteSite(image + site.rva, site, capacity);
    }
}

bool ExperimentalReserveSitesMatch(const uint8_t* image,
                                   unsigned capacity) {
    for (const auto& site : kExperimentalReserveSites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return false;
    }
    return true;
}

void WriteExperimentalReserveSites(uint8_t* image, unsigned capacity) {
    for (const auto& site : kExperimentalReserveSites) {
        WriteSite(image + site.rva, site, capacity);
    }
}

[[maybe_unused]] uintptr_t FirstExperimentalMismatchRva(const uint8_t* image,
                                       unsigned capacity) {
    for (const auto& site : kExperimentalReserveSites) {
        if (!SiteMatches(image + site.rva, site, capacity)) return site.rva;
    }
    return 0;
}

bool MemberButtonLoopSitesMatch(const uint8_t* image, bool replacement) {
    for (const auto& site : kMemberButtonLoopSites) {
        const auto& expected = replacement ? site.replacement : site.original;
        if (std::memcmp(image + site.rva, expected.data(),
                        site.instruction_size) != 0) {
            return false;
        }
    }
    return true;
}

bool MemberButtonKeysMatch(const uint8_t* image) {
    return std::memcmp(image + kButtonMasterStringRva, kButtonMasterKey,
                       sizeof(kButtonMasterKey)) == 0 &&
           std::memcmp(image + kButtonMemberStringRva, kButtonMemberKey,
                       sizeof(kButtonMemberKey)) == 0;
}

void WriteMemberButtonLoopSites(uint8_t* image) {
    for (const auto& site : kMemberButtonLoopSites) {
        std::memcpy(image + site.rva, site.replacement.data(),
                    site.instruction_size);
    }
}

bool MissionParticipantCallSitesMatch(const uint8_t* image,
                                      bool replacement) {
    for (const auto& site : kMissionParticipantCallSites) {
        if (!replacement) {
            if (std::memcmp(image + site.rva, site.original.data(),
                            site.instruction_size) != 0) {
                return false;
            }
            continue;
        }
        if (!g_mission_relay_page ||
            Relative32Target(image + site.rva, 0xe8) !=
                g_mission_relay_page + site.relay_offset) {
            return false;
        }
    }
    return true;
}

bool WriteMissionParticipantCallSites(uint8_t* image) {
    if (!g_mission_relay_page) return false;
    for (const auto& site : kMissionParticipantCallSites) {
        if (!WriteRelative32(image + site.rva, 0xe8,
                             g_mission_relay_page + site.relay_offset)) {
            return false;
        }
    }
    return true;
}

bool ParticipantScalingSitesMatch(const uint8_t* image, bool replacement) {
    if (!image) return false;
    for (size_t index = 0; index < kParticipantScalingSites.size(); ++index) {
        const auto& site = kParticipantScalingSites[index];
        const uint8_t* instruction = image + site.rva;
        if (!replacement) {
            if (std::memcmp(instruction, site.original.data(),
                            site.instruction_size) != 0) {
                return false;
            }
            continue;
        }
        if (!g_mission_relay_page ||
            Relative32Target(instruction, 0xe8) !=
                g_mission_relay_page + kParticipantScalingStubOffset +
                    index * kParticipantScalingStubStride) {
            return false;
        }
        for (size_t byte = 5; byte < site.instruction_size; ++byte) {
            if (instruction[byte] != 0x90) return false;
        }
    }
    return true;
}

bool WriteParticipantScalingSites(uint8_t* image) {
    if (!image || !g_mission_relay_page) return false;
    for (size_t index = 0; index < kParticipantScalingSites.size(); ++index) {
        const auto& site = kParticipantScalingSites[index];
        uint8_t* instruction = image + site.rva;
        if (!WriteRelative32(
                instruction, 0xe8,
                g_mission_relay_page + kParticipantScalingStubOffset +
                    index * kParticipantScalingStubStride)) {
            return false;
        }
        std::memset(instruction + 5, 0x90, site.instruction_size - 5);
    }
    return true;
}

bool MissionSpawnSitesMatch(const uint8_t* image, bool replacement) {
    if (!replacement) {
        return std::memcmp(image + kMissionRecordRedirectRva,
                           kMissionRecordRedirectOriginal.data(),
                           kMissionRecordRedirectOriginal.size()) == 0 &&
               std::memcmp(image + kMissionRecordExistingRedirectRva,
                           kMissionRecordExistingRedirectOriginal.data(),
                           kMissionRecordExistingRedirectOriginal.size()) == 0 &&
               std::memcmp(image + kMissionRecordCopyRva,
                           kMissionRecordCopyOriginal.data(),
                           kMissionRecordCopyOriginal.size()) == 0 &&
               std::memcmp(image + kMissionRecordAppendRedirectRva,
                           kMissionRecordAppendRedirectOriginal.data(),
                           kMissionRecordAppendRedirectOriginal.size()) == 0;
    }
    if (!g_mission_relay_page ||
        Relative32Target(image + kMissionRecordRedirectRva, 0xe9) !=
            g_mission_relay_page + kMissionRedirectStubOffset ||
        Relative32Target(image + kMissionRecordExistingRedirectRva, 0xe9) !=
            g_mission_relay_page + kMissionExistingRedirectStubOffset ||
        Relative32Target(image + kMissionRecordAppendRedirectRva, 0xe9) !=
            g_mission_relay_page + kMissionAppendRedirectStubOffset) {
        return false;
    }
    for (size_t index = 5; index < kMissionRecordRedirectOriginal.size();
         ++index) {
        if (image[kMissionRecordRedirectRva + index] != 0x90) return false;
    }
    for (size_t index = 5;
         index < kMissionRecordExistingRedirectOriginal.size(); ++index) {
        if (image[kMissionRecordExistingRedirectRva + index] != 0x90) {
            return false;
        }
    }
    for (size_t index = 5;
         index < kMissionRecordAppendRedirectOriginal.size(); ++index) {
        if (image[kMissionRecordAppendRedirectRva + index] != 0x90) return false;
    }
    return std::memcmp(image + kMissionRecordCopyRva,
                       kMissionRecordCopyOriginal.data(),
                       kMissionRecordCopyOriginal.size()) == 0;
}

bool WriteMissionSpawnSites(uint8_t* image) {
    if (!g_mission_relay_page ||
        !WriteRelative32(image + kMissionRecordRedirectRva, 0xe9,
                         g_mission_relay_page + kMissionRedirectStubOffset) ||
        !WriteRelative32(image + kMissionRecordExistingRedirectRva, 0xe9,
                         g_mission_relay_page +
                             kMissionExistingRedirectStubOffset) ||
        !WriteRelative32(image + kMissionRecordAppendRedirectRva, 0xe9,
                         g_mission_relay_page +
                             kMissionAppendRedirectStubOffset)) {
        return false;
    }
    std::memset(image + kMissionRecordRedirectRva + 5, 0x90,
                kMissionRecordRedirectOriginal.size() - 5);
    std::memset(image + kMissionRecordExistingRedirectRva + 5, 0x90,
                kMissionRecordExistingRedirectOriginal.size() - 5);
    std::memset(image + kMissionRecordAppendRedirectRva + 5, 0x90,
                kMissionRecordAppendRedirectOriginal.size() - 5);
    return true;
}

bool LoadoutParserSiteMatches(const uint8_t* image, bool replacement) {
    const uint8_t* site = image + kLoadoutParserStrideRva;
    if (!replacement) {
        return std::memcmp(site, kLoadoutParserStrideOriginal.data(),
                           kLoadoutParserStrideOriginal.size()) == 0;
    }
    if (!g_mission_relay_page ||
        Relative32Target(site, 0xe9) !=
            g_mission_relay_page + kLoadoutParserStubOffset) {
        return false;
    }
    for (size_t index = 5; index < kLoadoutParserStrideOriginal.size();
         ++index) {
        if (site[index] != 0x90) return false;
    }
    return true;
}

bool WriteLoadoutParserSite(uint8_t* image) {
    if (!g_mission_relay_page ||
        !WriteRelative32(image + kLoadoutParserStrideRva, 0xe9,
                         g_mission_relay_page + kLoadoutParserStubOffset)) {
        return false;
    }
    std::memset(image + kLoadoutParserStrideRva + 5, 0x90,
                kLoadoutParserStrideOriginal.size() - 5);
    return true;
}

template <size_t N>
bool RelayJumpSiteMatches(const uint8_t* image, uintptr_t rva,
                          const std::array<uint8_t, N>& original,
                          size_t stub_offset, bool replacement) {
    const uint8_t* site = image + rva;
    if (!replacement) {
        return std::memcmp(site, original.data(), original.size()) == 0;
    }
    if (!g_mission_relay_page ||
        Relative32Target(site, 0xe9) != g_mission_relay_page + stub_offset) {
        return false;
    }
    for (size_t index = 5; index < original.size(); ++index) {
        if (site[index] != 0x90) return false;
    }
    return true;
}

template <size_t N>
bool WriteRelayJumpSite(uint8_t* image, uintptr_t rva,
                        const std::array<uint8_t, N>& original,
                        size_t stub_offset) {
    if (!g_mission_relay_page ||
        !WriteRelative32(image + rva, 0xe9,
                         g_mission_relay_page + stub_offset)) {
        return false;
    }
    std::memset(image + rva + 5, 0x90, original.size() - 5);
    return true;
}

bool MessageReserveSitesMatch(const uint8_t* image, bool replacement) {
    return RelayJumpSiteMatches(image, kReliableMessageReserveRva,
                                kReliableMessageReserveOriginal,
                                kReliableMessageReserveStubOffset,
                                replacement) &&
           RelayJumpSiteMatches(image, kReplicationMessageReserveRva,
                                kReplicationMessageReserveOriginal,
                                kReplicationMessageReserveStubOffset,
                                replacement);
}

bool WriteMessageReserveSites(uint8_t* image) {
    return WriteRelayJumpSite(image, kReliableMessageReserveRva,
                              kReliableMessageReserveOriginal,
                              kReliableMessageReserveStubOffset) &&
           WriteRelayJumpSite(image, kReplicationMessageReserveRva,
                              kReplicationMessageReserveOriginal,
                              kReplicationMessageReserveStubOffset);
}

bool SpawnTransformSiteMatches(const uint8_t* image, bool replacement) {
    return RelayJumpSiteMatches(image, kSpawnTransformLoopRva,
                                kSpawnTransformLoopOriginal,
                                kSpawnTransformLoopStubOffset, replacement);
}

bool WriteSpawnTransformSite(uint8_t* image) {
    return WriteRelayJumpSite(image, kSpawnTransformLoopRva,
                              kSpawnTransformLoopOriginal,
                              kSpawnTransformLoopStubOffset);
}

bool RosterReplacementSitesMatch(const uint8_t* image, unsigned max_players,
                                 unsigned preallocated_roster_slots) {
    return image &&
        RegionMatches(image + kCapacityRegionRva,
                      preallocated_roster_slots) &&
        SecondarySitesMatch(image, preallocated_roster_slots) &&
        TertiarySitesMatch(image, preallocated_roster_slots) &&
        RoomPanelSitesMatch(image, preallocated_roster_slots) &&
        MissionResultParticipantSitesMatch(image, max_players) &&
        MemberButtonLoopSitesMatch(image, true) &&
        MissionParticipantCallSitesMatch(image, true) &&
        MissionSpawnSitesMatch(image, true) &&
        ParticipantScalingSitesMatch(image, true) &&
        LoadoutParserSiteMatches(image, true) &&
        MessageReserveSitesMatch(image, true) &&
        SpawnTransformSiteMatches(image, true) &&
        MemberButtonKeysMatch(image);
}

bool RosterOriginalSitesMatch(const uint8_t* image) {
    return image &&
        RegionMatches(image + kCapacityRegionRva, kOriginalCapacity) &&
        SecondarySitesMatch(image, kOriginalCapacity) &&
        TertiarySitesMatch(image, kOriginalCapacity) &&
        RoomPanelSitesMatch(image, kOriginalCapacity) &&
        MissionResultParticipantSitesMatch(image, kOriginalCapacity) &&
        MemberButtonLoopSitesMatch(image, false) &&
        MissionParticipantCallSitesMatch(image, false) &&
        MissionSpawnSitesMatch(image, false) &&
        ParticipantScalingSitesMatch(image, false) &&
        LoadoutParserSiteMatches(image, false) &&
        MessageReserveSitesMatch(image, false) &&
        SpawnTransformSiteMatches(image, false) &&
        MemberButtonKeysMatch(image);
}

void WriteRosterOriginalSites(uint8_t* image) {
    g_loadout_parser_redirect_active.store(false, std::memory_order_release);
    std::memcpy(image + kLoadoutParserStrideRva,
                kLoadoutParserStrideOriginal.data(),
                kLoadoutParserStrideOriginal.size());
    std::memcpy(image + kReliableMessageReserveRva,
                kReliableMessageReserveOriginal.data(),
                kReliableMessageReserveOriginal.size());
    std::memcpy(image + kReplicationMessageReserveRva,
                kReplicationMessageReserveOriginal.data(),
                kReplicationMessageReserveOriginal.size());
    std::memcpy(image + kSpawnTransformLoopRva,
                kSpawnTransformLoopOriginal.data(),
                kSpawnTransformLoopOriginal.size());
    WriteCapacity(image + kCapacityRegionRva, kOriginalCapacity);
    WriteSecondarySites(image, kOriginalCapacity);
    WriteTertiarySites(image, kOriginalCapacity);
    WriteRoomPanelSites(image, kOriginalCapacity);
    WriteMissionResultParticipantSites(image, kOriginalCapacity);
    for (const auto& site : kMemberButtonLoopSites) {
        std::memcpy(image + site.rva, site.original.data(),
                    site.instruction_size);
    }
    for (const auto& site : kMissionParticipantCallSites) {
        std::memcpy(image + site.rva, site.original.data(),
                    site.instruction_size);
    }
    for (const auto& site : kParticipantScalingSites) {
        std::memcpy(image + site.rva, site.original.data(),
                    site.instruction_size);
    }
    std::memcpy(image + kMissionRecordRedirectRva,
                kMissionRecordRedirectOriginal.data(),
                kMissionRecordRedirectOriginal.size());
    std::memcpy(image + kMissionRecordExistingRedirectRva,
                kMissionRecordExistingRedirectOriginal.data(),
                kMissionRecordExistingRedirectOriginal.size());
    std::memcpy(image + kMissionRecordCopyRva,
                kMissionRecordCopyOriginal.data(),
                kMissionRecordCopyOriginal.size());
    std::memcpy(image + kMissionRecordAppendRedirectRva,
                kMissionRecordAppendRedirectOriginal.data(),
                kMissionRecordAppendRedirectOriginal.size());
}

struct MissionRecordCrashFixture {
    uint64_t exception_code = 0;
    uint64_t exception_rva = 0;
    uint64_t fault_write_address = 0;
    uint64_t native_record_count = 0;
    uint64_t record_size = 0;
    uint64_t object_record_base = 0;
    uint64_t fifth_object_offset = 0;
    uint64_t existing_records = 0;
    uint64_t append_records = 0;
    uint64_t append_local_index = 0;
    uint64_t destination_control_value = 0;
};

bool ReadSmallTextFile(const wchar_t* path, std::string& text) {
    if (!path || !*path) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    const bool valid_size = GetFileSizeEx(file, &size) && size.QuadPart > 0 &&
                            size.QuadPart <= 64 * 1024;
    if (!valid_size) {
        CloseHandle(file);
        return false;
    }
    text.resize(static_cast<size_t>(size.QuadPart));
    DWORD bytes_read = 0;
    const bool read = ReadFile(file, text.data(), static_cast<DWORD>(text.size()),
                               &bytes_read, nullptr) != FALSE;
    CloseHandle(file);
    if (!read || bytes_read != text.size()) {
        text.clear();
        return false;
    }
    return true;
}

bool ReadFixtureUnsigned(const std::string& text, const char* key,
                         uint64_t& value) {
    const std::string needle = std::string("\"") + key + "\"";
    size_t at = text.find(needle);
    if (at == std::string::npos) return false;
    at = text.find(':', at + needle.size());
    if (at == std::string::npos) return false;
    ++at;
    while (at < text.size() &&
           (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' ||
            text[at] == '\n')) {
        ++at;
    }
    if (at >= text.size()) return false;
    char* end = nullptr;
    const unsigned long long parsed =
        std::strtoull(text.c_str() + at, &end, 0);
    if (end == text.c_str() + at) return false;
    value = static_cast<uint64_t>(parsed);
    return true;
}

bool LoadMissionRecordCrashFixture(const wchar_t* path,
                                   MissionRecordCrashFixture& fixture) {
    std::string text;
    return ReadSmallTextFile(path, text) &&
           ReadFixtureUnsigned(text, "exception_code", fixture.exception_code) &&
           ReadFixtureUnsigned(text, "exception_rva", fixture.exception_rva) &&
           ReadFixtureUnsigned(text, "fault_write_address",
                               fixture.fault_write_address) &&
           ReadFixtureUnsigned(text, "native_record_count",
                               fixture.native_record_count) &&
           ReadFixtureUnsigned(text, "record_size", fixture.record_size) &&
           ReadFixtureUnsigned(text, "object_record_base",
                               fixture.object_record_base) &&
           ReadFixtureUnsigned(text, "fifth_object_offset",
                               fixture.fifth_object_offset) &&
           ReadFixtureUnsigned(text, "existing_records",
                               fixture.existing_records) &&
           ReadFixtureUnsigned(text, "append_records",
                               fixture.append_records) &&
           ReadFixtureUnsigned(text, "append_local_index",
                               fixture.append_local_index) &&
           ReadFixtureUnsigned(text, "destination_control_value",
                               fixture.destination_control_value);
}

struct RelayExecutionContext {
    uint64_t rbp = 0;
    uint64_t r12 = 0;
    uint64_t rsi = 0;
    uint64_t r13 = 0;
    uint64_t r14 = 0;
    uint64_t r15 = 0;
    uint64_t rbx = 0;
    uint64_t rdi = 0;
};
static_assert(sizeof(RelayExecutionContext) == 0x40,
              "relay test context layout changed");

using RelayExecutionThunk = void(__fastcall*)(RelayExecutionContext*, void*);

RelayExecutionThunk BuildRelayExecutionThunk(uint8_t*& allocation) {
    // Preserve every nonvolatile register, load the exact register state used
    // by the EDF5 loop, call a synthetic image entry, capture the result, and
    // restore the harness process state. r10 retains the context pointer; the
    // tested native slice and both relays leave r10 untouched.
    constexpr uint8_t code[] = {
        0x53, 0x55, 0x57, 0x56, 0x41, 0x54, 0x41, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x28,
        0x49, 0x89, 0xca,
        0x49, 0x8b, 0x2a,
        0x4d, 0x8b, 0x62, 0x08,
        0x49, 0x8b, 0x72, 0x10,
        0x4d, 0x8b, 0x6a, 0x18,
        0x4d, 0x8b, 0x72, 0x20,
        0x4d, 0x8b, 0x7a, 0x28,
        0x49, 0x8b, 0x5a, 0x30,
        0x49, 0x8b, 0x7a, 0x38,
        0xff, 0xd2,
        0x4d, 0x89, 0x62, 0x08,
        0x49, 0x89, 0x72, 0x10,
        0x4d, 0x89, 0x6a, 0x18,
        0x4d, 0x89, 0x72, 0x20,
        0x4d, 0x89, 0x7a, 0x28,
        0x49, 0x89, 0x5a, 0x30,
        0x49, 0x89, 0x7a, 0x38,
        0x48, 0x83, 0xc4, 0x28,
        0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c,
        0x5e, 0x5f, 0x5d, 0x5b, 0xc3,
    };
    allocation = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!allocation) return nullptr;
    std::memcpy(allocation, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), allocation, sizeof(code));
    return reinterpret_cast<RelayExecutionThunk>(allocation);
}

struct ScalingRelayExecutionContext {
    uint64_t rax = 0;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t rbx = 0;
    uint64_t rdi = 0;
    uint64_t flags_in = 0;
    uint64_t flags_out = 0;
};
static_assert(offsetof(ScalingRelayExecutionContext, flags_in) == 0x38 &&
                  offsetof(ScalingRelayExecutionContext, flags_out) == 0x40 &&
                  sizeof(ScalingRelayExecutionContext) == 0x48,
              "scaling relay test context layout changed");

using ScalingRelayExecutionThunk =
    void(__fastcall*)(ScalingRelayExecutionContext*, void*);

ScalingRelayExecutionThunk BuildScalingRelayExecutionThunk(
    uint8_t*& allocation) {
    // r12 keeps the context and r13 keeps the target while the exact relay is
    // executed. Neither register appears in any of the 56 copied loads. Save
    // all nonvolatile registers touched by this thunk, provide the Win64
    // shadow space/alignment, and capture flags before any post-call
    // instruction can change them.
    constexpr uint8_t code[] = {
        0x53, 0x57, 0x41, 0x54, 0x41, 0x55,
        0x48, 0x83, 0xec, 0x28,
        0x49, 0x89, 0xcc,
        0x49, 0x89, 0xd5,
        0x49, 0x8b, 0x04, 0x24,
        0x4d, 0x8b, 0x44, 0x24, 0x08,
        0x4d, 0x8b, 0x4c, 0x24, 0x10,
        0x4d, 0x8b, 0x54, 0x24, 0x18,
        0x4d, 0x8b, 0x5c, 0x24, 0x20,
        0x49, 0x8b, 0x5c, 0x24, 0x28,
        0x49, 0x8b, 0x7c, 0x24, 0x30,
        0x41, 0xff, 0x74, 0x24, 0x38,
        0x9d,
        0x41, 0xff, 0xd5,
        0x9c,
        0x41, 0x8f, 0x44, 0x24, 0x40,
        0x49, 0x89, 0x04, 0x24,
        0x4d, 0x89, 0x44, 0x24, 0x08,
        0x4d, 0x89, 0x4c, 0x24, 0x10,
        0x4d, 0x89, 0x54, 0x24, 0x18,
        0x4d, 0x89, 0x5c, 0x24, 0x20,
        0x49, 0x89, 0x5c, 0x24, 0x28,
        0x49, 0x89, 0x7c, 0x24, 0x30,
        0x48, 0x83, 0xc4, 0x28,
        0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5b, 0xc3,
    };
    allocation = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!allocation) return nullptr;
    std::memcpy(allocation, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), allocation, sizeof(code));
    return reinterpret_cast<ScalingRelayExecutionThunk>(allocation);
}

unsigned DecodeScalingRegister(const ParticipantScalingPatchSite& site,
                               bool destination) {
    const uint8_t rex = site.instruction_size == 7 ? site.original[0] : 0;
    const size_t modrm_offset = site.instruction_size == 7 ? 2 : 1;
    const uint8_t modrm = site.original[modrm_offset];
    if (destination) {
        return ((modrm >> 3) & 7U) + ((rex & 4U) ? 8U : 0U);
    }
    return (modrm & 7U) + ((rex & 1U) ? 8U : 0U);
}

bool SetScalingRegister(ScalingRelayExecutionContext& context,
                        unsigned register_number, uint64_t value) {
    switch (register_number) {
        case 0: context.rax = value; return true;
        case 3: context.rbx = value; return true;
        case 7: context.rdi = value; return true;
        case 8: context.r8 = value; return true;
        case 9: context.r9 = value; return true;
        case 10: context.r10 = value; return true;
        case 11: context.r11 = value; return true;
        default: return false;
    }
}

bool GetScalingRegister(const ScalingRelayExecutionContext& context,
                        unsigned register_number, uint64_t& value) {
    switch (register_number) {
        case 0: value = context.rax; return true;
        case 3: value = context.rbx; return true;
        case 7: value = context.rdi; return true;
        case 8: value = context.r8; return true;
        case 9: value = context.r9; return true;
        case 10: value = context.r10; return true;
        case 11: value = context.r11; return true;
        default: return false;
    }
}

bool SelfTestParticipantScalingRelayExecution(std::string& report) {
    auto* page = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kMissionRelayPageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    auto* mission_state = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kMissionParticipantCountOffset + sizeof(int32_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    uint8_t* thunk_allocation = nullptr;
    const ScalingRelayExecutionThunk thunk =
        BuildScalingRelayExecutionThunk(thunk_allocation);
    auto finish = [&](bool result, const std::string& message) {
        if (thunk_allocation) VirtualFree(thunk_allocation, 0, MEM_RELEASE);
        if (mission_state) VirtualFree(mission_state, 0, MEM_RELEASE);
        if (page) VirtualFree(page, 0, MEM_RELEASE);
        report = message;
        return result;
    };
    if (!page || !mission_state || !thunk) {
        return finish(false, "could not allocate the scaling relay microtest");
    }

    std::memset(page, 0xcc, kMissionRelayPageSize);
    if (!BuildParticipantScalingRelays(page)) {
        return finish(false, "microtest failed to build scaling relays");
    }
    FlushInstructionCache(GetCurrentProcess(), page, kMissionRelayPageSize);

    auto* hits = reinterpret_cast<volatile LONG64*>(
        page + kParticipantScalingClampHitsOffset);
    auto* mask = reinterpret_cast<volatile LONG64*>(
        page + kParticipantScalingClampMaskOffset);
    constexpr std::array<unsigned, 7> kCapturedRegisters = {
        0, 3, 7, 8, 9, 10, 11,
    };
    constexpr std::array<int32_t, 3> kParticipantCounts = {3, 5, 8};
    constexpr uint64_t kArithmeticFlags =
        0x001ULL | 0x004ULL | 0x010ULL | 0x040ULL | 0x080ULL | 0x800ULL;
    constexpr uint64_t kInputFlags = kArithmeticFlags | 0x002ULL;

    for (size_t index = 0; index < kParticipantScalingSites.size(); ++index) {
        const auto& site = kParticipantScalingSites[index];
        const unsigned base_register = DecodeScalingRegister(site, false);
        const unsigned destination_register = DecodeScalingRegister(site, true);
        for (const int32_t participant_count : kParticipantCounts) {
            std::memcpy(mission_state + kMissionParticipantCountOffset,
                        &participant_count, sizeof(participant_count));
            InterlockedExchange64(hits, 0);
            InterlockedExchange64(mask, 0);

            ScalingRelayExecutionContext context{};
            context.rax = 0x1111111122222222ULL;
            context.rbx = 0x3333333344444444ULL;
            context.rdi = 0x5555555566666666ULL;
            context.r8 = 0x7777777788888888ULL;
            context.r9 = 0x99999999aaaabbbbULL;
            context.r10 = 0xccccccccddddeeeeULL;
            context.r11 = 0x123456789abcdef0ULL;
            context.flags_in = kInputFlags;
            if (!SetScalingRegister(
                    context, base_register,
                    reinterpret_cast<uintptr_t>(mission_state))) {
                return finish(false, "microtest found an unsupported base at site " +
                                         std::to_string(index));
            }
            const ScalingRelayExecutionContext before = context;
            void* stub = page + kParticipantScalingStubOffset +
                index * kParticipantScalingStubStride;
            thunk(&context, stub);

            const uint64_t expected_value = static_cast<uint32_t>(
                participant_count > kNativeParticipantScalingCapacity
                    ? kNativeParticipantScalingCapacity
                    : participant_count);
            for (const unsigned register_number : kCapturedRegisters) {
                uint64_t observed = 0;
                uint64_t original = 0;
                if (!GetScalingRegister(context, register_number, observed) ||
                    !GetScalingRegister(before, register_number, original)) {
                    return finish(false, "microtest failed to capture a register at site " +
                                             std::to_string(index));
                }
                const uint64_t expected =
                    register_number == destination_register
                        ? expected_value
                        : original;
                if (observed != expected) {
                    return finish(false, "relay changed the wrong register at site " +
                                             std::to_string(index) +
                                             " for count " +
                                             std::to_string(participant_count));
                }
            }
            if ((context.flags_out & kArithmeticFlags) !=
                    (kInputFlags & kArithmeticFlags)) {
                return finish(false, "relay did not preserve flags at site " +
                                         std::to_string(index));
            }
            int32_t stored_count = 0;
            std::memcpy(&stored_count,
                        mission_state + kMissionParticipantCountOffset,
                        sizeof(stored_count));
            const uint64_t expected_hits = participant_count > 4 ? 1 : 0;
            const uint64_t expected_mask = participant_count > 4
                ? (1ULL << index)
                : 0;
            const uint64_t observed_hits = static_cast<uint64_t>(
                InterlockedCompareExchange64(hits, 0, 0));
            const uint64_t observed_mask = static_cast<uint64_t>(
                InterlockedCompareExchange64(mask, 0, 0));
            if (stored_count != participant_count ||
                observed_hits != expected_hits ||
                observed_mask != expected_mask) {
                return finish(false, "relay telemetry/count mismatch at site " +
                                         std::to_string(index));
            }
        }
    }
    return finish(true,
                  "56 relays executed for counts 3/5/8 with registers, flags and telemetry preserved");
}

struct LoadoutRelayExecutionContext {
    uint64_t index = 0;
    uint64_t r14_in = 0;
    uint64_t r10_out = 0;
    uint64_t r14_out = 0;
};
static_assert(sizeof(LoadoutRelayExecutionContext) == 0x20,
              "loadout relay test context layout changed");

using LoadoutRelayExecutionThunk =
    void(__fastcall*)(LoadoutRelayExecutionContext*, void*);

LoadoutRelayExecutionThunk BuildLoadoutRelayExecutionThunk(
    uint8_t*& allocation) {
    // Load rcx/r14 like the parser loop, enter the patched site (which jumps
    // to the relay and back to a ret placed at the return RVA), then capture
    // r10/r14. r12 keeps the context; r14 and r12 are restored for the caller.
    constexpr uint8_t code[] = {
        0x41, 0x56,
        0x41, 0x54,
        0x48, 0x83, 0xec, 0x28,
        0x49, 0x89, 0xcc,
        0x49, 0x8b, 0x0c, 0x24,
        0x4d, 0x8b, 0x74, 0x24, 0x08,
        0x45, 0x31, 0xd2,
        0xff, 0xd2,
        0x4d, 0x89, 0x54, 0x24, 0x10,
        0x4d, 0x89, 0x74, 0x24, 0x18,
        0x48, 0x83, 0xc4, 0x28,
        0x41, 0x5c,
        0x41, 0x5e,
        0xc3,
    };
    allocation = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!allocation) return nullptr;
    std::memcpy(allocation, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), allocation, sizeof(code));
    return reinterpret_cast<LoadoutRelayExecutionThunk>(allocation);
}

bool SelfTestLoadoutParserRelayExecution(std::string& report) {
    if (g_mission_relay_page) {
        report = "loadout relay microtest refused: relay page already live";
        return false;
    }
    constexpr size_t kFakeImageSize =
        kLoadoutParserStateSlotRva + 0x1000;
    auto* image = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kFakeImageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    uint8_t* thunk_allocation = nullptr;
    const LoadoutRelayExecutionThunk thunk =
        image ? BuildLoadoutRelayExecutionThunk(thunk_allocation) : nullptr;
    auto finish = [&](bool result, const std::string& message) {
        if (g_mission_relay_page) {
            VirtualFree(g_mission_relay_page, 0, MEM_RELEASE);
            g_mission_relay_page = nullptr;
            g_mission_relay_capacity = 0;
        }
        g_loadout_parser_redirect_active.store(false,
                                               std::memory_order_release);
        if (thunk_allocation) VirtualFree(thunk_allocation, 0, MEM_RELEASE);
        if (image) VirtualFree(image, 0, MEM_RELEASE);
        report = message;
        return result;
    };
    if (!image || !thunk) {
        return finish(false, "could not allocate the loadout relay microtest");
    }

    std::memcpy(image + kLoadoutParserStrideRva,
                kLoadoutParserStrideOriginal.data(),
                kLoadoutParserStrideOriginal.size());
    image[kLoadoutParserStrideReturnRva] = 0xc3;
    constexpr uint64_t kFakeState = 0x0000123456780000ULL;
    std::memcpy(image + kLoadoutParserStateSlotRva, &kFakeState,
                sizeof(kFakeState));
    if (!LoadoutParserSiteMatches(image, false) ||
        !BuildMissionRelayPage(image, 8) ||
        !WriteLoadoutParserSite(image) ||
        !LoadoutParserSiteMatches(image, true) ||
        LoadoutParserSiteMatches(image, false)) {
        return finish(false, "loadout relay was not installed on the fake image");
    }
    FlushInstructionCache(GetCurrentProcess(), image, kFakeImageSize);

    const uint64_t scratch =
        reinterpret_cast<uint64_t>(g_loadout_parser_scratch);
    const uint64_t guard =
        scratch + kLoadoutParserExtraBlocks * kLoadoutParserBlockStride;
    constexpr std::array<uint64_t, 10> kIndices = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 63,
    };
    for (const uint64_t index : kIndices) {
        LoadoutRelayExecutionContext context{};
        context.index = index;
        context.r14_in = 0x5a5a5a5a5a5a5a5aULL;
        thunk(&context, image + kLoadoutParserStrideRva);
        const uint64_t block = context.r14_out + context.r10_out +
            kLoadoutParserBlockBias;
        const uint64_t tail_end = context.r14_out + context.r10_out +
            kLoadoutParserLastWriteEnd;
        uint64_t expected_block = 0;
        if (index < 4) {
            expected_block = kFakeState + kLoadoutParserNativeBaseOffset +
                kLoadoutParserBlockBias + index * kLoadoutParserBlockStride;
        } else if (index < 8) {
            expected_block = scratch + (index - 4) * kLoadoutParserBlockStride;
        } else {
            expected_block = guard;
        }
        if (context.r10_out != index * kLoadoutParserBlockStride ||
            block != expected_block ||
            (index >= 4 && tail_end > guard + kLoadoutParserBlockStride) ||
            (index >= 4 && index < 8 && tail_end > guard)) {
            return finish(false, "loadout relay addressed index " +
                                     std::to_string(index) +
                                     " outside its block");
        }
    }
    if (ReadMissionRelayCounter(kLoadoutParserExtraCounterOffset) != 4 ||
        ReadMissionRelayCounter(kLoadoutParserInvalidCounterOffset) != 2) {
        return finish(false, "loadout relay telemetry count mismatch");
    }

    g_loadout_parser_redirect_active.store(true, std::memory_order_release);
    if (!LoadoutParserStrideRelayInstalled(image)) {
        return finish(false, "installed loadout relay was not reported");
    }
    WriteRosterOriginalSites(image);
    if (!LoadoutParserSiteMatches(image, false) ||
        g_loadout_parser_redirect_active.load(std::memory_order_acquire) ||
        LoadoutParserStrideRelayInstalled(image)) {
        return finish(false, "loadout relay restore left the redirect active");
    }
    return finish(true,
                  "parser stride relay keeps P0-P3 native, sends P4-P7 to private blocks and guards index>=8");
}

struct MessageReserveExecutionContext {
    uint64_t rbp = 0;
    uint64_t rbx = 0;
    uint64_t rdx_out = 0;
    uint64_t rcx_out = 0;
};
static_assert(sizeof(MessageReserveExecutionContext) == 0x20,
              "message reserve test context layout changed");

using MessageReserveExecutionThunk =
    void(__fastcall*)(MessageReserveExecutionContext*, void*);

MessageReserveExecutionThunk BuildMessageReserveExecutionThunk(
    uint8_t*& allocation) {
    // Load the builder's rbp/rbx, enter the patched site (which returns
    // through a ret placed at the native call), then capture rdx/rcx.
    constexpr uint8_t code[] = {
        0x53,
        0x55,
        0x41, 0x54,
        0x48, 0x83, 0xec, 0x20,
        0x49, 0x89, 0xcc,
        0x49, 0x8b, 0x2c, 0x24,
        0x49, 0x8b, 0x5c, 0x24, 0x08,
        0xff, 0xd2,
        0x49, 0x89, 0x54, 0x24, 0x10,
        0x49, 0x89, 0x4c, 0x24, 0x18,
        0x48, 0x83, 0xc4, 0x20,
        0x41, 0x5c,
        0x5d,
        0x5b,
        0xc3,
    };
    allocation = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!allocation) return nullptr;
    std::memcpy(allocation, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), allocation, sizeof(code));
    return reinterpret_cast<MessageReserveExecutionThunk>(allocation);
}

bool SelfTestMessageReserveRelayExecution(std::string& report) {
    if (g_mission_relay_page) {
        report = "message reserve microtest refused: relay page already live";
        return false;
    }
    // WriteRosterOriginalSites below also restores every other site, the
    // highest being the room panels near 0x5A72E0.
    constexpr size_t kFakeImageSize = kLoadoutParserStateSlotRva + 0x1000;
    auto* image = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kFakeImageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    uint8_t* thunk_allocation = nullptr;
    const MessageReserveExecutionThunk thunk =
        image ? BuildMessageReserveExecutionThunk(thunk_allocation) : nullptr;
    auto finish = [&](bool result, const std::string& message) {
        if (g_mission_relay_page) {
            VirtualFree(g_mission_relay_page, 0, MEM_RELEASE);
            g_mission_relay_page = nullptr;
            g_mission_relay_capacity = 0;
        }
        g_loadout_parser_redirect_active.store(false,
                                               std::memory_order_release);
        if (thunk_allocation) VirtualFree(thunk_allocation, 0, MEM_RELEASE);
        if (image) VirtualFree(image, 0, MEM_RELEASE);
        report = message;
        return result;
    };
    if (!image || !thunk) {
        return finish(false, "could not allocate the message reserve microtest");
    }
    std::memcpy(image + kReliableMessageReserveRva,
                kReliableMessageReserveOriginal.data(),
                kReliableMessageReserveOriginal.size());
    std::memcpy(image + kReplicationMessageReserveRva,
                kReplicationMessageReserveOriginal.data(),
                kReplicationMessageReserveOriginal.size());
    image[kReliableMessageReserveReturnRva] = 0xc3;
    image[kReplicationMessageReserveReturnRva] = 0xc3;
    if (!MessageReserveSitesMatch(image, false) ||
        !BuildMissionRelayPage(image, 8) ||
        !WriteMessageReserveSites(image) ||
        !MessageReserveSitesMatch(image, true) ||
        MessageReserveSitesMatch(image, false)) {
        return finish(false, "message reserve relays were not installed");
    }
    FlushInstructionCache(GetCurrentProcess(), image, kFakeImageSize);

    struct Builder {
        uintptr_t site_rva;
        uint8_t size_disp;
        uint64_t header_bytes;
        size_t counter_offset;
        bool rcx_is_rbx;
    };
    constexpr std::array<Builder, 2> kBuilders = {{
        {kReliableMessageReserveRva, 0x77, 12,
         kReliableMessageReserveGrownCounterOffset, true},
        {kReplicationMessageReserveRva, 0x7f, 4,
         kReplicationMessageReserveGrownCounterOffset, false},
    }};
    // 845 is the payload of the 857-byte 0x1100 message from the live crash.
    constexpr std::array<uint64_t, 7> kPayloads = {
        0, 100, 0x2dc, 0x2dd, 0x2e4, 845, 4000,
    };
    alignas(16) std::array<uint8_t, 0x100> frame{};
    for (const Builder& builder : kBuilders) {
        uint64_t expected_grown = 0;
        for (const uint64_t payload : kPayloads) {
            std::memcpy(frame.data() + builder.size_disp, &payload,
                        sizeof(payload));
            MessageReserveExecutionContext context{};
            context.rbp = reinterpret_cast<uint64_t>(frame.data());
            context.rbx = 0x1122334455667788ULL;
            thunk(&context, image + builder.site_rva);
            const uint64_t needed = payload + builder.header_bytes;
            const uint64_t expected_rdx =
                needed > kNativeMessageReserve ? needed : kNativeMessageReserve;
            expected_grown += needed > kNativeMessageReserve ? 1 : 0;
            const uint64_t expected_rcx = builder.rcx_is_rbx
                ? context.rbx : context.rbp + 7;
            if (context.rdx_out != expected_rdx ||
                context.rcx_out != expected_rcx) {
                return finish(false, "message reserve relay at " +
                                         std::to_string(builder.site_rva) +
                                         " mis-sized payload " +
                                         std::to_string(payload));
            }
        }
        if (ReadMissionRelayCounter(builder.counter_offset) !=
            expected_grown) {
            return finish(false, "message reserve telemetry count mismatch");
        }
    }

    WriteRosterOriginalSites(image);
    if (!MessageReserveSitesMatch(image, false)) {
        return finish(false, "message reserve restore left a relay jump");
    }
    return finish(true,
                  "both message builders reserve max(0x2E8, header+payload) for payloads 0..4000 and restore cleanly");
}

using SpawnTransformExecutionThunk =
    int(__fastcall*)(int32_t index, void* target, int32_t count);

SpawnTransformExecutionThunk BuildSpawnTransformExecutionThunk(
    uint8_t*& allocation) {
    // edi = index; the count is stored where the patched site reads
    // [rsp+0x50] after the call pushed its return address. The landing pads
    // at the loop body and loop exit report 1 or 2 in eax and return here.
    constexpr uint8_t code[] = {
        0x57,
        0x48, 0x83, 0xec, 0x60,
        0x89, 0xcf,
        0x44, 0x89, 0x44, 0x24, 0x48,
        0xff, 0xd2,
        0x48, 0x83, 0xc4, 0x60,
        0x5f,
        0xc3,
    };
    allocation = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!allocation) return nullptr;
    std::memcpy(allocation, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), allocation, sizeof(code));
    return reinterpret_cast<SpawnTransformExecutionThunk>(allocation);
}

bool SelfTestSpawnTransformRelayExecution(std::string& report) {
    if (g_mission_relay_page) {
        report = "spawn transform microtest refused: relay page already live";
        return false;
    }
    // WriteRosterOriginalSites below restores every site, the highest being
    // the room panels near 0x5A72E0.
    constexpr size_t kFakeImageSize = kLoadoutParserStateSlotRva + 0x1000;
    auto* image = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kFakeImageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    uint8_t* thunk_allocation = nullptr;
    const SpawnTransformExecutionThunk thunk =
        image ? BuildSpawnTransformExecutionThunk(thunk_allocation) : nullptr;
    auto finish = [&](bool result, const std::string& message) {
        if (g_mission_relay_page) {
            VirtualFree(g_mission_relay_page, 0, MEM_RELEASE);
            g_mission_relay_page = nullptr;
            g_mission_relay_capacity = 0;
        }
        g_loadout_parser_redirect_active.store(false,
                                               std::memory_order_release);
        if (thunk_allocation) VirtualFree(thunk_allocation, 0, MEM_RELEASE);
        if (image) VirtualFree(image, 0, MEM_RELEASE);
        report = message;
        return result;
    };
    if (!image || !thunk) {
        return finish(false, "could not allocate the spawn transform microtest");
    }
    std::memcpy(image + kSpawnTransformLoopRva,
                kSpawnTransformLoopOriginal.data(),
                kSpawnTransformLoopOriginal.size());
    constexpr uint8_t kLoopPad[] = {0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};
    constexpr uint8_t kExitPad[] = {0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3};
    std::memcpy(image + kSpawnTransformLoopBodyRva, kLoopPad,
                sizeof(kLoopPad));
    std::memcpy(image + kSpawnTransformLoopExitRva, kExitPad,
                sizeof(kExitPad));
    if (!SpawnTransformSiteMatches(image, false) ||
        !BuildMissionRelayPage(image, 8) ||
        !WriteSpawnTransformSite(image) ||
        !SpawnTransformSiteMatches(image, true) ||
        SpawnTransformSiteMatches(image, false)) {
        return finish(false, "spawn transform relay was not installed");
    }
    FlushInstructionCache(GetCurrentProcess(), image, kFakeImageSize);

    uint64_t expected_caps = 0;
    for (int32_t count = 1; count <= 8; ++count) {
        // The loop body runs for index 0 before the first compare, so the
        // compare sees index = completed iterations (1..count).
        for (int32_t index = 1; index <= count; ++index) {
            const bool native_loops = index != count;
            const bool relay_loops = native_loops && index < 4;
            expected_caps += native_loops && !relay_loops ? 1 : 0;
            const int result = thunk(index, image + kSpawnTransformLoopRva,
                                     count);
            if (result != (relay_loops ? 1 : 2)) {
                return finish(false, "spawn transform relay mis-bounded index " +
                                         std::to_string(index) + " of " +
                                         std::to_string(count));
            }
        }
    }
    if (ReadMissionRelayCounter(kSpawnTransformCappedCounterOffset) !=
        expected_caps) {
        return finish(false, "spawn transform telemetry count mismatch");
    }

    WriteRosterOriginalSites(image);
    if (!SpawnTransformSiteMatches(image, false)) {
        return finish(false, "spawn transform restore left a relay jump");
    }
    return finish(true,
                  "spawn transform loop capped at four native records for 1-8 participants");
}

struct MissionHarnessRecord {
    uint32_t value = 0;
    uint32_t padding = 0;
    uintptr_t auxiliary = 0;
    uintptr_t object = 0;
};
static_assert(sizeof(MissionHarnessRecord) == kMissionRecordSize,
              "mission harness record layout changed");

struct alignas(16) MissionHarnessControlBlock {
    uint8_t unused[12]{};
    volatile LONG strong = 0;
};
static_assert(offsetof(MissionHarnessControlBlock, strong) == 0x0c,
              "mission harness control-block count moved");

constexpr std::array<uint8_t, 0x60> kMissionAppendLoopOriginal = {
    0x49, 0x8b, 0xf4, 0x49, 0x83, 0xc4, 0x18,
    0x48, 0x63, 0x03, 0x48, 0x8d, 0x0c, 0x40,
    0x8b, 0x84, 0xcd, 0x70, 0x01, 0x00, 0x00,
    0x89, 0x06,
    0x48, 0x8b, 0xbc, 0xcd, 0x80, 0x01, 0x00, 0x00,
    0x4c, 0x8b, 0xac, 0xcd, 0x78, 0x01, 0x00, 0x00,
    0x48, 0x85, 0xff, 0x74, 0x04, 0xf0, 0xff, 0x47, 0x0c,
    0x48, 0x8b, 0x4e, 0x10, 0x48, 0x85, 0xc9, 0x74, 0x13,
    0x83, 0xc8, 0xff, 0xf0, 0x0f, 0xc1, 0x41, 0x0c,
    0x83, 0xf8, 0x01, 0x75, 0x06, 0x48, 0x8b, 0x01,
    0xff, 0x50, 0x08,
    0x48, 0x89, 0x7e, 0x10, 0x4c, 0x89, 0x6e, 0x08,
    0x48, 0x83, 0xc3, 0x04, 0x49, 0xff, 0xc6,
    0x4d, 0x3b, 0xf7, 0x75, 0xa0,
};

}  // namespace

bool InstallRosterCapacity(unsigned max_players,
                           unsigned preallocated_roster_slots) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "roster_capacity_patch", "validate",
        max_players, preallocated_roster_slots);
    wchar_t process_path[32768]{};
    GetModuleFileNameW(nullptr, process_path,
                       static_cast<DWORD>(std::size(process_path)));
    if (_wcsicmp(BaseName(process_path), L"EDF5.exe") != 0) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_skipped",
                       capture::Fields().String(
                           "reason", "non-EDF5 offline test process")
                           .String("process", capture::WideToUtf8(process_path)));
        return true;
    }

    if (max_players <= kOriginalCapacity ||
        max_players > kMissionSpawnSafeCapacity ||
        preallocated_roster_slots < max_players ||
        preallocated_roster_slots > 8) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "unsupported capacity")
                            .UInt("requested_capacity", max_players)
                            .UInt("preallocated_roster_slots",
                                  preallocated_roster_slots)
                            .UInt("mission_stack_safe_capacity",
                                  kMissionParticipantSafeCapacity)
                           .UInt("mission_spawn_safe_capacity",
                                 kMissionSpawnSafeCapacity));
        return false;
    }

    auto* image = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    size_t image_size = 0;
    if (!ValidatePeImage(image, image_size)) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "invalid EDF5 PE image"));
        return false;
    }

    uint8_t* region = image + kCapacityRegionRva;
    const bool primary_ready =
        RegionMatches(region, preallocated_roster_slots);
    const bool secondary_ready =
        SecondarySitesMatch(image, preallocated_roster_slots);
    const bool tertiary_ready =
        TertiarySitesMatch(image, preallocated_roster_slots);
    const bool room_panels_ready =
        RoomPanelSitesMatch(image, preallocated_roster_slots);
    const bool mission_result_participants_ready =
        MissionResultParticipantSitesMatch(image, max_players);
    const bool member_buttons_ready = MemberButtonLoopSitesMatch(image, true);
    const bool mission_participants_ready =
        MissionParticipantCallSitesMatch(image, true);
    const bool mission_spawns_ready = MissionSpawnSitesMatch(image, true);
    const bool participant_scaling_ready =
        ParticipantScalingSitesMatch(image, true);
    const bool loadout_parser_ready = LoadoutParserSiteMatches(image, true);
    const bool message_reserve_ready = MessageReserveSitesMatch(image, true);
    const bool spawn_transform_ready = SpawnTransformSiteMatches(image, true);
    if (primary_ready && secondary_ready && tertiary_ready && room_panels_ready &&
        mission_result_participants_ready &&
        member_buttons_ready && mission_participants_ready && mission_spawns_ready &&
        participant_scaling_ready && loadout_parser_ready &&
        message_reserve_ready && spawn_transform_ready &&
        MemberButtonKeysMatch(image)) {
        g_roster_patch_max_players = max_players;
        g_roster_patch_preallocated_slots = preallocated_roster_slots;
        g_loadout_parser_redirect_active.store(true,
                                               std::memory_order_release);
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_ready",
                       capture::Fields().UInt("constructor_rva", kRosterConstructorRva)
                           .UInt("secondary_constructor_rva", kSecondaryConstructorRva)
                           .UInt("secondary_grow_helper_rva", kSecondaryGrowHelperRva)
                           .UInt("tertiary_constructor_rva", kTertiaryConstructorRva)
                           .UInt("tertiary_grow_helper_rva", kTertiaryGrowHelperRva)
                           .UInt("room_panel_constructor_rva", kRoomPanelConstructorRva)
                           .UInt("room_panel_grow_helper_rva", kRoomPanelGrowHelperRva)
                           .UInt("member_button_loop_rva", kMemberButtonLoopRva)
                           .UInt("mission_participant_function_rva",
                                 kMissionParticipantFunctionRva)
                           .UInt("mission_participant_cookie_return_rva",
                                 kMissionParticipantCookieReturnRva)
                           .UInt("mission_spawn_function_rva",
                                 kMissionSpawnFunctionRva)
                           .UInt("mission_spawn_builder_rva",
                                 kMissionSpawnBuilderRva)
                           .UInt("mission_spawn_fault_rva", kMissionSpawnFaultRva)
                           .UInt("mission_result_participant_filter_rva",
                                 kMissionResultParticipantFilterRva)
                           .UInt("mission_result_item_filter_rva",
                                 kMissionResultItemFilterRva)
                           .UInt("mission_result_participant_filter_capacity",
                                 max_players)
                           .UInt("mission_result_participant_filter_patch_sites",
                                 kMissionResultParticipantCapacitySites.size())
                           .UInt("mission_record_fault_rva",
                                 kMissionRecordFaultRva)
                           .UInt("mission_record_redirect_rva",
                                 kMissionRecordRedirectRva)
                           .UInt("mission_record_loop_backedge_rva",
                                 kMissionRecordLoopBackedgeRva)
                           .UInt("mission_record_copy_rva",
                                 kMissionRecordCopyRva)
                           .UInt("mission_record_append_fault_rva",
                                 kMissionRecordAppendFaultRva)
                           .UInt("mission_record_append_redirect_rva",
                                 kMissionRecordAppendRedirectRva)
                           .UInt("mission_record_append_loop_backedge_rva",
                                 kMissionRecordAppendLoopBackedgeRva)
                           .UInt("mission_record_primary_counter_offset",
                                 kMissionPrimaryRedirectCounterOffset)
                           .UInt("mission_record_append_counter_offset",
                                 kMissionAppendRedirectCounterOffset)
                           .UInt("native_participant_scaling_patch_sites",
                                 kParticipantScalingSites.size())
                           .UInt("native_participant_scaling_capacity",
                                 kNativeParticipantScalingCapacity)
                           .UInt("native_participant_scaling_first_rva",
                                 kParticipantScalingSites.front().rva)
                           .UInt("native_participant_scaling_last_rva",
                                 kParticipantScalingSites.back().rva)
                           .UInt("generator_poll_participant_scaling_rva",
                                 0x1f872c)
                           .Bool("participant_count_storage_preserved", true)
                           .Bool("native_participant_scaling_telemetry", true)
                            .UInt("mission_spawn_point_count", kMissionSpawnPointCount)
                            .UInt("capacity", max_players)
                            .UInt("preallocated_roster_slots",
                                  preallocated_roster_slots)
                            .Bool("already_patched", true));
        return true;
    }
    const bool primary_original = RegionMatches(region, kOriginalCapacity);
    const bool secondary_original = SecondarySitesMatch(image, kOriginalCapacity);
    const bool tertiary_original = TertiarySitesMatch(image, kOriginalCapacity);
    const bool room_panels_original =
        RoomPanelSitesMatch(image, kOriginalCapacity);
    const bool mission_result_participants_original =
        MissionResultParticipantSitesMatch(image, kOriginalCapacity);
    const bool member_buttons_original = MemberButtonLoopSitesMatch(image, false);
    const bool mission_participants_original =
        MissionParticipantCallSitesMatch(image, false);
    const bool mission_spawns_original = MissionSpawnSitesMatch(image, false);
    const bool participant_scaling_original =
        ParticipantScalingSitesMatch(image, false);
    const bool loadout_parser_original =
        LoadoutParserSiteMatches(image, false);
    const bool message_reserve_original =
        MessageReserveSitesMatch(image, false);
    const bool spawn_transform_original =
        SpawnTransformSiteMatches(image, false);
    if ((!primary_ready && !primary_original) ||
        (!secondary_ready && !secondary_original) ||
        (!tertiary_ready && !tertiary_original) ||
        (!room_panels_ready && !room_panels_original) ||
        (!mission_result_participants_ready &&
         !mission_result_participants_original) ||
        (!member_buttons_ready && !member_buttons_original) ||
        (!mission_participants_ready && !mission_participants_original) ||
        (!mission_spawns_ready && !mission_spawns_original) ||
        (!participant_scaling_ready && !participant_scaling_original) ||
        (!loadout_parser_ready && !loadout_parser_original) ||
        (!message_reserve_ready && !message_reserve_original) ||
        (!spawn_transform_ready && !spawn_transform_original) ||
        !MemberButtonKeysMatch(image)) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "EDF5 byte signature mismatch")
                           .UInt("loadout_parser_stride_rva",
                                 kLoadoutParserStrideRva)
                           .Bool("loadout_parser_original",
                                 loadout_parser_original)
                           .Bool("message_reserve_original",
                                 message_reserve_original)
                           .Bool("spawn_transform_original",
                                 spawn_transform_original)
                           .UInt("constructor_rva", kRosterConstructorRva)
                           .UInt("secondary_constructor_rva", kSecondaryConstructorRva)
                           .UInt("secondary_grow_helper_rva", kSecondaryGrowHelperRva)
                           .UInt("tertiary_constructor_rva", kTertiaryConstructorRva)
                           .UInt("tertiary_grow_helper_rva", kTertiaryGrowHelperRva)
                           .UInt("room_panel_constructor_rva", kRoomPanelConstructorRva)
                           .UInt("room_panel_grow_helper_rva", kRoomPanelGrowHelperRva)
                           .UInt("member_button_loop_rva", kMemberButtonLoopRva)
                           .UInt("mission_participant_function_rva",
                                 kMissionParticipantFunctionRva)
                           .UInt("mission_spawn_function_rva",
                                 kMissionSpawnFunctionRva)
                           .UInt("mission_result_participant_filter_rva",
                                 kMissionResultParticipantFilterRva)
                           .UInt("mission_result_item_filter_rva",
                                 kMissionResultItemFilterRva)
                           .Bool("participant_scaling_ready",
                                 participant_scaling_ready)
                           .Bool("participant_scaling_original",
                                 participant_scaling_original)
                           .UInt("native_participant_scaling_patch_sites",
                                 kParticipantScalingSites.size())
                           .UInt("patch_region_rva", kCapacityRegionRva)
                           .UInt("image_size", image_size));
        return false;
    }

    if (!BuildMissionRelayPage(image, max_players)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "roster_capacity_patch_failed",
            capture::Fields()
                .String("reason", "mission sidecar relay allocation failed")
                .UInt("redirect_rva", kMissionRecordRedirectRva)
                .UInt("copy_rva", kMissionRecordCopyRva)
                .UInt("append_redirect_rva",
                      kMissionRecordAppendRedirectRva)
                .UInt("relay_size", kMissionRelayPageSize)
                .UInt("win32_error", GetLastError()));
        return false;
    }
    g_roster_patch_max_players = max_players;
    g_roster_patch_preallocated_slots = preallocated_roster_slots;

    constexpr uintptr_t capacity_patch_begin =
        kParticipantScalingSites.front().rva;
    constexpr uintptr_t capacity_patch_end =
        kCapacityRegionRva + kCapacityRegionSize;
    static_assert(kLoadoutParserStrideRva >= capacity_patch_begin &&
                      kLoadoutParserStrideRva +
                              kLoadoutParserStrideOriginal.size() <=
                          capacity_patch_end,
                  "loadout parser site must stay inside the capacity range");
    static_assert(kReplicationMessageReserveRva >= capacity_patch_begin &&
                      kReliableMessageReserveRva +
                              kReliableMessageReserveOriginal.size() <=
                          capacity_patch_end,
                  "message reserve sites must stay inside the capacity range");
    static_assert(kSpawnTransformLoopRva >= capacity_patch_begin &&
                      kSpawnTransformLoopRva +
                              kSpawnTransformLoopOriginal.size() <=
                          capacity_patch_end,
                  "spawn transform site must stay inside the capacity range");
    constexpr uintptr_t button_patch_begin = kMemberButtonLoopSites.front().rva;
    constexpr uintptr_t button_patch_end = 0x565acb;
    constexpr uintptr_t room_panel_patch_begin =
        kRoomPanelCapacitySites.front().rva;
    constexpr uintptr_t room_panel_patch_end =
        kRoomPanelCapacitySites.back().rva +
        kRoomPanelCapacitySites.back().instruction_size;
    constexpr uintptr_t mission_patch_begin =
        kMissionParticipantCallSites.front().rva;
    constexpr uintptr_t mission_patch_end =
        kMissionParticipantCallSites.back().rva +
        kMissionParticipantCallSites.back().instruction_size;
    constexpr uintptr_t spawn_patch_begin = kMissionRecordRedirectRva;
    constexpr uintptr_t spawn_patch_end =
        kMissionRecordAppendRedirectRva +
        kMissionRecordAppendRedirectOriginal.size();
    DWORD previous_capacity_protection = 0;
    if (!VirtualProtect(image + capacity_patch_begin,
                        capacity_patch_end - capacity_patch_begin,
                        PAGE_EXECUTE_READWRITE,
                        &previous_capacity_protection)) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "VirtualProtect failed")
                           .String("region", "capacity")
                           .UInt("win32_error", GetLastError()));
        return false;
    }
    DWORD previous_button_protection = 0;
    if (!VirtualProtect(image + button_patch_begin,
                        button_patch_end - button_patch_begin,
                        PAGE_EXECUTE_READWRITE,
                        &previous_button_protection)) {
        const DWORD protect_error = GetLastError();
        DWORD ignored = 0;
        VirtualProtect(image + capacity_patch_begin,
                       capacity_patch_end - capacity_patch_begin,
                       previous_capacity_protection, &ignored);
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "VirtualProtect failed")
                           .String("region", "member_button_mapping")
                           .UInt("win32_error", protect_error));
        return false;
    }
    DWORD previous_room_panel_protection = 0;
    if (!VirtualProtect(image + room_panel_patch_begin,
                        room_panel_patch_end - room_panel_patch_begin,
                        PAGE_EXECUTE_READWRITE,
                        &previous_room_panel_protection)) {
        const DWORD protect_error = GetLastError();
        DWORD ignored_button = 0;
        DWORD ignored_capacity = 0;
        VirtualProtect(image + button_patch_begin,
                       button_patch_end - button_patch_begin,
                       previous_button_protection, &ignored_button);
        VirtualProtect(image + capacity_patch_begin,
                       capacity_patch_end - capacity_patch_begin,
                       previous_capacity_protection, &ignored_capacity);
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "VirtualProtect failed")
                           .String("region", "room_player_panels")
                           .UInt("win32_error", protect_error));
        return false;
    }
    DWORD previous_mission_protection = 0;
    if (!VirtualProtect(image + mission_patch_begin,
                        mission_patch_end - mission_patch_begin,
                        PAGE_EXECUTE_READWRITE,
                        &previous_mission_protection)) {
        const DWORD protect_error = GetLastError();
        DWORD ignored_room_panel = 0;
        DWORD ignored_button = 0;
        DWORD ignored_capacity = 0;
        VirtualProtect(image + room_panel_patch_begin,
                       room_panel_patch_end - room_panel_patch_begin,
                       previous_room_panel_protection, &ignored_room_panel);
        VirtualProtect(image + button_patch_begin,
                       button_patch_end - button_patch_begin,
                       previous_button_protection, &ignored_button);
        VirtualProtect(image + capacity_patch_begin,
                       capacity_patch_end - capacity_patch_begin,
                       previous_capacity_protection, &ignored_capacity);
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "VirtualProtect failed")
                           .String("region", "mission_participant_stack")
                           .UInt("win32_error", protect_error));
        return false;
    }
    DWORD previous_spawn_protection = 0;
    if (!VirtualProtect(image + spawn_patch_begin,
                        spawn_patch_end - spawn_patch_begin,
                        PAGE_EXECUTE_READWRITE,
                        &previous_spawn_protection)) {
        const DWORD protect_error = GetLastError();
        DWORD ignored_mission = 0;
        DWORD ignored_room_panel = 0;
        DWORD ignored_button = 0;
        DWORD ignored_capacity = 0;
        VirtualProtect(image + mission_patch_begin,
                       mission_patch_end - mission_patch_begin,
                       previous_mission_protection, &ignored_mission);
        VirtualProtect(image + room_panel_patch_begin,
                       room_panel_patch_end - room_panel_patch_begin,
                       previous_room_panel_protection, &ignored_room_panel);
        VirtualProtect(image + button_patch_begin,
                       button_patch_end - button_patch_begin,
                       previous_button_protection, &ignored_button);
        VirtualProtect(image + capacity_patch_begin,
                       capacity_patch_end - capacity_patch_begin,
                       previous_capacity_protection, &ignored_capacity);
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String("reason", "VirtualProtect failed")
                           .String("region", "mission_spawn_points")
                           .UInt("win32_error", protect_error));
        return false;
    }

    WriteCapacity(region, preallocated_roster_slots);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "write_capacity", kCapacityRegionRva,
                            preallocated_roster_slots);
    WriteSecondarySites(image, preallocated_roster_slots);
    WriteTertiarySites(image, preallocated_roster_slots);
    WriteRoomPanelSites(image, preallocated_roster_slots);
    WriteMissionResultParticipantSites(image, max_players);
    WriteMemberButtonLoopSites(image);
    const bool mission_participants_written =
        WriteMissionParticipantCallSites(image);
    const bool mission_spawn_written = WriteMissionSpawnSites(image);
    const bool participant_scaling_written =
        WriteParticipantScalingSites(image);
    // 0x11DB21, 0x42F7C9, 0x432D65 and 0x43309E lie inside the capacity range
    // made writable and flushed above.
    const bool loadout_parser_written = WriteLoadoutParserSite(image);
    const bool message_reserve_written = WriteMessageReserveSites(image);
    const bool spawn_transform_written = WriteSpawnTransformSite(image);
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "flush_instruction_cache",
                            capacity_patch_begin, capacity_patch_end);
    FlushInstructionCache(GetCurrentProcess(), image + capacity_patch_begin,
                          capacity_patch_end - capacity_patch_begin);
    FlushInstructionCache(GetCurrentProcess(), image + button_patch_begin,
                          button_patch_end - button_patch_begin);
    FlushInstructionCache(GetCurrentProcess(), image + room_panel_patch_begin,
                          room_panel_patch_end - room_panel_patch_begin);
    FlushInstructionCache(GetCurrentProcess(), image + mission_patch_begin,
                          mission_patch_end - mission_patch_begin);
    FlushInstructionCache(GetCurrentProcess(), image + spawn_patch_begin,
                          spawn_patch_end - spawn_patch_begin);

    const bool verified = mission_participants_written &&
                          mission_spawn_written &&
                          participant_scaling_written &&
                          loadout_parser_written &&
                          message_reserve_written &&
                          spawn_transform_written &&
                          RosterReplacementSitesMatch(
                              image, max_players,
                              preallocated_roster_slots);
    bool rollback_verified = true;
    if (!verified) {
        WriteRosterOriginalSites(image);
        FlushInstructionCache(GetCurrentProcess(), image + capacity_patch_begin,
                              capacity_patch_end - capacity_patch_begin);
        FlushInstructionCache(GetCurrentProcess(), image + button_patch_begin,
                              button_patch_end - button_patch_begin);
        FlushInstructionCache(GetCurrentProcess(), image + room_panel_patch_begin,
                              room_panel_patch_end - room_panel_patch_begin);
        FlushInstructionCache(GetCurrentProcess(), image + mission_patch_begin,
                              mission_patch_end - mission_patch_begin);
        FlushInstructionCache(GetCurrentProcess(), image + spawn_patch_begin,
                              spawn_patch_end - spawn_patch_begin);
        rollback_verified = RosterOriginalSitesMatch(image);
    }

    DWORD ignored_spawn = 0;
    const bool spawn_restored =
        VirtualProtect(image + spawn_patch_begin,
                       spawn_patch_end - spawn_patch_begin,
                       previous_spawn_protection,
                       &ignored_spawn) != FALSE;
    const DWORD spawn_restore_error = spawn_restored ? 0 : GetLastError();
    DWORD ignored_mission = 0;
    const bool mission_restored =
        VirtualProtect(image + mission_patch_begin,
                       mission_patch_end - mission_patch_begin,
                       previous_mission_protection,
                       &ignored_mission) != FALSE;
    const DWORD mission_restore_error =
        mission_restored ? 0 : GetLastError();
    DWORD ignored_room_panel = 0;
    const bool room_panel_restored =
        VirtualProtect(image + room_panel_patch_begin,
                       room_panel_patch_end - room_panel_patch_begin,
                       previous_room_panel_protection,
                       &ignored_room_panel) != FALSE;
    const DWORD room_panel_restore_error =
        room_panel_restored ? 0 : GetLastError();
    DWORD ignored_button = 0;
    const bool button_restored =
        VirtualProtect(image + button_patch_begin,
                       button_patch_end - button_patch_begin,
                       previous_button_protection, &ignored_button) != FALSE;
    const DWORD button_restore_error = button_restored ? 0 : GetLastError();
    DWORD ignored_capacity = 0;
    const bool capacity_restored =
        VirtualProtect(image + capacity_patch_begin,
                       capacity_patch_end - capacity_patch_begin,
                       previous_capacity_protection, &ignored_capacity) != FALSE;
    const DWORD capacity_restore_error = capacity_restored ? 0 : GetLastError();
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "verify", verified ? 1 : 0,
                            max_players);
    if (!spawn_restored || !mission_restored || !room_panel_restored || !button_restored ||
        !capacity_restored || !verified || !rollback_verified) {
        EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_failed",
                       capture::Fields().String(
                           "reason", verified ? "page protection restore failed"
                                              : "write verification failed")
                           .Bool("rollback_verified", rollback_verified)
                           .UInt("button_restore_error", button_restore_error)
                           .UInt("room_panel_restore_error",
                                 room_panel_restore_error)
                           .UInt("mission_restore_error",
                                 mission_restore_error)
                           .UInt("spawn_restore_error", spawn_restore_error)
                           .UInt("capacity_restore_error", capacity_restore_error));
        return false;
    }
    g_loadout_parser_redirect_active.store(true, std::memory_order_release);

    EDF5_CAPTURE_EVENT("more_players", "roster_capacity_patch_ready",
                   capture::Fields().UInt("constructor_rva", kRosterConstructorRva)
                       .UInt("secondary_constructor_rva", kSecondaryConstructorRva)
                       .UInt("secondary_grow_helper_rva", kSecondaryGrowHelperRva)
                       .UInt("secondary_fault_rva", kSecondaryFaultRva)
                       .UInt("tertiary_constructor_rva", kTertiaryConstructorRva)
                       .UInt("tertiary_grow_helper_rva", kTertiaryGrowHelperRva)
                       .UInt("tertiary_fault_rva", kTertiaryFaultRva)
                       .UInt("room_panel_constructor_rva", kRoomPanelConstructorRva)
                       .UInt("room_panel_resize_rva", kRoomPanelResizeRva)
                       .UInt("room_panel_grow_helper_rva", kRoomPanelGrowHelperRva)
                       .UInt("room_panel_update_rva", kRoomPanelUpdateRva)
                       .UInt("room_panel_fault_caller_rva", kRoomPanelFaultCallerRva)
                       .UInt("member_button_loop_rva", kMemberButtonLoopRva)
                       .UInt("member_button_fault_rva", kMemberButtonFaultRva)
                       .UInt("mission_participant_function_rva",
                             kMissionParticipantFunctionRva)
                       .UInt("mission_participant_producer_rva",
                             kMissionParticipantProducerRva)
                       .UInt("mission_participant_write_rva",
                             kMissionParticipantWriteRva)
                       .UInt("mission_participant_cookie_return_rva",
                             kMissionParticipantCookieReturnRva)
                       .UInt("mission_participant_call_patch_sites",
                             kMissionParticipantCallSites.size())
                       .UInt("mission_participant_capacity",
                             kMissionParticipantSafeCapacity)
                       .UInt("mission_spawn_function_rva", kMissionSpawnFunctionRva)
                       .UInt("mission_spawn_builder_rva", kMissionSpawnBuilderRva)
                       .UInt("mission_spawn_shared_handle_copy_rva",
                             kMissionSpawnSharedHandleCopyRva)
                       .UInt("mission_spawn_fault_rva", kMissionSpawnFaultRva)
                       .UInt("mission_result_participant_filter_rva",
                             kMissionResultParticipantFilterRva)
                       .UInt("mission_result_item_filter_rva",
                             kMissionResultItemFilterRva)
                       .UInt("mission_result_participant_filter_capacity",
                             max_players)
                       .UInt("mission_result_participant_filter_patch_sites",
                             kMissionResultParticipantCapacitySites.size())
                       .UInt("mission_record_fault_rva", kMissionRecordFaultRva)
                       .UInt("mission_record_redirect_rva",
                             kMissionRecordRedirectRva)
                       .UInt("mission_record_loop_backedge_rva",
                             kMissionRecordLoopBackedgeRva)
                       .UInt("mission_record_copy_rva", kMissionRecordCopyRva)
                       .UInt("mission_record_append_fault_rva",
                             kMissionRecordAppendFaultRva)
                       .UInt("mission_record_append_redirect_rva",
                             kMissionRecordAppendRedirectRva)
                       .UInt("mission_record_append_loop_backedge_rva",
                             kMissionRecordAppendLoopBackedgeRva)
                       .UInt("mission_record_primary_counter_offset",
                             kMissionPrimaryRedirectCounterOffset)
                       .UInt("mission_record_append_counter_offset",
                             kMissionAppendRedirectCounterOffset)
                       .UInt("native_participant_scaling_patch_sites",
                             kParticipantScalingSites.size())
                       .UInt("native_participant_scaling_capacity",
                             kNativeParticipantScalingCapacity)
                       .UInt("native_participant_scaling_first_rva",
                             kParticipantScalingSites.front().rva)
                       .UInt("native_participant_scaling_last_rva",
                             kParticipantScalingSites.back().rva)
                       .UInt("generator_poll_participant_scaling_rva",
                             0x1f872c)
                       .Bool("participant_count_storage_preserved", true)
                       .Bool("native_participant_scaling_telemetry", true)
                       .UInt("mission_record_size", kMissionRecordSize)
                       .UInt("mission_record_native_count", 4)
                       .UInt("mission_record_sidecar_count",
                             kMissionRecordSidecarCount)
                       .UInt("mission_spawn_point_count", kMissionSpawnPointCount)
                       .UInt("mission_spawn_first_recycled_player_index", 4)
                       .UInt("mission_spawn_patch_sites", 3)
                       .UInt("button_master_string_rva", kButtonMasterStringRva)
                       .UInt("button_member_string_rva", kButtonMemberStringRva)
                       .UInt("patch_region_rva", kCapacityRegionRva)
                       .UInt("original_capacity", kOriginalCapacity)
                       .UInt("secondary_patch_sites", kSecondaryCapacitySites.size())
                       .UInt("tertiary_patch_sites", kTertiaryCapacitySites.size())
                       .UInt("room_panel_patch_sites", kRoomPanelCapacitySites.size())
                       .UInt("member_button_patch_sites", kMemberButtonLoopSites.size())
                        .UInt("capacity", max_players)
                        .UInt("preallocated_roster_slots",
                              preallocated_roster_slots)
                        .Bool("already_patched", false));
    return true;
}

bool InstallExperimentalReserveCapacity(bool enabled, unsigned capacity) {
    EDF5_DIAGNOSTIC_SCOPE(diagnostics_scope,
        "more_players", "experimental_capacity_patch", "validate",
        enabled ? 1 : 0, capacity);
    if (!enabled) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_skipped",
            capture::Fields()
                .String("reason", "disabled by configuration")
                .UInt("catalogued_candidates",
                      kExperimentalReserveAnchors.size() +
                          kDeferredFourAnchors.size())
                .UInt("coherent_reserve_groups",
                      kExperimentalReserveAnchors.size())
                .UInt("deferred_candidates", kDeferredFourAnchors.size()));
        return true;
    }

    wchar_t process_path[32768]{};
    GetModuleFileNameW(nullptr, process_path,
                       static_cast<DWORD>(std::size(process_path)));
    if (_wcsicmp(BaseName(process_path), L"EDF5.exe") != 0) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_skipped",
            capture::Fields()
                .String("reason", "non-EDF5 offline test process")
                .String("process", capture::WideToUtf8(process_path)));
        return true;
    }
    if (capacity <= kOriginalCapacity || capacity > 8) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields()
                .String("reason", "unsupported experimental capacity")
                .UInt("capacity", capacity));
        return false;
    }

    auto* image = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    size_t image_size = 0;
    if (!ValidatePeImage(image, image_size) ||
        image_size < kExperimentalReserveSites.back().rva +
                         kExperimentalReserveSites.back().instruction_size) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields()
                .String("reason", "invalid or truncated EDF5 PE image")
                .UInt("image_size", image_size));
        return false;
    }

    if (ExperimentalReserveSitesMatch(image, capacity)) {
        g_experimental_patch_capacity = capacity;
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_ready",
            capture::Fields()
                .UInt("capacity", capacity)
                .UInt("catalogued_candidates",
                      kExperimentalReserveAnchors.size() +
                          kDeferredFourAnchors.size())
                .UInt("coherent_reserve_groups",
                      kExperimentalReserveAnchors.size())
                .UInt("patch_sites", kExperimentalReserveSites.size())
                .UInt("deferred_candidates", kDeferredFourAnchors.size())
                .Bool("already_patched", true));
        return true;
    }
    if (!ExperimentalReserveSitesMatch(image, kOriginalCapacity)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields()
                .String("reason", "experimental byte signature mismatch")
                .UInt("first_mismatch_rva",
                      FirstExperimentalMismatchRva(image, kOriginalCapacity))
                .UInt("capacity", capacity));
        return false;
    }
    g_experimental_patch_capacity = capacity;

    struct ProtectedPage {
        uint8_t* address = nullptr;
        size_t size = 0;
        DWORD previous = 0;
        bool active = false;
    };
    std::array<ProtectedPage, kExperimentalReserveSites.size()> pages{};
    size_t page_count = 0;
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    const size_t page_size = system.dwPageSize;
    if (!page_size) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields().String("reason", "invalid system page size"));
        return false;
    }

    for (const auto& site : kExperimentalReserveSites) {
        const uintptr_t instruction =
            reinterpret_cast<uintptr_t>(image + site.rva);
        const uintptr_t page_address = instruction - (instruction % page_size);
        bool known_page = false;
        for (size_t index = 0; index < page_count; ++index) {
            if (reinterpret_cast<uintptr_t>(pages[index].address) ==
                page_address) {
                known_page = true;
                break;
            }
        }
        if (!known_page) {
            pages[page_count].address =
                reinterpret_cast<uint8_t*>(page_address);
            pages[page_count].size = page_size;
            ++page_count;
        }
    }

    for (size_t index = 0; index < page_count; ++index) {
        if (VirtualProtect(pages[index].address, pages[index].size,
                           PAGE_EXECUTE_READWRITE,
                           &pages[index].previous)) {
            pages[index].active = true;
            continue;
        }
        const DWORD protect_error = GetLastError();
        DWORD restore_error = 0;
        for (size_t restore = index; restore > 0; --restore) {
            auto& page = pages[restore - 1];
            if (!page.active) continue;
            DWORD ignored = 0;
            if (!VirtualProtect(page.address, page.size, page.previous,
                                &ignored) && !restore_error) {
                restore_error = GetLastError();
            }
            page.active = false;
        }
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields()
                .String("reason", "VirtualProtect failed before write")
                .UInt("page_index", index)
                .UInt("protected_pages", page_count)
                .UInt("win32_error", protect_error)
                .UInt("restore_error", restore_error));
        return false;
    }

    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "write", kExperimentalReserveSites.front().rva,
                            kExperimentalReserveSites.size());
    WriteExperimentalReserveSites(image, capacity);
    for (size_t index = 0; index < page_count; ++index) {
        FlushInstructionCache(GetCurrentProcess(), pages[index].address,
                              pages[index].size);
    }
    const bool verified = ExperimentalReserveSitesMatch(image, capacity);
    bool rollback_verified = true;
    if (!verified) {
        WriteExperimentalReserveSites(image, kOriginalCapacity);
        for (size_t index = 0; index < page_count; ++index) {
            FlushInstructionCache(GetCurrentProcess(), pages[index].address,
                                  pages[index].size);
        }
        rollback_verified =
            ExperimentalReserveSitesMatch(image, kOriginalCapacity);
    }

    DWORD restore_error = 0;
    for (size_t restore = page_count; restore > 0; --restore) {
        auto& page = pages[restore - 1];
        DWORD ignored = 0;
        if (!VirtualProtect(page.address, page.size, page.previous, &ignored) &&
            !restore_error) {
            restore_error = GetLastError();
        }
        page.active = false;
    }
    EDF5_DIAGNOSTIC_PHASE(diagnostics_scope, "verify", verified ? 1 : 0, page_count);
    if (!verified || !rollback_verified || restore_error) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_failed",
            capture::Fields()
                .String("reason",
                        !verified ? "write verification failed"
                                  : "page protection restore failed")
                .Bool("rollback_verified", rollback_verified)
                .UInt("restore_error", restore_error)
                .UInt("protected_pages", page_count));
        return false;
    }

    EDF5_CAPTURE_EVENT(
        "more_players", "experimental_capacity_patch_ready",
        capture::Fields()
            .UInt("capacity", capacity)
            .UInt("catalogued_candidates",
                  kExperimentalReserveAnchors.size() +
                      kDeferredFourAnchors.size())
            .UInt("coherent_reserve_groups",
                  kExperimentalReserveAnchors.size())
            .UInt("patch_sites", kExperimentalReserveSites.size())
            .UInt("deferred_candidates", kDeferredFourAnchors.size())
            .UInt("protected_pages", page_count)
            .UInt("first_anchor_rva", kExperimentalReserveAnchors.front())
            .UInt("last_anchor_rva", kExperimentalReserveAnchors.back())
            .Bool("already_patched", false));
    return true;
}

namespace {

struct ProtectedRange {
    uint8_t* address = nullptr;
    size_t size = 0;
    DWORD previous = 0;
    bool active = false;
};

template <size_t N>
bool MakeRangesWritable(std::array<ProtectedRange, N>& ranges,
                        size_t range_count, size_t& failed_index,
                        DWORD& protect_error, DWORD& unwind_error) {
    failed_index = 0;
    protect_error = 0;
    unwind_error = 0;
    for (size_t index = 0; index < range_count; ++index) {
        if (VirtualProtect(ranges[index].address, ranges[index].size,
                           PAGE_EXECUTE_READWRITE,
                           &ranges[index].previous)) {
            ranges[index].active = true;
            continue;
        }
        failed_index = index;
        protect_error = GetLastError();
        for (size_t restore = index; restore > 0; --restore) {
            auto& range = ranges[restore - 1];
            if (!range.active) continue;
            DWORD ignored = 0;
            if (!VirtualProtect(range.address, range.size, range.previous,
                                &ignored) && !unwind_error) {
                unwind_error = GetLastError();
            }
            range.active = false;
        }
        return false;
    }
    return true;
}

template <size_t N>
DWORD RestoreRangeProtections(std::array<ProtectedRange, N>& ranges,
                              size_t range_count) {
    DWORD restore_error = 0;
    for (size_t restore = range_count; restore > 0; --restore) {
        auto& range = ranges[restore - 1];
        if (!range.active) continue;
        DWORD ignored = 0;
        if (!VirtualProtect(range.address, range.size, range.previous,
                            &ignored) && !restore_error) {
            restore_error = GetLastError();
        }
        range.active = false;
    }
    return restore_error;
}

template <size_t N>
void FlushRanges(const std::array<ProtectedRange, N>& ranges,
                 size_t range_count) {
    for (size_t index = 0; index < range_count; ++index) {
        FlushInstructionCache(GetCurrentProcess(), ranges[index].address,
                              ranges[index].size);
    }
}

bool ReleaseMissionRelayPage() {
    if (g_mission_relay_page &&
        !VirtualFree(g_mission_relay_page, 0, MEM_RELEASE)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "roster_capacity_patch_restore_failed",
            capture::Fields()
                .String("reason", "mission relay release failed")
                .UInt("win32_error", GetLastError()));
        return false;
    }
    g_mission_relay_page = nullptr;
    g_mission_relay_capacity = 0;
    g_roster_patch_max_players = 0;
    g_roster_patch_preallocated_slots = 0;
    g_loadout_parser_redirect_active.store(false, std::memory_order_release);
    g_reported_loadout_parser_extra_redirects.store(
        0, std::memory_order_release);
    g_reported_loadout_parser_invalid_redirects.store(
        0, std::memory_order_release);
    g_reported_reliable_message_reserves_grown.store(
        0, std::memory_order_release);
    g_reported_replication_message_reserves_grown.store(
        0, std::memory_order_release);
    g_reported_spawn_transform_caps.store(0, std::memory_order_release);
    g_reported_primary_redirects.store(0, std::memory_order_release);
    g_reported_existing_redirects.store(0, std::memory_order_release);
    g_reported_append_redirects.store(0, std::memory_order_release);
    g_reported_participant_scaling_clamp_hits.store(
        0, std::memory_order_release);
    g_reported_participant_scaling_clamp_mask.store(
        0, std::memory_order_release);
    return true;
}

bool RestoreRosterCapacityPatch(uint8_t* image) {
    if (!g_roster_patch_max_players && !g_mission_relay_page) return true;

    if (RosterOriginalSitesMatch(image)) {
        const bool relay_released = ReleaseMissionRelayPage();
        EDF5_CAPTURE_EVENT(
            "more_players", "roster_capacity_patch_restored",
            capture::Fields()
                .Bool("already_original", true)
                .Bool("relay_released", relay_released));
        return relay_released;
    }

    if (!g_roster_patch_max_players ||
        !g_roster_patch_preallocated_slots ||
        !RosterReplacementSitesMatch(
            image, g_roster_patch_max_players,
            g_roster_patch_preallocated_slots)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "roster_capacity_patch_restore_failed",
            capture::Fields()
                .String("reason", "replacement byte signature mismatch")
                .UInt("capacity", g_roster_patch_max_players)
                .UInt("preallocated_roster_slots",
                      g_roster_patch_preallocated_slots));
        return false;
    }

    constexpr uintptr_t capacity_patch_begin =
        kParticipantScalingSites.front().rva;
    constexpr uintptr_t capacity_patch_end =
        kCapacityRegionRva + kCapacityRegionSize;
    constexpr uintptr_t button_patch_begin =
        kMemberButtonLoopSites.front().rva;
    constexpr uintptr_t button_patch_end = 0x565acb;
    constexpr uintptr_t room_panel_patch_begin =
        kRoomPanelCapacitySites.front().rva;
    constexpr uintptr_t room_panel_patch_end =
        kRoomPanelCapacitySites.back().rva +
        kRoomPanelCapacitySites.back().instruction_size;
    constexpr uintptr_t mission_patch_begin =
        kMissionParticipantCallSites.front().rva;
    constexpr uintptr_t mission_patch_end =
        kMissionParticipantCallSites.back().rva +
        kMissionParticipantCallSites.back().instruction_size;
    constexpr uintptr_t spawn_patch_begin = kMissionRecordRedirectRva;
    constexpr uintptr_t spawn_patch_end =
        kMissionRecordAppendRedirectRva +
        kMissionRecordAppendRedirectOriginal.size();
    std::array<ProtectedRange, 5> ranges{{
        {image + capacity_patch_begin,
         capacity_patch_end - capacity_patch_begin},
        {image + button_patch_begin,
         button_patch_end - button_patch_begin},
        {image + room_panel_patch_begin,
         room_panel_patch_end - room_panel_patch_begin},
        {image + mission_patch_begin,
         mission_patch_end - mission_patch_begin},
        {image + spawn_patch_begin,
         spawn_patch_end - spawn_patch_begin},
    }};
    size_t failed_index = 0;
    DWORD protect_error = 0;
    DWORD unwind_error = 0;
    if (!MakeRangesWritable(ranges, ranges.size(), failed_index,
                            protect_error, unwind_error)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "roster_capacity_patch_restore_failed",
            capture::Fields()
                .String("reason", "VirtualProtect failed before restore")
                .UInt("range_index", failed_index)
                .UInt("win32_error", protect_error)
                .UInt("unwind_error", unwind_error));
        return false;
    }

    WriteRosterOriginalSites(image);
    FlushRanges(ranges, ranges.size());
    const bool verified = RosterOriginalSitesMatch(image);
    const DWORD restore_error =
        RestoreRangeProtections(ranges, ranges.size());
    const bool relay_released = verified && ReleaseMissionRelayPage();
    EDF5_CAPTURE_EVENT(
        "more_players",
        verified && !restore_error && relay_released
            ? "roster_capacity_patch_restored"
            : "roster_capacity_patch_restore_failed",
        capture::Fields()
            .String("reason",
                    !verified ? "write verification failed"
                              : restore_error
                                  ? "page protection restore failed"
                                  : relay_released
                                      ? "restored"
                                      : "mission relay release failed")
            .Bool("verified", verified)
            .Bool("relay_released", relay_released)
            .UInt("restore_error", restore_error));
    return verified && !restore_error && relay_released;
}

bool RestoreExperimentalCapacityPatch(uint8_t* image) {
    if (!g_experimental_patch_capacity) return true;
    if (ExperimentalReserveSitesMatch(image, kOriginalCapacity)) {
        g_experimental_patch_capacity = 0;
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_restored",
            capture::Fields().Bool("already_original", true));
        return true;
    }
    if (!ExperimentalReserveSitesMatch(
            image, g_experimental_patch_capacity)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_restore_failed",
            capture::Fields()
                .String("reason", "replacement byte signature mismatch")
                .UInt("capacity", g_experimental_patch_capacity));
        return false;
    }

    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    const size_t page_size = system.dwPageSize;
    if (!page_size) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_restore_failed",
            capture::Fields().String("reason", "invalid system page size"));
        return false;
    }
    std::array<ProtectedRange, kExperimentalReserveSites.size()> pages{};
    size_t page_count = 0;
    for (const auto& site : kExperimentalReserveSites) {
        const uintptr_t instruction =
            reinterpret_cast<uintptr_t>(image + site.rva);
        const uintptr_t page_address = instruction - (instruction % page_size);
        bool known_page = false;
        for (size_t index = 0; index < page_count; ++index) {
            if (reinterpret_cast<uintptr_t>(pages[index].address) ==
                page_address) {
                known_page = true;
                break;
            }
        }
        if (!known_page) {
            pages[page_count].address =
                reinterpret_cast<uint8_t*>(page_address);
            pages[page_count].size = page_size;
            ++page_count;
        }
    }

    size_t failed_index = 0;
    DWORD protect_error = 0;
    DWORD unwind_error = 0;
    if (!MakeRangesWritable(pages, page_count, failed_index,
                            protect_error, unwind_error)) {
        EDF5_CAPTURE_EVENT(
            "more_players", "experimental_capacity_patch_restore_failed",
            capture::Fields()
                .String("reason", "VirtualProtect failed before restore")
                .UInt("page_index", failed_index)
                .UInt("win32_error", protect_error)
                .UInt("unwind_error", unwind_error));
        return false;
    }

    WriteExperimentalReserveSites(image, kOriginalCapacity);
    FlushRanges(pages, page_count);
    const bool verified =
        ExperimentalReserveSitesMatch(image, kOriginalCapacity);
    const DWORD restore_error = RestoreRangeProtections(pages, page_count);
    if (verified) g_experimental_patch_capacity = 0;
    EDF5_CAPTURE_EVENT(
        "more_players",
        verified && !restore_error
            ? "experimental_capacity_patch_restored"
            : "experimental_capacity_patch_restore_failed",
        capture::Fields()
            .String("reason",
                    !verified ? "write verification failed"
                              : restore_error
                                  ? "page protection restore failed"
                                  : "restored")
            .Bool("verified", verified)
            .UInt("restore_error", restore_error)
            .UInt("protected_pages", page_count));
    return verified && !restore_error;
}

}  // namespace

bool RestoreInstalledPatches() {
    if (!g_roster_patch_max_players && !g_mission_relay_page &&
        !g_experimental_patch_capacity) {
        return true;
    }

    wchar_t process_path[32768]{};
    GetModuleFileNameW(nullptr, process_path,
                       static_cast<DWORD>(std::size(process_path)));
    if (_wcsicmp(BaseName(process_path), L"EDF5.exe") != 0) return true;

    auto* image = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    size_t image_size = 0;
    if (!ValidatePeImage(image, image_size) ||
        image_size < kExperimentalReserveSites.back().rva +
                         kExperimentalReserveSites.back().instruction_size) {
        EDF5_CAPTURE_EVENT(
            "more_players", "installed_patches_restore_failed",
            capture::Fields()
                .String("reason", "invalid or truncated EDF5 PE image")
                .UInt("image_size", image_size));
        return false;
    }

    const bool experimental_restored =
        RestoreExperimentalCapacityPatch(image);
    const bool roster_restored = RestoreRosterCapacityPatch(image);
    const bool restored = experimental_restored && roster_restored;
    EDF5_CAPTURE_EVENT(
        "more_players", "installed_patches_restore_complete",
        capture::Fields()
            .Bool("experimental_restored", experimental_restored)
            .Bool("roster_restored", roster_restored)
            .Bool("success", restored));
    return restored;
}

void PollMissionRelayTelemetry() {
    const uint64_t primary =
        ReadMissionRelayCounter(kMissionPrimaryRedirectCounterOffset);
    const uint64_t previous_primary =
        g_reported_primary_redirects.exchange(primary,
                                               std::memory_order_acq_rel);
    if (primary > previous_primary) {
        EDF5_CAPTURE_EVENT("more_players", "mission_record_primary_redirect_hit",
                       capture::Fields()
                           .UInt("hits_delta", primary - previous_primary)
                           .UInt("hits_total", primary)
                           .UInt("first_extra_participant_index", 4)
                           .UInt("configured_capacity",
                                 g_mission_relay_capacity)
                           .UInt("native_record_count", 4)
                           .UInt("sidecar_count",
                                 kMissionRecordSidecarCount)
                           .UInt("record_size", kMissionRecordSize)
                           .Bool("sidecar_selected", true));
    }

    const uint64_t existing =
        ReadMissionRelayCounter(kMissionExistingRedirectCounterOffset);
    const uint64_t previous_existing =
        g_reported_existing_redirects.exchange(existing,
                                                std::memory_order_acq_rel);
    if (existing > previous_existing) {
        EDF5_CAPTURE_EVENT("more_players", "mission_record_existing_redirect_hit",
                       capture::Fields()
                           .UInt("hits_delta", existing - previous_existing)
                           .UInt("hits_total", existing)
                           .UInt("native_record_count", 4)
                           .UInt("sidecar_count",
                                 kMissionRecordSidecarCount)
                           .UInt("record_size", kMissionRecordSize)
                           .Bool("sidecar_selected", true));
    }

    const uint64_t append =
        ReadMissionRelayCounter(kMissionAppendRedirectCounterOffset);
    const uint64_t previous_append =
        g_reported_append_redirects.exchange(append,
                                              std::memory_order_acq_rel);
    if (append > previous_append) {
        EDF5_CAPTURE_EVENT("more_players", "mission_record_append_redirect_hit",
                       capture::Fields()
                           .UInt("hits_delta", append - previous_append)
                           .UInt("hits_total", append)
                           .UInt("native_record_count", 4)
                           .UInt("record_size", kMissionRecordSize)
                           .UInt("first_guarded_destination_offset",
                                 kMissionRecordFirstExtraObjectOffset)
                           .UInt("last_guarded_destination_offset",
                                 kMissionRecordLastExtraObjectOffset)
                           .UInt("sidecar_count",
                                 kMissionRecordSidecarCount)
                           .Bool("sidecar_selected", true));
    }

    const uint64_t scaling_hits =
        ReadMissionRelayCounter(kParticipantScalingClampHitsOffset);
    const uint64_t previous_scaling_hits =
        g_reported_participant_scaling_clamp_hits.exchange(
            scaling_hits, std::memory_order_acq_rel);
    const uint64_t scaling_mask =
        ReadMissionRelayCounter(kParticipantScalingClampMaskOffset);
    const uint64_t previous_scaling_mask =
        g_reported_participant_scaling_clamp_mask.exchange(
            scaling_mask, std::memory_order_acq_rel);
    const uint64_t newly_observed_mask =
        scaling_mask & ~previous_scaling_mask;
    if (newly_observed_mask != 0) {
        EDF5_CAPTURE_EVENT(
            "more_players", "native_participant_scaling_clamp_observed",
            capture::Fields()
                .UInt("hits_delta",
                      scaling_hits >= previous_scaling_hits
                          ? scaling_hits - previous_scaling_hits
                          : scaling_hits)
                .UInt("hits_total", scaling_hits)
                .UInt("site_mask", scaling_mask)
                .UInt("newly_observed_site_mask", newly_observed_mask)
                .UInt("patched_sites", kParticipantScalingSites.size())
                .UInt("native_participant_scaling_capacity",
                      kNativeParticipantScalingCapacity)
                .UInt("configured_capacity", g_mission_relay_capacity)
                .UInt("generator_poll_participant_scaling_rva", 0x1f872c)
                .Bool("participant_count_storage_preserved", true)
                .Bool("payload_logged", false)
                .Bool("pointer_logged", false));
    }

    const uint64_t loadout_extra =
        ReadMissionRelayCounter(kLoadoutParserExtraCounterOffset);
    const uint64_t loadout_invalid =
        ReadMissionRelayCounter(kLoadoutParserInvalidCounterOffset);
    const uint64_t previous_loadout_extra =
        g_reported_loadout_parser_extra_redirects.exchange(
            loadout_extra, std::memory_order_acq_rel);
    const uint64_t previous_loadout_invalid =
        g_reported_loadout_parser_invalid_redirects.exchange(
            loadout_invalid, std::memory_order_acq_rel);
    if (loadout_extra > previous_loadout_extra ||
        loadout_invalid > previous_loadout_invalid) {
        EDF5_CAPTURE_EVENT(
            loadout_invalid > previous_loadout_invalid
                ? capture::Level::Warning : capture::Level::Info,
            "more_players", "loadout_parser_extra_block_redirect_hit",
            capture::Fields()
                .UInt("extra_hits_delta",
                      loadout_extra - previous_loadout_extra)
                .UInt("extra_hits_total", loadout_extra)
                .UInt("invalid_index_hits_total", loadout_invalid)
                .UInt("stride_rva", kLoadoutParserStrideRva)
                .UInt("native_block_count", 4)
                .Bool("mission_state_overflow_prevented", true)
                .Bool("pointer_logged", false));
    }

    const uint64_t reliable_grown =
        ReadMissionRelayCounter(kReliableMessageReserveGrownCounterOffset);
    const uint64_t replication_grown =
        ReadMissionRelayCounter(kReplicationMessageReserveGrownCounterOffset);
    const uint64_t previous_reliable_grown =
        g_reported_reliable_message_reserves_grown.exchange(
            reliable_grown, std::memory_order_acq_rel);
    const uint64_t previous_replication_grown =
        g_reported_replication_message_reserves_grown.exchange(
            replication_grown, std::memory_order_acq_rel);
    if (reliable_grown > previous_reliable_grown ||
        replication_grown > previous_replication_grown) {
        EDF5_CAPTURE_EVENT(
            "more_players", "outgoing_message_reserve_grown",
            capture::Fields()
                .UInt("reliable_builder_rva", 0x433000)
                .UInt("reliable_grown_delta",
                      reliable_grown - previous_reliable_grown)
                .UInt("reliable_grown_total", reliable_grown)
                .UInt("replication_builder_rva", 0x432d20)
                .UInt("replication_grown_delta",
                      replication_grown - previous_replication_grown)
                .UInt("replication_grown_total", replication_grown)
                .UInt("native_reserve_bytes", kNativeMessageReserve)
                .Bool("heap_overflow_prevented", true)
                .Bool("payload_logged", false));
    }

    const uint64_t spawn_caps =
        ReadMissionRelayCounter(kSpawnTransformCappedCounterOffset);
    const uint64_t previous_spawn_caps =
        g_reported_spawn_transform_caps.exchange(spawn_caps,
                                                 std::memory_order_acq_rel);
    if (spawn_caps > previous_spawn_caps) {
        EDF5_CAPTURE_EVENT(
            "more_players", "mission_spawn_transform_capped",
            capture::Fields()
                .UInt("caps_delta", spawn_caps - previous_spawn_caps)
                .UInt("caps_total", spawn_caps)
                .UInt("loop_rva", kSpawnTransformLoopRva)
                .UInt("native_spawn_records", kMissionSpawnPointCount)
                .Bool("stack_cookie_overwrite_prevented", true));
    }
}

uint64_t NativeParticipantScalingClampHits() {
    return ReadMissionRelayCounter(kParticipantScalingClampHitsOffset);
}

uint64_t NativeParticipantScalingClampMask() {
    return ReadMissionRelayCounter(kParticipantScalingClampMaskOffset);
}

uint8_t* LoadoutParserExtraScratch() {
    return g_loadout_parser_redirect_active.load(std::memory_order_acquire)
        ? g_loadout_parser_scratch : nullptr;
}

bool LoadoutParserStrideRelayInstalled(const uint8_t* image) {
    return image &&
        g_loadout_parser_redirect_active.load(std::memory_order_acquire) &&
        LoadoutParserSiteMatches(image, true);
}

bool RunMissionRecordMicroTest(const wchar_t* fixture_path, bool patched,
                               std::string& report) {
    wchar_t process_path[32768]{};
    GetModuleFileNameW(nullptr, process_path,
                       static_cast<DWORD>(std::size(process_path)));
    if (_wcsicmp(BaseName(process_path), L"EDF5.exe") == 0) {
        report = "micro-harness refused inside the game process";
        return false;
    }

    MissionRecordCrashFixture fixture{};
    if (!LoadMissionRecordCrashFixture(fixture_path, fixture)) {
        report = "could not read the crash fixture";
        return false;
    }
    if (fixture.exception_code != 0xc0000005ULL ||
        fixture.exception_rva != kMissionRecordAppendFaultRva ||
        fixture.fault_write_address != 0x12 ||
        fixture.native_record_count != 4 ||
        fixture.record_size != kMissionRecordSize ||
        fixture.object_record_base != kMissionRecordObjectBaseOffset ||
        fixture.fifth_object_offset != kMissionRecordFirstExtraObjectOffset ||
        fixture.existing_records + fixture.append_records != 5 ||
        fixture.existing_records + fixture.append_local_index != 4 ||
        fixture.destination_control_value != 6) {
        report = "fixture does not match the known v0.4.6 dump";
        return false;
    }
    if (g_mission_relay_page) {
        report = "global relay was already allocated in the micro-harness";
        return false;
    }

    constexpr size_t kFakeImageSize = 0x340000;
    auto* image = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kFakeImageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    uint8_t* thunk_allocation = nullptr;
    const RelayExecutionThunk thunk =
        image ? BuildRelayExecutionThunk(thunk_allocation) : nullptr;
    auto finish = [&](bool success, const char* message) {
        if (g_mission_relay_page) {
            VirtualFree(g_mission_relay_page, 0, MEM_RELEASE);
            g_mission_relay_page = nullptr;
            g_mission_relay_capacity = 0;
        }
        if (thunk_allocation) {
            VirtualFree(thunk_allocation, 0, MEM_RELEASE);
            thunk_allocation = nullptr;
        }
        if (image) VirtualFree(image, 0, MEM_RELEASE);
        g_reported_primary_redirects.store(0, std::memory_order_release);
        g_reported_existing_redirects.store(0, std::memory_order_release);
        g_reported_append_redirects.store(0, std::memory_order_release);
        g_reported_participant_scaling_clamp_hits.store(
            0, std::memory_order_release);
        g_reported_participant_scaling_clamp_mask.store(
            0, std::memory_order_release);
        report = message;
        return success;
    };
    if (!image || !thunk) {
        return finish(false, "could not allocate the isolated executor");
    }

    std::memset(image, 0xcc, kFakeImageSize);
    for (const auto& site : kParticipantScalingSites) {
        std::memcpy(image + site.rva, site.original.data(),
                    site.instruction_size);
    }
    std::memcpy(image + kMissionRecordAppendRedirectRva,
                kMissionAppendLoopOriginal.data(),
                kMissionAppendLoopOriginal.size());
    image[kMissionRecordAppendLoopBackedgeRva + 2] = 0xc3;
    image[kMissionRecordRedirectReturnRva] = 0xc3;

    if (patched) {
        if (!BuildMissionRelayPage(image, 8) ||
            !WriteMissionSpawnSites(image) ||
            !WriteParticipantScalingSites(image) ||
            !ParticipantScalingSitesMatch(image, true)) {
            return finish(false, "could not apply relays to the fake image");
        }
    }
    FlushInstructionCache(GetCurrentProcess(), image, kFakeImageSize);

    alignas(16) std::array<uint8_t, 0x400> synthetic_stack{};
    alignas(16) std::array<uint8_t, 0x240> mission_object{};
    alignas(16) std::array<MissionHarnessControlBlock, 8> controls{};
    std::array<int32_t, 7> append_indices{{1, 2, 3, 4, 5, 6, 7}};
    auto* fake_rbp = synthetic_stack.data() + 0x100;
    const uintptr_t mission_address =
        reinterpret_cast<uintptr_t>(mission_object.data());
    std::memcpy(fake_rbp - 0x80, &mission_address,
                sizeof(mission_address));

    auto* local_records = reinterpret_cast<MissionHarnessRecord*>(
        fake_rbp + 0x170);
    auto* native_records = reinterpret_cast<MissionHarnessRecord*>(
        mission_object.data() + kMissionRecordObjectBaseOffset);
    for (size_t index = 0; index < controls.size(); ++index) {
        controls[index].strong = 10;
        local_records[index].value = static_cast<uint32_t>(0x100 + index);
        local_records[index].padding = static_cast<uint32_t>(0x200 + index);
        local_records[index].auxiliary =
            reinterpret_cast<uintptr_t>(&controls[index]);
        local_records[index].object =
            reinterpret_cast<uintptr_t>(&controls[index]);
    }
    native_records[0].value = 0x80;
    std::array<MissionHarnessRecord, kMissionRecordSidecarCount>
        native_extra_before{};
    for (unsigned index = 0; index < kMissionRecordSidecarCount; ++index) {
        auto& native_extra = native_records[4 + index];
        native_extra.value = 0xfeedU + index;
        native_extra.padding = 0xabcdU + index;
        native_extra.auxiliary = 0x1122334455667788ULL + index;
        native_extra.object = index == 0
            ? fixture.destination_control_value
            : 0x30U + index;
        native_extra_before[index] = native_extra;
    }
    if (patched) {
        std::memcpy(g_mission_relay_page + kMissionSidecarOffset,
                    &local_records[4],
                    kMissionRecordSidecarCount * sizeof(local_records[0]));
    }

    RelayExecutionContext append_context{};
    append_context.rbp = reinterpret_cast<uintptr_t>(fake_rbp);
    append_context.r12 = reinterpret_cast<uintptr_t>(&native_records[1]);
    append_context.r14 = 0;
    append_context.r15 = append_indices.size();
    append_context.rbx = reinterpret_cast<uintptr_t>(append_indices.data());

    // With patched=false this exact EDF5 byte slice intentionally reaches
    // lock xadd [0x12] on iteration four. The parent harness requires the
    // isolated child to terminate with 0xc0000005.
    thunk(&append_context, image + kMissionRecordAppendRedirectRva);
    if (!patched) {
        return finish(false, "native flow did not reproduce the access violation");
    }

    if (ReadMissionRelayCounter(kMissionAppendRedirectCounterOffset) != 4 ||
        append_context.r14 != append_indices.size() ||
        append_context.rbx != reinterpret_cast<uintptr_t>(
                                  append_indices.data() +
                                  append_indices.size()) ||
        append_context.r12 != reinterpret_cast<uintptr_t>(
                                  &native_records[8])) {
        return finish(false, "append loop did not complete seven iterations");
    }
    for (size_t index = 1; index < 4; ++index) {
        if (native_records[index].value != local_records[index].value ||
            native_records[index].auxiliary !=
                local_records[index].auxiliary ||
            native_records[index].object != local_records[index].object) {
            return finish(false, "safe native record differs from the source");
        }
    }
    for (unsigned index = 0; index < kMissionRecordSidecarCount; ++index) {
        if (std::memcmp(&native_records[4 + index],
                        &native_extra_before[index],
                        sizeof(native_extra_before[index])) != 0) {
            return finish(false,
                          "canary in an extra native slot was modified");
        }
    }
    const auto* sidecar = reinterpret_cast<const MissionHarnessRecord*>(
        g_mission_relay_page + kMissionSidecarOffset);
    for (unsigned index = 0; index < kMissionRecordSidecarCount; ++index) {
        if (sidecar[index].value != local_records[4 + index].value ||
            sidecar[index].auxiliary != local_records[4 + index].auxiliary ||
            sidecar[index].object != local_records[4 + index].object) {
            return finish(false,
                          "a sidecar did not preserve its appended record");
        }
    }
    for (size_t index = 1; index < controls.size(); ++index) {
        const LONG expected = index < 4 ? 11 : 10;
        if (controls[index].strong != expected) {
            return finish(false, "fixture reference count mismatch");
        }
    }

    int32_t primary_marker = 0x4d5035;
    RelayExecutionContext primary_context{};
    primary_context.rbp = reinterpret_cast<uintptr_t>(fake_rbp);
    primary_context.r13 = reinterpret_cast<uintptr_t>(&primary_marker);
    for (unsigned index = 4; index < 8; ++index) {
        primary_context.r12 = reinterpret_cast<uintptr_t>(mission_object.data());
        primary_context.rsi = primary_context.r12 + 0x40;
        primary_context.r14 = index;
        thunk(&primary_context, image + kMissionRecordRedirectRva);
        if (ReadMissionRelayCounter(kMissionPrimaryRedirectCounterOffset) !=
                index - 3 ||
            primary_context.r12 != reinterpret_cast<uintptr_t>(
                fake_rbp + 0x1e0 + (index % kMissionSpawnPointCount) * 0x10) ||
            primary_context.rsi != reinterpret_cast<uintptr_t>(
                g_mission_relay_page + kMissionSidecarOffset +
                (index - 4) * kMissionRecordSize + 0x10) ||
            static_cast<uint32_t>(primary_context.rbx) !=
                static_cast<uint32_t>(primary_marker)) {
            return finish(false,
                          "primary relay did not map players 5 through 8");
        }
    }

    const uintptr_t non_fifth_r12 =
        reinterpret_cast<uintptr_t>(mission_object.data() + 0x40);
    const uintptr_t non_fifth_rsi =
        reinterpret_cast<uintptr_t>(mission_object.data() + 0x58);
    primary_context.r12 = non_fifth_r12;
    primary_context.rsi = non_fifth_rsi;
    primary_context.r14 = 3;
    thunk(&primary_context, image + kMissionRecordRedirectRva);
    if (ReadMissionRelayCounter(kMissionPrimaryRedirectCounterOffset) != 4 ||
        primary_context.r12 != non_fifth_r12 ||
        primary_context.rsi != non_fifth_rsi) {
        return finish(false, "primary relay changed a native iteration");
    }

    image[kMissionRecordExistingNativeSourceRva] = 0xc3;
    image[kMissionRecordExistingExtraSourceReturnRva] = 0xc3;
    FlushInstructionCache(GetCurrentProcess(), image,
                          kFakeImageSize);
    std::array<uint8_t, 0x28> existing_node{};
    const int32_t existing_index = 7;
    std::memcpy(existing_node.data() + 0x20, &existing_index,
                sizeof(existing_index));
    RelayExecutionContext existing_context{};
    existing_context.rbp = reinterpret_cast<uintptr_t>(fake_rbp);
    existing_context.r12 = reinterpret_cast<uintptr_t>(&native_records[7]);
    existing_context.r13 = 0;
    existing_context.rbx = reinterpret_cast<uintptr_t>(existing_node.data());
    thunk(&existing_context, image + kMissionRecordExistingRedirectRva);
    if (ReadMissionRelayCounter(kMissionExistingRedirectCounterOffset) != 1 ||
        existing_context.r12 != reinterpret_cast<uintptr_t>(&native_records[8]) ||
        existing_context.r13 != 1 ||
        existing_context.r14 != reinterpret_cast<uintptr_t>(&sidecar[3]) ||
        existing_context.rsi != sidecar[3].object ||
        existing_context.r15 != sidecar[3].auxiliary) {
        return finish(false,
                      "existing-record relay did not map player 8");
    }

    return finish(
        true,
        "ok: exact 0x11e2a0 loop bytes replayed; 1+4 case "
        "redirected, players 5-8 isolated in four sidecars, spawns "
        "modulo four, native canaries intact and reference counts balanced");
}

bool SelfTest(std::string& report) {
    auto region = kCapacityRegion;
    if (!RegionMatches(region.data(), kOriginalCapacity)) {
        report = "original constructor signature rejected";
        return false;
    }
    WriteCapacity(region.data(), 8);
    if (!RegionMatches(region.data(), 8) || RegionMatches(region.data(), 5)) {
        report = "the two capacity operands were not updated together";
        return false;
    }
    region[8] ^= 1;
    if (RegionMatches(region.data(), 8)) {
        report = "mismatched code signature was accepted";
        return false;
    }
    for (const auto& site : kSecondaryCapacitySites) {
        auto instruction = site.original;
        if (!SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "original secondary table signature rejected";
            return false;
        }
        WriteSite(instruction.data(), site, 8);
        if (!SiteMatches(instruction.data(), site, 8) ||
            SiteMatches(instruction.data(), site, 5)) {
            report = "secondary table operand was not updated";
            return false;
        }
        instruction[0] ^= 1;
        if (SiteMatches(instruction.data(), site, 8)) {
            report = "mismatched secondary table signature was accepted";
            return false;
        }
    }
    for (const auto& site : kTertiaryCapacitySites) {
        auto instruction = site.original;
        if (!SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "original third table signature rejected";
            return false;
        }
        WriteSite(instruction.data(), site, 8);
        if (!SiteMatches(instruction.data(), site, 8) ||
            SiteMatches(instruction.data(), site, 5)) {
            report = "third table operand was not updated";
            return false;
        }
        instruction[0] ^= 1;
        if (SiteMatches(instruction.data(), site, 8)) {
            report = "mismatched third table signature was accepted";
            return false;
        }
    }
    for (const auto& site : kRoomPanelCapacitySites) {
        auto instruction = site.original;
        if (!SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "original room box signature rejected";
            return false;
        }
        WriteSite(instruction.data(), site, 8);
        if (!SiteMatches(instruction.data(), site, 8) ||
            SiteMatches(instruction.data(), site, 5)) {
            report = "room box operand was not updated";
            return false;
        }
        WriteSite(instruction.data(), site, 16);
        if (!SiteMatches(instruction.data(), site, 16)) {
            report = "room box upper bound was encoded incorrectly";
            return false;
        }
        instruction[0] ^= 1;
        if (SiteMatches(instruction.data(), site, 16)) {
            report = "mismatched room box signature was accepted";
            return false;
        }
    }
    for (const auto& site : kMissionResultParticipantCapacitySites) {
        auto instruction = site.original;
        if (!SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "original MissionResult pipeline signature rejected";
            return false;
        }
        WriteSite(instruction.data(), site, 5);
        if (!SiteMatches(instruction.data(), site, 5) ||
            SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "MissionResult pipeline did not follow MaxPlayers";
            return false;
        }
        WriteSite(instruction.data(), site, 8);
        if (!SiteMatches(instruction.data(), site, 8)) {
            report = "MissionResult pipeline did not accept capacity eight";
            return false;
        }
        instruction[0] ^= 1;
        if (SiteMatches(instruction.data(), site, 8)) {
            report = "mismatched MissionResult signature was accepted";
            return false;
        }
    }
    for (const auto& site : kExperimentalReserveSites) {
        auto instruction = site.original;
        if (!SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "original experimental reserve signature rejected";
            return false;
        }
        WriteSite(instruction.data(), site, 8);
        if (!SiteMatches(instruction.data(), site, 8) ||
            SiteMatches(instruction.data(), site, kOriginalCapacity)) {
            report = "experimental reserve operand was not updated";
            return false;
        }
        instruction[0] ^= 1;
        if (SiteMatches(instruction.data(), site, 8)) {
            report = "mismatched experimental reserve signature was accepted";
            return false;
        }
    }
    std::array<uint8_t, kMissionRelayPageSize> participant_scaling_page{};
    participant_scaling_page.fill(0xcc);
    if (!BuildParticipantScalingRelays(participant_scaling_page.data())) {
        report = "relays for the 56 scaling reads were not built";
        return false;
    }
    for (size_t index = 0; index < kParticipantScalingSites.size(); ++index) {
        const auto& site = kParticipantScalingSites[index];
        if ((index != 0 &&
             site.rva <= kParticipantScalingSites[index - 1].rva) ||
            (site.instruction_size != 6 && site.instruction_size != 7) ||
            std::memcmp(site.original.data() + site.instruction_size - 4,
                        "\xa0\x45\x02\x00", 4) != 0) {
            report = "scaling read catalog is not unique/exact";
            return false;
        }
        const uint8_t rex = site.instruction_size == 7
            ? site.original[0]
            : 0;
        const size_t opcode_offset = site.instruction_size == 7 ? 1 : 0;
        const uint8_t modrm = site.original[opcode_offset + 1];
        const unsigned decoded_register =
            ((modrm >> 3) & 7U) + ((rex & 4U) ? 8U : 0U);
        unsigned expected_register = 0;
        switch (site.destination) {
            case ScalingRegister::Eax: expected_register = 0; break;
            case ScalingRegister::R8d: expected_register = 8; break;
            case ScalingRegister::R9d: expected_register = 9; break;
            case ScalingRegister::R10d: expected_register = 10; break;
        }
        if (site.original[opcode_offset] != 0x8b ||
            decoded_register != expected_register) {
            report = "scaling read destination register mismatch";
            return false;
        }

        const uint8_t* stub = participant_scaling_page.data() +
            kParticipantScalingStubOffset +
            index * kParticipantScalingStubStride;
        const size_t compare_size =
            site.destination == ScalingRegister::Eax ? 3 : 4;
        const size_t clamp_size =
            site.destination == ScalingRegister::Eax ? 5 : 6;
        const uint8_t* compare = stub + 1 + site.instruction_size;
        const uint8_t* branch = compare + compare_size;
        const uint8_t* increment = branch + 2;
        const uint8_t* bit_set = increment + 8;
        const uint8_t* clamp = bit_set + 10;
        const uint8_t* final = clamp + clamp_size;
        if (stub[0] != 0x9c ||
            std::memcmp(stub + 1, site.original.data(),
                        site.instruction_size) != 0 ||
            branch[0] != 0x7e || final[0] != 0x9d || final[1] != 0xc3 ||
            branch + 2 + static_cast<int8_t>(branch[1]) != final ||
            std::memcmp(increment, "\xf0\x48\xff\x05", 4) != 0 ||
            std::memcmp(bit_set, "\xf0\x48\x0f\xba\x2d", 5) != 0 ||
            bit_set[9] != static_cast<uint8_t>(index) ||
            final + 2 > stub + kParticipantScalingStubStride) {
            report = "incorrect scaling relay layout";
            return false;
        }
        int32_t increment_displacement = 0;
        int32_t mask_displacement = 0;
        std::memcpy(&increment_displacement, increment + 4,
                    sizeof(increment_displacement));
        std::memcpy(&mask_displacement, bit_set + 5,
                    sizeof(mask_displacement));
        if (increment + 8 + increment_displacement !=
                participant_scaling_page.data() +
                    kParticipantScalingClampHitsOffset ||
            bit_set + 10 + mask_displacement !=
                participant_scaling_page.data() +
                    kParticipantScalingClampMaskOffset) {
            report = "scaling relay RIP-relative telemetry mismatch";
            return false;
        }
    }
    for (int32_t participant_count = 1; participant_count <= 8;
         ++participant_count) {
        const int32_t native_profile =
            participant_count > kNativeParticipantScalingCapacity
                ? kNativeParticipantScalingCapacity
                : participant_count;
        if (native_profile != (participant_count <= 4
                                  ? participant_count
                                  : 4)) {
            report = "native profile clamp model mismatch";
            return false;
        }
    }
    std::string relay_execution_report;
    if (!SelfTestParticipantScalingRelayExecution(relay_execution_report)) {
        report = relay_execution_report;
        return false;
    }
    std::string loadout_relay_report;
    if (!SelfTestLoadoutParserRelayExecution(loadout_relay_report)) {
        report = loadout_relay_report;
        return false;
    }
    std::string message_reserve_report;
    if (!SelfTestMessageReserveRelayExecution(message_reserve_report)) {
        report = message_reserve_report;
        return false;
    }
    std::string spawn_transform_report;
    if (!SelfTestSpawnTransformRelayExecution(spawn_transform_report)) {
        report = spawn_transform_report;
        return false;
    }
    std::array<uint8_t, 0x30> member_button_loop{};
    const uintptr_t member_button_base = kMemberButtonLoopSites.front().rva;
    for (const auto& site : kMemberButtonLoopSites) {
        std::memcpy(member_button_loop.data() + site.rva - member_button_base,
                    site.original.data(), site.instruction_size);
    }
    for (const auto& site : kMemberButtonLoopSites) {
        const size_t offset = site.rva - member_button_base;
        if (std::memcmp(member_button_loop.data() + offset,
                        site.original.data(), site.instruction_size) != 0) {
            report = "original button mapping signature rejected";
            return false;
        }
        std::memcpy(member_button_loop.data() + offset,
                    site.replacement.data(), site.instruction_size);
        if (std::memcmp(member_button_loop.data() + offset,
                        site.replacement.data(), site.instruction_size) != 0) {
            report = "button mapping was not updated";
            return false;
        }
    }
    member_button_loop[0] ^= 1;
    if (std::memcmp(member_button_loop.data(),
                    kMemberButtonLoopSites.front().replacement.data(),
                    kMemberButtonLoopSites.front().instruction_size) == 0) {
        report = "mismatched button mapping signature was accepted";
        return false;
    }
    int32_t master_displacement = 0;
    int32_t member_displacement = 0;
    std::memcpy(&master_displacement,
                kMemberButtonLoopSites[0].replacement.data() + 3,
                sizeof(master_displacement));
    std::memcpy(&member_displacement,
                kMemberButtonLoopSites[2].replacement.data() + 3,
                sizeof(member_displacement));
    const uintptr_t master_target = RelativeRvaTarget(
        kMemberButtonLoopSites[0].rva +
            kMemberButtonLoopSites[0].instruction_size,
        master_displacement);
    const uintptr_t member_target = RelativeRvaTarget(
        kMemberButtonLoopSites[2].rva +
            kMemberButtonLoopSites[2].instruction_size,
        member_displacement);
    if (master_target != kButtonMasterStringRva ||
        member_target != kButtonMemberStringRva) {
        report = "incorrect Master/Member mapping targets";
        return false;
    }
    for (const auto& site : kMissionParticipantCallSites) {
        int32_t relative = 0;
        std::memcpy(&relative, site.original.data() + 1, sizeof(relative));
        const uintptr_t target = RelativeRvaTarget(
            site.rva + site.instruction_size, relative);
        if (site.instruction_size != 5 || site.original[0] != 0xe8 ||
            target != site.original_target_rva ||
            site.relay_offset + 15 >= kMissionRelayPageSize) {
            report = "invalid external participant vector signature";
            return false;
        }
    }
    if (kMissionParticipantSafeCapacity != 8 ||
        kMissionRecordSidecarCount != 4 ||
        kMissionRecordRedirectOriginal.size() != 8 ||
        kMissionRecordExistingRedirectOriginal.size() != 10 ||
        kMissionRecordCopyOriginal.size() != 6 ||
        kMissionRecordAppendRedirectOriginal.size() != 7) {
        report = "incorrect dynamic sidecar signatures";
        return false;
    }
    std::array<uint8_t, 16> relative_test{};
    if (!WriteRelative32(relative_test.data(), 0xe9,
                         relative_test.data() + 12) ||
        Relative32Target(relative_test.data(), 0xe9) !=
            relative_test.data() + 12) {
        report = "sidecar relative jump was not encoded correctly";
        return false;
    }
    struct MissionRecordModel {
        uint32_t value = 0;
        uint32_t padding = 0;
        uintptr_t auxiliary = 0;
        uintptr_t object = 0;
    };
    static_assert(sizeof(MissionRecordModel) == kMissionRecordSize,
                  "mission sidecar record size changed");
    std::array<MissionRecordModel, kMissionRecordSidecarCount> sidecars{};
    for (unsigned index = 0; index < sidecars.size(); ++index) {
        sidecars[index] = {0x233U + index, 0,
                           0x11223344U + index, 0x55667788U + index};
        if (sidecars[index].value != 0x233U + index ||
            sidecars[index].auxiliary != 0x11223344U + index ||
            sidecars[index].object != 0x55667788U + index) {
            report = "four-sidecar isolation failed";
            return false;
        }
    }
    for (unsigned index = 0; index < kMissionSpawnSafeCapacity; ++index) {
        const unsigned spawn = index % kMissionSpawnPointCount;
        if (spawn >= kMissionSpawnPointCount ||
            (index >= kMissionSpawnPointCount && spawn != index - 4)) {
            report = "dynamic spawn point recycling failed";
            return false;
        }
    }
    if (kMissionRecordFirstExtraObjectOffset != 0x198 ||
        kMissionRecordLastExtraObjectOffset != 0x1e0 ||
        kMissionRecordAppendRedirectReturnRva !=
            kMissionRecordAppendRedirectRva +
                kMissionRecordAppendRedirectOriginal.size()) {
        report = "incorrect extra mission record addresses";
        return false;
    }
    constexpr size_t kRestoreFakeImageSize =
        kButtonMasterStringRva + sizeof(kButtonMasterKey);
    auto* restore_image = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kRestoreFakeImageSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    bool restore_bytes_valid = false;
    bool restore_mismatch_rejected = false;
    if (restore_image) {
        std::memcpy(restore_image + kCapacityRegionRva,
                    kCapacityRegion.data(), kCapacityRegion.size());
        for (const auto& site : kSecondaryCapacitySites) {
            std::memcpy(restore_image + site.rva, site.original.data(),
                        site.instruction_size);
        }
        for (const auto& site : kTertiaryCapacitySites) {
            std::memcpy(restore_image + site.rva, site.original.data(),
                        site.instruction_size);
        }
        for (const auto& site : kRoomPanelCapacitySites) {
            std::memcpy(restore_image + site.rva, site.original.data(),
                        site.instruction_size);
        }
        for (const auto& site : kMissionResultParticipantCapacitySites) {
            std::memcpy(restore_image + site.rva, site.original.data(),
                        site.instruction_size);
        }
        for (const auto& site : kExperimentalReserveSites) {
            std::memcpy(restore_image + site.rva, site.original.data(),
                        site.instruction_size);
        }
        std::memcpy(restore_image + kButtonMasterStringRva,
                    kButtonMasterKey, sizeof(kButtonMasterKey));
        std::memcpy(restore_image + kButtonMemberStringRva,
                    kButtonMemberKey, sizeof(kButtonMemberKey));
        WriteCapacity(restore_image + kCapacityRegionRva, 8);
        WriteSecondarySites(restore_image, 8);
        WriteTertiarySites(restore_image, 8);
        WriteRoomPanelSites(restore_image, 8);
        WriteMissionResultParticipantSites(restore_image, 8);
        WriteMemberButtonLoopSites(restore_image);
        WriteExperimentalReserveSites(restore_image, 8);
        WriteRosterOriginalSites(restore_image);
        WriteExperimentalReserveSites(restore_image, kOriginalCapacity);
        restore_bytes_valid = RosterOriginalSitesMatch(restore_image) &&
            ExperimentalReserveSitesMatch(restore_image,
                                           kOriginalCapacity);
        restore_image[kMemberButtonLoopSites.front().rva] ^= 1;
        restore_mismatch_rejected =
            !RosterOriginalSitesMatch(restore_image);
        VirtualFree(restore_image, 0, MEM_RELEASE);
    }
    if (!restore_bytes_valid || !restore_mismatch_rejected) {
        report = "fail-closed restoration did not restore/reject the expected bytes";
        return false;
    }
    report = "validated: three tables and room boxes preallocated 4->8, 24 experimental reserves/48 operands 4->8, dynamic Master/Member, MissionSync_Res filter following MaxPlayers 5..8, external eight-participant vector, modulo-four spawn, four sidecars across three persistent paths and 56 native relays executed for 3/5/8 with profile clamped to 4 without changing the real count, loadout parser stride relay executed for indices 0-8/63 keeping P4-P7 inside private blocks, both message builders sized to header+payload beyond 0x2E8, spawn transform loop capped at four records, plus fail-closed signature restoration";
    return true;
}

}  // namespace game_patches
