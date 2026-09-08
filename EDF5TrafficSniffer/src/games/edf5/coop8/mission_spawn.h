#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace mission_spawn {

inline constexpr uint32_t kNativeEnemyCapacity = 400;
inline constexpr unsigned kMinimumMultiplier = 1;
inline constexpr unsigned kMaximumMultiplier = 8;
inline constexpr int32_t kNativeParticipantCapacity = 4;
inline constexpr int32_t kMaximumParticipantCapacity = 8;
inline constexpr uint32_t kMaximumSaneScaleDenominator = 1000000;

// Every direct call to EDF5's common enemy-instantiation routine in the
// supported executable. RTTI maps these callers to AlienTrailer, Deiroi,
// GeneratorPoll, InsectBase, Monster*, Nephila, AntHill and UFO enemy types.
// Keeping a closed allowlist prevents an indirect or newly introduced caller
// from inheriting spawn multiplication or the extra-player scale repair.
inline constexpr std::array<uintptr_t, 24> kConfirmedEnemySpawnCallRvas = {{
    0x1d0477, 0x1d517a, 0x1d7560, 0x1d80da,
    0x1dbd54, 0x1e0862, 0x1f9120, 0x1fa763,
    0x243cad, 0x245f8f, 0x261bf8, 0x262d98,
    0x26fded, 0x2755c9, 0x28d4b4, 0x291030,
    0x297fe5, 0x299709, 0x2c0c3b, 0x2c1ae4,
    0x2c9c6e, 0x2cff51, 0x2d3452, 0x2d7586,
}};

struct Input {
    uintptr_t caller_return_rva = 0;
    uint32_t requested_count = 0;
    bool multiplier_enabled = false;
    unsigned configured_multiplier = kMinimumMultiplier;
    int32_t participant_count = 0;
    unsigned configured_max_players = kMaximumParticipantCapacity;
    bool scale_fields_readable = false;
    bool spawn_source_present = false;
    uint32_t scale_numerator = 0;
    uint32_t scale_denominator = 0;
};

struct Decision {
    uint32_t effective_count = 0;
    unsigned multiplier = kMinimumMultiplier;
    bool multiplier_enabled = false;
    bool confirmed_enemy_caller = false;
    bool multiplier_applied = false;
    bool saturated = false;
    bool repair_zero_scale = false;
};

unsigned ClampMultiplier(unsigned multiplier);
bool IsConfirmedEnemySpawnReturnRva(uintptr_t return_rva);
Decision Evaluate(const Input& input);

// Pure policy checks used by EDF5MP_SelfTest. No game state is touched.
bool SelfTest(std::string& report);

}  // namespace mission_spawn
