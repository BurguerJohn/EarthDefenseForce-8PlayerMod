#include "mission_spawn.h"

#include <algorithm>
#include <limits>

namespace mission_spawn {

unsigned ClampMultiplier(unsigned multiplier) {
    return std::max(kMinimumMultiplier,
                    std::min(kMaximumMultiplier, multiplier));
}

bool IsConfirmedEnemySpawnReturnRva(uintptr_t return_rva) {
    return std::any_of(
        kConfirmedEnemySpawnCallRvas.begin(),
        kConfirmedEnemySpawnCallRvas.end(),
        [return_rva](uintptr_t call_rva) {
            // Every allowlisted instruction is a five-byte x64 rel32 call.
            return return_rva == call_rva + 5;
        });
}

Decision Evaluate(const Input& input) {
    Decision decision{};
    decision.effective_count = input.requested_count;
    decision.multiplier_enabled = input.multiplier_enabled;
    decision.multiplier = input.multiplier_enabled
        ? ClampMultiplier(input.configured_multiplier)
        : kMinimumMultiplier;
    decision.confirmed_enemy_caller =
        IsConfirmedEnemySpawnReturnRva(input.caller_return_rva);
    if (!decision.confirmed_enemy_caller) return decision;

    const uint64_t multiplied =
        static_cast<uint64_t>(input.requested_count) * decision.multiplier;
    decision.effective_count = static_cast<uint32_t>(
        std::min<uint64_t>(multiplied, kNativeEnemyCapacity));
    decision.multiplier_applied =
        decision.multiplier > 1 && input.requested_count > 0;
    decision.saturated = multiplied > kNativeEnemyCapacity;

    const int32_t maximum_players = std::max(
        kNativeParticipantCapacity + 1,
        std::min(kMaximumParticipantCapacity,
                 static_cast<int32_t>(input.configured_max_players)));
    const bool extra_player_mission =
        input.participant_count > kNativeParticipantCapacity &&
        input.participant_count <= maximum_players;
    const bool sane_denominator = input.scale_denominator > 0 &&
        input.scale_denominator <= kMaximumSaneScaleDenominator;
    decision.repair_zero_scale = extra_player_mission &&
        input.requested_count > 0 && input.scale_fields_readable &&
        input.spawn_source_present && input.scale_numerator == 0 &&
        sane_denominator;
    return decision;
}

bool SelfTest(std::string& report) {
    const uintptr_t confirmed_return =
        kConfirmedEnemySpawnCallRvas.front() + 5;

    Input input{};
    input.caller_return_rva = confirmed_return;
    input.requested_count = 10;
    input.configured_multiplier = 1;
    input.participant_count = 4;
    input.configured_max_players = 8;
    input.scale_fields_readable = true;
    input.spawn_source_present = true;
    input.scale_numerator = 1;
    input.scale_denominator = 1;
    Decision decision = Evaluate(input);
    if (!decision.confirmed_enemy_caller || decision.effective_count != 10 ||
        decision.multiplier_enabled || decision.multiplier != 1 ||
        decision.multiplier_applied || decision.saturated ||
        decision.repair_zero_scale) {
        report = "spawn policy changed the disabled multiplier path";
        return false;
    }

    input.configured_multiplier = kMaximumMultiplier;
    decision = Evaluate(input);
    if (decision.effective_count != 10 || decision.multiplier != 1 ||
        decision.multiplier_applied || decision.saturated) {
        report = "disabled experimental multiplier changed an enemy count";
        return false;
    }

    input.multiplier_enabled = true;
    input.configured_multiplier = 2;
    decision = Evaluate(input);
    if (!decision.multiplier_enabled || decision.effective_count != 20 ||
        !decision.multiplier_applied || decision.saturated) {
        report = "spawn policy did not multiply a confirmed enemy count";
        return false;
    }

    input.requested_count = 300;
    decision = Evaluate(input);
    if (decision.effective_count != kNativeEnemyCapacity ||
        !decision.saturated) {
        report = "spawn policy did not saturate at EDF5's native capacity";
        return false;
    }

    input.requested_count = 10;
    input.configured_multiplier = 1;
    input.participant_count = 5;
    input.scale_numerator = 0;
    input.scale_denominator = 4;
    decision = Evaluate(input);
    if (!decision.repair_zero_scale) {
        report = "spawn policy did not accept the guarded P5 zero-scale candidate";
        return false;
    }

    input.participant_count = 4;
    if (Evaluate(input).repair_zero_scale) {
        report = "spawn policy repaired a native one-to-four-player scale";
        return false;
    }
    input.participant_count = 5;
    input.spawn_source_present = false;
    if (Evaluate(input).repair_zero_scale) {
        report = "spawn policy repaired a generator without a spawn source";
        return false;
    }
    input.spawn_source_present = true;
    input.scale_denominator = 0;
    if (Evaluate(input).repair_zero_scale) {
        report = "spawn policy accepted a zero scale denominator";
        return false;
    }

    input.caller_return_rva = 0x1234;
    input.requested_count = std::numeric_limits<uint32_t>::max();
    input.configured_multiplier = kMaximumMultiplier;
    decision = Evaluate(input);
    if (decision.confirmed_enemy_caller ||
        decision.effective_count != input.requested_count ||
        decision.multiplier_applied || decision.repair_zero_scale) {
        report = "spawn policy modified an unknown caller";
        return false;
    }

    report = "disabled-by-default experimental multiplier/scale policy ok";
    return true;
}

}  // namespace mission_spawn
