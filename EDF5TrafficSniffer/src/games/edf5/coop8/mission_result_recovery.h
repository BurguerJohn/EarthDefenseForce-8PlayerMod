#pragma once

#include <cstdint>
#include <string>

namespace mission_result_recovery {

inline constexpr int32_t kNativeParticipantCapacity = 4;
inline constexpr int32_t kMaximumParticipantCapacity = 8;
inline constexpr int32_t kExecBeginArgument = -20000;
inline constexpr uint64_t kExecBeginGraceMs = 1000;

struct QueueInput {
    bool script_origin = false;
    bool sync_state_readable = false;
    int32_t sync_state = -1;
    int32_t sync_result = -1;
    int32_t participant_count = -1;
    unsigned configured_max_players = kMaximumParticipantCapacity;
    bool local_mission_harness = false;
    bool native_exec_begin_present = false;
    uint64_t native_exec_begin_calls = 0;
    uint64_t mission_generation = 0;
};

bool ShouldQueueExecBegin(const QueueInput& input);

enum class ApplyAction {
    Wait,
    Cancel,
    Apply,
};

struct ApplyInput {
    bool pending = false;
    uint64_t now = 0;
    uint64_t queued_tick = 0;
    uint64_t queued_generation = 0;
    uint64_t current_generation = 0;
    int32_t participant_count = -1;
    unsigned configured_max_players = kMaximumParticipantCapacity;
    bool local_mission_harness = false;
    bool native_exec_begin_present = false;
    uint64_t native_exec_begin_calls = 0;
};

ApplyAction EvaluateExecBeginApply(const ApplyInput& input);

// Pure policy checks used by EDF5MP_SelfTest. No game state is touched.
bool SelfTest(std::string& report);

}  // namespace mission_result_recovery
