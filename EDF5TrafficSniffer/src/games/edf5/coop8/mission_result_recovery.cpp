#include "mission_result_recovery.h"

#include <algorithm>

namespace mission_result_recovery {
namespace {

bool ExtraParticipantMission(int32_t participant_count,
                             unsigned configured_max_players) {
    const int32_t maximum_players = std::max(
        kNativeParticipantCapacity + 1,
        std::min(kMaximumParticipantCapacity,
                 static_cast<int32_t>(configured_max_players)));
    return participant_count > kNativeParticipantCapacity &&
        participant_count <= maximum_players;
}

}  // namespace

bool ShouldQueueExecBegin(const QueueInput& input) {
    return input.script_origin && input.sync_state_readable &&
        input.sync_state == 0 && input.sync_result == 0 &&
        ExtraParticipantMission(input.participant_count,
                                input.configured_max_players) &&
        !input.local_mission_harness && input.native_exec_begin_present &&
        input.native_exec_begin_calls == 0 && input.mission_generation != 0;
}

ApplyAction EvaluateExecBeginApply(const ApplyInput& input) {
    if (!input.pending) return ApplyAction::Wait;
    if (!input.queued_tick || input.now < input.queued_tick ||
        input.now - input.queued_tick < kExecBeginGraceMs) {
        return ApplyAction::Wait;
    }
    const bool eligible = input.queued_generation != 0 &&
        input.queued_generation == input.current_generation &&
        ExtraParticipantMission(input.participant_count,
                                input.configured_max_players) &&
        !input.local_mission_harness && input.native_exec_begin_present &&
        input.native_exec_begin_calls == 0;
    return eligible ? ApplyAction::Apply : ApplyAction::Cancel;
}

bool SelfTest(std::string& report) {
    QueueInput queue{};
    queue.script_origin = true;
    queue.sync_state_readable = true;
    queue.sync_state = 0;
    queue.sync_result = 0;
    queue.participant_count = 5;
    queue.configured_max_players = 8;
    queue.native_exec_begin_present = true;
    queue.mission_generation = 2;
    if (!ShouldQueueExecBegin(queue)) {
        report = "result recovery did not queue the proven P5 stall";
        return false;
    }
    queue.participant_count = 4;
    if (ShouldQueueExecBegin(queue)) {
        report = "result recovery changed the native one-to-four-player path";
        return false;
    }
    queue.participant_count = 5;
    queue.native_exec_begin_calls = 1;
    if (ShouldQueueExecBegin(queue)) {
        report = "result recovery queued after native Exec_Begin";
        return false;
    }
    queue.native_exec_begin_calls = 0;
    queue.local_mission_harness = true;
    if (ShouldQueueExecBegin(queue)) {
        report = "result recovery queued for the local mission harness";
        return false;
    }

    ApplyInput apply{};
    apply.pending = true;
    apply.now = 2000;
    apply.queued_tick = apply.now - kExecBeginGraceMs;
    apply.queued_generation = 3;
    apply.current_generation = 3;
    apply.participant_count = 5;
    apply.configured_max_players = 8;
    apply.native_exec_begin_present = true;
    if (EvaluateExecBeginApply(apply) != ApplyAction::Apply) {
        report = "result recovery did not apply after its grace period";
        return false;
    }
    apply.now = apply.queued_tick + kExecBeginGraceMs - 1;
    if (EvaluateExecBeginApply(apply) != ApplyAction::Wait) {
        report = "result recovery did not preserve its native grace period";
        return false;
    }
    apply.now = 2000;
    apply.current_generation = 4;
    if (EvaluateExecBeginApply(apply) != ApplyAction::Cancel) {
        report = "result recovery did not cancel a stale mission generation";
        return false;
    }

    report = "mission result Exec_Begin recovery policy ok";
    return true;
}

}  // namespace mission_result_recovery
