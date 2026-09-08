#pragma once

namespace edf41::sniffer::callback_dispatch {

enum class RegistrationKind {
    Callback,
    CallResult,
};

// Steam's CCallbackBase ABI has exactly three virtual slots and no virtual
// destructor: Run(payload, io_failure, api_call), Run(payload), then
// GetCallbackSizeBytes(). ObserveRegistration installs a per-object shadow
// vtable so the callback payload can be recorded without changing its result
// or ownership.
bool ObserveRegistration(void* callback, int callback_id,
                         RegistrationKind kind);
void ForgetRegistration(void* callback, RegistrationKind kind);

// Delivers a synthetic persistent callback through the exact original Run
// slot recorded for EDF 4.1. Called only from SteamAPI_RunCallbacks' game
// thread so callback registration and object lifetime follow Steam's model.
unsigned DispatchSyntheticCallback(int callback_id, const void* payload,
                                   unsigned payload_bytes);

}  // namespace edf41::sniffer::callback_dispatch
