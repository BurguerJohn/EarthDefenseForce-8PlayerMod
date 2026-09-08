#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>

#include "crash_handler.h"
#include "logger.h"
#include "runtime_config.h"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

bool EnsureDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash > 0 &&
        !EnsureDirectory(path.substr(0, slash)))
        return false;
    return CreateDirectoryW(path.c_str(), nullptr) != FALSE ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

bool WriteConfig() {
    const std::wstring directory = L"Mods\\TrafficSniffer";
    if (!EnsureDirectory(directory)) return false;
    static constexpr char config[] =
        "[EDF5.Sniffer]\r\n"
        "Enabled=true\r\n"
        "\r\n"
        "[EDF5.Coop8]\r\n"
        "Enabled=true\r\n"
        "\r\n"
        "[Diagnostics]\r\n"
        "Enabled=true\r\n"
        "Profile=Balanced\r\n"
        "CrashDumpMode=Mini\r\n"
        "SnapshotHotkeyVK=120\r\n"
        "DeepCaptureHotkeyVK=121\r\n"
        "StallWarningSeconds=5\r\n"
        "MaxSessions=20\r\n"
        "MaxTotalMiB=1024\r\n"
        "QueueMaxEvents=256\r\n"
        "QueueMaxMiB=1\r\n"
        "RotateMiB=4\r\n"
        "DeepSessionMiB=2\r\n"
        "MaxPayloadBytes=4096\r\n"
        "\r\n"
        "[Capture]\r\n"
        "Enabled=true\r\n"
        "Steam=true\r\n"
        "SteamCallbacks=true\r\n"
        "Winsock=true\r\n"
        "PayloadPreviewBytes=32\r\n"
        "FlushEveryEvents=8\r\n"
        "LogDirectory=Mods\\TrafficSniffer\\logs\r\n"
        "\r\n"
        "[MorePlayers]\r\n"
        "Enabled=true\r\n"
        "MaxPlayers=5\r\n";
    HANDLE file = CreateFileW(L"Mods\\TrafficSniffer\\config.ini",
                              GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(file, config, sizeof(config) - 1, &written,
                              nullptr) != FALSE &&
                    written == sizeof(config) - 1;
    CloseHandle(file);
    return ok;
}

bool InitializeDiagnostics(const wchar_t* root, bool diagnostics_enabled,
                           const wchar_t* dump_mode, bool deep_limit_test) {
    if (!root || !*root || !EnsureDirectory(root) ||
        !SetCurrentDirectoryW(root) || !WriteConfig())
        return false;
    if (!diagnostics_enabled &&
        !WritePrivateProfileStringW(L"Diagnostics", L"Enabled", L"false",
                                    L".\\Mods\\TrafficSniffer\\config.ini"))
        return false;
    if (dump_mode &&
        !WritePrivateProfileStringW(L"Diagnostics", L"CrashDumpMode",
                                    dump_mode,
                                    L".\\Mods\\TrafficSniffer\\config.ini"))
        return false;
    if (deep_limit_test) {
        if (!WritePrivateProfileStringW(
                L"Diagnostics", L"DeepSessionMiB", L"1",
                L".\\Mods\\TrafficSniffer\\config.ini") ||
            !WritePrivateProfileStringW(
                L"Diagnostics", L"MaxPayloadBytes", L"65536",
                L".\\Mods\\TrafficSniffer\\config.ini"))
            return false;
    }
    runtime_config::SelectGame(game::Id::Edf5);
    if (!capture::Initialize(GetModuleHandleW(nullptr))) return false;
    return crash_capture::Initialize(GetModuleHandleW(nullptr));
}

LONG WINAPI FixtureExceptionFilter(EXCEPTION_POINTERS*) {
    return EXCEPTION_CONTINUE_SEARCH;
}

void PublishMatchingState() {
    capture::RuntimeState state;
    state.flow_id = 42;
    state.lobby_steam_id = 109775241899999999ULL;
    state.last_progress_tick = GetTickCount64() - 7000;
    state.gameplay_contact_mask = 0x0f;
    state.real_gameplay_peers = 1;
    state.ready_mask = 0x0f;
    state.mission_group_mask = 0x03;
    state.actual_members = 1;
    state.synthetic_members = 4;
    state.max_players = 5;
    std::snprintf(state.phase, sizeof(state.phase), "matching");
    capture::UpdateRuntimeState(state);
}

void CleanShutdown() {
    crash_capture::Stop();
    capture::StopAndFlush();
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    if (argc < 3) {
        std::fwprintf(stderr,
                      L"usage: diagnostics_fixture.exe MODE OUTPUT_ROOT\n");
        return 2;
    }
    const std::wstring mode = argv[1];
    const bool disabled_mode = mode == L"disabled";
    const auto previous_filter = disabled_mode
        ? SetUnhandledExceptionFilter(FixtureExceptionFilter)
        : nullptr;
    if (!InitializeDiagnostics(argv[2], !disabled_mode,
                               mode == L"crash_off" ? L"Off" : L"Mini",
                               mode == L"deep_limit")) {
        if (disabled_mode) SetUnhandledExceptionFilter(previous_filter);
        std::fwprintf(stderr, L"diagnostics initialization failed: %lu\n",
                      GetLastError());
        return 3;
    }

    if (disabled_mode) {
        crash_capture::Stop();
        capture::StopAndFlush();
        const auto observed = SetUnhandledExceptionFilter(previous_filter);
        return observed == FixtureExceptionFilter ? 0 : 7;
    }

    crash_capture::Breadcrumb("fixture", "main", "initialized", 1, 2);
    capture::Event(capture::Level::Info, "fixture", "initialized",
                   capture::Fields().String("mode",
                                            capture::WideToUtf8(mode.c_str())));
    capture::Event(capture::Level::Info, "fixture", "text_context",
                   capture::Fields().String("context", "player_create"));
    capture::Event(capture::Level::Info, "fixture", "address_context",
                   capture::Fields().UInt("context", 140737488351232ULL));
    // Mirrors the scalar-only runtime gate event.  The report privacy test
    // proves these diagnostic bit patterns survive sanitization while the
    // explicit pointer/payload markers remain false.
    capture::Event(
        capture::Level::Info, "more_players", "generator_poll_gate_path",
        capture::Fields()
            .UInt("call", 1)
            .String("outcome", "quota_blocked_inside_time_window")
            .Bool("original_returned", true)
            .Bool("owner_is_generator_poll", true)
            .Bool("gate_state_matches_owner_offset", true)
            .Bool("state_readable", true)
            .Bool("owner_time_fields_readable", true)
            .Int("pre_remaining_count", 0)
            .Int("pre_cooldown_ticks", 0)
            .Int("cooldown_after_decrement", -1)
            .UInt("pre_last_time_bits", 1065353216)
            .UInt("period_scale_bits", 1073741824)
            .UInt("current_time_bits", 1077936128)
            .UInt("spawn_method_calls_in_gate", 0)
            .UInt("spawn_method_true_calls_in_gate", 0)
            .Bool("method_call_count_valid", true)
            .UInt("cooldown_threshold", 460)
            .Bool("gate_state_pointer_logged", false)
            .Bool("owner_pointer_logged", false)
            .Bool("spawn_payload_logged", false));

    if (mode == L"clean") {
        capture::Fields fields;
        fields.Bool("preserve_last_error_test", true);
        WSASetLastError(0x2345);
        capture::Event(capture::Level::Info, "fixture", "winsock_last_error",
                       fields);
        const int observed_winsock = WSAGetLastError();
        SetLastError(0x1234);
        capture::Event(capture::Level::Info, "fixture", "win32_last_error",
                       fields);
        const DWORD observed_win32 = GetLastError();
        const bool errors_preserved =
            observed_win32 == 0x1234 && observed_winsock == 0x2345;
        if (!errors_preserved) {
            std::fprintf(stderr,
                         "last_error_failure win32=%lu winsock=%d\n",
                         observed_win32, observed_winsock);
        }
        PublishMatchingState();
        capture::EmitNetworkSummary(true);
        CleanShutdown();
        return errors_preserved ? 0 : 8;
    }
    if (mode == L"snapshot") {
        PublishMatchingState();
        if (!crash_capture::RequestSnapshot("fixture") ||
            !crash_capture::WaitForIdle(15000)) {
            CleanShutdown();
            return 4;
        }
        CleanShutdown();
        return 0;
    }
    if (mode == L"network") {
        capture::RecordP2P(true, 76561198012345678ULL, 0, 246, true,
                           false, 0x123450);
        capture::RecordP2P(true, 76561198012345678ULL, 0, 300, true,
                           true, 0x123450);
        capture::RecordP2P(false, 76561198012345678ULL, 2, 512, false,
                           false, 0x234560);
        capture::RecordGamePacketRoute(true, 0, 128, 0x345670, 0, 0);
        capture::RecordGamePacketRoute(true, 0, 622, 0x345670, 0, 0);
        capture::RecordGamePacketRoute(false, 0, 172, 0, 0x456780,
                                       0x567890);
        capture::RecordGamePacketRoute(false, 0, 607, 0, 0x456780,
                                       0x567890);
        capture::RecordGameMessageRoute(true, 0x1200, 0x1200, 0, true, 8,
                                        0x654320, true, true, false);
        capture::RecordGameMessageRoute(true, 0x1200, 0x1200, 0, true, 8,
                                        0x654320, true, true, false);
        capture::RecordGameMessageRoute(true, 0x11100, 0x1100, 1, false, 12,
                                        0x765430, true, false, true);
        capture::RecordGameMessageRoute(false, 3, 0, 2, true, 0,
                                        0x114d50, true, true, false, false);
        CleanShutdown();
        return 0;
    }
    if (mode == L"deep") {
        static constexpr std::array<uint8_t, 32> prefix = {
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2d, 0x74,
            0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        };
        std::vector<uint8_t> payload(5000, 0xa5);
        std::memcpy(payload.data(), prefix.data(), prefix.size());
        crash_capture::SetDeepCapture(true, "fixture");
        capture::Event(capture::Level::Trace, "steam_p2p", "fixture_send",
                       capture::Fields()
                           .UInt("peer_steam_id", 76561198012345678ULL)
                           .String("remote_endpoint", "203.0.113.55:7777")
                           .String("authorization",
                                   "Bearer fixture-secret-token"),
                       payload.data(), payload.size());
        capture::Event(
            capture::Level::Info, "fixture", "sensitive_metadata",
            capture::Fields()
                .UInt("lobby_steam_id", 109775241899999999ULL)
                .UInt("peer_steam_id", 76561198012345678ULL)
                .String("remote_endpoint", "203.0.113.55:7777")
                .String("player_name", "Fixture Persona")
                .String("persona_name", "Fixture Persona Exact")
                .String("host", "private.fixture.invalid")
                .String("node", "node.fixture.invalid")
                .String("url", "https://api.fixture.invalid/private")
                .String("ticket", "secret-ticket-1234567890ABCDEFGH")
                .String("value", "generic-lobby-secret")
                .String("user_agent", "FixtureAgent/1.0")
                .String("executable", "C:\\private\\EDF5.exe")
                .UInt("context", 0x00007ff612345678ULL)
                .UInt("networking", 0x00007ff687654321ULL)
                .String("instruction_pointer", "0x00007ff6abcdef01")
                .String("address", "0x140abcdef"));
        crash_capture::SetDeepCapture(false, "fixture");
        CleanShutdown();
        return 0;
    }
    if (mode == L"deep_limit") {
        std::array<uint8_t, 65536> payload{};
        payload.fill(0x5a);
        crash_capture::SetDeepCapture(true, "fixture_limit");
        std::vector<std::thread> workers;
        for (unsigned thread = 0; thread < 8; ++thread) {
            workers.emplace_back([thread, &payload] {
                for (unsigned event = 0; event < 4; ++event) {
                    capture::Event(
                        capture::Level::Trace, "steam_p2p", "limit_send",
                        capture::Fields().UInt("producer", thread)
                            .UInt("index", event),
                        payload.data(), payload.size());
                }
            });
        }
        for (auto& worker : workers) worker.join();
        capture::Flush();
        crash_capture::SetDeepCapture(true, "after_limit");
        CleanShutdown();
        return 0;
    }
    if (mode == L"flood") {
        std::atomic<unsigned> ready{0};
        std::vector<std::thread> workers;
        for (unsigned thread = 0; thread < 8; ++thread) {
            workers.emplace_back([thread, &ready] {
                ready.fetch_add(1, std::memory_order_acq_rel);
                while (ready.load(std::memory_order_acquire) < 8)
                    YieldProcessor();
                for (unsigned event = 0; event < 25000; ++event) {
                    capture::Event(capture::Level::Info, "fixture", "flood",
                                   capture::Fields().UInt("producer", thread)
                                       .UInt("index", event));
                }
            });
        }
        for (auto& worker : workers) worker.join();
        CleanShutdown();
        return 0;
    }
    if (mode == L"rotate") {
        const std::string padding(320, 'R');
        for (unsigned event = 0; event < 20000; ++event) {
            capture::Event(capture::Level::Info, "fixture", "rotation",
                           capture::Fields().UInt("index", event)
                               .String("padding", padding));
            if ((event & 127u) == 127u) capture::Flush();
        }
        CleanShutdown();
        return 0;
    }
    if (mode == L"crash" || mode == L"crash_off") {
        PublishMatchingState();
        crash_capture::HookScope scope("fixture", "intentional_crash",
                                       "raise_exception", 0x1111, 0x2222);
        RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE,
                       0, nullptr);
        return 5;
    }
    if (mode == L"fast_fail") {
        PublishMatchingState();
        crash_capture::HookScope scope("fixture", "simulated_fast_fail",
                                       "security_cookie", 2, 0x3333);
        const bool captured = crash_capture::CaptureFastFail(
            2, reinterpret_cast<uintptr_t>(&PublishMatchingState));
        CleanShutdown();
        return captured ? 0 : 9;
    }

    CleanShutdown();
    return 6;
}
