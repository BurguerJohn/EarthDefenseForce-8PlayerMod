#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "game_patches.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::wstring Quote(const wchar_t* value) {
    return std::wstring(L"\"") + (value ? value : L"") + L"\"";
}

int RunNativeChild(const wchar_t* fixture) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);
    std::string report;
    const bool returned =
        game_patches::RunMissionRecordMicroTest(fixture, false, report);
    std::printf("native_fixture_returned=%s report=%s\n",
                returned ? "true" : "false", report.c_str());
    return 20;
}

bool ReproduceNativeCrash(const wchar_t* fixture, DWORD& exit_code,
                          std::string& error) {
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable,
                            static_cast<DWORD>(std::size(executable)))) {
        error = "GetModuleFileNameW failed";
        return false;
    }
    std::wstring command = Quote(executable) + L" --native-child " +
                           Quote(fixture);
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable, mutable_command.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &process)) {
        error = "CreateProcessW failed";
        return false;
    }
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 21);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        error = "native fixture child timed out";
        return false;
    }
    const bool read_exit = GetExitCodeProcess(process.hProcess, &exit_code) != FALSE;
    CloseHandle(process.hProcess);
    if (!read_exit) {
        error = "GetExitCodeProcess failed";
        return false;
    }
    return true;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wcscmp(argv[1], L"--native-child") == 0) {
        return RunNativeChild(argv[2]);
    }
    if (argc != 2) {
        std::fwprintf(stderr,
                      L"usage: mission_record_harness.exe <fixture.json>\n");
        return 2;
    }

    DWORD native_exit = 0;
    std::string error;
    if (!ReproduceNativeCrash(argv[1], native_exit, error)) {
        std::fprintf(stderr, "micro_harness_failure=%s\n", error.c_str());
        return 3;
    }
    if (native_exit != 0xc0000005UL) {
        std::fprintf(stderr,
                     "micro_harness_failure=native exit 0x%08lx, expected 0xc0000005\n",
                     static_cast<unsigned long>(native_exit));
        return 4;
    }

    std::string report;
    const bool patched =
        game_patches::RunMissionRecordMicroTest(argv[1], true, report);
    std::printf("native_reproduction=true exception=0x%08lx rva=0x11e2dc "
                "fault_write=0x12\n",
                static_cast<unsigned long>(native_exit));
    std::printf("patched_replay=%s report=%s\n",
                patched ? "true" : "false", report.c_str());
    return patched ? 0 : 5;
}
