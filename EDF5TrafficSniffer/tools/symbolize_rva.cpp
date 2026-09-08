#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#include <cstdio>
#include <cstdlib>

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        fwprintf(stderr, L"usage: symbolize_rva.exe <image.dll> <rva-hex>\n");
        return 2;
    }
    const DWORD64 rva = _wcstoui64(argv[2], nullptr, 16);
    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
    if (!SymInitializeW(process, nullptr, FALSE)) {
        fwprintf(stderr, L"SymInitializeW failed: %lu\n", GetLastError());
        return 3;
    }
    const DWORD64 base = SymLoadModuleExW(process, nullptr, argv[1], nullptr, 0, 0, nullptr, 0);
    if (!base) {
        fwprintf(stderr, L"SymLoadModuleExW failed: %lu\n", GetLastError());
        return 4;
    }
    alignas(SYMBOL_INFO) unsigned char storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacement = 0;
    const DWORD64 address = base + rva;
    if (!SymFromAddr(process, address, &displacement, symbol)) {
        fwprintf(stderr, L"SymFromAddr failed: %lu\n", GetLastError());
        return 5;
    }
    IMAGEHLP_LINEW64 line{};
    line.SizeOfStruct = sizeof(line);
    DWORD line_displacement = 0;
    const BOOL has_line = SymGetLineFromAddrW64(process, address, &line_displacement, &line);
    printf("image_base=0x%llx rva=0x%llx symbol=%s+0x%llx\n",
           static_cast<unsigned long long>(base), static_cast<unsigned long long>(rva),
           symbol->Name, static_cast<unsigned long long>(displacement));
    if (has_line) {
        wprintf(L"source=%ls:%lu+0x%lx\n", line.FileName, line.LineNumber, line_displacement);
    }
    SymCleanup(process);
    return 0;
}
