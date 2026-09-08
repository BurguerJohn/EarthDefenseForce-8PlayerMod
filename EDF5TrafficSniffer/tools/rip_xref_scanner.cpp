#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hde64.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

bool FindText(const std::vector<uint8_t>& image, uint32_t& rva,
              uint32_t& offset, uint32_t& size) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        char name[9]{};
        std::memcpy(name, sections[index].Name, 8);
        if (std::strcmp(name, ".text") != 0) continue;
        rva = sections[index].VirtualAddress;
        offset = sections[index].PointerToRawData;
        size = sections[index].SizeOfRawData;
        return static_cast<size_t>(offset) + size <= image.size();
    }
    return false;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::fwprintf(stderr,
                      L"usage: rip_xref_scanner.exe <pe> <target-rva> [...]\n");
        return 2;
    }
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) return 3;
    const std::streamsize file_size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> image(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(image.data()), file_size)) return 4;

    uint32_t text_rva = 0, text_offset = 0, text_size = 0;
    if (!FindText(image, text_rva, text_offset, text_size)) return 5;
    std::vector<uint32_t> targets;
    for (int index = 2; index < argc; ++index) {
        wchar_t* end = nullptr;
        const unsigned long value = std::wcstoul(argv[index], &end, 0);
        if (!end || *end) return 6;
        targets.push_back(static_cast<uint32_t>(value));
    }

    for (uint32_t target : targets) {
        unsigned matches = 0;
        uint32_t cursor_rva = text_rva;
        uint32_t cursor_offset = text_offset;
        while (cursor_rva < text_rva + text_size) {
            hde64s decoded{};
            const unsigned length = hde64_disasm(
                image.data() + cursor_offset, &decoded);
            if (!length) return 7;
            const bool rip_relative =
                (decoded.flags & F_MODRM) && (decoded.flags & F_DISP32) &&
                decoded.modrm_mod == 0 && decoded.modrm_rm == 5;
            if (rip_relative) {
                const uint32_t resolved = static_cast<uint32_t>(
                    static_cast<int64_t>(cursor_rva + length) +
                    static_cast<int32_t>(decoded.disp.disp32));
                if (resolved == target) {
                    ++matches;
                    std::printf("  xref_rva=0x%08x len=%u op=%02x",
                                cursor_rva, length, decoded.opcode);
                    if (decoded.opcode == 0x0f) {
                        std::printf("/%02x", decoded.opcode2);
                    }
                    std::printf(" modrm=%02x\n", decoded.modrm);
                }
            }
            cursor_rva += length;
            cursor_offset += length;
        }
        std::printf("target_rva=0x%08x xrefs=%u\n", target, matches);
    }
    return 0;
}
