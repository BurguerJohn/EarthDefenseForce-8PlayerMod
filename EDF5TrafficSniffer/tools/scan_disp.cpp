#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hde64.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

namespace {

bool FindText(const std::vector<uint8_t>& image, uint32_t& rva, uint32_t& offset,
              uint32_t& size) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
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
    if (argc < 3 || argc > 5) {
        std::fwprintf(stderr, L"usage: scan_disp.exe <pe> <disp32> [begin-rva] [end-rva]\n");
        return 2;
    }
    wchar_t* end = nullptr;
    const uint32_t wanted = static_cast<uint32_t>(std::wcstoul(argv[2], &end, 0));
    if (!end || *end) return 3;

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) return 4;
    const std::streamsize file_size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> image(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(image.data()), file_size)) return 5;

    uint32_t text_rva = 0, text_offset = 0, text_size = 0;
    if (!FindText(image, text_rva, text_offset, text_size)) return 6;
    uint32_t begin_rva = text_rva;
    uint32_t end_rva = text_rva + text_size;
    if (argc >= 4) begin_rva = static_cast<uint32_t>(std::wcstoul(argv[3], &end, 0));
    if (!end || *end) return 3;
    if (argc >= 5) end_rva = static_cast<uint32_t>(std::wcstoul(argv[4], &end, 0));
    if (!end || *end || begin_rva < text_rva || end_rva > text_rva + text_size ||
        end_rva <= begin_rva) return 3;

    uint32_t cursor_rva = text_rva;
    uint32_t cursor_offset = text_offset;
    while (cursor_rva < end_rva && cursor_offset < text_offset + text_size) {
        hde64s decoded{};
        const unsigned length = hde64_disasm(image.data() + cursor_offset, &decoded);
        if (!length) return 7;
        if (cursor_rva >= begin_rva && (decoded.flags & F_DISP32) &&
            decoded.disp.disp32 == wanted) {
            std::printf("%08x  ", cursor_rva);
            for (unsigned index = 0; index < 15; ++index) {
                if (index < length) std::printf("%02x ", image[cursor_offset + index]);
                else std::printf("   ");
            }
            std::printf(" op=%02x", decoded.opcode);
            if (decoded.opcode == 0x0f) std::printf("/%02x", decoded.opcode2);
            if (decoded.flags & F_PREFIX_REX) std::printf(" rex=%02x", decoded.rex);
            if (decoded.flags & F_MODRM) std::printf(" modrm=%02x", decoded.modrm);
            if (decoded.flags & F_SIB) std::printf(" sib=%02x", decoded.sib);
            if (decoded.flags & F_IMM8) std::printf(" imm8=%02x", decoded.imm.imm8);
            if (decoded.flags & F_IMM32) std::printf(" imm32=%08x", decoded.imm.imm32);
            std::printf("\n");
        }
        cursor_rva += length;
        cursor_offset += length;
    }
    return 0;
}
