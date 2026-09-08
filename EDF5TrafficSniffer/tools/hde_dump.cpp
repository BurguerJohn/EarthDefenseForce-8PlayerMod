#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hde64.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

namespace {

bool RvaToOffset(const std::vector<uint8_t>& image, uint32_t rva, uint32_t& offset) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const uint32_t start = sections[index].VirtualAddress;
        const uint32_t size = (std::max)(sections[index].Misc.VirtualSize,
                                         sections[index].SizeOfRawData);
        if (start <= rva && rva < start + size) {
            offset = sections[index].PointerToRawData + rva - start;
            return offset < image.size();
        }
    }
    return false;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) {
        std::fwprintf(stderr, L"usage: hde_dump.exe <pe> <begin-rva> <end-rva>\n");
        return 2;
    }
    wchar_t* end = nullptr;
    const uint32_t begin_rva = static_cast<uint32_t>(std::wcstoul(argv[2], &end, 0));
    if (!end || *end) return 3;
    const uint32_t end_rva = static_cast<uint32_t>(std::wcstoul(argv[3], &end, 0));
    if (!end || *end || end_rva <= begin_rva) return 3;

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file) return 4;
    const std::streamsize size = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> image(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(image.data()), size)) return 5;

    uint32_t begin_offset = 0;
    if (!RvaToOffset(image, begin_rva, begin_offset)) return 6;
    uint32_t cursor_rva = begin_rva;
    uint32_t cursor_offset = begin_offset;
    while (cursor_rva < end_rva && cursor_offset < image.size()) {
        hde64s decoded{};
        const unsigned length = hde64_disasm(image.data() + cursor_offset, &decoded);
        if (!length || cursor_rva + length > end_rva) break;
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
        if (decoded.flags & F_DISP8) std::printf(" disp8=%02x", decoded.disp.disp8);
        if (decoded.flags & F_DISP16) std::printf(" disp16=%04x", decoded.disp.disp16);
        if (decoded.flags & F_DISP32) std::printf(" disp32=%08x", decoded.disp.disp32);
        if (decoded.flags & F_IMM8) std::printf(" imm8=%02x", decoded.imm.imm8);
        if (decoded.flags & F_IMM16) std::printf(" imm16=%04x", decoded.imm.imm16);
        if (decoded.flags & F_IMM32) std::printf(" imm32=%08x", decoded.imm.imm32);
        if (decoded.flags & F_IMM64) std::printf(" imm64=%016llx",
                                                static_cast<unsigned long long>(decoded.imm.imm64));
        if (decoded.flags & F_RELATIVE) std::printf(" relative");
        if (decoded.flags & F_ERROR) std::printf(" ERROR");
        std::printf("\n");
        cursor_rva += length;
        cursor_offset += length;
    }
    return 0;
}
