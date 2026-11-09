#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ultrawide.h"

#include "hook_manager.h"
#include "logger.h"

#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

// How EDF5 draws a screen wider than 16:9 (2560x1080 here): 0x60C120 lays out
// a centred 16:9 "area" (globals at 0x125A9D0: screen w/h, off_y, off_x, area
// w/h), and with the keep-aspect option (byte 0x115408C) every consumer uses
// the area instead of the screen. The swap chain, depth buffer and several
// effect targets are already screen-sized; the scene itself renders in view
// render targets sized by the view rect (view+0x34 x/y/w/h, from the screen
// object's 16:9 size), and the camera takes its aspect from that rect.
//
// Ultrawide picture:
//  - a view rect equal to the area becomes the whole screen when 0x6153A0
//    (re)creates the view's render targets; the camera follows (Hor+);
//  - viewports pushed through 0x5EF930 that the widened rect would place
//    past the right edge are moved back on screen;
//  - the scene composite (0x3D8920) uses the full screen: its viewport test
//    takes the screen path and its 2D projection the screen size;
//  - HUD corners: the UI viewport (0x3D7D30) and the layer/HUD viewport
//    (0x623FF7) use the full screen; every UI projection built by the UI
//    draw paths is compressed on x by area/screen (no stretching) and the
//    HUD gauges (power gauge left, radar and weapons right) move by the area
//    offset towards their side.
//
// EDF5 is built with whole-program optimisation: some callers rely on
// registers that the Windows x64 ABI calls volatile surviving a direct call
// (a plain C++ detour on 0x5BE700 clobbered r8/r9 and crashed at 0x5DB061).
// Every hook here therefore enters through a stub that saves all general and
// XMM registers, runs a C++ callback on that block and restores all of it
// (callback edits included) before continuing at the address the callback
// returns: the trampoline (run the original) or edf5mp_uw_ret (return to the
// caller with the saved rax; the callback already ran the original).

namespace ultrawide {
namespace {

struct HookRegs {
    uint8_t xmm[16][16];
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rflags;
    uint64_t target;      // where the stub continues
    uint64_t caller_ret;  // return address into the caller
    uint64_t shadow[4];
    uint64_t stack_args[4];  // 5th argument onwards
};
static_assert(offsetof(HookRegs, r15) == 256, "stub layout");
static_assert(offsetof(HookRegs, target) == 384, "stub layout");
static_assert(offsetof(HookRegs, caller_ret) == 392, "stub layout");
static_assert(offsetof(HookRegs, stack_args) == 432, "stub layout");

}  // namespace
}  // namespace ultrawide

extern "C" {
void edf5mp_uw_ret();
void edf5mp_uw_stub_scene_update();
void edf5mp_uw_stub_view_refresh();
void edf5mp_uw_stub_set_viewport();
void edf5mp_uw_stub_ortho();
void edf5mp_uw_stub_perspective();
void edf5mp_uw_stub_self_test();
uint64_t EDF5MP_UwSceneUpdate(ultrawide::HookRegs* regs);
uint64_t EDF5MP_UwViewRefresh(ultrawide::HookRegs* regs);
uint64_t EDF5MP_UwSetViewport(ultrawide::HookRegs* regs);
uint64_t EDF5MP_UwOrtho(ultrawide::HookRegs* regs);
uint64_t EDF5MP_UwPerspective(ultrawide::HookRegs* regs);
uint64_t EDF5MP_UwSelfTestCallback(ultrawide::HookRegs* regs);
}

#define EDF5MP_UW_SAVE_XMM(i) "movdqu [rsp+" #i "*16], xmm" #i "\n"
#define EDF5MP_UW_LOAD_XMM(i) "movdqu xmm" #i ", [rsp+" #i "*16]\n"
asm(R"(
.intel_syntax noprefix
.text
.globl edf5mp_uw_ret
edf5mp_uw_ret:
    ret
.macro EDF5MP_UW_STUB name, callback
.globl \name
\name:
    sub rsp, 8
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp, 256
)" EDF5MP_UW_SAVE_XMM(0) EDF5MP_UW_SAVE_XMM(1) EDF5MP_UW_SAVE_XMM(2)
    EDF5MP_UW_SAVE_XMM(3) EDF5MP_UW_SAVE_XMM(4) EDF5MP_UW_SAVE_XMM(5)
    EDF5MP_UW_SAVE_XMM(6) EDF5MP_UW_SAVE_XMM(7) EDF5MP_UW_SAVE_XMM(8)
    EDF5MP_UW_SAVE_XMM(9) EDF5MP_UW_SAVE_XMM(10) EDF5MP_UW_SAVE_XMM(11)
    EDF5MP_UW_SAVE_XMM(12) EDF5MP_UW_SAVE_XMM(13) EDF5MP_UW_SAVE_XMM(14)
    EDF5MP_UW_SAVE_XMM(15) R"(
    mov rbx, rsp
    mov rcx, rsp
    sub rsp, 32
    call \callback
    mov rsp, rbx
    mov [rsp+384], rax
)" EDF5MP_UW_LOAD_XMM(0) EDF5MP_UW_LOAD_XMM(1) EDF5MP_UW_LOAD_XMM(2)
    EDF5MP_UW_LOAD_XMM(3) EDF5MP_UW_LOAD_XMM(4) EDF5MP_UW_LOAD_XMM(5)
    EDF5MP_UW_LOAD_XMM(6) EDF5MP_UW_LOAD_XMM(7) EDF5MP_UW_LOAD_XMM(8)
    EDF5MP_UW_LOAD_XMM(9) EDF5MP_UW_LOAD_XMM(10) EDF5MP_UW_LOAD_XMM(11)
    EDF5MP_UW_LOAD_XMM(12) EDF5MP_UW_LOAD_XMM(13) EDF5MP_UW_LOAD_XMM(14)
    EDF5MP_UW_LOAD_XMM(15) R"(
    add rsp, 256
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
.endm
EDF5MP_UW_STUB edf5mp_uw_stub_scene_update, EDF5MP_UwSceneUpdate
EDF5MP_UW_STUB edf5mp_uw_stub_view_refresh, EDF5MP_UwViewRefresh
EDF5MP_UW_STUB edf5mp_uw_stub_set_viewport, EDF5MP_UwSetViewport
EDF5MP_UW_STUB edf5mp_uw_stub_ortho, EDF5MP_UwOrtho
EDF5MP_UW_STUB edf5mp_uw_stub_perspective, EDF5MP_UwPerspective
EDF5MP_UW_STUB edf5mp_uw_stub_self_test, EDF5MP_UwSelfTestCallback
.att_syntax prefix
)");

namespace ultrawide {
namespace {

// Game functions (all entered through the stubs above).
constexpr uintptr_t kSceneUpdateRva = 0x611bb0;  // (scene manager, ...)
constexpr uint8_t kSceneUpdateSignature[] = {
    0x44, 0x89, 0x44, 0x24, 0x18, 0xf3, 0x0f, 0x11, 0x4c, 0x24, 0x10,
};
constexpr uintptr_t kViewRefreshRva = 0x6153a0;  // (view)
constexpr uint8_t kViewRefreshSignature[] = {
    0x40, 0x55, 0x53, 0x48, 0x8d, 0x6c, 0x24, 0xb1,
    0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00,
};
constexpr uintptr_t kSetViewportRva = 0x5ef930;  // (context, rect)
constexpr uint8_t kSetViewportSignature[] = {
    0x48, 0x83, 0xec, 0x48, 0x48, 0x8b, 0x05,
};
constexpr uintptr_t kOrthoRva = 0x5be700;  // (out, cx, cy, w, h, n, f)
constexpr uint8_t kOrthoSignature[] = {
    0x48, 0x8b, 0xc4, 0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00,
};
constexpr uintptr_t kPerspectiveRva = 0x5be600;  // (out, fov, aspect, n, f)
constexpr uint8_t kPerspectiveSignature[] = {
    0x40, 0x53, 0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,
};

// UI matrix builder call sites (the return addresses). 0x4B2FB0 (UI object
// draw) and 0x4B2390 keep the UI object in rdi; slot 10 (0x4B2590) does not.
struct UiCallSite {
    uintptr_t call_rva;  // e8 rel32 to the ortho or perspective builder
    uintptr_t builder_rva;
    bool object_in_rdi;
};
constexpr UiCallSite kUiCallSites[] = {
    {0x4b30a1, kOrthoRva, true},       {0x4b30ce, kPerspectiveRva, true},
    {0x4b244b, kOrthoRva, true},       {0x4b2478, kPerspectiveRva, true},
    {0x4b25df, kOrthoRva, false},      {0x4b2616, kPerspectiveRva, false},
};
// mov rdi, rcx in 0x4B2FB0 and 0x4B2390 (the object stays in rdi).
constexpr uintptr_t kUiDrawObjectRegisterRva = 0x4b2fdc;
constexpr uintptr_t kUiMatrixObjectRegisterRva = 0x4b23be;
constexpr uint8_t kMovRdiRcxSignature[] = {0x48, 0x8b, 0xf9};

// HUD gauges moved to the corners, checked against their RTTI names.
struct HudGauge {
    uintptr_t vtable_rva;
    const char* type_name;
    int side;  // -1 left, +1 right
};
constexpr HudGauge kHudGauges[] = {
    {0xecaf90, ".?AVHUiHudPowerGuage@ui@@", -1},
    {0xecb230, ".?AVHUiHudRader@ui@@", 1},
    {0xecb3c0, ".?AVHUiHudWeapon@ui@@", 1},
};

// Code patches, each checked on its whole instruction context.
// 0x3D8920 composite viewport: cmp byte [keep-aspect], 0; je screen path.
constexpr uintptr_t kCompositeViewportContextRva = 0x3d899f;
constexpr uintptr_t kUltrawideCompositeViewportRva = 0x3d89a6;
constexpr uint8_t kCompositeViewportContext[] = {
    0x80, 0x3d, 0xe6, 0xb6, 0xd7, 0x00, 0x00, 0x74, 0x1a,
};
// 0x3D7D30 UI viewport.
constexpr uintptr_t kUiViewportContextRva = 0x3d7ed3;
constexpr uintptr_t kUltrawideUiViewportRva = 0x3d7eda;
constexpr uint8_t kUiViewportContext[] = {
    0x80, 0x3d, 0xb2, 0xc1, 0xd7, 0x00, 0x00, 0x74, 0x1b,
};
// 0x623FF7 layer viewport (the HUD draws with the viewport it restores).
constexpr uintptr_t kLayerViewportContextRva = 0x624060;
constexpr uintptr_t kUltrawideLayerViewportRva = 0x624075;
constexpr uint8_t kLayerViewportContext[] = {
    0x80, 0x3d, 0x25, 0x00, 0xb3, 0x00, 0x00, 0x44, 0x8b, 0x0d, 0x72, 0x69,
    0xc3, 0x00, 0x44, 0x8b, 0x15, 0x6f, 0x69, 0xc3, 0x00, 0x74, 0x15,
};
constexpr uint8_t kJmpShort[] = {0xeb};
// 0x3D8920 composite 2D projection: the screen object's 16:9 size is
// replaced by the screen size (mov eax, [screen h]; cvt; mov eax,
// [screen w]; cvt; nop5).
constexpr uintptr_t kUltrawideCompositeProjectionRva = 0x3d8a99;
constexpr uint8_t kCompositeProjectionContext[] = {
    0x48, 0x8b, 0x05, 0x18, 0xe2, 0xe7, 0x00, 0x48, 0x8b, 0x48, 0x18,
    0x8b, 0x41, 0x24, 0x0f, 0x57, 0xd2, 0xf3, 0x48, 0x0f, 0x2a, 0xd0,
    0x8b, 0x41, 0x20, 0x0f, 0x57, 0xc0, 0xf3, 0x48, 0x0f, 0x2a, 0xc0,
};

constexpr uintptr_t kScreenGlobalsRva = 0x125a9d0;  // 6 x int32
constexpr uintptr_t kScreenWidthRva = kScreenGlobalsRva;
constexpr uintptr_t kScreenHeightRva = kScreenGlobalsRva + 4;
constexpr uintptr_t kKeepAspectFlagRva = 0x115408c;
constexpr uintptr_t kViewBlockOffset = 0x230;  // scene manager + i * 0x188
constexpr uintptr_t kViewStride = 0x188;
constexpr uintptr_t kViewRectOffset = 0x34;
constexpr unsigned kViewCount = 4;

// Builds the composite projection replacement for code at rva.
std::array<uint8_t, sizeof(kCompositeProjectionContext)>
CompositeProjectionPatch(uintptr_t rva) {
    std::array<uint8_t, sizeof(kCompositeProjectionContext)> out{};
    size_t at = 0;
    auto rip_load_eax = [&](uintptr_t instruction_rva, uintptr_t target) {
        const int64_t displacement = static_cast<int64_t>(target) -
            static_cast<int64_t>(instruction_rva + 6);
        const auto disp32 = static_cast<uint32_t>(
            static_cast<int32_t>(displacement));
        out[at++] = 0x8b;
        out[at++] = 0x05;
        for (int shift = 0; shift < 32; shift += 8) {
            out[at++] = static_cast<uint8_t>(disp32 >> shift);
        }
    };
    auto bytes = [&](std::initializer_list<uint8_t> list) {
        for (const uint8_t value : list) out[at++] = value;
    };
    rip_load_eax(rva, kScreenHeightRva);
    bytes({0x0f, 0x57, 0xd2, 0xf3, 0x48, 0x0f, 0x2a, 0xd0});
    rip_load_eax(rva + at, kScreenWidthRva);
    bytes({0x0f, 0x57, 0xc0, 0xf3, 0x48, 0x0f, 0x2a, 0xc0});
    bytes({0x0f, 0x1f, 0x44, 0x00, 0x00});
    return out;
}

struct Layout {
    int32_t screen_w = 0, screen_h = 0, off_y = 0, off_x = 0;
    int32_t area_w = 0, area_h = 0;
    // The keep-aspect area is narrower than the screen (pillarbox only).
    bool Wider() const {
        return screen_w > area_w && area_w > 0 && screen_h == area_h &&
               off_x > 0 && off_y == 0;
    }
};

uintptr_t g_base = 0;
size_t g_image_size = 0;
uint64_t g_tramp_scene_update = 0;
uint64_t g_tramp_view_refresh = 0;
uint64_t g_tramp_set_viewport = 0;
uint64_t g_tramp_ortho = 0;
uint64_t g_tramp_perspective = 0;
std::atomic<bool> g_installed{false};
std::atomic<bool> g_enabled{true};
// GetTickCount64 when the current mission was first seen, 0 outside one.
std::atomic<uint64_t> g_mission_since{0};
constexpr uint64_t kMissionSettleMs = 1000;
// Written by the scene update (game thread), read by every callback.
std::atomic<bool> g_applied{false};
std::atomic<bool> g_corners{false};
bool g_corners_supported = false;  // UI call sites verified
int g_gauge_sides[std::size(kHudGauges)] = {};
std::array<uint8_t, sizeof(kCompositeProjectionContext)> g_projection_patch{};
std::atomic<unsigned> g_widen_logs{0};
std::atomic<unsigned> g_viewport_fix_logs{0};
thread_local int32_t t_fixed_rect[6];

Layout ReadLayout() {
    Layout layout;
    if (!g_base) return layout;
    int32_t values[6] = {};
    std::memcpy(values, reinterpret_cast<const void*>(g_base + kScreenGlobalsRva),
                sizeof(values));
    layout.screen_w = values[0];
    layout.screen_h = values[1];
    layout.off_y = values[2];
    layout.off_x = values[3];
    layout.area_w = values[4];
    layout.area_h = values[5];
    return layout;
}

bool KeepAspect() {
    return g_base &&
           *reinterpret_cast<const volatile uint8_t*>(g_base +
                                                       kKeepAspectFlagRva) != 0;
}

bool Matches(uintptr_t rva, const uint8_t* expected, size_t size) {
    return g_base && rva <= g_image_size && size <= g_image_size - rva &&
           std::memcmp(reinterpret_cast<const void*>(g_base + rva), expected,
                       size) == 0;
}

bool CallTargets(uintptr_t call_rva, uintptr_t target_rva) {
    if (!g_base || call_rva + 5 > g_image_size) return false;
    const auto* code = reinterpret_cast<const uint8_t*>(g_base + call_rva);
    if (code[0] != 0xe8) return false;
    int32_t relative = 0;
    std::memcpy(&relative, code + 1, sizeof(relative));
    return static_cast<int64_t>(call_rva) + 5 + relative ==
           static_cast<int64_t>(target_rva);
}

// The RTTI name of the class owning the vtable at vtable_rva.
bool VtableTypeIs(uintptr_t vtable_rva, const char* type_name) {
    if (!g_base || vtable_rva < 8 || vtable_rva > g_image_size) return false;
    uint64_t locator = 0;
    std::memcpy(&locator, reinterpret_cast<const void*>(g_base + vtable_rva - 8),
                sizeof(locator));
    if (locator < g_base + 0x1000 || locator + 24 > g_base + g_image_size) {
        return false;
    }
    uint32_t descriptor_rva = 0;
    std::memcpy(&descriptor_rva,
                reinterpret_cast<const void*>(locator + 12),
                sizeof(descriptor_rva));
    const size_t name_size = std::strlen(type_name) + 1;
    if (descriptor_rva + 16 + name_size > g_image_size) return false;
    return std::memcmp(
               reinterpret_cast<const void*>(g_base + descriptor_rva + 16),
               type_name, name_size) == 0;
}

void WriteCode(uintptr_t rva, const uint8_t* bytes, size_t size) {
    auto* address = reinterpret_cast<void*>(g_base + rva);
    DWORD old_protection = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE,
                        &old_protection)) {
        return;
    }
    std::memcpy(address, bytes, size);
    DWORD ignored = 0;
    VirtualProtect(address, size, old_protection, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, size);
}

void SetPatches(bool picture, bool corners) {
    const uint8_t original_je[] = {0x74};
    WriteCode(kUltrawideCompositeViewportRva,
              picture ? kJmpShort : original_je, 1);
    WriteCode(kUltrawideCompositeProjectionRva,
              picture ? g_projection_patch.data() : kCompositeProjectionContext,
              sizeof(kCompositeProjectionContext));
    WriteCode(kUltrawideUiViewportRva, corners ? kJmpShort : original_je, 1);
    WriteCode(kUltrawideLayerViewportRva, corners ? kJmpShort : original_je, 1);
}

// --- rules shared by the callbacks and the self-test --------------------

// A scene view rect equal to the 16:9 area becomes the whole screen.
bool WidenRect(int32_t* rect, const Layout& layout) {
    if (!layout.Wider() || rect[0] != 0 || rect[1] != 0 ||
        rect[2] != layout.area_w || rect[3] != layout.area_h) {
        return false;
    }
    rect[2] = layout.screen_w;
    rect[3] = layout.screen_h;
    return true;
}

// Back to the area (switching to the original picture).
bool RestoreRect(int32_t* rect, const Layout& layout) {
    if (!layout.Wider() || rect[0] != 0 || rect[1] != 0 ||
        rect[2] != layout.screen_w || rect[3] != layout.screen_h) {
        return false;
    }
    rect[2] = layout.area_w;
    rect[3] = layout.area_h;
    return true;
}

// A viewport the widened view would push off screen: shifted by the area
// offset (layer and camera paths) or scaled past the screen (layer path with
// the full-screen test). rect = {x, y, w, h, ...}.
bool FixViewport(int32_t* rect, const Layout& layout) {
    if (!layout.Wider()) return false;
    const bool shifted = rect[0] == layout.off_x && rect[2] == layout.screen_w;
    const bool too_wide = rect[0] == 0 && rect[2] > layout.screen_w;
    if (!shifted && !too_wide) return false;
    rect[0] = 0;
    rect[2] = layout.screen_w;
    return true;
}

// Row-vector 4x4 (column 0 = x, column 3 = w): compress on x by area/screen
// and move by side * area offset.
void AdjustUiProjection(float* matrix, const Layout& layout, int side) {
    if (!layout.Wider()) return;
    const float scale = static_cast<float>(layout.area_w) /
                        static_cast<float>(layout.screen_w);
    const float shift = static_cast<float>(side) *
        static_cast<float>(layout.off_x) /
        (static_cast<float>(layout.screen_w) * 0.5f);
    for (int row = 0; row < 4; ++row) {
        float* m = matrix + row * 4;
        m[0] = m[0] * scale + shift * m[3];
    }
}

int GaugeSide(uint64_t object) {
    if (!object) return 0;
    uint64_t vtable = 0;
    std::memcpy(&vtable, reinterpret_cast<const void*>(object), sizeof(vtable));
    for (size_t index = 0; index < std::size(kHudGauges); ++index) {
        if (vtable == g_base + kHudGauges[index].vtable_rva) {
            return g_gauge_sides[index];
        }
    }
    return 0;
}

// The UI call site a builder returns to, or nullptr.
const UiCallSite* UiSiteForReturn(uint64_t caller_ret, uintptr_t builder) {
    if (!g_corners_supported) return nullptr;
    for (const auto& site : kUiCallSites) {
        if (site.builder_rva == builder &&
            caller_ret == g_base + site.call_rva + 5) {
            return &site;
        }
    }
    return nullptr;
}

float XmmFloat(const HookRegs* regs, int index) {
    float value = 0.0f;
    std::memcpy(&value, regs->xmm[index], sizeof(value));
    return value;
}

float StackFloat(const HookRegs* regs, int index) {
    float value = 0.0f;
    std::memcpy(&value, &regs->stack_args[index], sizeof(value));
    return value;
}

std::string DescribeViews(uintptr_t manager) {
    std::string out = "[";
    for (unsigned index = 0; manager && index < kViewCount; ++index) {
        const uintptr_t view = manager + kViewBlockOffset + index * kViewStride;
        int32_t rect[4] = {};
        std::memcpy(rect, reinterpret_cast<const void*>(view + kViewRectOffset),
                    sizeof(rect));
        uint64_t targets = 0;
        std::memcpy(&targets, reinterpret_cast<const void*>(view + 0x20),
                    sizeof(targets));
        if (index) out += ",";
        out += "[" + std::to_string(rect[0]) + "," + std::to_string(rect[1]) +
               "," + std::to_string(rect[2]) + "," + std::to_string(rect[3]) +
               "," + (targets ? "1" : "0") + "]";
    }
    return out + "]";
}

void RefreshViews(uintptr_t manager, bool widen, const Layout& layout) {
    if (!manager || !g_tramp_view_refresh) return;
    using RefreshFn = void(__fastcall*)(uintptr_t);
    const auto refresh = reinterpret_cast<RefreshFn>(g_tramp_view_refresh);
    for (unsigned index = 0; index < kViewCount; ++index) {
        const uintptr_t view = manager + kViewBlockOffset + index * kViewStride;
        auto* rect = reinterpret_cast<int32_t*>(view + kViewRectOffset);
        const bool changed =
            widen ? WidenRect(rect, layout) : RestoreRect(rect, layout);
        if (changed) refresh(view);
    }
}

}  // namespace
}  // namespace ultrawide

using ultrawide::HookRegs;

// 0x611BB0(scene manager, ...): once per frame on the game thread, at the
// point where EDF5 itself refreshes scene views. The picture is switched
// here: code patches, then the views' render targets.
extern "C" uint64_t EDF5MP_UwSceneUpdate(HookRegs* regs) {
    using namespace ultrawide;
    const Layout layout = ReadLayout();
    const uint64_t mission_since =
        g_mission_since.load(std::memory_order_acquire);
    const bool mission_settled = mission_since &&
        GetTickCount64() - mission_since >= kMissionSettleMs;
    const bool want = g_enabled.load(std::memory_order_acquire) &&
                      mission_settled && layout.Wider() && KeepAspect();
    if (want != g_applied.load(std::memory_order_acquire)) {
        const bool corners =
            want && g_corners_supported &&
            capture::GetConfig().ultrawide_hud_corners;
        const auto manager = static_cast<uintptr_t>(regs->rcx);
        const std::string views_before = DescribeViews(manager);
        SetPatches(want, corners);
        g_corners.store(corners, std::memory_order_release);
        g_applied.store(want, std::memory_order_release);
        RefreshViews(manager, want, layout);
        EDF5_CAPTURE_EVENT("more_players", "ultrawide_picture",
                           capture::Fields()
                               .Raw("views_before", views_before)
                               .Raw("views_after", DescribeViews(manager))
                               .Bool("ultrawide", want)
                               .Bool("hud_corners", corners)
                               .Bool("enabled", g_enabled.load(
                                   std::memory_order_acquire))
                               .Int("screen_w", layout.screen_w)
                               .Int("screen_h", layout.screen_h)
                               .Int("area_w", layout.area_w)
                               .Int("area_h", layout.area_h));
    }
    return g_tramp_scene_update;
}

// 0x6153A0(view): (re)creates a view's render targets when its rect changed;
// every rect setter calls it.
extern "C" uint64_t EDF5MP_UwViewRefresh(HookRegs* regs) {
    using namespace ultrawide;
    if (g_applied.load(std::memory_order_acquire) && regs->rcx) {
        auto* rect = reinterpret_cast<int32_t*>(regs->rcx + kViewRectOffset);
        const Layout layout = ReadLayout();
        if (WidenRect(rect, layout) &&
            g_widen_logs.fetch_add(1, std::memory_order_acq_rel) < 4) {
            EDF5_CAPTURE_EVENT(
                "more_players", "ultrawide_view_widened",
                capture::Fields()
                    .Int("width", rect[2])
                    .Int("height", rect[3])
                    .UInt("caller_rva", regs->caller_ret - g_base));
        }
    }
    return g_tramp_view_refresh;
}

// 0x5EF930(context, rect = {int x, y, w, h; float min_z, max_z}).
extern "C" uint64_t EDF5MP_UwSetViewport(HookRegs* regs) {
    using namespace ultrawide;
    if (g_applied.load(std::memory_order_acquire) && regs->rdx) {
        std::memcpy(ultrawide::t_fixed_rect,
                    reinterpret_cast<const void*>(regs->rdx),
                    sizeof(ultrawide::t_fixed_rect));
        if (FixViewport(ultrawide::t_fixed_rect, ReadLayout())) {
            regs->rdx = reinterpret_cast<uint64_t>(ultrawide::t_fixed_rect);
            if (g_viewport_fix_logs.fetch_add(1, std::memory_order_acq_rel) <
                4) {
                EDF5_CAPTURE_EVENT(
                    "more_players", "ultrawide_viewport_fixed",
                    capture::Fields().UInt("caller_rva",
                                           regs->caller_ret - g_base));
            }
        }
    }
    return g_tramp_set_viewport;
}

// 0x5BE700(out, cx, cy, width, height, near, far): ortho builder.
extern "C" uint64_t EDF5MP_UwOrtho(HookRegs* regs) {
    using namespace ultrawide;
    const UiCallSite* site = g_corners.load(std::memory_order_acquire)
        ? UiSiteForReturn(regs->caller_ret, kOrthoRva)
        : nullptr;
    if (!site) return g_tramp_ortho;
    using OrthoFn = float*(__fastcall*)(float*, float, float, float, float,
                                        float, float);
    auto* out = reinterpret_cast<float*>(regs->rcx);
    reinterpret_cast<OrthoFn>(g_tramp_ortho)(
        out, XmmFloat(regs, 1), XmmFloat(regs, 2), XmmFloat(regs, 3),
        StackFloat(regs, 0), StackFloat(regs, 1), StackFloat(regs, 2));
    AdjustUiProjection(out, ReadLayout(),
                       site->object_in_rdi ? GaugeSide(regs->rdi) : 0);
    regs->rax = regs->rcx;
    return reinterpret_cast<uint64_t>(&edf5mp_uw_ret);
}

// 0x5BE600(out, fov, aspect, near, far): perspective builder.
extern "C" uint64_t EDF5MP_UwPerspective(HookRegs* regs) {
    using namespace ultrawide;
    const UiCallSite* site = g_corners.load(std::memory_order_acquire)
        ? UiSiteForReturn(regs->caller_ret, kPerspectiveRva)
        : nullptr;
    if (!site) return g_tramp_perspective;
    using PerspectiveFn = float*(__fastcall*)(float*, float, float, float,
                                              float);
    auto* out = reinterpret_cast<float*>(regs->rcx);
    reinterpret_cast<PerspectiveFn>(g_tramp_perspective)(
        out, XmmFloat(regs, 1), XmmFloat(regs, 2), XmmFloat(regs, 3),
        StackFloat(regs, 0));
    AdjustUiProjection(out, ReadLayout(),
                       site->object_in_rdi ? GaugeSide(regs->rdi) : 0);
    regs->rax = regs->rcx;
    return reinterpret_cast<uint64_t>(&edf5mp_uw_ret);
}

// Self-test: the stub continues at the test target with the edited rdx, or
// returns directly with the edited rax.
namespace ultrawide {
namespace {
uint64_t g_test_target = 0;
uint64_t __fastcall SelfTestTarget(uint64_t a, uint64_t b, uint64_t c,
                                   uint64_t d, uint64_t e) {
    return a + b * 10 + c * 100 + d * 1000 + e * 10000;
}
}  // namespace
}  // namespace ultrawide

extern "C" uint64_t EDF5MP_UwSelfTestCallback(HookRegs* regs) {
    using namespace ultrawide;
    if (regs->rcx == 9) {
        regs->rax = 4242 + regs->stack_args[0];
        return reinterpret_cast<uint64_t>(&edf5mp_uw_ret);
    }
    regs->rdx += 1;
    return g_test_target;
}

namespace ultrawide {

bool Install() {
    const auto& config = capture::GetConfig();
    g_enabled.store(config.ultrawide && config.ultrawide_start_enabled,
                    std::memory_order_release);
    if (!config.ultrawide) return true;
    HMODULE module = GetModuleHandleW(nullptr);
    g_base = reinterpret_cast<uintptr_t>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        g_base + static_cast<uintptr_t>(dos->e_lfanew));
    g_image_size = nt->OptionalHeader.SizeOfImage;
    g_projection_patch = CompositeProjectionPatch(kUltrawideCompositeProjectionRva);

    const bool functions_ok =
        Matches(kSceneUpdateRva, kSceneUpdateSignature,
                sizeof(kSceneUpdateSignature)) &&
        Matches(kViewRefreshRva, kViewRefreshSignature,
                sizeof(kViewRefreshSignature)) &&
        Matches(kSetViewportRva, kSetViewportSignature,
                sizeof(kSetViewportSignature)) &&
        Matches(kOrthoRva, kOrthoSignature, sizeof(kOrthoSignature)) &&
        Matches(kPerspectiveRva, kPerspectiveSignature,
                sizeof(kPerspectiveSignature));
    const bool patches_ok =
        Matches(kCompositeViewportContextRva, kCompositeViewportContext,
                sizeof(kCompositeViewportContext)) &&
        Matches(kUltrawideCompositeProjectionRva, kCompositeProjectionContext,
                sizeof(kCompositeProjectionContext));
    bool corners_ok =
        Matches(kUiViewportContextRva, kUiViewportContext,
                sizeof(kUiViewportContext)) &&
        Matches(kLayerViewportContextRva, kLayerViewportContext,
                sizeof(kLayerViewportContext)) &&
        Matches(kUiDrawObjectRegisterRva, kMovRdiRcxSignature,
                sizeof(kMovRdiRcxSignature)) &&
        Matches(kUiMatrixObjectRegisterRva, kMovRdiRcxSignature,
                sizeof(kMovRdiRcxSignature));
    for (const auto& site : kUiCallSites) {
        corners_ok = corners_ok && CallTargets(site.call_rva, site.builder_rva);
    }
    unsigned gauges_found = 0;
    for (size_t index = 0; index < std::size(kHudGauges); ++index) {
        const bool found = VtableTypeIs(kHudGauges[index].vtable_rva,
                                        kHudGauges[index].type_name);
        g_gauge_sides[index] = found ? kHudGauges[index].side : 0;
        if (found) ++gauges_found;
    }
    g_corners_supported = corners_ok;

    bool hooked = functions_ok && patches_ok;
    hooked = hooked &&
        hooks::Address(reinterpret_cast<void*>(g_base + kViewRefreshRva),
                       reinterpret_cast<void*>(&edf5mp_uw_stub_view_refresh),
                       reinterpret_cast<void**>(&g_tramp_view_refresh),
                       "ultrawide scene view refresh", false);
    hooked = hooked &&
        hooks::Address(reinterpret_cast<void*>(g_base + kSetViewportRva),
                       reinterpret_cast<void*>(&edf5mp_uw_stub_set_viewport),
                       reinterpret_cast<void**>(&g_tramp_set_viewport),
                       "ultrawide viewport setter", false);
    if (hooked && corners_ok) {
        corners_ok =
            hooks::Address(reinterpret_cast<void*>(g_base + kOrthoRva),
                           reinterpret_cast<void*>(&edf5mp_uw_stub_ortho),
                           reinterpret_cast<void**>(&g_tramp_ortho),
                           "ultrawide UI ortho builder", false) &&
            hooks::Address(reinterpret_cast<void*>(g_base + kPerspectiveRva),
                           reinterpret_cast<void*>(&edf5mp_uw_stub_perspective),
                           reinterpret_cast<void**>(&g_tramp_perspective),
                           "ultrawide UI perspective builder", false);
        g_corners_supported = corners_ok;
    }
    // Last: the scene update switches the picture, so it only runs once the
    // other hooks are in place.
    hooked = hooked &&
        hooks::Address(reinterpret_cast<void*>(g_base + kSceneUpdateRva),
                       reinterpret_cast<void*>(&edf5mp_uw_stub_scene_update),
                       reinterpret_cast<void**>(&g_tramp_scene_update),
                       "ultrawide scene update", false);
    g_installed.store(hooked, std::memory_order_release);
    EDF5_CAPTURE_EVENT(hooked ? capture::Level::Info : capture::Level::Warning,
                       "more_players", "ultrawide_installed",
                       capture::Fields()
                           .Bool("installed", hooked)
                           .Bool("functions_signature", functions_ok)
                           .Bool("patch_signature", patches_ok)
                           .Bool("hud_corners_supported", g_corners_supported)
                           .Bool("hud_corners_enabled",
                                 config.ultrawide_hud_corners)
                           .UInt("hud_gauges_found", gauges_found)
                           .UInt("hotkey_vk", config.ultrawide_hotkey_vk));
    return hooked;
}

void Toggle() {
    const bool enabled = !g_enabled.load(std::memory_order_acquire);
    g_enabled.store(enabled, std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "ultrawide_toggled",
                       capture::Fields()
                           .Bool("enabled", enabled)
                           .Bool("installed",
                                 g_installed.load(std::memory_order_acquire)));
}

bool Enabled() { return g_enabled.load(std::memory_order_acquire); }

void SetMissionActive(bool active) {
    if (!active) {
        g_mission_since.store(0, std::memory_order_release);
        return;
    }
    uint64_t expected = 0;
    g_mission_since.compare_exchange_strong(expected, GetTickCount64(),
                                            std::memory_order_acq_rel);
}

bool SelfTest(std::string& report) {
    // Stub: pass-through with an edited argument, then a direct return.
    g_test_target = reinterpret_cast<uint64_t>(&SelfTestTarget);
    using StubFn = uint64_t(__fastcall*)(uint64_t, uint64_t, uint64_t,
                                         uint64_t, uint64_t);
    const auto stub = reinterpret_cast<StubFn>(&edf5mp_uw_stub_self_test);
    const uint64_t passed = stub(1, 2, 3, 4, 5);
    const uint64_t returned = stub(9, 0, 0, 0, 7);
    const bool stub_ok = passed == 1 + 3 * 10 + 300 + 4000 + 50000 &&
                         returned == 4242 + 7;

    const Layout wide{2560, 1080, 0, 320, 1920, 1080};
    const Layout plain{1920, 1080, 0, 0, 1920, 1080};
    const Layout tall{1920, 1200, 60, 0, 1920, 1080};
    int32_t rect[6] = {0, 0, 1920, 1080, 0, 0};
    const bool widen_ok = WidenRect(rect, wide) && rect[2] == 2560 &&
        rect[3] == 1080 && !WidenRect(rect, wide) && RestoreRect(rect, wide) &&
        rect[2] == 1920;
    int32_t small[4] = {100, 50, 600, 400};
    int32_t plain_rect[4] = {0, 0, 1920, 1080};
    int32_t tall_rect[4] = {0, 0, 1920, 1080};
    const bool widen_guard_ok = !WidenRect(small, wide) &&
        !WidenRect(plain_rect, plain) && !WidenRect(tall_rect, tall);
    int32_t shifted[4] = {320, 0, 2560, 1080};
    int32_t too_wide[4] = {0, 0, 3413, 1080};
    int32_t ui[4] = {320, 0, 1920, 1080};
    int32_t embedded[4] = {420, 100, 600, 400};
    const bool viewport_ok = FixViewport(shifted, wide) && shifted[0] == 0 &&
        shifted[2] == 2560 && FixViewport(too_wide, wide) &&
        too_wide[2] == 2560 && !FixViewport(ui, wide) &&
        !FixViewport(embedded, wide) && !FixViewport(shifted, plain);

    // Ortho 1920x1080 centred: x' = x / 960. After the adjustment x' =
    // 0.75 * x / 960 (+ 0.25 for a right-side gauge).
    float ortho[16] = {1.0f / 960.0f, 0, 0, 0, 0, 1.0f / 540.0f, 0, 0,
                       0, 0, 1, 0, 0, 0, 0, 1};
    float right[16];
    std::memcpy(right, ortho, sizeof(ortho));
    AdjustUiProjection(ortho, wide, 0);
    AdjustUiProjection(right, wide, 1);
    auto close_to = [](float a, float b) { return std::fabs(a - b) < 1e-6f; };
    const bool projection_ok = close_to(ortho[0], 0.75f / 960.0f) &&
        close_to(ortho[12], 0.0f) && close_to(right[12], 0.25f) &&
        close_to(right[5], 1.0f / 540.0f);
    float untouched[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    AdjustUiProjection(untouched, plain, 1);
    const bool plain_ok =
        close_to(untouched[0], 1.0f) && close_to(untouched[12], 0.0f);

    // Composite projection patch: same length, loads the screen height then
    // width, ends on a 5-byte nop.
    const auto patch = CompositeProjectionPatch(kUltrawideCompositeProjectionRva);
    int32_t height_disp = 0;
    int32_t width_disp = 0;
    std::memcpy(&height_disp, patch.data() + 2, sizeof(height_disp));
    std::memcpy(&width_disp, patch.data() + 16, sizeof(width_disp));
    const bool patch_ok = patch[0] == 0x8b && patch[1] == 0x05 &&
        kUltrawideCompositeProjectionRva + 6 +
                static_cast<uintptr_t>(static_cast<int64_t>(height_disp)) ==
            kScreenHeightRva &&
        patch[14] == 0x8b &&
        kUltrawideCompositeProjectionRva + 14 + 6 +
                static_cast<uintptr_t>(static_cast<int64_t>(width_disp)) ==
            kScreenWidthRva &&
        patch[28] == 0x0f && patch[32] == 0x00;

    const bool ok = stub_ok && widen_ok && widen_guard_ok && viewport_ok &&
                    projection_ok && plain_ok && patch_ok;
    report = ok ? "ultrawide stub, rect, viewport, projection and patch "
                  "checks passed"
                : std::string("ultrawide self-test failed: stub=") +
                      (stub_ok ? "1" : "0") + " widen=" +
                      (widen_ok && widen_guard_ok ? "1" : "0") +
                      " viewport=" + (viewport_ok ? "1" : "0") +
                      " projection=" +
                      (projection_ok && plain_ok ? "1" : "0") +
                      " patch=" + (patch_ok ? "1" : "0");
    return ok;
}

}  // namespace ultrawide
