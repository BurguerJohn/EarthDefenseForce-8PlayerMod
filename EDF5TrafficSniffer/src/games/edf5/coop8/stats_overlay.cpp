#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "stats_overlay.h"

#include "hook_manager.h"
#include "logger.h"
#include "mod_info.h"
#include "more_players.h"

// Third-party and DirectX headers are not held to the first-party warning set.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <dxgi1_2.h>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#pragma clang diagnostic pop

#include <algorithm>
#include <atomic>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>

// imgui_impl_dx11 compiles its two shaders with D3DCompile. Resolve it from
// d3dcompiler_47.dll on first use instead of importing that DLL, so the plugin
// still loads where it is missing (the overlay then simply stays off).
extern "C" HRESULT WINAPI D3DCompile(
    const void* data, SIZE_T data_size, const char* filename,
    const D3D_SHADER_MACRO* defines, ID3DInclude* include,
    const char* entrypoint, const char* target, UINT sflags, UINT eflags,
    ID3DBlob** shader, ID3DBlob** error_messages) {
    static const pD3DCompile compile = [] {
        HMODULE module = LoadLibraryW(L"d3dcompiler_47.dll");
        return module ? reinterpret_cast<pD3DCompile>(reinterpret_cast<void*>(
                            GetProcAddress(module, "D3DCompile")))
                      : nullptr;
    }();
    if (!compile) return E_NOTIMPL;
    return compile(data, data_size, filename, defines, include, entrypoint,
                   target, sflags, eflags, shader, error_messages);
}

namespace stats_overlay {
namespace {

// IDXGISwapChain vtable: IUnknown 0-2, IDXGIObject 3-6, GetDevice 7.
constexpr size_t kSwapChainPresentSlot = 8;
constexpr size_t kSwapChainResizeBuffersSlot = 13;
// IDXGISwapChain1 (DXGI 1.2) continues after slot 17: GetDesc1 18,
// GetFullscreenDesc 19, GetHwnd 20, GetCoreWindow 21, Present1 22.
constexpr size_t kSwapChain1Present1Slot = 22;

using PresentFn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Fn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGISwapChain1*, UINT, UINT, const DXGI_PRESENT_PARAMETERS*);
using ResizeBuffersFn = HRESULT(STDMETHODCALLTYPE*)(
    IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);

enum class HookState : int { none = 0, installed = 1, failed = 2 };

PresentFn g_present = nullptr;
Present1Fn g_present1 = nullptr;
ResizeBuffersFn g_resize_buffers = nullptr;
// Set while the original Present/Present1 runs, so a DXGI implementation
// that forwards one to the other does not draw the overlay twice.
thread_local bool g_in_original_present = false;
// First call seen by each hook (0 = Present, 1 = Present1), for the log.
std::atomic<bool> g_present_observed[2] = {};
std::atomic<bool> g_first_frame_logged{false};
std::atomic<bool> g_render_target_logged{false};
// Self-test only: draw through the intermediate texture even when the back
// buffer accepts a render target view.
bool g_force_copy_mode = false;
std::atomic<int> g_hook_state{static_cast<int>(HookState::none)};
std::atomic<bool> g_visible{false};
// The first Toggle replaces the configured start state.
std::atomic<bool> g_toggled{false};
std::atomic<unsigned> g_hidden_reason_logs{0};
std::atomic<bool> g_stats_frame_logged{false};
std::atomic<bool> g_shutdown{false};

// Renderer state, touched only under g_render_lock (Present, ResizeBuffers
// and the self-test).
struct RenderState {
    IDXGISwapChain* swap = nullptr;  // identity only, not referenced
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    ID3D11RenderTargetView* target = nullptr;
    // EDF5's back buffer is only copied into (no render-target binding), so
    // the overlay draws on this copy of it and copies the result back.
    ID3D11Texture2D* scratch = nullptr;
    bool via_copy = false;
    // No view could be created for the current back buffer; retried after
    // ResizeBuffers only.
    bool target_failed = false;
    bool imgui_ready = false;
    // Binding failed for good (not a D3D11 swap chain, backend init failed).
    bool failed = false;
    float font_pixels = 0.0f;
    uint64_t last_frame_tick = 0;
    uint64_t frames = 0;
};

SRWLOCK g_render_lock = SRWLOCK_INIT;
RenderState g_render;

template <typename T>
void SafeRelease(T*& object) {
    if (object) {
        object->Release();
        object = nullptr;
    }
}

// Diagnostics only (the event is compiled out of Users builds).
[[maybe_unused]] const char* HookStateName(int state) {
    switch (static_cast<HookState>(state)) {
    case HookState::none: return "none";
    case HookState::installed: return "installed";
    case HookState::failed: return "failed";
    }
    return "unknown";
}

// 1234567 -> "1,234,567"
std::string Thousands(double value) {
    const long long rounded = value > 0.0 && std::isfinite(value)
        ? std::llround(value) : 0;
    const std::string digits = std::to_string(rounded);
    std::string out;
    for (size_t index = 0; index < digits.size(); ++index) {
        if (index && (digits.size() - index) % 3 == 0) out += ',';
        out += digits[index];
    }
    return out;
}

// 950 -> "950 m", 12345 -> "12.35 km"
std::string Distance(double metres) {
    char text[32] = {};
    if (!(metres > 0.0) || !std::isfinite(metres)) metres = 0.0;
    if (metres < 1000.0) {
        std::snprintf(text, sizeof(text), "%.0f m", metres);
    } else {
        std::snprintf(text, sizeof(text), "%.2f km", metres / 1000.0);
    }
    return text;
}

// m:ss, h:mm:ss from one hour.
std::string Clock(uint64_t seconds) {
    char text[32] = {};
    const unsigned long long hours = seconds / 3600;
    const unsigned long long minutes = (seconds / 60) % 60;
    const unsigned long long rest = seconds % 60;
    if (hours) {
        std::snprintf(text, sizeof(text), "%llu:%02llu:%02llu", hours,
                      minutes, rest);
    } else {
        std::snprintf(text, sizeof(text), "%llu:%02llu", minutes, rest);
    }
    return text;
}

void ReleaseRenderStateLocked() {
    if (g_render.imgui_ready) {
        ImGui_ImplDX11_Shutdown();
        ImGui::DestroyContext();
    }
    SafeRelease(g_render.target);
    SafeRelease(g_render.scratch);
    SafeRelease(g_render.context);
    SafeRelease(g_render.device);
    const bool failed = g_render.failed;
    g_render = {};
    g_render.failed = failed;
}

bool BindSwapChainLocked(IDXGISwapChain* swap) {
    if (g_render.imgui_ready && g_render.swap == swap) return true;
    ReleaseRenderStateLocked();
    ID3D11Device* device = nullptr;
    if (FAILED(swap->GetDevice(__uuidof(ID3D11Device),
                               reinterpret_cast<void**>(&device))) ||
        !device) {
        g_render.failed = true;
        EDF5_CAPTURE_EVENT("more_players", "stats_overlay_bind_failed",
                           capture::Fields().String("reason", "not_d3d11"));
        return false;
    }
    ID3D11DeviceContext* context = nullptr;
    device->GetImmediateContext(&context);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.WindowBorderSize = 0.0f;
    if (!context || !ImGui_ImplDX11_Init(device, context)) {
        ImGui::DestroyContext();
        SafeRelease(context);
        SafeRelease(device);
        g_render.failed = true;
        EDF5_CAPTURE_EVENT("more_players", "stats_overlay_bind_failed",
                           capture::Fields().String("reason", "backend_init"));
        return false;
    }
    g_render.swap = swap;
    g_render.device = device;
    g_render.context = context;
    g_render.imgui_ready = true;
    EDF5_CAPTURE_EVENT("more_players", "stats_overlay_bound",
                       capture::Fields().Bool("pointer_logged", false));
    return true;
}

// Bold UI font from the Windows font folder; the atlas owns the buffer.
bool AddWindowsFont(ImGuiIO& io, float pixels) {
    wchar_t folder[MAX_PATH] = {};
    const UINT length = GetWindowsDirectoryW(folder, MAX_PATH);
    if (!length || length >= MAX_PATH) return false;
    for (const wchar_t* name : {L"\\Fonts\\segoeuib.ttf", L"\\Fonts\\arialbd.ttf",
                                L"\\Fonts\\segoeui.ttf"}) {
        const std::wstring path = std::wstring(folder) + name;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                  nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) continue;
        LARGE_INTEGER size{};
        void* data = nullptr;
        DWORD read = 0;
        const bool ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 &&
            size.QuadPart < 64 * 1024 * 1024 &&
            (data = IM_ALLOC(static_cast<size_t>(size.QuadPart))) != nullptr &&
            ReadFile(file, data, static_cast<DWORD>(size.QuadPart), &read,
                     nullptr) &&
            read == static_cast<DWORD>(size.QuadPart);
        CloseHandle(file);
        if (!ok) {
            if (data) IM_FREE(data);
            continue;
        }
        if (io.Fonts->AddFontFromMemoryTTF(data, static_cast<int>(read),
                                           pixels)) {
            return true;
        }
    }
    return false;
}

void EnsureFontLocked(float pixels) {
    if (std::fabs(pixels - g_render.font_pixels) < 0.5f) return;
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    if (!AddWindowsFont(io, pixels)) {
        ImFontConfig config;
        config.SizePixels = pixels;
        io.Fonts->AddFontDefault(&config);
    }
    // The backend rebuilds the font texture on the next NewFrame.
    ImGui_ImplDX11_InvalidateDeviceObjects();
    g_render.font_pixels = pixels;
}

DXGI_FORMAT ViewFormat(DXGI_FORMAT format) {
    switch (format) {
    case DXGI_FORMAT_R8G8B8A8_TYPELESS: return DXGI_FORMAT_R8G8B8A8_UNORM;
    case DXGI_FORMAT_B8G8R8A8_TYPELESS: return DXGI_FORMAT_B8G8R8A8_UNORM;
    case DXGI_FORMAT_R10G10B10A2_TYPELESS:
        return DXGI_FORMAT_R10G10B10A2_UNORM;
    case DXGI_FORMAT_R16G16B16A16_TYPELESS:
        return DXGI_FORMAT_R16G16B16A16_FLOAT;
    default: return format;
    }
}

HRESULT CreateTargetView(ID3D11Texture2D* texture,
                         const D3D11_TEXTURE2D_DESC& desc) {
    D3D11_RENDER_TARGET_VIEW_DESC view{};
    view.Format = ViewFormat(desc.Format);
    view.ViewDimension = desc.SampleDesc.Count > 1
        ? D3D11_RTV_DIMENSION_TEXTURE2DMS : D3D11_RTV_DIMENSION_TEXTURE2D;
    return g_render.device->CreateRenderTargetView(texture, &view,
                                                   &g_render.target);
}

// Returns the current back buffer (referenced) with a view to draw on: the
// back buffer itself when it is bindable, otherwise an intermediate texture
// of the same description (see RenderFrameLocked).
ID3D11Texture2D* EnsureRenderTargetLocked(IDXGISwapChain* swap, UINT& width,
                                          UINT& height) {
    ID3D11Texture2D* back_buffer = nullptr;
    if (FAILED(swap->GetBuffer(0, __uuidof(ID3D11Texture2D),
                               reinterpret_cast<void**>(&back_buffer))) ||
        !back_buffer) {
        return nullptr;
    }
    D3D11_TEXTURE2D_DESC desc{};
    back_buffer->GetDesc(&desc);
    width = desc.Width;
    height = desc.Height;
    if (!g_render.target && !g_render.target_failed) {
        HRESULT direct = E_FAIL;
        const bool bindable =
            (desc.BindFlags & D3D11_BIND_RENDER_TARGET) != 0;
        if (bindable && !g_force_copy_mode) {
            direct = CreateTargetView(back_buffer, desc);
        }
        HRESULT copy = S_FALSE;
        if (FAILED(direct)) {
            g_render.target = nullptr;
            D3D11_TEXTURE2D_DESC scratch = desc;
            scratch.Usage = D3D11_USAGE_DEFAULT;
            scratch.BindFlags = D3D11_BIND_RENDER_TARGET;
            scratch.CPUAccessFlags = 0;
            scratch.MiscFlags = 0;
            copy = g_render.device->CreateTexture2D(&scratch, nullptr,
                                                    &g_render.scratch);
            if (SUCCEEDED(copy)) copy = CreateTargetView(g_render.scratch, desc);
            if (FAILED(copy)) {
                SafeRelease(g_render.scratch);
                g_render.target = nullptr;
            }
        }
        g_render.via_copy = g_render.target && g_render.scratch;
        g_render.target_failed = !g_render.target;
        if (!g_render_target_logged.exchange(true, std::memory_order_acq_rel)) {
            EDF5_CAPTURE_EVENT(
                "more_players",
                g_render.target ? "stats_overlay_render_target"
                                : "stats_overlay_render_target_failed",
                capture::Fields()
                    .String("mode", !g_render.target ? "none"
                                    : g_render.via_copy ? "copy" : "direct")
                    .UInt("format", desc.Format)
                    .UInt("bind_flags", desc.BindFlags)
                    .UInt("misc_flags", desc.MiscFlags)
                    .UInt("usage", desc.Usage)
                    .UInt("samples", desc.SampleDesc.Count)
                    .UInt("array_size", desc.ArraySize)
                    .Int("direct_hresult", direct)
                    .Int("copy_hresult", copy));
        }
    }
    if (!g_render.target) {
        back_buffer->Release();
        return nullptr;
    }
    return back_buffer;
}

void Row(const char* label, const std::string& value,
         const ImVec4& color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f)) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextColored(ImVec4(0.72f, 0.76f, 0.80f, 1.0f), "%s", label);
    ImGui::TableSetColumnIndex(1);
    const float width = ImGui::CalcTextSize(value.c_str()).x;
    const float available = ImGui::GetContentRegionAvail().x;
    if (available > width) {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + available - width);
    }
    ImGui::TextColored(color, "%s", value.c_str());
}

void DrawStats(const more_players::CombatStats& stats, float display_width,
               float display_height) {
    const auto& config = capture::GetConfig();
    const float anchor_x =
        static_cast<float>(config.stats_overlay_x_percent) / 100.0f;
    const float anchor_y =
        static_cast<float>(config.stats_overlay_y_percent) / 100.0f;
    const float font = g_render.font_pixels;
    ImGui::SetNextWindowPos(
        ImVec2(display_width * anchor_x, display_height * anchor_y),
        ImGuiCond_Always, ImVec2(anchor_x, anchor_y));
    ImGui::SetNextWindowBgAlpha(0.55f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(font * 0.55f, font * 0.4f));
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding,
                        ImVec2(font * 0.35f, font * 0.08f));
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin("##edf5mp_stats", nullptr, kFlags) &&
        ImGui::BeginTable("##edf5mp_stats_rows", 2,
                          ImGuiTableFlags_SizingFixedFit)) {
        const double seconds =
            std::max(1.0, static_cast<double>(stats.active_ms) / 1000.0);
        for (uint32_t index = 0; index < stats.count; ++index) {
            const auto& player = stats.players[index];
            if (stats.count > 1) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.35f, 1.0f), "P%d",
                                   player.participant_index + 1);
            }
            Row("Damage", Thousands(player.damage));
            Row("DPS", Thousands(player.damage / seconds));
            Row("DPS (10s)", Thousands(player.recent_dps));
            Row("Kills", stats.kills_supported
                             ? std::to_string(player.kills)
                             : std::string("-"));
            Row("Distance", Distance(player.distance));
            // Orange once any friendly fire happened.
            const ImVec4 friendly_color = player.friendly_damage > 0.0
                ? ImVec4(1.0f, 0.6f, 0.25f, 1.0f)
                : ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
            Row("Friendly fire", Thousands(player.friendly_damage),
                friendly_color);
            Row("Friendly kills", std::to_string(player.friendly_kills),
                friendly_color);
        }
        if (stats.enemies_alive >= 0) {
            Row("Enemies", std::to_string(stats.enemies_alive));
        }
        Row("Time", Clock(stats.active_ms / 1000));
        ImGui::EndTable();
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
}

std::string WatermarkText() {
    std::string text = std::string(mod_info::kName) + " v" + mod_info::kVersion;
#if EDF5_COMPILE_DIAGNOSTICS
    text += " Diagnostics";
#endif
    return text;
}

// Mod name and version in the top-right corner, with a drop shadow.
void DrawWatermark(float display_width) {
    const std::string text = WatermarkText();
    ImFont* font = ImGui::GetFont();
    const float size = ImGui::GetFontSize() * 0.85f;
    const ImVec2 extent = font->CalcTextSizeA(size, FLT_MAX, 0.0f, text.c_str());
    const float margin = size * 0.6f;
    const ImVec2 position(display_width - extent.x - margin, margin);
    ImDrawList* draw = ImGui::GetForegroundDrawList();
    draw->AddText(font, size, ImVec2(position.x + 2.0f, position.y + 2.0f),
                  IM_COL32(0, 0, 0, 200), text.c_str());
    draw->AddText(font, size, position, IM_COL32(255, 255, 255, 235),
                  text.c_str());
}

// Draws one frame into the swap chain's back buffer, preserving the game's
// output-merger bindings (the backend restores everything else it changes).
// stats is null when only the watermark is shown.
bool RenderFrameLocked(IDXGISwapChain* swap,
                       const more_players::CombatStats* stats,
                       bool watermark) {
    if (g_render.failed || !BindSwapChainLocked(swap)) return false;
    UINT width = 0;
    UINT height = 0;
    ID3D11Texture2D* back_buffer =
        EnsureRenderTargetLocked(swap, width, height);
    if (!back_buffer) return false;
    if (!width || !height) {
        back_buffer->Release();
        return false;
    }
    const float scale = static_cast<float>(
        capture::GetConfig().stats_overlay_scale_percent) / 100.0f;
    EnsureFontLocked(std::clamp(
        std::round(static_cast<float>(height) / 45.0f * scale), 11.0f,
        96.0f));
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2(static_cast<float>(width),
                            static_cast<float>(height));
    const uint64_t now = GetTickCount64();
    io.DeltaTime = g_render.last_frame_tick && now > g_render.last_frame_tick
        ? static_cast<float>(now - g_render.last_frame_tick) / 1000.0f
        : 1.0f / 60.0f;
    g_render.last_frame_tick = now;
    ImGui_ImplDX11_NewFrame();
    ImGui::NewFrame();
    if (stats) DrawStats(*stats, io.DisplaySize.x, io.DisplaySize.y);
    if (watermark) DrawWatermark(io.DisplaySize.x);
    ImGui::Render();
    ID3D11RenderTargetView* saved_targets
        [D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT] = {};
    ID3D11DepthStencilView* saved_depth = nullptr;
    g_render.context->OMGetRenderTargets(
        D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, saved_targets, &saved_depth);
    if (g_render.via_copy) {
        g_render.context->CopyResource(g_render.scratch, back_buffer);
    }
    g_render.context->OMSetRenderTargets(1, &g_render.target, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_render.context->OMSetRenderTargets(
        D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, saved_targets, saved_depth);
    if (g_render.via_copy) {
        g_render.context->CopyResource(back_buffer, g_render.scratch);
    }
    back_buffer->Release();
    for (auto*& target : saved_targets) SafeRelease(target);
    SafeRelease(saved_depth);
    ++g_render.frames;
    if (!g_first_frame_logged.exchange(true, std::memory_order_acq_rel)) {
        EDF5_CAPTURE_EVENT("more_players", "stats_overlay_first_frame",
                           capture::Fields()
                               .UInt("width", width)
                               .UInt("height", height)
                               .UInt("font_pixels", static_cast<uint64_t>(
                                                        g_render.font_pixels))
                               .Bool("stats", stats != nullptr)
                               .Bool("watermark", watermark)
                               .Bool("via_copy", g_render.via_copy));
    }
    return true;
}

bool WindowInThisProcess(HWND window) {
    DWORD process_id = 0;
    return window && GetWindowThreadProcessId(window, &process_id) &&
        process_id == GetCurrentProcessId();
}

// Shared by Present and Present1, before the original call.
void RenderBeforePresent(IDXGISwapChain* swap, UINT flags, size_t source) {
    if (g_in_original_present || !swap) return;
    if (!g_present_observed[source].exchange(true,
                                              std::memory_order_acq_rel)) {
        DXGI_SWAP_CHAIN_DESC desc{};
        const bool described = SUCCEEDED(swap->GetDesc(&desc));
        EDF5_CAPTURE_EVENT(
            "more_players", "stats_overlay_present_observed",
            capture::Fields()
                .String("method", source ? "Present1" : "Present")
                .Bool("described", described)
                .Bool("window_in_process",
                      described && WindowInThisProcess(desc.OutputWindow))
                .Bool("window_is_hotkey_window",
                      described && desc.OutputWindow ==
                          static_cast<HWND>(more_players::GameWindow()))
                .UInt("width", described ? desc.BufferDesc.Width : 0)
                .UInt("height", described ? desc.BufferDesc.Height : 0)
                .Bool("windowed", described && desc.Windowed));
    }
    if ((flags & DXGI_PRESENT_TEST) ||
        g_shutdown.load(std::memory_order_acquire)) {
        return;
    }
    const bool watermark = capture::GetConfig().mod_watermark_enabled &&
        more_players::TitleScreenActive();
    more_players::CombatStats stats;
    const bool show_stats = g_visible.load(std::memory_order_acquire) &&
        more_players::GetCombatStats(stats) && stats.in_mission && stats.count;
    if (g_visible.load(std::memory_order_acquire) && !show_stats &&
        g_hidden_reason_logs.load(std::memory_order_acquire) < 4 &&
        stats.measurement_active) {
        // Visible during a measurement but not drawn: record why (a few
        // times per session).
        static uint64_t last_log = 0;
        const uint64_t now = GetTickCount64();
        if (now - last_log > 5000) {
            last_log = now;
            g_hidden_reason_logs.fetch_add(1, std::memory_order_acq_rel);
            EDF5_CAPTURE_EVENT(
                "more_players", "stats_overlay_stats_hidden",
                capture::Fields()
                    .Bool("in_mission", stats.in_mission)
                    .Bool("measurement_ended", stats.measurement_ended)
                    .UInt("last_update_age_ms", stats.last_update_age_ms)
                    .UInt("local_participants", stats.count));
        }
    }
    if (!watermark && !show_stats) return;
    DXGI_SWAP_CHAIN_DESC desc{};
    if (FAILED(swap->GetDesc(&desc)) ||
        !WindowInThisProcess(desc.OutputWindow)) {
        return;
    }
    // Never wait on the renderer thread.
    if (TryAcquireSRWLockExclusive(&g_render_lock)) {
        const bool drawn =
            RenderFrameLocked(swap, show_stats ? &stats : nullptr, watermark);
        ReleaseSRWLockExclusive(&g_render_lock);
        if (drawn && show_stats &&
            !g_stats_frame_logged.exchange(true, std::memory_order_acq_rel)) {
            EDF5_CAPTURE_EVENT("more_players", "stats_overlay_stats_drawn",
                               capture::Fields()
                                   .UInt("local_participants", stats.count)
                                   .UInt("active_ms", stats.active_ms));
        }
    }
}

HRESULT STDMETHODCALLTYPE PresentHook(IDXGISwapChain* swap, UINT sync_interval,
                                      UINT flags) {
    RenderBeforePresent(swap, flags, 0);
    const bool outer = !g_in_original_present;
    g_in_original_present = true;
    const HRESULT result = g_present(swap, sync_interval, flags);
    if (outer) g_in_original_present = false;
    return result;
}

HRESULT STDMETHODCALLTYPE Present1Hook(
    IDXGISwapChain1* swap, UINT sync_interval, UINT flags,
    const DXGI_PRESENT_PARAMETERS* parameters) {
    RenderBeforePresent(swap, flags, 1);
    const bool outer = !g_in_original_present;
    g_in_original_present = true;
    const HRESULT result = g_present1(swap, sync_interval, flags, parameters);
    if (outer) g_in_original_present = false;
    return result;
}

HRESULT STDMETHODCALLTYPE ResizeBuffersHook(IDXGISwapChain* swap, UINT count,
                                            UINT width, UINT height,
                                            DXGI_FORMAT format, UINT flags) {
    AcquireSRWLockExclusive(&g_render_lock);
    // The back buffers cannot be resized while a view references them.
    if (g_render.swap == swap) {
        SafeRelease(g_render.target);
        SafeRelease(g_render.scratch);
        g_render.via_copy = false;
        g_render.target_failed = false;
    }
    const HRESULT result =
        g_resize_buffers(swap, count, width, height, format, flags);
    ReleaseSRWLockExclusive(&g_render_lock);
    return result;
}

LRESULT CALLBACK ProbeWindowProc(HWND window, UINT message, WPARAM wparam,
                                 LPARAM lparam) {
    return DefWindowProcW(window, message, wparam, lparam);
}

constexpr wchar_t kProbeWindowClass[] = L"EDF5MPStatsOverlayProbe";

HWND CreateProbeWindow(UINT width, UINT height) {
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = &ProbeWindowProc;
    window_class.hInstance = GetModuleHandleW(nullptr);
    window_class.lpszClassName = kProbeWindowClass;
    RegisterClassExW(&window_class);  // fails harmlessly if registered
    return CreateWindowExW(0, kProbeWindowClass, L"", WS_OVERLAPPEDWINDOW, 0,
                           0, static_cast<int>(width),
                           static_cast<int>(height), nullptr, nullptr,
                           window_class.hInstance, nullptr);
}

// Creates a windowed D3D11 swap chain on a hidden window: hardware first,
// then WARP unless warp_only.
bool CreateProbeSwapChain(HWND window, UINT width, UINT height, bool warp_only,
                          IDXGISwapChain** swap, ID3D11Device** device,
                          ID3D11DeviceContext** context) {
    HMODULE d3d11 = GetModuleHandleW(L"d3d11.dll");
    if (!d3d11) d3d11 = LoadLibraryW(L"d3d11.dll");
    const auto create = d3d11
        ? reinterpret_cast<PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN>(
              reinterpret_cast<void*>(
                  GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain")))
        : nullptr;
    if (!create || !window) return false;
    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferDesc.Width = width;
    desc.BufferDesc.Height = height;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferDesc.RefreshRate.Numerator = 60;
    desc.BufferDesc.RefreshRate.Denominator = 1;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 1;
    desc.OutputWindow = window;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    for (const D3D_DRIVER_TYPE type :
         {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP}) {
        if (warp_only && type != D3D_DRIVER_TYPE_WARP) continue;
        D3D_FEATURE_LEVEL level{};
        if (SUCCEEDED(create(nullptr, type, nullptr, 0, nullptr, 0,
                             D3D11_SDK_VERSION, &desc, swap, device, &level,
                             context))) {
            return true;
        }
    }
    return false;
}

// The swap chain methods live in dxgi.dll and are shared by every swap chain
// of the process, so a throwaway swap chain exposes the game's Present.
bool InstallPresentHooks() {
    HWND window = CreateProbeWindow(8, 8);
    IDXGISwapChain* swap = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    const bool created = CreateProbeSwapChain(window, 8, 8, false, &swap,
                                              &device, &context);
    void* present = nullptr;
    void* present1 = nullptr;
    void* resize_buffers = nullptr;
    if (created) {
        void** vtable = *reinterpret_cast<void***>(swap);
        present = vtable[kSwapChainPresentSlot];
        resize_buffers = vtable[kSwapChainResizeBuffersSlot];
        IDXGISwapChain1* swap1 = nullptr;
        if (SUCCEEDED(swap->QueryInterface(__uuidof(IDXGISwapChain1),
                                           reinterpret_cast<void**>(&swap1))) &&
            swap1) {
            present1 = (*reinterpret_cast<void***>(swap1))
                [kSwapChain1Present1Slot];
            swap1->Release();
        }
    }
    SafeRelease(context);
    SafeRelease(device);
    SafeRelease(swap);
    if (window) DestroyWindow(window);
    const bool resize_hooked = present && resize_buffers &&
        hooks::Address(resize_buffers,
                       reinterpret_cast<void*>(&ResizeBuffersHook),
                       reinterpret_cast<void**>(&g_resize_buffers),
                       "IDXGISwapChain::ResizeBuffers stats overlay", false);
    const bool present_hooked = resize_hooked &&
        hooks::Address(present, reinterpret_cast<void*>(&PresentHook),
                       reinterpret_cast<void**>(&g_present),
                       "IDXGISwapChain::Present stats overlay", false);
    // Optional: games that present through DXGI 1.2 call Present1 instead.
    const bool present1_hooked = present_hooked && present1 &&
        present1 != present &&
        hooks::Address(present1, reinterpret_cast<void*>(&Present1Hook),
                       reinterpret_cast<void**>(&g_present1),
                       "IDXGISwapChain1::Present1 stats overlay", false);
    EDF5_CAPTURE_EVENT("more_players", "stats_overlay_hooks_installed",
                       capture::Fields()
                           .Bool("probe_swap_chain", created)
                           .Bool("resize_buffers_hooked", resize_hooked)
                           .Bool("present_hooked", present_hooked)
                           .Bool("present1_found", present1 != nullptr)
                           .Bool("present1_hooked", present1_hooked));
    return present_hooked;
}

}  // namespace

void EnsureInstalled() {
    if (g_shutdown.load(std::memory_order_acquire) ||
        g_hook_state.load(std::memory_order_acquire) !=
            static_cast<int>(HookState::none)) {
        return;
    }
    const bool installed = InstallPresentHooks();
    g_hook_state.store(static_cast<int>(installed ? HookState::installed
                                                  : HookState::failed),
                       std::memory_order_release);
    if (installed && !g_toggled.load(std::memory_order_acquire)) {
        g_visible.store(capture::GetConfig().stats_overlay_start_visible,
                        std::memory_order_release);
    }
}

void Toggle() {
    if (g_shutdown.load(std::memory_order_acquire)) return;
    // Marked first, so a first install here does not apply the start state.
    g_toggled.store(true, std::memory_order_release);
    EnsureInstalled();
    const bool show = !g_visible.load(std::memory_order_acquire);
    const int state = g_hook_state.load(std::memory_order_acquire);
    g_visible.store(show && state == static_cast<int>(HookState::installed),
                    std::memory_order_release);
    EDF5_CAPTURE_EVENT("more_players", "stats_overlay_toggled",
                       capture::Fields()
                           .Bool("visible",
                                 g_visible.load(std::memory_order_acquire))
                           .String("hook_state", HookStateName(state)));
}

bool Visible() { return g_visible.load(std::memory_order_acquire); }

// Called while the plugin stops (game exit). Drawing stops at once; the D3D
// objects stay referenced until the process ends, so the game's device is
// never released from here during teardown.
void Shutdown() {
    g_shutdown.store(true, std::memory_order_release);
    g_visible.store(false, std::memory_order_release);
}

bool SelfTest(std::string& report) {
    const bool formats_ok = Distance(0.0) == "0 m" &&
        Distance(950.4) == "950 m" && Distance(12345.0) == "12.35 km" &&
        Thousands(0.0) == "0" &&
        Thousands(999.4) == "999" && Thousands(1000.0) == "1,000" &&
        Thousands(1234567.0) == "1,234,567" && Clock(5) == "0:05" &&
        Clock(754) == "12:34" && Clock(3725) == "1:02:05";
    if (!formats_ok) {
        report = "stats overlay number formatting failed";
        return false;
    }
    if (g_hook_state.load(std::memory_order_acquire) !=
        static_cast<int>(HookState::none)) {
        report = "stats overlay self-test needs an uninstalled overlay";
        return false;
    }
    HWND window = CreateProbeWindow(640, 360);
    IDXGISwapChain* swap = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    if (!CreateProbeSwapChain(window, 640, 360, true, &swap, &device,
                              &context)) {
        if (window) DestroyWindow(window);
        report = "stats overlay render skipped (no WARP device)";
        return true;
    }
    more_players::CombatStats stats;
    stats.in_mission = true;
    stats.kills_supported = true;
    stats.active_ms = 754000;
    stats.count = 2;
    stats.players[0] = {0, 1234567.0, 2048.0, 321};
    stats.players[1] = {5, 845210.0, 0.0, 12};
    AcquireSRWLockExclusive(&g_render_lock);
    // ImGui hides a new auto-resized window for its first frame while it
    // measures it, so the drawing is checked on the second frame.
    const bool first = RenderFrameLocked(swap, &stats, true);
    const float first_font = g_render.font_pixels;
    const bool first_direct = first && !g_render.via_copy;
    // A resize drops the view; the next frame recreates it and the font, and
    // this time draws through the intermediate copy like EDF5 needs.
    SafeRelease(g_render.target);
    SafeRelease(g_render.scratch);
    g_render.via_copy = false;
    g_render.target_failed = false;
    const bool resized =
        SUCCEEDED(swap->ResizeBuffers(1, 1280, 720, DXGI_FORMAT_UNKNOWN, 0));
    g_force_copy_mode = true;
    const bool second = resized && RenderFrameLocked(swap, &stats, true);
    g_force_copy_mode = false;
    const bool second_copy = second && g_render.via_copy;
    const bool watermark_text_ok = WatermarkText().rfind(
        std::string(mod_info::kName) + " v" + mod_info::kVersion, 0) == 0;
    const ImDrawData* draw_data = second ? ImGui::GetDrawData() : nullptr;
    const int vertices = draw_data ? draw_data->TotalVtxCount : 0;
    const float second_font = g_render.font_pixels;
    const uint64_t frames = g_render.frames;
    ReleaseRenderStateLocked();
    g_render.failed = false;
    ReleaseSRWLockExclusive(&g_render_lock);
    SafeRelease(context);
    SafeRelease(device);
    SafeRelease(swap);
    DestroyWindow(window);
    const bool ok = first_direct && second_copy && vertices > 0 &&
        frames == 2 &&
        watermark_text_ok &&
        first_font >= 11.0f && second_font > first_font;
    char text[160] = {};
    std::snprintf(text, sizeof(text),
                  "stats overlay WARP frames=%llu vertices=%d font_px=%.0f->%.0f",
                  static_cast<unsigned long long>(frames), vertices,
                  static_cast<double>(first_font),
                  static_cast<double>(second_font));
    report = ok ? text : std::string("stats overlay render failed: ") + text;
    return ok;
}

}  // namespace stats_overlay
