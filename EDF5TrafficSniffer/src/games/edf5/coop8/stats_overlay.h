#pragma once

#include <string>

// On-screen combat statistics of the local character (total damage, DPS,
// kills, stage time), toggled by a hotkey during a mission. Drawn with Dear
// ImGui from a DXGI IDXGISwapChain::Present hook that is installed the first
// time the overlay is shown, so nothing touches the renderer until then. Any
// failure leaves the overlay disabled without affecting the rest of the mod.
namespace stats_overlay {

// Hotkey thread: flips visibility; installs the Present hook on first show.
void Toggle();
bool Visible();
// Hotkey thread: installs the Present hook if it is not installed yet (used
// for the title-screen mod watermark). Never retries after a failure.
void EnsureInstalled();

// Releases the renderer resources. The hooks stay installed until MinHook is
// shut down and pass straight through afterwards.
void Shutdown();

// Renders frames into a hidden WARP swap chain (no Present hook, no game) to
// prove shader compilation, font loading and drawing.
bool SelfTest(std::string& report);

}  // namespace stats_overlay
