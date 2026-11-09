#pragma once

#include <string>

namespace ultrawide {

// Screens wider than 16:9: the 3D scene fills the whole screen (vertical FOV
// kept, more of the world visible at the sides) and the HUD gauges move to
// the screen corners (UltrawideHudCorners), instead of EDF5's centred 16:9
// picture with black side bars. Installs register-safe hooks on the game's
// scene update, scene view refresh, viewport setter and matrix builders when
// config.ultrawide is on and every signature matches; the code patches are
// applied per frame from the scene update, only while the screen is wider
// than 16:9 with the game's keep-aspect option on, so 16:9 and 16:10 screens
// stay untouched.
bool Install();

// Hotkey: switches between the ultrawide picture and the original one.
// Takes effect on the next frame, including the scene render targets.
void Toggle();

// The picture is only used during a mission: it starts a moment after the
// mission's UI exists (UI built while it is on would scale itself to the
// wider viewport) and ends with the mission, so the title, menus, room and
// result screens keep the original picture. Polled by the hotkey thread.
void SetMissionActive(bool active);

// The user setting (Toggle flips it); the picture changes only on wide
// screens.
bool Enabled();

// Pure checks of the stub machinery, the rect rules, the projection
// adjustment and the composite patch bytes; no game image is touched.
bool SelfTest(std::string& report);

}  // namespace ultrawide
