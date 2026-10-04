#pragma once

#include "build_config.h"
#include "game_id.h"

// Keep all runtime-facing identity and version values in one place. The
// diagnostics metadata, loader manifest and local room banner must always
// describe the same binary.
namespace mod_info {

inline constexpr char kName[] = "EDF5_MultiSlotMod";
inline constexpr char kVersion[] = "0.6.79";
inline constexpr wchar_t kChatBanner[] =
    L"*** EDF5_MultiSlotMod v0.6.79 ***";
inline constexpr wchar_t kChatInviteHintLine1[] =
    L"If you have 4 players in the room,";
inline constexpr wchar_t kChatInviteHintLine2[] =
    L"press F4 to invite more.";
#if EDF5_COMPILE_DIAGNOSTICS
inline constexpr char kBuildId[] =
    "edf5mp-0.6.79-diagnostics-win64";
inline constexpr char kBuildFlavor[] = "Diagnostics";
#else
inline constexpr char kBuildId[] = "edf5mp-0.6.79-users-win64";
inline constexpr char kBuildFlavor[] = "Users";
#endif

inline constexpr unsigned kVersionMajor = 0;
inline constexpr unsigned kVersionMinor = 6;
inline constexpr unsigned kVersionPatch = 79;
inline constexpr unsigned kVersionRevision = 0;

inline constexpr const char* NameForGame(game::Id game_id) {
    switch (game_id) {
    case game::Id::Edf41: return "EDF41_MultiSlotMod";
    case game::Id::Edf5: return kName;
    case game::Id::Edf6: return "EDF6_MultiSlotMod";
    case game::Id::Unknown: break;
    }
    return kName;
}

static_assert(kVersionMajor <= 255 && kVersionMinor <= 255 &&
              kVersionPatch <= 255 && kVersionRevision <= 255,
              "plugin version components must fit PLUG_VER");
static_assert(sizeof(kChatBanner) / sizeof(wchar_t) - 1 <= 34 &&
              sizeof(kChatInviteHintLine1) / sizeof(wchar_t) - 1 <= 34 &&
              sizeof(kChatInviteHintLine2) / sizeof(wchar_t) - 1 <= 34,
              "local room chat lines must remain within 34 characters");

}  // namespace mod_info
