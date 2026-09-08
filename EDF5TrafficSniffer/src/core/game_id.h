#pragma once

namespace game {

enum class Id {
    Unknown = 0,
    Edf41,
    Edf5,
    Edf6,
};

inline constexpr const char* Name(Id id) {
    switch (id) {
    case Id::Edf41: return "EDF 4.1";
    case Id::Edf5: return "EDF5";
    case Id::Edf6: return "EDF6";
    case Id::Unknown: break;
    }
    return "Unknown";
}

}  // namespace game
