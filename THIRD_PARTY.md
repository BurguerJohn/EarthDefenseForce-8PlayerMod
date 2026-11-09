# Third-party dependencies

Dependencies are installed locally and excluded from this repository.

| Component | Pinned version / revision | Purpose |
| --- | --- | --- |
| EDFModLoader | 1.0.10 / `c686e8fb48121e0a6b3f6b7f42d6df0d5249678b` | Plugin API and separately installed runtime loader |
| MinHook | 1.3.4 / `c3fcafdc10146beb5919319d0683e44e3c30d537` | Native hooks compiled into the plugin |
| Dear ImGui | 1.91.8 / `dbb5eeaadffb6a3ba6a60de1290312e5802dba5a` | Stats overlay drawing (core and DirectX 11 backend) compiled into the plugin |
| Steamworks SDK headers | Compatible legacy interface declarations | Steam API types |
| Zig | 0.14.1 | Windows x64 C/C++ compiler |
| Capstone | Python package for disassembly helpers | Offline disassembly |

Upstreams used by this workspace:

- EDFModLoader: https://github.com/BlueAmulet/EDFModLoader
- MinHook: https://github.com/TsudaKageyu/minhook
- Dear ImGui: https://github.com/ocornut/imgui (MIT)

Read each dependency's license and notices before redistribution. Preserve
applicable MinHook, Dear ImGui and disassembler notices when packaging compiled
code.
Steamworks headers and game binaries are not licensed by this project and are
not included in the public source tree. Static audits read local game files.
