# EDF 4.1 research index

This directory separates EDF 4.1 measurements from EDF5 knowledge. An EDF5 RVA
is never evidence for EDF 4.1.

- [Baseline and reuse](01-BASELINE-AND-REUSE.md): fingerprints, Steam ABI and sharing boundaries.
- [Passive sniffer](02-SNIFFER.md): implementation, configuration and tests.
- [Initial Coop8 map](03-COOP8-INITIAL-MAP.md): static evidence, Steam entry points and patch gates.
- [First live capture](04-FIRST-LIVE-CAPTURE-AND-HOOKS.md): initial session, gaps and 0.6.56 hooks.
- [Four-player online mission](05-FOUR-PLAYER-ONLINE-MISSION.md): 0.6.57 hotfix, P2P/auth, indices and synchronized objects.
- [Room-bot laboratory](06-ROOM-BOT-LAB.md): invisible rows, host-template projection, P5 crashes and native roster/UI patches.

The sniffer passed a real client mission with three peers, observing callbacks,
authentication and three P2P channels. Coop8 fillers exist only in the local
Steam view; the real Steam lobby remains four.

Version 0.6.60 visually validated host plus three fillers. Version 0.6.61 reached
P5 but crashed in the four-slot consumer at 0x3BE316. Version 0.6.62 rejected P5
before callbacks. Version 0.6.63 expanded net::Users and exposed the four-record
net::SessionController vector, crashing at 0xCB070.

The original 0.6.64 expansion changed eight roster operands. The current source
also contains two room-UI protection sites: ten sites in total, four native
visible member windows, and intentionally headless overflow members. It does not
provide an eight-row UI. The updated offline suite verifies these markers.
Real expanded mission, Ready, spawn, gameplay replication and result behavior
remain unsupported; offline success does not establish a live P5-P8 mission.
