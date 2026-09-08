# EDF 4.1 Coop8

The first laboratory is implemented in `room_bots.cpp`: F8/F7 synthetic room
fillers with private identities, entry/exit callbacks and a local channel-2
handshake. This is an EDF 4.1 implementation; it does not call EDF5 patches or RVAs.

Version 0.6.61 proved P5 reaches the four-pointer `net::Users` table and crashes
at `EDF41.exe+0x3BE316`. Version 0.6.63 expanded it and exposed a second
four-record table at `net::SessionController+0xD0`, crashing at `+0xCB070`.
Version 0.6.64 expands both vectors in one eight-operand transaction, keeping
allocation, capacity and logical size consistent. Any signature mismatch retains
`NativeSafeLimit=4`. Only the local list expands: Ready, spawn, results and the
real Steam room do not. Mission launch above four remains unsupported.

Configuration: `[EDF41.Coop8]` and `[EDF41.Coop8.Settings]`. The laboratory is
Diagnostics-only pending in-game validation.

See the [research index](../../../../docs/technical-research/edf41/README.md).
