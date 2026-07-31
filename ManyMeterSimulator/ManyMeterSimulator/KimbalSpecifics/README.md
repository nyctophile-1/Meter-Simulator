# KimbalSpecifics — vendored HES definitions

Copies of generated protobuf definitions from the HES codebase. **Do not hand-edit**: they are
generated, and they are the authority for what goes on the wire.

| File | Source | Stack |
|------|--------|-------|
|  `Wirepas/WirepasProto.cs` | `vayu-common/CrystalHES.Common/Helpers/WirepasProto.cs` | protobuf-net |
|  `Kmesh/KMeshCommon.cs` | `vayu-common/CrystalHES.Common/KMeshHelpers/KMeshCommon.cs` | Google.Protobuf |
|  `Kmesh/KMeshMeter.cs` | `vayu-common/CrystalHES.Common/KMeshHelpers/KMeshMeter.cs` | Google.Protobuf |

Copied rather than referenced so the simulator does not depend on the HES build. The only change
from the originals is the namespace (`ManyMeterSimulator.KimbalSpecifics`).

Note the two variants use *different* protobuf stacks — Wirepas is protobuf-net (`[ProtoContract]`),
Kmesh is Google.Protobuf (`IMessage`). Both packages are therefore referenced.

`KMeshGateway.cs` and `KMeshDiagnostics.cs` are deliberately NOT vendored — the pull path does not
reference them. Add them only if a future variant needs them.

Wire formats derived from these are documented in `virtual_nics.md` §14.
