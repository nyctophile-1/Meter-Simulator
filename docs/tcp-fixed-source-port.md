# TCP push source endpoint

`Push:TcpSourcePort` defaults to `40000`. Each meter binds that port on its own assigned IP for every new TCP push connection. Stress, historical and ordinary pushes share `TcpPushSender`; the existing per-meter gate still covers connect, write and the optional wait for HES to close. Historical bad-communication skips and rate settings are unchanged.

Setting the port to `0` restores an OS-assigned source port per connection. This application option is read at startup; apply a setting change through the existing configuration/deployment process. Existing server appsettings files do not need editing to get the new default.

On Linux, fixed-port sockets use `SO_REUSEADDR` before binding to permit local endpoint rebinding after close. This does not bypass TCP state or guarantee immediate reconnection to a peer retaining the previous connection. Bind/connect failures remain failures and are included in the connection-failure counter. No automatic ephemeral-port fallback, abortive close, kernel tuning or new retry loop is introduced. The existing explicit default-source bring-up fallback remains governed by `RequireMeterSourceIp`; use its normal `true` setting for attributable meter tests.

The repeated loopback-IP test fixtures explicitly select port `0`, because their different simulated meters share one test IP. Dedicated fixed-port socket tests check repeated peer-closed IPv4/IPv6 connections, distinct IPs sharing a port, occupied-port failure and recovery, and invalid settings.

## Deployment comparison

Before restarting MAYA, save the current live profile/rate, run checkpoint and matched MAYA/HES metrics. Deploy the exact reviewed commit with the existing staged-overlay SOP. Preserve source IPv6 prefix ownership and all saved settings/data. The restart interrupts live sockets; do not interpret their teardown or a changed offered rate as the benefit of fixed ports.

After the same workload is resumed, verify that every observed push source port is `40000`, that each meter keeps its IP, and that HES still closes the held connections. Compare at least two complete fleet passes at a fixed offered rate: local writes, HES accepted/handler rates, queue depth/age, AWS tracking availability and drop deltas, bind/connect errors, and peer-close/wait-expiry counts. Track failed reconnects after MAYA-initiated close separately from clean HES-initiated close.

Stable TCP endpoints are a testable way to reduce flow-identity churn, not proof that AWS reuses a tracking allocation. Retained state from the previous deployment can affect early samples. Record it as a transition window. The optional untracked AWS-networking experiment is separate and must not be changed during this comparison.
