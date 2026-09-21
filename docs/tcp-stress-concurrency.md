# TCP stress concurrency and connection lifetime

Testing > TCP stress defaults to concurrency 0 (unlimited), no meter limit, whole-pass waves, no wave pause and prepared-memory budget 0 (unlimited). Positive concurrency and memory values remain optional operator controls; the former 1024/16384 caps are removed. No application concurrency admission ceiling is applied when concurrency is 0. Actual parallel sockets depend on the fleet, payload generation, scheduler, network and host resources. CPU-only preparation uses available processors; it opens no sockets.

The TCP stress and historical TCP UI default to a 15-second maximum wait for HES closure after sending. MAYA does not send FIN first in this mode. HES's current framed listener closes after about 10 seconds waiting for another frame. A peer can close earlier. Set wait to 0 for immediate send/close; this is also the backward-compatible request default for old persisted plans/checkpoints and normal scheduled traffic.

A wait timeout closes locally without replaying the written payload. Stop cancels outstanding connect, write and peer-close waits. TCP stress accounts already-written payloads on cancellation; historical checkpoint accounting preserves its existing partial-cancellation semantics. Closure does not acknowledge database persistence.

The connection panel counts all TCP push sockets in the MAYA process, including background traffic. It separates connecting/active/peak sockets, connections opened per second, local payload writes per second, connection failures, peer EOF, local wait expiry and close/read errors. Active sockets exclude disposed sockets still retained in kernel closing states; counters and peaks reset on service restart.

Historical replay retains chronological IP/LS timestamp boundaries. Unlimited concurrency removes the old per-timestamp dispatch chunk ceiling and the 2048-completion checkpoint restriction. Existing saved runs retain explicit positive concurrency settings. Set concurrency to 0 when starting the new unrestricted comparison. MQTT publisher pools remain separate transport controls.

No OS limits, VM capacity, traffic start or HES settings are changed by this release. A healthy deployment is not a throughput benchmark.
