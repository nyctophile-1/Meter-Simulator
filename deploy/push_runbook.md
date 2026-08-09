# On-demand Push — deployment & end-to-end test runbook

Companion to `deploy_checklist.md`. Covers ONLY what on-demand push adds on top of the
already-working pull deployment. Phases are gated: do not advance until the gate passes.

Push reverses the traffic direction. Pull is **inbound** (HES → meter IP, one wildcard listener).
Push is **outbound** (meter IP → head-end), with the socket's LOCAL endpoint bound to the meter's
own IPv6 so the receiver correlates the meter by source IP. Everything new below exists because
that direction is new.

---

## Phase 0 — Pre-flight (do before touching the host)

### 0.1 Template choice — HARD BLOCKER

The push payload ("buffer") is the PushSetup `push_object_list` baked into the template at load
time. Two of the four shipped templates define it as EMPTY:

| Template | Instant push (`0.0.25.9.0.255`) | Alert push (`0.4.25.9.0.255`) | Usable |
|---|---|---|---|
| `SA1231166HP_values.xml` | empty | empty | ❌ |
| `SA1231166HP_values_bill.xml` | empty | empty | ❌ |
| `SZ0000014HP_Only_Push.xml` | populated | empty | ✅ instant only |
| `Values_SZ0000014HP.xml` | populated | populated | ✅ both |

**A push batch MUST use `Values_SZ0000014HP.xml` or `SZ0000014HP_Only_Push.xml`.**
Empty-ObjectList PushSetups are now skipped and logged as a warning rather than sending an
empty frame, so a wrong template shows up as "nothing to send" in the log, not a silent success.

Instant-push buffer contents: meter id (`0.0.96.1.2.255`), push setup, clock (`0.0.1.0.0.255`),
per-phase voltages (`1.0.32/52/72.7.0.255`) and currents (`1.0.31/51/71.7.0.255`).

### 0.2 Memory ceiling — sizes the whole test

`Values_SZ0000014HP.xml` is **4 MB of XML per meter**. Pull is lazy (only meters the HES actually
polls get a session); **push materializes every meter in the batch at once**. That is a different
memory profile entirely.

Consequence: **batch size is bounded by RAM, not by the address space.** Start at 10 meters,
measure, extrapolate. Do NOT click Send Push on a large batch until Phase 3.5 gives you a
per-meter RSS number.

### 0.3 Config

`deploy/appsettings.Production.json` now carries:

```json
"Push": { "DefaultPort": 4059, "UseCiphering": false, "DefaultDestination": "", "MaxConcurrency": 256 }
```

`UseCiphering: false` = plaintext DataNotification, readable in Wireshark. Keep it false until
Phase 4 passes; the encrypted path additionally needs the local Gurux CryptoNotifier null-guard patch.

---

## Phase 1 — Host prep

`host-prep.sh` already installs everything push needs on the host side. Re-run it (idempotent) and
confirm the meter prefix is locally owned — this is what makes the source bind succeed:

```bash
sudo bash host-prep.sh
```

**Gate 1** — all three must hold:

```bash
# a) kernel owns the meter prefix (prints "local")
ip -6 route get 2406:da1a:1c29:500:bc96::1

# b) route unit is active
systemctl is-active maya-meter-route.service

# c) prefix in config matches the routed prefix EXACTLY
grep AddressPrefix /opt/maya-sim/app/appsettings.Production.json
```

If (a) does not say `local`, push binds will fail and the app falls back to the host's default
source address (logged as a warning) — meaning the receiver cannot tell meters apart.

### 1.1 AWS source/destination check — new for push

Pull never sends from a non-primary address, so this was never exercised. Push does. EC2 drops
egress whose source is not recognised as belonging to the ENI. The delegated prefix *is* assigned
to the ENI, so this normally passes — but verify at Phase 3, and if frames leave the host
(tcpdump) yet never arrive, this is the first suspect:

```bash
aws ec2 modify-network-interface-attribute --network-interface-id <eni-id> --no-source-dest-check
```

Also confirm the security group allows **egress** to the head-end on the push port, and the
head-end allows **ingress** from `2406:da1a:1c29:500:bc96::/80`.

---

## Phase 2 — Deploy

```bash
# from the dev box
pwsh deploy/build.ps1
scp maya-sim.tar.gz <host>:/tmp/
# on the host
sudo bash deploy.sh /tmp/maya-sim.tar.gz
```

**Gate 2**: `systemctl is-active maya-sim` is `active`, and the startup log shows the listener
bound with the **real** prefix (not the `fd00:` dev default):

```bash
journalctl -u maya-sim -n 40 --no-pager | grep -i "prefix\|bound"
```

Rollback if needed: `deploy.sh` snapshots the previous release to `/opt/maya-sim/app.prev`.

---

## Phase 3 — Local end-to-end (proves push WITHOUT depending on the head-end)

This is the highest-value step: it isolates "does source-IP binding work and are the frames
well-formed" from "does the head-end accept them". Run entirely on the simulator host.

**Terminal A — receiver that prints the source address of each connection:**

```bash
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 9999)); s.listen(128)
print("listening on [::]:9999")
while True:
    c, a = s.accept()
    d = c.recv(65535)
    print(f"from {a[0]}  {len(d)} bytes  {d[:48].hex()}")
    c.close()
EOF
```

**Terminal B — capture for Wireshark:**

```bash
sudo tcpdump -i any -nn 'tcp port 9999' -vv -w /tmp/push.pcap
```

**Then, in the dashboard** (`http://<host>/`):
1. Create a batch of **10** meters on template `Values_SZ0000014HP.xml`, NIC = 4G TCP. Start it.
2. Put the host's own global IPv6 in the **TCP push IP** box, with the test port:
   `[<host-global-ipv6>]:9999` — get it via `ip -6 addr show scope global`.
3. Click **Send Push** on that batch.

**Gate 3 — the decisive check.** Terminal A must print **10 lines with 10 DIFFERENT source
addresses**, each inside the meter prefix and matching the batch's index range:

```
from 2406:da1a:1c29:500:bc96::1   N bytes  ...
from 2406:da1a:1c29:500:bc96::2   N bytes  ...
```

- All 10 from the **same** address → the bind failed and fell back. Check `journalctl -u maya-sim | grep "could not bind"` and re-check Gate 1.
- Zero connections → check the snackbar and `journalctl -u maya-sim | grep -i push`.
- "nothing to send" in the log → wrong template (Phase 0.1).

Open `/tmp/push.pcap` in Wireshark, decode as DLMS, and confirm the DataNotification carries the
expected OBIS codes and this meter's serial.

### 3.5 Measure before scaling

With the 10-meter batch materialized:

```bash
systemctl status maya-sim | grep Memory
```

Divide by 10 → per-meter cost. Multiply by your intended batch size **before** creating it, and
compare against instance RAM (t3.micro = 1 GB + 2 GB swap). Size the instance up, or the batch
down, accordingly. This is the number that decides how far push can scale on this box.

---

## Phase 4 — Head-end end-to-end

Only after Gate 3 passes. Same 10-meter batch, but put the **real head-end address** in the push
IP box (e.g. `[2406:da1a:5f3:cf01:b537:fac6:a948:5ba4]:4059`).

Keep tcpdump running on the host, filtered to the head-end:

```bash
sudo tcpdump -i any -nn 'host 2406:da1a:5f3:cf01:b537:fac6:a948:5ba4' -vv
```

**Gate 4**, in order — this ordering is what tells you *which side* is at fault:
1. SYN leaves the host with **src = meter IP** → local side is correct.
2. SYN-ACK comes back → routing + security groups + source/dest check are all fine.
   If (1) but not (2): suspect AWS source/dest check (§1.1), SGs, or head-end firewall.
3. Head-end ingests the notification and attributes it to the right meter → **done**.

Note the simulator closes the connection immediately after writing the frames. If the head-end
expects the meter to hold the connection open or to answer a response, that is a protocol gap to
raise before scaling.

---

## Phase 5 — Scale up

Only after Gate 4. Increase in steps (10 → 100 → target), re-measuring memory at each step, and
watch:

- `MaxConcurrency` (256 in production config) caps simultaneous outbound sockets.
- Per-meter TIME_WAIT after each push: `ss -6 -tan state time-wait | wc -l`.
  `tcp_fin_timeout=15` is already set by host-prep.
- Head-end ingest rate — a whole batch firing at once is a burst the receiver may rate-limit.

---

## Known limitations (deliberate, not defects)

- **On-demand only.** No periodic push timer is wired; `PushConfig` stays null. Every push comes
  from a button click.
- **4G TCP batches only.** MQTT meters have no per-meter source IP to correlate on; the
  coordinator rejects them with a clear message.
- **Destination is not persisted.** The push-IP box is per-session UI state. Set
  `Push:DefaultDestination` in config to pre-fill it.
- **Bind failure degrades rather than fails.** If the meter address is not locally owned, push
  still sends from the host's default address and logs a warning — good for a dev box, but in
  production that warning means the receiver cannot distinguish meters. Treat it as an error.
