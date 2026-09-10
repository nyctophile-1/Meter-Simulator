# Deterministic Behaviour Model — Mathematical Specification

## 1. Goal and notation

This document specifies the first deterministic model family used by the meter brain.
It must satisfy all of these properties:

- the same model artifact, node id, and UTC timestamp produce the same result;
- cumulative energy evaluates in constant time, independent of meter age or profile
  retention;
- profile interval energy is the difference of two cumulative-energy evaluations;
- pull, scheduled profile capture, and push are projections of the same snapshot;
- no pseudorandom interval noise contributes to an integrated register.

Notation:

| Symbol | Meaning |
|---|---|
| `n` | Stable meter node id/index |
| `t` | UTC time measured in seconds from the model epoch |
| `t0` | Model epoch in UTC seconds |
| `x = t - t0` | Seconds since the model epoch |
| `P(t)` | Energy-bearing active power in kW |
| `E(t)` | Cumulative import energy in kWh |
| `h(...)` | Stable deterministic hash returning a uniform number in `[0, 1)` |
| `T_day` | 86,400 seconds |
| `T_week` | 604,800 seconds |

The artifact fixes `t0`, timezone, unit/scaler conventions, master seed, and all global
parameters. Internally calculations use UTC; a configured project timezone is used only
to select local calendar/tariff regimes deterministically.

The model, the meter clock, and HES all operate in UTC. This matches the real system:
meters and HES exchange UTC time, and any local offset (e.g. IST, +330 minutes) is applied
only at the presentation layer (UI). The harmonic curve's phase is therefore fixed in UTC,
not local wall-clock time, and is not expected to track DST transitions in any project
timezone — this is the intended behaviour, not a limitation.

## 2. Stable node-derived coefficients

All meter variation starts from a cryptographic or well-defined non-cryptographic
stable hash, for example `HMAC-SHA256(masterSeed, canonicalInput)`. It is never sourced
from process-local `Random`.

```text
u(n, label) = UInt64(HMAC-SHA256(seed, modelVersion | n | label)[0..7]) / 2^64
signed(n, label) = 2 * u(n, label) - 1
```

For each harmonic `k`:

```text
A_k(n)   = A_k_global * (1 + variationA_k * signed(n, "amplitude:" + k))
phi_k(n) = 2π * u(n, "phase:" + k)
```

For a stable load-scale factor:

```text
S(n) = clamp(1 + sigma_scale * signed(n, "load-scale"), S_min, S_max)
```

All labels are part of the model format. Changing a label, hash algorithm, or coefficient
derivation is a new model version because it changes historic replay.

## 3. Energy-bearing active-power curve

The initial model is a bounded harmonic curve. It is intentionally small: a typical
artifact can use 3–8 daily terms and 1–3 weekly terms.

```text
P_raw(n, x) = P_base * S(n)
            + Σ(i = 1..D) A_daily_i(n) * sin(2π * i * x / T_day + phi_daily_i(n))
            + Σ(j = 1..W) A_weekly_j(n) * sin(2π * j * x / T_week + phi_weekly_j(n))
```

`P_raw` is in kW. Coefficients are trained/calibrated or configured so the normal curve
does not approach invalid negative import power. The simple deployable v1 form uses a
strict positive floor:

```text
P_import(n, x) = P_floor + P_raw(n, x)
```

with the required constraint:

```text
P_floor > Σ abs(A_daily_i_max) + Σ abs(A_weekly_j_max) - minimum(P_base * S(n))
```

This keeps the curve analytic and avoids a `max(0, P_raw)` kink. If a future model needs
net generation, it represents import and export as separate non-negative analytic curves:

```text
P_import(n, x) = P_import_floor + harmonic_import(n, x)
P_export(n, x) = P_export_floor + harmonic_export(n, x)
```

Net active power is then `P_import - P_export`, while the two cumulative registers remain
separately monotonic.

## 4. Antiderivative and cumulative energy

For a term `A * sin(omega*x + phi)`, the antiderivative is:

```text
Integral(A * sin(omega*x + phi)) dx = -A/omega * cos(omega*x + phi)
```

Define:

```text
F_import(n, x) = (P_import_floor + P_base * S(n)) * x
               - Σ(i = 1..D) A_daily_i(n) / omega_daily_i
                   * cos(omega_daily_i * x + phi_daily_i(n))
               - Σ(j = 1..W) A_weekly_j(n) / omega_weekly_j
                   * cos(omega_weekly_j * x + phi_weekly_j(n))

omega_daily_i  = 2πi / T_day
omega_weekly_j = 2πj / T_week
```

Since power is in kW and `x` is seconds, convert seconds to hours:

```text
E_import(n, t) = E_import_at_epoch(n) + (F_import(n, x) - F_import(n, 0)) / 3600
```

`E_import_at_epoch(n)` is a deterministic, node-derived starting register value or an
explicit sparse override. `E_export` uses the same construction with the export curve.

This is O(D + W), where `D + W` is a small artifact constant. It is not O(number of
15-minute intervals since t0).

### Interval/profile energy

For a profile interval `[a, b]`:

```text
DeltaE_import(n, a, b) = E_import(n, b) - E_import(n, a)
AverageImportPower      = DeltaE_import(n, a, b) / ((b - a) / 3600)
```

These values are used for block-load profile rows. The same interval boundary convention
must be used by both capture and subsequent selective-access reads. The initial convention
is a half-open interval `[a, b)` and the timestamp stored in a row is `b` (interval end).

## 5. Calendar/tariff and seasonal regimes

The simplest artifact has one curve valid for all time. A richer artifact may contain a
small finite schedule of regimes (weekday/weekend, season, tariff period, or project
operating shift). Each regime contains its own analytic coefficients.

The implementation must not iterate through every historic day. It calculates the
bounded number of full repeating periods plus at most a bounded number of boundary
partials:

```text
E(t) = full_period_count * integral_over_one_period
     + integral_over_partial_period
     + integral_over_at_most_N_regime_boundaries
```

`N` is bounded by the shared artifact's finite regime rules, not by elapsed meter age.
For v1, prefer periodic daily/weekly harmonic terms because their antiderivative is
direct and avoids calendar boundary complexity.

## 6. Instantaneous display variation

Real meters exhibit small readings that should look less perfectly smooth. This is
allowed only outside integrated quantities.

For a display bucket `q = floor(x / bucketSeconds)`:

```text
noise(n, signal, q) = 2 * u(n, signal | q) - 1
P_display(n, t) = P_import(n, x) - P_export(n, x)
                + displayAmplitude * noise(n, "display-power", q)
```

Likewise, for voltage:

```text
V_display_phase(n, t) = V_nominal
                      + V_daily_amplitude * sin(2πx/T_day + phi_voltage(n))
                      + V_noise_amplitude * noise(n, "voltage:" + phase, q)
```

This noise is repeatable because `q` is derived from timestamp. It must not be included
in `P_import`, `P_export`, `E_import`, `E_export`, or any profile interval energy.

When exposing both values internally, use explicit names:

```text
EnergyBearingPowerKw
DisplayedInstantaneousPowerKw
```

If a meter template exposes only one active-power register, the behaviour profile decides
which projection it represents. The Inspector must disclose that choice. To preserve
physical coherence for display values, derive displayed current from the chosen displayed
power, voltage, and power factor.

## 7. Electrical relationships

### Single phase

For displayed RMS voltage `V`, current `I`, and power factor `pf`:

```text
P_display_kw = V * I * pf / 1000
I = 1000 * abs(P_display_kw) / max(V * max(abs(pf), pf_min), denominator_min)
```

### Three phase

For a balanced approximation using line-to-line voltage `V_ll`:

```text
P_display_kw = sqrt(3) * V_ll * I * pf / 1000
I = 1000 * abs(P_display_kw) / (sqrt(3) * max(V_ll * max(abs(pf), pf_min), denominator_min))
```

For a more realistic unbalanced model, derive stable phase allocation weights:

```text
w_a + w_b + w_c = 1
w_phase(n) = normalized positive node-derived weights
P_phase = w_phase * P_display
```

Then calculate each phase current using its phase voltage and power factor. CT/PT ratios,
scalers, and template data types are applied only at the DLMS projection boundary; the
model itself works in physical units.

## 8. Availability, outages, and alarms

Availability is a separate deterministic state function, never an afterthought in the
push pipeline:

```text
availability(n, t) = ApplySparseOverrides(
                       ApplyScenarios(
                         BaselineAvailability(model, n, t)))
```

The initial baseline may be always available. A deterministic outage generator can later
produce finite intervals from node id and a calendar period:

> TODO (before this generator ships): as specified below, an outage window is derived
> independently per period and can bleed across a period boundary (`startOffset + duration`
> exceeding `outagePeriodSeconds`). A timestamp evaluated in the next period will not see
> the still-running outage from the previous one. Fix by either clamping
> `duration <= outagePeriodSeconds - startOffset`, or by also checking a bounded number of
> preceding periods (`ceil(durationMax / outagePeriodSeconds)`) for an overlapping window.
> Not a v1 concern since v1's baseline is always-available.

```text
period = floor((t - t0) / outagePeriodSeconds)
candidate = u(n, "outage-candidate:" + period)
startOffset = outagePeriodSeconds * u(n, "outage-start:" + period)
duration = durationMin + (durationMax - durationMin) * u(n, "outage-duration:" + period)
```

An outage exists in that period only if `candidate < outageProbability`. A timestamp is
inside the outage when it lies in `[periodStart + startOffset, start + duration)`. The
same calculation identifies both power-fail and restoration boundaries without storing a
per-meter schedule. Scenarios and sparse overrides take precedence over this baseline.

Rules while `PoweredOff` are profile-policy controlled but must be uniform across all
paths: normal pull does not respond, normal scheduled push is skipped, and normal
profile capture is omitted/gapped/quality-marked according to the selected policy.

## 9. Sparse overrides and stateful exceptions

The deterministic baseline does not eliminate all storage. A sparse per-meter overlay is
required for facts that cannot be recovered from `(n, t)` alone:

- HES-written values and relay commands;
- manual operator overrides;
- acknowledged alarms;
- security invocation counters, where protocol policy requires persistence;
- externally injected events; and
- retained non-regenerable history.

An override has an effective interval and precedence:

```text
sparse meter override > explicit scenario > baseline model
```

For an energy register changed by a valid HES operation, store a compact change-point:

```text
E_effective(n, t) = E_model(n, t) + sum(delta_i where changeTime_i <= t)
```

Production storage should compact old change-points into a new base offset so evaluation
remains bounded. It must not grow an unbounded per-meter list.

## 10. Snapshot and parity

At a timestamp `t`, resolve exactly once:

```text
snapshot(n, t) = {
  availability,
  EnergyBearingPowerKw,
  DisplayedInstantaneousPowerKw,
  E_import, E_export,
  V/I/pf/frequency,
  relay and alarm state,
  interval profile row(s),
  event transitions
}
```

The same resolved snapshot is used to:

- answer a DLMS register/profile read;
- persist or regenerate a profile row;
- create a scheduled profile push;
- decide that a powered-off meter sends nothing; and
- render the Meter Inspector.

No component is permitted to independently reimplement a value calculation.

## 11. Numerical and reproducibility rules

- Use `decimal` or fixed-point integer units for cumulative meter-facing energy values;
  do not serialize binary floating-point accumulation into registers.
- Trigonometric evaluation may use `double`, but convert/round once at the final defined
  physical-unit/scaler boundary using a documented rounding mode.
- Define all timestamps as UTC instants. Calendar/tariff rules must specify an IANA
  timezone and a deterministic DST ambiguity policy.
- Use canonical serialization for every hash input: invariant decimal/index formatting,
  UTF-8 labels, explicit separators, and artifact version.
- Model artifacts are immutable. Altering parameters, hash derivation, epoch, or rounding
  mode creates a new version.
- Property tests must verify monotonic import/export registers, interval-energy identity,
  repeatability after restart, bounded evaluation time at far-future timestamps, and zero
  influence of display noise on integrated registers.
