#!/usr/bin/env bash
# Requires bash, GNU timeout and the official emqtt_bench binary on Linux.
set -euo pipefail

: "${BROKER_HOST:?Set BROKER_HOST to your EMQX hostname or IP}"
MODE=${MODE:-pub}
PORT=${PORT:-1883}
CLIENTS=${CLIENTS:-8}
QOS=${QOS:-2}
INFLIGHT=${INFLIGHT:-1}
PAYLOAD_BYTES=${PAYLOAD_BYTES:-256}
INTERVAL_MS=${INTERVAL_MS:-0}
DURATION_SECONDS=${DURATION_SECONDS:-60}
MQTT_VERSION=${MQTT_VERSION:-5}
TOPIC_PREFIX=${TOPIC_PREFIX:-maya-bench}
TLS=${TLS:-false}
BENCH_BIN=${BENCH_BIN:-emqtt_bench}

check_number() {
    local name=$1 value=$2 minimum=$3 maximum=$4
    [[ $value =~ ^[0-9]+$ && ${#value} -le 9 ]] || { printf '%s must be an integer\n' "$name" >&2; exit 2; }
    (( 10#$value >= minimum && 10#$value <= maximum )) || { printf '%s is out of range\n' "$name" >&2; exit 2; }
}
check_number PORT "$PORT" 1 65535
check_number CLIENTS "$CLIENTS" 1 60000
check_number QOS "$QOS" 0 2
check_number INFLIGHT "$INFLIGHT" 1 65535
check_number PAYLOAD_BYTES "$PAYLOAD_BYTES" 1 10485760
check_number INTERVAL_MS "$INTERVAL_MS" 0 3600000
check_number DURATION_SECONDS "$DURATION_SECONDS" 1 86400
[[ $MODE == pub || $MODE == sub ]] || { echo 'MODE must be pub or sub' >&2; exit 2; }
[[ $MQTT_VERSION == 4 || $MQTT_VERSION == 5 ]] || { echo 'MQTT_VERSION must be 4 or 5' >&2; exit 2; }
[[ $TLS == true || $TLS == false ]] || { echo 'TLS must be true or false' >&2; exit 2; }
[[ -n $TOPIC_PREFIX && $TOPIC_PREFIX != *['#+%']* ]] || { echo 'Use a literal TOPIC_PREFIX without wildcards/substitutions' >&2; exit 2; }
[[ ${1:-} == '' || ( $# == 1 && $1 == --run ) ]] || { echo 'Usage: emqtt-bench.sh [--run]' >&2; exit 2; }

args=("$MODE" -h "$BROKER_HOST" -p "$PORT" -V "$MQTT_VERSION" -c "$CLIENTS" -q "$QOS"
    --prefix "maya-$MODE-$$-$RANDOM" --log_to console)
if [[ $MODE == pub ]]; then
    args+=(-t "$TOPIC_PREFIX/%i" -s "$PAYLOAD_BYTES" -I "$INTERVAL_MS" -F "$INFLIGHT" -w true)
else
    args+=(-t "$TOPIC_PREFIX/#")
fi
[[ $TLS == false ]] || args+=(--ssl)
if [[ -n ${CA_CERT_FILE:-} ]]; then
    [[ $TLS == true && -f $CA_CERT_FILE ]] || { echo 'CA_CERT_FILE requires TLS=true and an existing file' >&2; exit 2; }
    args+=(--cacertfile "$CA_CERT_FILE")
fi
if [[ -n ${EMQTT_BENCH_USERNAME:-} ]]; then args+=(-u "$EMQTT_BENCH_USERNAME"); fi
printf '%s -> %s:%s; clients=%s; MQTT=%s; QoS=%s; TLS=%s; duration=%ss\n' "$MODE" "$BROKER_HOST" "$PORT" "$CLIENTS" "$MQTT_VERSION" "$QOS" "$TLS" "$DURATION_SECONDS"
printf 'Observe incoming message rate, drops and queues in EMQX. Each sub client receives the whole topic prefix.\n'
if [[ ${1:-} != --run ]]; then echo 'Dry run only. Add --run to connect and start the benchmark.'; exit 0; fi
command -v "$BENCH_BIN" >/dev/null
command -v timeout >/dev/null
if [[ -n ${EMQTT_BENCH_USERNAME:-} ]]; then
    if [[ ! ${EMQTT_BENCH_PASSWORD+x} ]]; then read -r -s -p 'MQTT password: ' EMQTT_BENCH_PASSWORD; printf '\n'; fi
    args+=(-P "$EMQTT_BENCH_PASSWORD")
fi
set +e
timeout --signal=TERM --kill-after=5s "${DURATION_SECONDS}s" "$BENCH_BIN" "${args[@]}"
bench_status=$?
set -e
if [[ $bench_status == 124 ]]; then echo 'Benchmark duration reached.'; exit 0; fi
exit "$bench_status"
