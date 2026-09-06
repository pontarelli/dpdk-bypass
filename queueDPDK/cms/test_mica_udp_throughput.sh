#!/bin/bash
# test_mica_udp_throughput.sh
#
# Benchmarks MICA-UDP throughput of the "dol" server (this host, cms/build/dol)
# against the DPDK load generator "packetgenmica" running on node118
# (/home/guest/dummy-packetgen/build/packetgenmica), across the matrix:
#
#   key/value size class : tiny (8B key / 8B value)  vs  small (16B key / 32B value)
#   GET/SET mix           : 50% GET  vs  95% GET
#   Zipfian skew (theta)  : 0.8, 0.9, 0.99
#
# i.e. 2 x 2 x 3 = 12 combinations, each driven for RUN_SECONDS (default 5s).
#
# Usage:  ./test_mica_udp_throughput.sh
# Run from queueDPDK/cms on the DUT (this host). Needs:
#   - build/dol built from the current main.c (run `make local` first)
#   - build/packetgenmica built on node118 (already there)
#   - passwordless SSH to node118 (key-based auth already set up)
#   - sudo on both hosts (you will be prompted for the password once per
#     host; run this in an interactive terminal)
#
# Output: results_<timestamp>/summary.tsv plus one raw log per side.

set -uo pipefail

# ---- Config -------------------------------------------------------------
DUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PCI="0000:41:00.0"

GEN_HOST="node118"
GEN_DIR="/home/guest/dummy-packetgen"
GEN_PCI="0000:41:00.0"

RUN_SECONDS="${RUN_SECONDS:-5}"
SIZES=(tiny small)
GET_PCTS=(50 95)
ZIPFS=(0.8 0.9 0.99)

# Server and generator must agree on the size of the MICA key space: the
# server preloads exactly this many keys (0..MICA_DB_SIZE-1) at startup
# (--mica-db-size, main.c), and the generator draws its Zipfian keys from
# the same range (--mica-db-size, main_mica.c). Mismatched sizes let SETs
# target never-seen keys once the (fixed-capacity, no-eviction) table is
# full, which currently crashes the server (process_mica_udp asserts(false)
# on a failed mehcached_set).
MICA_DB_SIZE=100000

SERVER_CMD=(sudo ./build/dol -d librte_net_qdma.so -l 0 -a "$SERVER_PCI" \
            -- -P 1 -q 1 -d 1024 -a 9 -T -Q --mica-db-size "$MICA_DB_SIZE")

RESULTS_DIR="$DUT_DIR/results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
SUMMARY="$RESULTS_DIR/summary.tsv"
COMBINED_GEN_LOG="$RESULTS_DIR/generator_combined.log"
SERVER_LOG="$RESULTS_DIR/server.log"

printf 'size\tget_pct\tzipf_theta\ttx_mpps\trx_mpps\tsent\treceived\tloss_pct\n' > "$SUMMARY"

# ---- Server lifecycle -----------------------------------------------------
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Stopping MICA UDP server (pid $SERVER_PID)..."
    sudo kill -INT "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

cd "$DUT_DIR" || exit 1

echo "=== Starting MICA UDP server ==="
echo "${SERVER_CMD[*]}"
"${SERVER_CMD[@]}" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

echo -n "Waiting for server to be ready"
ready=0
for _ in $(seq 1 30); do
  if grep -q "entering main loop" "$SERVER_LOG" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo
    echo "ERROR: server exited early, see $SERVER_LOG" >&2
    exit 1
  fi
  echo -n "."
  sleep 1
done
echo
if [[ "$ready" -ne 1 ]]; then
  echo "ERROR: server did not report readiness in time, see $SERVER_LOG" >&2
  exit 1
fi
echo "Server ready (pid $SERVER_PID)."

# ---- Build one remote script covering the whole matrix -------------------
# Running the whole loop inside a single ssh session means sudo is only
# asked for once (per sudo's timestamp cache) instead of once per combo.
{
  echo "set -u"
  echo "cd '$GEN_DIR' || exit 1"
  echo "sudo -v || exit 1"
  for size in "${SIZES[@]}"; do
    for pct in "${GET_PCTS[@]}"; do
      for theta in "${ZIPFS[@]}"; do
        tag="size=${size} get_pct=${pct} zipf=${theta}"
        echo "echo '=== BEGIN ${tag} ==='"
        echo "sudo timeout --signal=INT ${RUN_SECONDS}s ./build/packetgenmica -a $GEN_PCI -- --mica-size ${size} --mica-get-pct ${pct} --mica-zipf-theta ${theta} --mica-db-size ${MICA_DB_SIZE}"
        echo "echo '=== END ${tag} ==='"
        echo "sleep 1"
      done
    done
  done
} > "$RESULTS_DIR/remote_script.sh"

# Copy the script over and run it by path (rather than piping it into
# `ssh ... 'bash -s' < script`): redirecting ssh's own stdin from a file
# means it has no terminal to allocate a pty from, so `sudo` on the other
# end can't prompt for a password even with -t. Running it by path leaves
# ssh's stdin as whatever this script's stdin is (your terminal, when you
# run this interactively), so the remote sudo prompt works normally.
REMOTE_SCRIPT_PATH="/tmp/mica_udp_test_$$.sh"
scp -q "$RESULTS_DIR/remote_script.sh" "$GEN_HOST:$REMOTE_SCRIPT_PATH"

echo "=== Running ${#SIZES[@]}x${#GET_PCTS[@]}x${#ZIPFS[@]} combinations on $GEN_HOST (${RUN_SECONDS}s each) ==="
echo "You may be prompted once for the sudo password on $GEN_HOST."
# `ssh -t` allocates a pty on the remote end, which echoes back CRLF line
# endings; strip the trailing \r so the exact-match BEGIN/END markers below
# (and anything else parsing this log line-by-line) see plain LF.
ssh -t "$GEN_HOST" "bash '$REMOTE_SCRIPT_PATH'; rm -f '$REMOTE_SCRIPT_PATH'" | tr -d '\r' | tee "$COMBINED_GEN_LOG"

# ---- Parse results ---------------------------------------------------------
# packetgenmica picks its RX layout based on how many lcores are available:
# single-queue mode prints periodic "[RX] q0 total=..." lines, "pipeline"
# mode (seen on node118, which has plenty of lcores) splits RX across many
# queues instead, each with its own "[WORKER] qN total=..." line. Rather
# than chase both per-queue formats (and re-sum across however many queues
# pipeline mode happens to use), just take sent/received from the run's
# final "[STATS] Packet diff ..." line -- already the aggregate across all
# queues -- and divide by the fixed wall-clock duration we asked for
# (RUN_SECONDS). This slightly *under*-estimates the true rate (it counts
# the ~1s NIC/EAL startup delay against the budget too), which is a safe
# bias for a throughput floor rather than an inflated number.
for size in "${SIZES[@]}"; do
  for pct in "${GET_PCTS[@]}"; do
    for theta in "${ZIPFS[@]}"; do
      tag="size=${size} get_pct=${pct} zipf=${theta}"
      block=$(awk -v tag="=== BEGIN ${tag} ===" -v endtag="=== END ${tag} ===" \
                  '$0==tag{p=1;next} $0==endtag{p=0} p' "$COMBINED_GEN_LOG")

      stats_line=$(printf '%s\n' "$block" | grep -oP '\[STATS\] Packet diff.*' | tail -1)
      sent=$(printf '%s\n' "$stats_line" | grep -oP '(?<=sent=)[0-9]+')
      received=$(printf '%s\n' "$stats_line" | grep -oP '(?<=received=)[0-9]+')
      sent=${sent:-0}
      received=${received:-0}

      loss_pct="0"
      if [[ "$sent" -gt 0 ]]; then
        loss_pct=$(awk -v s="$sent" -v r="$received" 'BEGIN{printf "%.2f", 100.0*(s-r)/s}')
      fi

      tx_mpps=$(awk -v v="$sent" -v d="$RUN_SECONDS" 'BEGIN{printf "%.3f", v/d/1e6}')
      rx_mpps=$(awk -v v="$received" -v d="$RUN_SECONDS" 'BEGIN{printf "%.3f", v/d/1e6}')

      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$size" "$pct" "$theta" "$tx_mpps" "$rx_mpps" "$sent" "$received" "$loss_pct" >> "$SUMMARY"
    done
  done
done

echo
echo "=== Results ==="
column -t "$SUMMARY"
echo
echo "Full summary: $SUMMARY"
echo "Raw generator log: $COMBINED_GEN_LOG"
echo "Server log: $SERVER_LOG"
