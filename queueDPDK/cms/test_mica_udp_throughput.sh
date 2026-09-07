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
#   QDMA bypass           : off (normal) vs on (dol -B)
#   MICA db size          : 100000, 1000000, 10000000 keys
#
# Each combination is run with packetgenmica's own --test mode: it sends a
# warmup burst, measures traffic for a fixed 10s, waits 2s to drain, then
# exits on its own -- no external timeout/kill needed, we just wait for it.
# The server is restarted once per (db size, bypass mode) pair (both
# --mica-db-size and -B are startup-only flags on dol), and each restart is
# followed by a short discarded "priming" burst so the table's lazy,
# one-time preload of that many keys happens before the first *measured*
# combination instead of skewing it.
#
# Usage:  ./test_mica_udp_throughput.sh
# Run from queueDPDK/cms on the DUT (this host). Needs:
#   - build/dol built from the current main.c (run `make local` first)
#   - build/packetgenmica built on node118 (already there)
#   - passwordless SSH to node118 (key-based auth already set up)
#   - NOPASSWD sudoers entries on both hosts for the specific commands this
#     script runs as root (dol, kill -INT, timeout+packetgenmica) -- see
#     below. Without these the script would need an interactive sudo
#     password, which means ssh -t, which means a remote pty; that pty's
#     raw-mode terminal handling has been the source of repeated,
#     hard-to-reproduce trouble (broken CRLF log parsing, and occasionally
#     leaving the *local* shell in a broken/no-echo state). Running fully
#     non-interactively avoids that whole class of problem, so set these up
#     once rather than re-fighting ssh -t:
#
#     On this host:
#       sudo visudo -f /etc/sudoers.d/mica-udp-test
#     with:
#       guest ALL=(root) NOPASSWD: /home/guest/dpdk-20.11/queueDPDK/cms/build/dol *, /usr/bin/kill -INT *
#
#     On node118:
#       ssh node118 'sudo visudo -f /etc/sudoers.d/mica-udp-test'
#     with:
#       guest ALL=(root) NOPASSWD: /usr/bin/timeout --signal=INT * /home/guest/dummy-packetgen/build/packetgenmica -a 0000:41:00.0 -- *, /home/guest/dummy-packetgen/build/packetgenmica -a 0000:41:00.0 -- *
#     (the first covers the discarded priming burst, still wrapped in
#     `timeout` since it's meant to be cut short; the second covers the
#     --test-mode matrix runs below, which are run directly since they
#     stop on their own)
#
#     `visudo -f` validates syntax before saving. To revert: remove
#     /etc/sudoers.d/mica-udp-test on each host.
#
# Output: results_<timestamp>/summary.tsv plus one raw log per side per
# (db_size, bypass mode) pair.

set -uo pipefail

# ---- Config -------------------------------------------------------------
DUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PCI="0000:41:00.0"
SERVER_STARTUP_SECONDS="${SERVER_STARTUP_SECONDS:-8}"

GEN_HOST="node118"
GEN_DIR="/home/guest/dummy-packetgen"
GEN_PCI="0000:41:00.0"

# packetgenmica --test mode measures traffic for a fixed 10s (hardcoded in
# main_mica.c, not exposed as a flag) before draining 2s and exiting on its
# own; this is only used to turn sent/received counts into a rate, it does
# not control how long the run actually takes.
TEST_MODE_SECONDS=10
# Number of lcores packetgenmica uses for TX (includes its main lcore).
# Default 1 matches the generator's own default and what every prior run
# in this script used; bump it (e.g. TX_CORES=8 ./test_mica_udp_throughput.sh)
# to parallelize TX across more lcores -- with a single TX lcore the
# generator, not the server, is usually the throughput bottleneck for
# these small packet sizes.
TX_CORES="${TX_CORES:-16}"
SIZES=(tiny small)
GET_PCTS=(50 95)
#ZIPFS=(0.8 0.99)
ZIPFS=(0.99)
BYPASS_MODES=(yes no)   # dol without / with -B

# Server and generator must agree on the size of the MICA key space: the
# server preloads exactly this many keys (0..db_size-1) at startup
# (--mica-db-size, main.c), and the generator draws its Zipfian keys from
# the same range (--mica-db-size, main_mica.c). Mismatched sizes let SETs
# target never-seen keys once the (fixed-capacity, no-eviction) table is
# full, which used to crash the server (process_mica_udp asserted(false)
# on a failed mehcached_set -- now just silently dropped instead).
#
# --mica-db-size is a startup-only flag on dol (the table is sized and
# preloaded once in mica_table_init()), so each value here means a full
# server restart, same as BYPASS_MODES below.
#DB_SIZES=(1000000 5000000 10000000)
DB_SIZES=(10000000)

# Priming duration scales with db_size: mica_table_init()'s preload is a
# synchronous loop of db_size sequential mehcached_set() calls, run inline
# while handling the very first packet after a (re)start. The bigger the
# table, the longer that one-time freeze takes, and the priming burst needs
# to outlast it (its whole point is to absorb that freeze as *discarded*
# loss instead of having it skew the first real measurement). This is a
# rough estimate (not measured on this specific hardware), generous enough
# to be safe: 2s base + 2s per additional million keys, e.g. 100000 -> 2s,
# 1000000 -> 4s, 10000000 -> 22s.
prime_seconds_for() {
  local db_size="$1"
  echo $(( 2 + (db_size / 1000000) * 2 ))
}

RESULTS_DIR="$DUT_DIR/results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
SUMMARY="$RESULTS_DIR/summary.tsv"

printf 'db_size\tbypass\tsize\tget_pct\tzipf_theta\ttx_mpps\trx_mpps\tsent\treceived\tloss_pct\n' > "$SUMMARY"

cd "$DUT_DIR" || exit 1

# ---- Server lifecycle -----------------------------------------------------
SERVER_PID=""

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Stopping MICA UDP server (pid $SERVER_PID)..."
    sudo kill -INT "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  SERVER_PID=""
  # Belt-and-suspenders: restore the terminal if we're exiting mid-ssh
  # (see the stty sane call after the ssh invocation in run_matrix for why).
  stty sane 2>/dev/null
}
trap stop_server EXIT INT TERM

# start_server <bypass: no|yes> <db_size> <server_log_path>
start_server() {
  local bypass="$1" db_size="$2" server_log="$3"
  local cmd=(sudo ./build/dol -d librte_net_qdma.so -l 0 -a "$SERVER_PCI" --
              -P 1 -q 1 -d 1024 -a 1 -T -Q --mica-db-size "$db_size")
  if [[ "$bypass" == yes ]]; then
    cmd+=(-B)
  fi

  echo "=== Starting MICA UDP server (bypass=$bypass, db_size=$db_size) ==="
  echo "${cmd[*]}"
  "${cmd[@]}" > "$server_log" 2>&1 &
  SERVER_PID=$!

  # dol's stdout is fully block-buffered once redirected to a file (only
  # line-buffered when attached to a real terminal), so "entering main
  # loop" typically never actually appears in $server_log until the
  # process exits and its buffer gets flushed at exit() -- checking for it
  # here would either never fire (idle server, no crash) or only "work" by
  # accident right as the process dies. Grep for it anyway in case it
  # shows up early (harmless), but the real readiness signal is just: still
  # alive after a fixed startup grace period.
  echo -n "Waiting for server to start up"
  local ready=0
  for _ in $(seq 1 "$SERVER_STARTUP_SECONDS"); do
    if grep -q "entering main loop" "$server_log" 2>/dev/null; then
      ready=1
      break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo
      echo "ERROR: server exited early (after less than ${SERVER_STARTUP_SECONDS}s), see $server_log" >&2
      exit 1
    fi
    echo -n "."
    sleep 1
  done
  echo
  if [[ "$ready" -ne 1 ]] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: server exited during startup, see $server_log" >&2
    exit 1
  fi
  echo "Server still running after ${SERVER_STARTUP_SECONDS}s startup grace period (pid $SERVER_PID) -- assuming ready."
}

# ---- One matrix run against whichever server is currently up -------------
# run_matrix <bypass: no|yes> <db_size> <remote_script_path> <combined_gen_log>
run_matrix() {
  local bypass="$1" db_size="$2" remote_script="$3" combined_gen_log="$4"
  local prime_seconds
  prime_seconds=$(prime_seconds_for "$db_size")

  # Priming: mica_table_init() preloads db_size keys lazily, on the
  # very first packet the (freshly (re)started) server sees. That preload
  # is synchronous and runs in-line with packet processing, so without a
  # priming burst the first *measured* combination eats that one-time cost
  # as packet loss. Send a short throwaway burst first and discard it.
  #
  # --range: without it every packet uses the exact same fixed 5-tuple
  # (main_mica.c: SRC_IP/DST_IP/SRC_PORT/DST_PORT are constants), and dol's
  # process_mica_udp() never touches the IP/UDP headers (only swaps
  # Ethernet MACs, generically, before dispatch) -- so replies come back
  # with that same unvarying tuple every time. RSS on the generator's own
  # NIC hashes on that tuple, so all response traffic lands on a single RX
  # queue no matter how many queues "Pipeline mode" launches. --range
  # varies the low 16 bits of the destination IP per packet; since dol
  # echoes the IP header back unchanged, that variation survives on the
  # reply and lets RSS actually spread it across queues.
  {
    echo "set -u"
    echo "cd '$GEN_DIR' || exit 1"
    echo "echo '=== PRIMING (${prime_seconds}s, discarded) ==='"
    prime_cmd="sudo timeout --signal=INT ${prime_seconds}s ./build/packetgenmica -a $GEN_PCI -- --mica-size tiny --mica-get-pct 50 --mica-zipf-theta 0.8 --mica-db-size ${db_size} --tx-cores ${TX_CORES} --range -q"
    echo "echo 'CMD: $prime_cmd'"
    echo "$prime_cmd"
    echo "sleep 1"
    for size in "${SIZES[@]}"; do
      for pct in "${GET_PCTS[@]}"; do
        for theta in "${ZIPFS[@]}"; do
          tag="size=${size} get_pct=${pct} zipf=${theta}"
          echo "echo '=== BEGIN ${tag} ==='"
          # No timeout wrapper here: --test makes packetgenmica measure for
          # a fixed window and exit by itself, so we just run it in the
          # foreground and this generated script naturally waits for it
          # before moving on to the next combination's "echo" line.
          combo_cmd="sudo ./build/packetgenmica -a $GEN_PCI -- --mica-size ${size} --mica-get-pct ${pct} --mica-zipf-theta ${theta} --mica-db-size ${db_size} --tx-cores ${TX_CORES} --range --test -q"
          echo "echo 'CMD: $combo_cmd'"
          echo "$combo_cmd"
          echo "echo '=== END ${tag} ==='"
          echo "sleep 1"
        done
      done
    done
  } > "$remote_script"

  # Copy the script over and run it by path, plain ssh (no -t). This needs
  # NOPASSWD sudoers entries for `dol`/`kill -INT` (local) and `timeout ...
  # packetgenmica` (on $GEN_HOST) -- see the setup note at the top of this
  # file -- since without a pty there's nowhere for an interactive sudo
  # password prompt to go. That also sidesteps the two problems a pty here
  # used to cause: CRLF line endings breaking the log parsing below, and
  # `-t`'s raw-mode terminal handling occasionally leaking into your shell
  # session when the ssh command ended any way other than a clean interactive
  # exit (piped through tr/tee, or timeout killing the remote process).
  local remote_path="/tmp/mica_udp_test_$$.sh"
  scp -q "$remote_script" "$GEN_HOST:$remote_path"

  echo "=== Running ${#SIZES[@]}x${#GET_PCTS[@]}x${#ZIPFS[@]} combinations on $GEN_HOST (bypass=$bypass, db_size=$db_size, --test mode: ~${TEST_MODE_SECONDS}s measured + 2s drain each, plus ${prime_seconds}s priming) ==="
  ssh "$GEN_HOST" "bash '$remote_path'; rm -f '$remote_path'" | tr -d '\r' | tee "$combined_gen_log"

  # ---- Parse results -------------------------------------------------------
  # packetgenmica picks its RX layout based on how many lcores are available:
  # single-queue mode prints periodic "[RX] q0 total=..." lines, "pipeline"
  # mode (seen on node118, which has plenty of lcores) splits RX across many
  # queues instead, each with its own "[WORKER] qN total=..." line. Rather
  # than chase both per-queue formats (and re-sum across however many queues
  # pipeline mode happens to use), just take sent/received from the run's
  # final "[STATS] Packet diff ..." line -- already the aggregate across all
  # queues -- and divide by --test's fixed measurement window
  # (TEST_MODE_SECONDS). The priming burst above has no BEGIN/END tag, so
  # it's simply never matched here.
  for size in "${SIZES[@]}"; do
    for pct in "${GET_PCTS[@]}"; do
      for theta in "${ZIPFS[@]}"; do
        tag="size=${size} get_pct=${pct} zipf=${theta}"
        block=$(awk -v tag="=== BEGIN ${tag} ===" -v endtag="=== END ${tag} ===" \
                    '$0==tag{p=1;next} $0==endtag{p=0} p' "$combined_gen_log")

        stats_line=$(printf '%s\n' "$block" | grep -oP '\[STATS\] Packet diff.*' | tail -1)
        sent=$(printf '%s\n' "$stats_line" | grep -oP '(?<=sent=)[0-9]+')
        received=$(printf '%s\n' "$stats_line" | grep -oP '(?<=received=)[0-9]+')
        sent=${sent:-0}
        received=${received:-0}

        loss_pct="0"
        if [[ "$sent" -gt 0 ]]; then
          loss_pct=$(awk -v s="$sent" -v r="$received" 'BEGIN{printf "%.2f", 100.0*(s-r)/s}')
        fi

        tx_mpps=$(awk -v v="$sent" -v d="$TEST_MODE_SECONDS" 'BEGIN{printf "%.3f", v/d/1e6}')
        rx_mpps=$(awk -v v="$received" -v d="$TEST_MODE_SECONDS" 'BEGIN{printf "%.3f", v/d/1e6}')

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$db_size" "$bypass" "$size" "$pct" "$theta" "$tx_mpps" "$rx_mpps" "$sent" "$received" "$loss_pct" >> "$SUMMARY"
      done
    done
  done
}

# ---- Main: once per (db_size, bypass mode) pair ---------------------------
for db_size in "${DB_SIZES[@]}"; do
  for bypass in "${BYPASS_MODES[@]}"; do
    tag="${db_size}_${bypass}bypass"
    start_server "$bypass" "$db_size" "$RESULTS_DIR/server_${tag}.log"
    run_matrix "$bypass" "$db_size" "$RESULTS_DIR/remote_script_${tag}.sh" \
               "$RESULTS_DIR/generator_${tag}.log"
    stop_server
  done
done

echo
echo "=== Results ==="
column -t "$SUMMARY"
echo
echo "Full summary: $SUMMARY"
echo "Per-mode server/generator logs: $RESULTS_DIR/"
