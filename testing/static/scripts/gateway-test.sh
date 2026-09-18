#!/bin/bash
# Gateway integration test: non-FIPS LAN client reaches mesh HTTP server.
#
# Topology:
#   gw-client (non-FIPS) → gw-gateway (fips + fips-gateway) → gw-server (fips + http)
#
# Usage:
#   ./scripts/gateway-test.sh [inject-config]
#
# Subcommands:
#   inject-config  — post-process generated configs to add gateway section
#   (no args)      — run the test (containers must be running)
set -e

trap 'echo ""; echo "Test interrupted"; exit 130' INT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/wait-converge.sh"

GENERATED_DIR="$SCRIPT_DIR/../generated-configs${FIPS_CI_NAME_SUFFIX:-}"
ENV_FILE="$GENERATED_DIR/npubs.env"

GATEWAY="fips-gw-gateway${FIPS_CI_NAME_SUFFIX:-}"
SERVER="fips-gw-server${FIPS_CI_NAME_SUFFIX:-}"
SERVER2="fips-gw-server-2${FIPS_CI_NAME_SUFFIX:-}"
CLIENT="fips-gw-client${FIPS_CI_NAME_SUFFIX:-}"
CLIENT2="fips-gw-client-2${FIPS_CI_NAME_SUFFIX:-}"

# LAN-side IPv6 addressing. run_gateway claims a per-run /64 and exports
# FIPS_GW_LAN6_PREFIX; unset (standalone / GitHub) these render the base
# compose's fd02:: addresses, byte-identical to before. GW_DNS is the gateway's
# LAN address (nameserver + route next-hop); GW_CLIENT_LAN is gw-client's LAN
# address (inbound port-forward target). fd01::/112 (the virtual pool) is NOT
# claimed and stays literal below.
GW_LAN6_PREFIX="${FIPS_GW_LAN6_PREFIX:-fd02}"
GW_DNS="${GW_LAN6_PREFIX}::10"
GW_CLIENT_LAN="${GW_LAN6_PREFIX}::20"

# ── inject-config subcommand ─────────────────────────────────────────────

inject_gateway_config() {
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"

    if [ ! -f "$config_file" ]; then
        echo "Error: $config_file not found. Run generate-configs.sh gateway first." >&2
        exit 1
    fi

    echo "Injecting gateway config into $config_file"
    python3 -c "
import yaml

with open('$config_file') as f:
    cfg = yaml.safe_load(f)

cfg['gateway'] = {
    'enabled': True,
    'pool': 'fd01::/112',
    # Docker assigns gateway-lan to eth1 (fips-net is eth0). The
    # LAN-side masquerade for inbound port forwards gates on this.
    'lan_interface': 'eth1',
    'dns': {
        'listen': '[::]:53',
        'ttl': 5,
    },
    'pool_grace_period': 5,
    'port_forwards': [
        {
            'listen_port': 18080,
            'proto': 'tcp',
            'target': '[${GW_CLIENT_LAN}]:8080',
        },
        # 6B: second TCP forward — exercises multiple simultaneous TCP
        # rules sharing the same LAN backend on a different listen port.
        {
            'listen_port': 18082,
            'proto': 'tcp',
            'target': '[${GW_CLIENT_LAN}]:8081',
        },
        # 6A: UDP forward — exercises the runtime UDP DNAT path (rule
        # shape + conntrack handling) end-to-end.
        {
            'listen_port': 18081,
            'proto': 'udp',
            'target': '[${GW_CLIENT_LAN}]:8081',
        },
    ],
}

with open('$config_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
"
    echo "  ✓ Gateway config injected"
}

if [ "${1:-}" = "inject-config" ]; then
    inject_gateway_config
    exit 0
fi

# ── Main test ────────────────────────────────────────────────────────────

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found. Run generate-configs.sh gateway first." >&2
    exit 1
fi

# shellcheck source=../generated-configs/npubs.env
source "$ENV_FILE"

PASSED=0
FAILED=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  $label ... OK"
        PASSED=$((PASSED + 1))
    else
        echo "  $label ... FAIL"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== FIPS Gateway Integration Test ==="
echo ""

# Phase 1: Wait for mesh convergence (gateway ↔ server, gateway ↔ server-2)
echo "Phase 1: Mesh convergence"
wait_for_peers "$GATEWAY" 2 30 || true
wait_for_peers "$SERVER" 1 30 || true
wait_for_peers "$SERVER2" 1 30 || true

# Phase 2: Wait for gateway DNS to respond
echo ""
echo "Phase 2: Gateway DNS readiness"
DNS_READY=false
for i in $(seq 1 30); do
    # Try resolving the server's npub via the gateway DNS from the client.
    # Match fd01:: specifically (the pool prefix) to avoid false-positive
    # matches on error messages containing fd02::10.
    local_result=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
    if echo "$local_result" | grep -q "^fd01::"; then
        echo "  Gateway DNS responding after ${i}s"
        DNS_READY=true
        break
    fi
    sleep 1
done

if [ "$DNS_READY" != true ]; then
    echo "  WARNING: Gateway DNS did not respond within 30s, continuing anyway"
fi

# Phase 3: Client network setup — route virtual IP pool via gateway
echo ""
echo "Phase 3: Client network setup"
docker exec "$CLIENT" ip -6 route add fd01::/112 via ${GW_DNS} 2>/dev/null || true
echo "  Added route fd01::/112 via ${GW_DNS} on $CLIENT"
docker exec "$CLIENT2" ip -6 route add fd01::/112 via ${GW_DNS} 2>/dev/null || true
echo "  Added route fd01::/112 via ${GW_DNS} on $CLIENT2"

# Phase 4: DNS resolution test — resolve server npub from both clients,
# exercising concurrent multi-client mappings.
echo ""
echo "Phase 4: DNS resolution"
VIRTUAL_IP=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP" ] && echo "$VIRTUAL_IP" | grep -q "fd01"; then
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT → $VIRTUAL_IP" 0
else
    check "Resolve ${NPUB_B:0:20}...fips on $CLIENT (got: '$VIRTUAL_IP')" 1
fi

VIRTUAL_IP_2=$(docker exec "$CLIENT2" dig +short AAAA "${NPUB_C}.fips" @${GW_DNS} 2>/dev/null | head -1)
if [ -n "$VIRTUAL_IP_2" ] && echo "$VIRTUAL_IP_2" | grep -q "fd01"; then
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 → $VIRTUAL_IP_2" 0
else
    check "Resolve ${NPUB_C:0:20}...fips on $CLIENT2 (got: '$VIRTUAL_IP_2')" 1
fi

# Both clients must receive distinct virtual-IP mappings — this is the
# core multi-client invariant: each LAN client gets its own pool entry.
if [ -n "$VIRTUAL_IP" ] && [ -n "$VIRTUAL_IP_2" ] && [ "$VIRTUAL_IP" != "$VIRTUAL_IP_2" ]; then
    check "Distinct virtual IPs per client ($VIRTUAL_IP vs $VIRTUAL_IP_2)" 0
else
    check "Distinct virtual IPs per client (got: '$VIRTUAL_IP' vs '$VIRTUAL_IP_2')" 1
fi

# Verify gateway show_mappings reports both client mappings. Mapping
# allocation happens in the DNS response path, but the gateway control
# socket serves a snapshot that is refreshed on a 10s tick (see
# src/bin/fips-gateway.rs tick interval). Poll up to 15s so at least
# one post-allocation snapshot tick is guaranteed to land.
ACTIVE_COUNT="error"
# Control socket protocol is line-delimited JSON ({"command": "..."});
# bare "show_mappings" returns an "invalid request" error response with
# no data field and the parse below counts that as 0 mappings.
for _ in $(seq 1 15); do
    GW_MAPPINGS=$(docker exec "$GATEWAY" bash -c \
        'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' || echo "")
    ACTIVE_COUNT=$(echo "$GW_MAPPINGS" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('data',{}).get('mappings',[])))" 2>/dev/null || echo "error")
    if [ "$ACTIVE_COUNT" = "2" ]; then
        break
    fi
    sleep 1
done
if [ "$ACTIVE_COUNT" = "2" ]; then
    check "Gateway reports 2 active mappings (multi-client)" 0
else
    check "Gateway active mapping count (got: $ACTIVE_COUNT)" 1
fi

# Phase 5: End-to-end HTTP test from both clients in parallel
echo ""
echo "Phase 5: HTTP through gateway"

# Use --resolve to bind the .fips hostname to the virtual IP for curl.
# Run both client requests concurrently to exercise simultaneous flows
# through distinct NAT mappings.
RESP_FILE=$(mktemp)
RESP_FILE_2=$(mktemp)
trap 'rm -f "$RESP_FILE" "$RESP_FILE_2"' EXIT

if [ -n "$VIRTUAL_IP" ]; then
    docker exec "$CLIENT" curl -6 -s --max-time 10 \
        --resolve "${NPUB_B}.fips:8000:[$VIRTUAL_IP]" \
        "http://${NPUB_B}.fips:8000/" >"$RESP_FILE" 2>&1 &
    PID1=$!
else
    PID1=""
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    docker exec "$CLIENT2" curl -6 -s --max-time 10 \
        --resolve "${NPUB_C}.fips:8000:[$VIRTUAL_IP_2]" \
        "http://${NPUB_C}.fips:8000/" >"$RESP_FILE_2" 2>&1 &
    PID2=$!
else
    PID2=""
fi

[ -n "$PID1" ] && wait "$PID1" || true
[ -n "$PID2" ] && wait "$PID2" || true

RESPONSE=$(cat "$RESP_FILE")
RESPONSE_2=$(cat "$RESP_FILE_2")

if [ -n "$VIRTUAL_IP" ]; then
    if echo "$RESPONSE" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT" 0
    else
        check "HTTP GET from $CLIENT (response: '${RESPONSE:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT (skipped — no virtual IP)" 1
fi

if [ -n "$VIRTUAL_IP_2" ]; then
    if echo "$RESPONSE_2" | grep -q "Fuck IPs"; then
        check "HTTP GET from $CLIENT2" 0
    else
        check "HTTP GET from $CLIENT2 (response: '${RESPONSE_2:0:80}')" 1
    fi
else
    check "HTTP GET from $CLIENT2 (skipped — no virtual IP)" 1
fi

# Phase 6: Verify NAT state on gateway
echo ""
echo "Phase 6: Gateway NAT state"
# Check that nftables rules were created
NFT_RULES=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>/dev/null || echo "")
if echo "$NFT_RULES" | grep -q "dnat"; then
    check "nftables DNAT rules present" 0
else
    check "nftables DNAT rules" 1
fi

# Phase 7: Inbound port forwarding — UDP and a second simultaneous TCP forward.
#
# Three forwards exercised:
#   tcp 18080 → [fd02::20]:8080  (original — single TCP rule)
#   tcp 18082 → [fd02::20]:8081  (6B — second TCP rule, multiple forwards)
#   udp 18081 → [fd02::20]:8081  (6A — UDP DNAT runtime path)
#
# Mesh peer (gw-server) hits each gw-gateway fips0:<port> rule, which
# DNATs into the LAN-side gw-client. Exercises the DNAT rules + LAN-side
# masquerade installed by set_port_forwards().
echo ""
echo "Phase 7: Inbound port forwards"

# Confirm all three port-forward DNAT rules are present on the gateway.
# The distinctive listen ports identify our rules regardless of how nft
# renders the l4proto/dport predicates.
if echo "$NFT_RULES" | grep -q "18080"; then
    check "nftables port-forward DNAT rule (tcp 18080)" 0
else
    check "nftables port-forward DNAT rule (tcp 18080)" 1
fi
if echo "$NFT_RULES" | grep -q "18082"; then
    check "nftables port-forward DNAT rule (tcp 18082)" 0
else
    check "nftables port-forward DNAT rule (tcp 18082)" 1
fi
if echo "$NFT_RULES" | grep -q "18081"; then
    check "nftables port-forward DNAT rule (udp 18081)" 0
else
    check "nftables port-forward DNAT rule (udp 18081)" 1
fi

# Start marker HTTP servers on the LAN-side client.
#   :8080 → "inbound-forward-ok"   (target of tcp 18080)
#   :8081 → "inbound-forward-ok-2" (target of tcp 18082)
# `docker exec -d` is required; `docker exec bash -c 'cmd &'` doesn't
# keep the child alive past the exec session, even with nohup.
docker exec "$CLIENT" sh -c '
    mkdir -p /tmp/inbound /tmp/inbound2
    echo "inbound-forward-ok"   > /tmp/inbound/index.html
    echo "inbound-forward-ok-2" > /tmp/inbound2/index.html
    pkill -f "http.server 8080" 2>/dev/null || true
    pkill -f "http.server 8081" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
' >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 -m http.server 8080 --bind :: --directory /tmp/inbound \
    >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 -m http.server 8081 --bind :: --directory /tmp/inbound2 \
    >/dev/null 2>&1 || true

# Start a UDP echo server on the LAN-side client at [::]:8081/udp.
# This is the target of the udp 18081 forward. Stash the script as a
# named file (`udp_echo.py`) so the cleanup pkill above can find it.
docker exec "$CLIENT" sh -c 'cat > /tmp/udp_echo.py <<'\''PYEOF'\''
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 8081))
while True:
    data, addr = s.recvfrom(2048)
    s.sendto(b"udp-forward-ok:" + data, addr)
PYEOF' >/dev/null 2>&1 || true
docker exec -d "$CLIENT" python3 /tmp/udp_echo.py >/dev/null 2>&1 || true

# Give the servers a moment to bind.
for _ in 1 2 3 4 5; do
    TCP_READY=$(docker exec "$CLIENT" ss -6lnt 2>/dev/null | grep -cE ':8080|:8081' || true)
    UDP_READY=$(docker exec "$CLIENT" ss -6lnu 2>/dev/null | grep -c ':8081' || true)
    if [ "$TCP_READY" -ge 2 ] && [ "$UDP_READY" -ge 1 ]; then
        break
    fi
    sleep 1
done

# Derive the gateway's mesh IPv6 (fd00::/8 address assigned to fips0).
GW_MESH_IP=$(docker exec "$GATEWAY" bash -c \
    "ip -6 -o addr show fips0 | awk '/inet6 fd/ {print \$4}' | cut -d/ -f1 | head -1" \
    2>/dev/null || echo "")

if [ -z "$GW_MESH_IP" ]; then
    check "Gateway fips0 IPv6 address" 1
else
    echo "  Gateway mesh IPv6: $GW_MESH_IP"

    # From the mesh side (gw-server), fetch through each TCP forward.
    FWD_RESPONSE=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
        "http://[${GW_MESH_IP}]:18080/" 2>&1) || true
    # 8080 backend serves "inbound-forward-ok" (no -2 suffix) — distinct
    # from the 8081 backend so a misrouted response would be detectable.
    if echo "$FWD_RESPONSE" | grep -qE '^inbound-forward-ok$'; then
        check "Inbound HTTP via TCP forward 18080 → [${GW_CLIENT_LAN}]:8080" 0
    else
        check "Inbound HTTP via TCP forward 18080 (response: '${FWD_RESPONSE:0:80}')" 1
    fi

    FWD_RESPONSE_2=$(docker exec "$SERVER" curl -6 -s --max-time 10 \
        "http://[${GW_MESH_IP}]:18082/" 2>&1) || true
    if echo "$FWD_RESPONSE_2" | grep -q "inbound-forward-ok-2"; then
        check "Inbound HTTP via TCP forward 18082 → [${GW_CLIENT_LAN}]:8081 (6B)" 0
    else
        check "Inbound HTTP via TCP forward 18082 (response: '${FWD_RESPONSE_2:0:80}')" 1
    fi

    # 6A: UDP forward. Send a probe via a one-shot Python client on
    # gw-server; the LAN-side echo server prepends "udp-forward-ok:".
    UDP_RESPONSE=$(docker exec "$SERVER" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'ping-via-udp-fwd', ('${GW_MESH_IP}', 18081))
try:
    data, _ = s.recvfrom(2048)
    sys.stdout.write(data.decode('utf-8', 'replace'))
except Exception as e:
    sys.stdout.write('ERR: ' + str(e))
" 2>&1) || true
    if echo "$UDP_RESPONSE" | grep -q "udp-forward-ok:ping-via-udp-fwd"; then
        check "Inbound UDP via forward 18081 → [${GW_CLIENT_LAN}]:8081 (6A)" 0
    else
        check "Inbound UDP via forward 18081 (response: '${UDP_RESPONSE:0:80}')" 1
    fi
fi

# Cleanup: stop the LAN-side responders so Phase 8's pool-reclamation
# wait isn't interfered with by lingering sessions.
docker exec "$CLIENT" sh -c '
    pkill -f "http.server 8080" 2>/dev/null || true
    pkill -f "http.server 8081" 2>/dev/null || true
    pkill -f "udp_echo.py" 2>/dev/null || true
' >/dev/null 2>&1 || true

# Phase 8: TTL expiration and pool reclamation
echo ""
echo "Phase 8: TTL expiration and pool reclamation"
# Flush conntrack so stale sessions from Phase 5 don't keep the mapping alive.
docker exec "$GATEWAY" conntrack -F 2>/dev/null || true
# Config uses ttl=5, pool_grace_period=5. Pool tick interval is 10s, so:
#   tick 1 (~10s): TTL expired → Draining (sessions=0 after flush)
#   tick 2 (~20s): grace expired → freed
# Wait 25s to ensure two full tick cycles have passed.
echo "  Waiting 25s for TTL + grace period to expire (two tick cycles)..."
sleep 25

# Query gateway control socket for mapping count.
#
# The expected value here is zero, so the reader must not be able to
# produce a zero from a failed query: an error response carries no `data`
# field, and `r.get('data',{}).get('mappings',[])` would report that as
# zero mappings and pass this check without the gateway having answered.
# The same hazard is documented at the show_mappings poll above, which is
# safe only because it waits for a positive "2". Require the key to exist
# and exit non-zero if it does not, so the `|| echo "error"` fallback
# fires and the check reds.
MAPPING_COUNT=$(docker exec "$GATEWAY" bash -c \
    'echo "{\"command\":\"show_mappings\"}" | nc -U -w1 /run/fips/gateway.sock 2>/dev/null' \
    | python3 -c "
import sys, json
r = json.load(sys.stdin)
data = r.get('data')
if not isinstance(data, dict) or not isinstance(data.get('mappings'), list):
    sys.exit(1)
print(len(data['mappings']))
" 2>/dev/null || echo "error")
if [ "$MAPPING_COUNT" = "0" ]; then
    check "Mapping reclaimed after TTL+grace" 0
else
    check "Mapping reclaimed (count: $MAPPING_COUNT)" 1
fi

# Phase 9: SERVFAIL when daemon DNS is down
echo ""
echo "Phase 9: SERVFAIL when daemon DNS is down"
# Kill the fips daemon inside the gateway container (gateway stays running)
docker exec "$GATEWAY" pkill -f "^fips --config" 2>/dev/null || true
sleep 2

# Gateway upstream timeout is 5s, so dig must wait longer than that.
SERVFAIL_RESULT=$(docker exec "$CLIENT" dig +short +tries=1 +time=8 AAAA "test-servfail.fips" @${GW_DNS} 2>&1 || true)
SERVFAIL_STATUS=$(docker exec "$CLIENT" dig +tries=1 +time=8 AAAA "test-servfail.fips" @${GW_DNS} 2>&1 | grep -c "SERVFAIL" || true)
if [ "$SERVFAIL_STATUS" -ge 1 ]; then
    check "SERVFAIL when daemon DNS is down" 0
else
    check "SERVFAIL when daemon DNS down (got: '${SERVFAIL_RESULT:0:80}')" 1
fi

# Phase 10: Cleanup verification (nftables removed on shutdown)
echo ""
echo "Phase 10: Cleanup on shutdown"
# fips-gateway is PID 1 (exec in entrypoint), so SIGTERM stops the container.
# Verify cleanup by checking container logs for the shutdown sequence.
docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
sleep 1

LOGS=$(docker logs --tail=20 "$GATEWAY" 2>&1)
if echo "$LOGS" | grep -q "shutdown complete"; then
    check "Gateway shutdown completed cleanly" 0
else
    check "Gateway shutdown (no completion message in logs)" 1
fi

# ── Long-lived gateway restart, shared by phases 11 and 12 ───────────────

# Start the stopped gateway with mappings that outlive the phase, and gate on
# its readiness. A failure is recorded through check under the label prefix
# $1 and returns 1, and the caller ends its phase. On success it sets:
#   GW_STARTED   the container's start time, for `docker logs --since`, since
#                the log still holds every earlier phase
#   GW_T0        epoch seconds at the start
#   GW_BASELINE  allocations after the readiness probe, which allocates
#   GW_PROBE     the address the readiness probe got for NPUB_B
gw_long_lived_start() {
    local prefix="$1"
    local config_file="$GENERATED_DIR/gateway/node-a.yaml"
    local expect_rev
    expect_rev=$(git -C "$SCRIPT_DIR" rev-parse --short=10 HEAD)

    # Rewrite in place (same inode): the container sees the host file through
    # a single-file bind mount, which a replace-by-rename would leave behind.
    python3 - "$config_file" <<'PYEOF'
import sys, yaml
path = sys.argv[1]
with open(path, "r+") as f:
    cfg = yaml.safe_load(f)
    cfg["gateway"]["dns"]["ttl"] = 1800
    cfg["gateway"]["pool_grace_period"] = 1800
    f.seek(0)
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    f.truncate()
PYEOF

    docker start "$GATEWAY" >/dev/null
    GW_STARTED=$(docker inspect -f '{{.State.StartedAt}}' "$GATEWAY")
    GW_T0=$(date -u +%s)
    echo "  Gateway started at $GW_STARTED (expect rev $expect_rev)"

    local seen_ttl seen_grace
    seen_ttl=$(docker exec "$GATEWAY" grep -c "ttl: 1800" /etc/fips/fips.yaml || true)
    seen_grace=$(docker exec "$GATEWAY" grep -c "pool_grace_period: 1800" /etc/fips/fips.yaml || true)
    if [ "$seen_ttl" -ge 1 ] && [ "$seen_grace" -ge 1 ]; then
        check "$prefix: container sees ttl 1800 and grace 1800" 0
    else
        check "$prefix: container config rewrite (ttl: $seen_ttl, grace: $seen_grace)" 1
        return 1
    fi

    # Readiness is a hard gate here, unlike phases 1 and 2.
    if wait_for_peers "$GATEWAY" 2 60; then
        check "$prefix: gateway peers after restart" 0
    else
        check "$prefix: gateway peers after restart" 1
        return 1
    fi
    local probe
    GW_PROBE=""
    for _ in $(seq 1 60); do
        probe=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
        GW_PROBE=$(grep -m1 "^fd01::" <<< "$probe" || true)
        if [ -n "$GW_PROBE" ]; then
            break
        fi
        sleep 1
    done
    if [ -n "$GW_PROBE" ]; then
        check "$prefix: gateway DNS answers after restart" 0
    else
        check "$prefix: gateway DNS answers after restart" 1
        return 1
    fi

    sleep 1
    local started_log rev_lines
    started_log=$(docker logs --timestamps --since "$GW_STARTED" "$GATEWAY" 2>&1)
    # The co-resident daemon logs its own "(rev ...) starting" line, so
    # anchor on the gateway's name.
    rev_lines=$(grep -cE "fips-gateway [^ ]+ \(rev ${expect_rev}\) starting" <<< "$started_log" || true)
    if [ "$rev_lines" -eq 1 ]; then
        check "$prefix: startup line reads rev ${expect_rev}) with no -dirty" 0
    else
        check "$prefix: startup line for rev ${expect_rev} (found $rev_lines)" 1
        return 1
    fi
    GW_BASELINE=$(grep -c "Allocated virtual IP" <<< "$started_log" || true)
    return 0
}

# The pool's compiled-in admission limits. A new name is refused past
# MAPPING_CEILING live mappings, and past a burst of MAPPING_BURST new names
# are admitted at MAPPING_RATE per second, so phases that create many
# mappings retry the rate limit's refusals.
POOL_RS="$SCRIPT_DIR/../../../src/gateway/pool.rs"

# A compiled-in constant from pool.rs, or nothing if the line is not found.
pool_const() {
    sed -nE "s/^pub const $1: [a-z0-9]+ = ([0-9]+);$/\1/p" "$POOL_RS"
}

POOL_CEILING=$(pool_const MAPPING_CEILING)
POOL_BURST=$(pool_const MAPPING_BURST)
POOL_RATE=$(pool_const MAPPING_RATE)

# Per-name retry bound for the driver, in seconds: a fixed 30 s. A bound
# sized from the rate (workers x refill interval x 5) is 2 s at 10/s, shorter
# than two of the driver's 1 to 1.5 s retry pauses, and never above 20 s for
# any rate of 1/s or more; 30 s lets a name wait through many pauses. No run
# has had a name reach it. Empty when the rate could not be read, which the
# phases report.
gw_retry_bound() {
    [ -n "$POOL_RATE" ] && [ "$POOL_RATE" -gt 0 ] || return 0
    echo 30
    return 0
}

# Install the AAAA driver in the client: 4 closed-loop workers, one fresh
# socket per query, counts printed as key=value. Given a retry bound in
# seconds, a name answered SERVFAIL or not answered is asked again after a
# pause of 1 to 1.5 s until it is answered or the bound has passed since its
# first query; the exit status is 1 if any name was left unplaced. Without a
# bound each name is asked once and the exit status is 0.
gw_install_driver() {
    docker exec -i "$CLIENT" sh -c 'cat > /tmp/gw_driver.py' <<'PYEOF'
import random, socket, struct, sys, threading, time
server = sys.argv[1]
bound = float(sys.argv[2]) if len(sys.argv) > 2 else None
names = [n.strip() for n in sys.stdin if n.strip()]
lock = threading.Lock()
counts = {"answered": 0, "servfail": 0, "timeout": 0, "other": 0,
          "retries": 0, "unplaced": 0}
def query(name):
    qid = random.getrandbits(16)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in (name + ".fips").split("."):
        raw = label.encode()
        pkt += bytes([len(raw)]) + raw
    pkt += b"\x00" + struct.pack(">HH", 28, 1)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(6)
    try:
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
    except socket.timeout:
        return "timeout"
    finally:
        s.close()
    flags, _, ancount = struct.unpack(">HHH", data[2:8])
    rcode = flags & 0xF
    if rcode == 2:
        return "servfail"
    if rcode == 0 and ancount > 0:
        return "answered"
    return "other"
def place(name):
    first = time.monotonic()
    while True:
        outcome = query(name)
        with lock:
            counts[outcome] += 1
        if bound is None or outcome == "answered":
            return
        if outcome == "other" or time.monotonic() - first > bound:
            with lock:
                counts["unplaced"] += 1
            return
        with lock:
            counts["retries"] += 1
        time.sleep(1 + random.random() * 0.5)
def worker():
    while True:
        with lock:
            if not names:
                return
            name = names.pop()
        place(name)
threads = [threading.Thread(target=worker) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(" ".join(f"{k}={v}" for k, v in counts.items()))
sys.exit(1 if counts["unplaced"] else 0)
PYEOF
}

# Phase 11: NAT rebuild past the default netlink socket limits
#
# Every change rebuilds the whole fips_gateway table in one netlink batch.
# With the default socket buffers that batch failed from about 105 mappings
# (the acks overflowed the receive buffer, after the commit) and past about
# 313 (the batch overflowed the send buffer, and nothing was committed).
# Drive 400 new names through a gateway whose mappings outlive the phase and
# judge the result on the kernel's own table, which is what a lost rebuild
# leaves wrong, not on the daemon's debug-level success line. The names go
# through the pool's rate limit, so the driver retries its refusals. Runs
# after phase 10, so the gateway container is stopped when it starts, and it
# leaves it stopped.
echo ""
echo "Phase 11: NAT rebuild past default socket limits"

NATBIG_NAMES=400
NATBIG_CAP=180
NATBIG_SETTLE=30

natbig_now() {
    date -u +%s
}

natbig_slice() {
    NATBIG_LOG=$(docker logs --timestamps --since "$NATBIG_STARTED" "$GATEWAY" 2>&1)
}

natbig_allocated() {
    natbig_slice
    NATBIG_ALLOCATED=$(grep -c "Allocated virtual IP" <<< "$NATBIG_LOG" || true)
}

# Rules the kernel holds right now. A failed listing is recorded through
# NATBIG_RC, never read as a table with no rules.
natbig_kernel() {
    NATBIG_RC=0
    NATBIG_NFT=$(docker exec "$GATEWAY" nft list table inet fips_gateway 2>&1) || NATBIG_RC=$?
    NATBIG_DNAT=$(grep -cE "daddr fd01:[0-9a-f:]* .*dnat" <<< "$NATBIG_NFT" || true)
    NATBIG_SNAT=$(grep -cE "saddr [0-9a-f:]+ .*snat" <<< "$NATBIG_NFT" || true)
    NATBIG_MASQ=$(grep -c "masquerade" <<< "$NATBIG_NFT" || true)
}

natbig_phase() {
    gw_long_lived_start "NAT batch" || return 0
    NATBIG_STARTED="$GW_STARTED"
    local t0="$GW_T0"
    local baseline="$GW_BASELINE"
    local target=$((baseline + NATBIG_NAMES))
    echo "  Baseline allocations after readiness: $baseline; target $target"
    if [ "$baseline" -ge 1 ]; then
        check "NAT batch: readiness probe allocated (baseline $baseline)" 0
    else
        check "NAT batch: readiness probe allocated (baseline $baseline)" 1
        return 0
    fi

    # Names: real keys, since the daemon parses each one as a public key.
    local names_file have_names
    names_file=$(mktemp)
    docker exec "$GATEWAY" bash -c \
        "for i in \$(seq 1 $NATBIG_NAMES); do fipsctl keygen --stdout; done" \
        | grep '^npub1' >"$names_file" || true
    have_names=$(wc -l <"$names_file")
    if [ "$have_names" -lt "$NATBIG_NAMES" ]; then
        check "NAT batch: generated $NATBIG_NAMES names (got $have_names)" 1
        rm -f "$names_file"
        return 0
    fi

    local retry_bound
    retry_bound=$(gw_retry_bound)
    if [ -z "$retry_bound" ]; then
        check "NAT batch: MAPPING_RATE read from pool.rs ('$POOL_RATE')" 1
        rm -f "$names_file"
        return 0
    fi
    gw_install_driver
    local remaining out rc=0
    remaining=$((NATBIG_CAP - ($(natbig_now) - t0)))
    # timeout reads 0 as no limit and refuses a negative duration.
    if [ "$remaining" -le 0 ]; then
        check "NAT batch: setup exceeded ${NATBIG_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(docker exec -i "$CLIENT" timeout "$remaining" \
        python3 /tmp/gw_driver.py "$GW_DNS" "$retry_bound" <"$names_file" 2>&1) || rc=$?
    rm -f "$names_file"
    echo "  [$(($(natbig_now) - t0))s] sent $NATBIG_NAMES names: $out (rc=$rc)"
    natbig_allocated
    if [ "$rc" -eq 0 ] && [ "$NATBIG_ALLOCATED" -eq "$target" ]; then
        check "NAT batch: $NATBIG_ALLOCATED live mappings allocated" 0
    else
        check "NAT batch: live mappings allocated ($NATBIG_ALLOCATED of $target, rc $rc)" 1
    fi

    # Settle on the kernel: wait until it holds a DNAT rule per allocation,
    # or the cap expires. Reaching the cap decides nothing by itself; the
    # checks below do.
    local settle=0
    natbig_kernel
    while [ "$NATBIG_DNAT" -ne "$NATBIG_ALLOCATED" ] && [ "$settle" -lt "$NATBIG_SETTLE" ]; do
        sleep 1
        settle=$((settle + 1))
        natbig_kernel
    done
    # An error logged just after the last commit still counts.
    sleep 2
    natbig_kernel
    natbig_allocated
    local nat_fail
    nat_fail=$(grep -c "Failed to add NAT rules" <<< "$NATBIG_LOG" || true)
    echo "  [$(($(natbig_now) - t0))s] allocated=$NATBIG_ALLOCATED nat_add_fail=$nat_fail" \
        "table_rc=$NATBIG_RC dnat=$NATBIG_DNAT snat=$NATBIG_SNAT masquerade=$NATBIG_MASQ settle=${settle}s"
    if [ "$nat_fail" -gt 0 ]; then
        grep "Failed to add NAT rules" <<< "$NATBIG_LOG" | sed 's/\x1b\[[0-9;]*m//g' \
            | sed -n '1p;$p' | sed 's/^/    /'
    fi

    if [ "$nat_fail" -eq 0 ]; then
        check "NAT batch: no NAT rebuild failed" 0
    else
        check "NAT batch: NAT rebuilds failed ($nat_fail)" 1
    fi
    if [ "$NATBIG_RC" -eq 0 ]; then
        check "NAT batch: nft lists the fips_gateway table" 0
    else
        check "NAT batch: nft list table failed (rc $NATBIG_RC)" 1
    fi
    if [ "$NATBIG_DNAT" -eq "$NATBIG_ALLOCATED" ] && [ "$NATBIG_SNAT" -eq "$NATBIG_ALLOCATED" ]; then
        check "NAT batch: kernel holds a DNAT and SNAT rule per mapping ($NATBIG_DNAT)" 0
    else
        check "NAT batch: kernel rules (dnat $NATBIG_DNAT, snat $NATBIG_SNAT, allocated $NATBIG_ALLOCATED)" 1
    fi
    if [ "$NATBIG_MASQ" -eq 2 ]; then
        check "NAT batch: fips0 and LAN masquerades present" 0
    else
        check "NAT batch: masquerade rules ($NATBIG_MASQ, expected 2)" 1
    fi

    docker stop --time=10 "$GATEWAY" >/dev/null 2>&1 || true
    echo "  Phase time: $(($(natbig_now) - t0))s"
}

natbig_phase

# Phase 12: Pool admission limits
#
# The pool refuses a new name once it holds MAPPING_CEILING live mappings,
# and past a burst of MAPPING_BURST admits new names at MAPPING_RATE per
# second; the constants are read from src/gateway/pool.rs. Restart the gateway
# with mappings that outlive the phase, fill the pool to the ceiling through
# the rate limit, then ask once each for 20 more new names: all 20 must be
# refused at the ceiling while an existing name still resolves. Without the
# ceiling those 20 are allocated, whatever the creation rate. Reports rebuild
# and tick durations on the way up and the shutdown duration at the ceiling.
# Runs after phase 11, so the gateway container is stopped when it starts,
# and it leaves it stopped.
echo ""
echo "Phase 12: Pool admission limits"

LIMITS_EXTRA=20
# Sized from both trees: with the limits the fill takes about
# (ceiling - burst) / rate seconds plus retry pauses, and without them a
# measurement run reached ceiling + 20 mappings far sooner.
LIMITS_CAP=300
# Shutdown took 2.4 s at 2000 mappings in a measurement run.
LIMITS_STOP_TIME=30
limits_now() {
    date -u +%s
}

limits_slice() {
    SLICE=$(docker logs --timestamps --since "$STARTED" "$GATEWAY" 2>&1)
}

# Figures below read lines a grep on the slice has already selected, so the
# log-string guard sees each daemon-log literal. The Python matches no log
# text itself: it takes the daemon's own timestamp and key=value fields.
LIMITS_PY_FIELDS='
import re, sys, statistics
from datetime import datetime, timezone
ANSI = re.compile(r"\x1b\[[0-9;]*m")
FIELD = re.compile(r"\b(\w+)=(\S+)")
def parse(line):
    parts = ANSI.sub("", line.rstrip("\n")).split(" ", 2)
    whole, _, frac = parts[1].rstrip("Z").partition(".")
    t = datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    t = t.timestamp() + float("0." + (frac or "0"))
    return t, dict(FIELD.findall(parts[2] if len(parts) > 2 else ""))
'

limits_phase() {
    local ceiling="$POOL_CEILING" burst="$POOL_BURST" rate="$POOL_RATE"
    if [ -n "$ceiling" ] && [ -n "$burst" ] && [ -n "$rate" ] && [ "$rate" -gt 0 ] \
        && [ "$ceiling" -gt 1 ]; then
        check "Limits: read ceiling $ceiling, burst $burst, rate $rate/s from pool.rs" 0
    else
        check "Limits: constants in pool.rs (ceiling '$ceiling', burst '$burst', rate '$rate')" 1
        return 0
    fi
    local retry_bound
    retry_bound=$(gw_retry_bound)

    gw_long_lived_start "Limits" || return 0
    STARTED="$GW_STARTED"
    local t0="$GW_T0"
    local baseline="$GW_BASELINE"
    if [ "$baseline" -eq 1 ]; then
        check "Limits: the readiness probe holds the only mapping" 0
    else
        check "Limits: mappings after readiness ($baseline, expected 1)" 1
        return 0
    fi

    # Names: real keys, since the daemon parses each one as a public key.
    local fill=$((ceiling - baseline))
    local total=$((fill + LIMITS_EXTRA))
    local names_file have_names
    names_file=$(mktemp)
    docker exec "$GATEWAY" bash -c \
        "for i in \$(seq 1 $total); do fipsctl keygen --stdout; done" \
        | grep '^npub1' >"$names_file" || true
    have_names=$(wc -l <"$names_file")
    if [ "$have_names" -lt "$total" ]; then
        check "Limits: generated $total names (got $have_names)" 1
        rm -f "$names_file"
        return 0
    fi
    gw_install_driver

    # Fill: exactly ceiling - 1 new names, each retried through the rate
    # limit's refusals. A name left unplaced, or the cap firing, fails.
    local remaining out rc=0
    remaining=$((LIMITS_CAP - ($(limits_now) - t0)))
    if [ "$remaining" -le 0 ]; then
        check "Limits: setup exceeded ${LIMITS_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(sed -n "1,${fill}p" "$names_file" | docker exec -i "$CLIENT" timeout "$remaining" \
        python3 /tmp/gw_driver.py "$GW_DNS" "$retry_bound" 2>&1) || rc=$?
    echo "  [$(($(limits_now) - t0))s] fill of $fill names (retry bound ${retry_bound}s): $out (rc=$rc)"
    if [ "$rc" -eq 0 ]; then
        check "Limits: fill placed all $fill names" 0
    else
        check "Limits: fill driver failed (rc $rc)" 1
    fi
    sleep 1
    limits_slice
    local rate_refused_fill
    rate_refused_fill=$(grep -c "new-mapping rate limit reached" <<< "$SLICE" || true)

    # Past the ceiling: one query per name, never retried.
    rc=0
    remaining=$((LIMITS_CAP - ($(limits_now) - t0)))
    if [ "$remaining" -le 0 ]; then
        check "Limits: fill exceeded ${LIMITS_CAP}s cap" 1
        rm -f "$names_file"
        return 0
    fi
    out=$(sed -n "$((fill + 1)),${total}p" "$names_file" | docker exec -i "$CLIENT" \
        timeout "$remaining" python3 /tmp/gw_driver.py "$GW_DNS" 2>&1) || rc=$?
    rm -f "$names_file"
    echo "  [$(($(limits_now) - t0))s] $LIMITS_EXTRA names past the ceiling: $out (rc=$rc)"
    local post_servfail
    post_servfail=$(sed -nE 's/.*servfail=([0-9]+).*/\1/p' <<< "$out")
    if [ "$rc" -eq 0 ] && [ "${post_servfail:-0}" -eq "$LIMITS_EXTRA" ]; then
        check "Limits: all $LIMITS_EXTRA names past the ceiling got SERVFAIL" 0
    else
        check "Limits: names past the ceiling (servfail '${post_servfail}', rc $rc)" 1
    fi

    local probe
    probe=$(docker exec "$CLIENT" dig +short AAAA "${NPUB_B}.fips" @${GW_DNS} 2>/dev/null || true)
    if [ "$(grep -m1 "^fd01::" <<< "$probe" || true)" = "$GW_PROBE" ]; then
        check "Limits: NPUB_B still resolves to $GW_PROBE at the ceiling" 0
    else
        check "Limits: NPUB_B at the ceiling (got '${probe:0:60}', had $GW_PROBE)" 1
    fi

    sleep 1
    limits_slice
    local allocated reclaimed ceiling_refused rate_refused nat_fail nat_rm_fail ndp_fail
    allocated=$(grep -c "Allocated virtual IP" <<< "$SLICE" || true)
    reclaimed=$(grep -c "Reclaimed virtual IP" <<< "$SLICE" || true)
    ceiling_refused=$(grep -c "live-mapping ceiling reached" <<< "$SLICE" || true)
    rate_refused=$(grep -c "new-mapping rate limit reached" <<< "$SLICE" || true)
    nat_fail=$(grep -c "Failed to add NAT rules" <<< "$SLICE" || true)
    nat_rm_fail=$(grep -c "Failed to remove NAT rules" <<< "$SLICE" || true)
    ndp_fail=$(grep -c "Failed to add proxy NDP" <<< "$SLICE" || true)
    echo "  Slice counts: allocated=$allocated reclaimed=$reclaimed" \
        "ceiling_refused=$ceiling_refused rate_refused=$rate_refused_fill/$rate_refused" \
        "nat_add_fail=$nat_fail nat_remove_fail=$nat_rm_fail ndp_fail=$ndp_fail"
    if [ "$allocated" -eq "$ceiling" ]; then
        check "Limits: live mappings stop at the ceiling ($allocated)" 0
    else
        check "Limits: live mappings $allocated, ceiling $ceiling" 1
    fi
    if [ "$allocated" -gt 0 ]; then
        if [ "$reclaimed" -eq 0 ]; then
            check "Limits: no reclaims during the phase" 0
        else
            check "Limits: reclaims during the phase ($reclaimed)" 1
        fi
    else
        check "Limits: allocations present in the slice (0)" 1
    fi
    if [ "$ceiling_refused" -ge "$LIMITS_EXTRA" ]; then
        check "Limits: refusals logged as the ceiling ($ceiling_refused)" 0
    else
        check "Limits: ceiling refusals logged ($ceiling_refused, expected >= $LIMITS_EXTRA)" 1
    fi
    # The rate limit must have refused during the fill, so its count is a
    # live signal, and must refuse nothing after it: past the ceiling the
    # ceiling is checked first.
    if [ "$rate_refused_fill" -ge 1 ]; then
        check "Limits: the rate limit refused during the fill ($rate_refused_fill)" 0
    else
        check "Limits: rate refusals during the fill (0)" 1
    fi
    if [ "$rate_refused" -eq "$rate_refused_fill" ]; then
        check "Limits: no rate refusal after the fill" 0
    else
        check "Limits: rate refusals after the fill ($((rate_refused - rate_refused_fill)))" 1
    fi
    if [ $((nat_fail + nat_rm_fail + ndp_fail)) -eq 0 ]; then
        check "Limits: no NAT or proxy NDP failure lines" 0
    else
        check "Limits: failure lines (nat add $nat_fail, remove $nat_rm_fail, ndp $ndp_fail)" 1
    fi

    # Creations in any 10 s window of the fill can be at most a full burst
    # plus 10 s of refill. The bound is exact, not approximate: the bucket
    # holds at most burst whole tokens at the window's first creation and
    # gains one per 1/rate s, so one more creation needs the daemon's log
    # timestamps to lag its clock by a full token interval (100 ms at 10/s)
    # more at one end of the window than the other. Do not loosen it for skew.
    local bound=$((burst + 10 * rate)) most
    most=$(grep "Allocated virtual IP" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
b, fill = int(sys.argv[1]), int(sys.argv[2])
ts = sorted(parse(l)[0] for l in sys.stdin)[b:b + fill]
most = j = 0
for i in range(len(ts)):
    while ts[i] - ts[j] > 10:
        j += 1
    most = max(most, i - j + 1)
print(most)
" "$baseline" "$fill" || true)
    if [ -n "$most" ] && [ "$most" -le "$bound" ]; then
        check "Limits: at most $most creations in any 10 s of the fill (bound $bound)" 0
    else
        check "Limits: creations in a 10 s window of the fill ('$most', bound $bound)" 1
    fi

    local added_timed tick_timed
    added_timed=$(grep "Added DNAT/SNAT rules" <<< "$SLICE" | grep -c "elapsed_us" || true)
    tick_timed=$(grep "Pool tick" <<< "$SLICE" | grep -c "tick_us" || true)
    if [ "$added_timed" -ge 1 ] && [ "$tick_timed" -ge 1 ]; then
        check "Limits: rebuild and tick timing lines present" 0
    else
        check "Limits: timing lines (rebuild $added_timed, tick $tick_timed)" 1
    fi

    echo "  --- Rebuild duration (elapsed_us over the 20 adds ending at each count) ---"
    local targets=("$ceiling") rebuild_report
    [ "$ceiling" -gt 500 ] && targets=(500 "$ceiling")
    rebuild_report=$(grep "Added DNAT/SNAT rules" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
by_n = {}
for l in sys.stdin:
    _, f = parse(l)
    if 'error' in f or 'elapsed_us' not in f:
        continue
    by_n[int(f['mappings'])] = int(f['elapsed_us'])
missing = 0
for t in map(int, sys.argv[1:]):
    if t not in by_n:
        missing += 1
        print(f'  rebuild {t}: no successful add line with mappings={t}')
        continue
    xs = [by_n[n] for n in range(t - 19, t + 1) if n in by_n]
    print(f'  rebuild {t}: n={len(xs)} median={statistics.median(xs):.0f}us max={max(xs)}us')
print(f'REBUILD_MISSING={missing}')
" "${targets[@]}" || true)
    echo "$rebuild_report" | grep -v '^REBUILD_MISSING='
    if echo "$rebuild_report" | grep -q '^REBUILD_MISSING=0$'; then
        check "Limits: a successful add line at ${targets[*]} mappings" 0
    else
        check "Limits: a successful add line at ${targets[*]} mappings" 1
    fi

    echo "  --- Ticks as they fell ---"
    grep "Pool tick" <<< "$SLICE" | python3 -c "$LIMITS_PY_FIELDS
for l in sys.stdin:
    _, f = parse(l)
    print(f\"  tick: mappings={f.get('mappings')} read_us={f.get('read_us')} tick_us={f.get('tick_us')}\")
" || true

    echo "  --- Shutdown at the ceiling ---"
    docker stop --time="$LIMITS_STOP_TIME" "$GATEWAY" >/dev/null 2>&1 || true
    limits_slice
    local shut_lines
    shut_lines=$( { grep "fips-gateway shutting down" <<< "$SLICE"; \
        grep "fips-gateway shutdown complete" <<< "$SLICE"; } || true)
    if [ "$(echo "$shut_lines" | grep -c . || true)" -eq 2 ]; then
        echo "$shut_lines" | python3 -c "$LIMITS_PY_FIELDS
ts = [parse(l)[0] for l in sys.stdin]
print(f'  shutdown duration: {ts[1] - ts[0]:.3f}s')
" || true
        check "Limits: gateway shutdown completed within ${LIMITS_STOP_TIME}s" 0
    else
        check "Limits: gateway shutdown completion line present" 1
    fi
    echo "  Phase time: $(($(limits_now) - t0))s"
}

limits_phase

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
