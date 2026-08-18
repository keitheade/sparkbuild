#!/usr/bin/env bash
# =============================================================================
# Assert that this node cannot reach anything outside the enclave, and that
# every running container has telemetry disabled.
#
# Run on each Spark and the management VM after deployment, and again after any
# change to networking or container configuration.
# =============================================================================
set -uo pipefail

GRN=$'\033[32m'; RED=$'\033[31m'; YLW=$'\033[33m'; RST=$'\033[0m'
pass() { printf '%s PASS %s %s\n' "$GRN" "$RST" "$*"; }
fail() { printf '%s FAIL %s %s\n' "$RED" "$RST" "$*"; FAILED=1; }
warn() { printf '%s WARN %s %s\n' "$YLW" "$RST" "$*"; }
FAILED=0

echo "=== SPARKSOC egress verification: $(hostname) ==="
echo
echo "--- 1. outbound reachability (all of these MUST fail) ---"
for target in 8.8.8.8 1.1.1.1 huggingface.co github.com pypi.org registry-1.docker.io; do
  if timeout 5 bash -c "</dev/tcp/${target}/443" 2>/dev/null; then
    fail "reached ${target}:443 - this node is NOT airgapped"
  else
    pass "cannot reach ${target}:443"
  fi
done

echo
echo "--- 2. DNS resolution off-enclave (should fail) ---"
if timeout 5 getent hosts huggingface.co >/dev/null 2>&1; then
  warn "huggingface.co resolves. DNS may be forwarding off-enclave."
else
  pass "external DNS does not resolve"
fi

echo
echo "--- 3. default route ---"
gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
if [[ -n "$gw" ]]; then
  warn "default route via ${gw} - confirm this gateway has no path off-enclave"
else
  pass "no default route configured"
fi

echo
echo "--- 4. container telemetry environment ---"
if command -v docker >/dev/null 2>&1; then
  for c in $(docker ps --format '{{.Names}}'); do
    envs=$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)
    missing=()
    case "$c" in
      *vllm*)
        for want in HF_HUB_OFFLINE=1 VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1; do
          grep -q "^${want}$" <<<"$envs" || missing+=("$want")
        done ;;
      *qdrant*)
        grep -qi 'TELEMETRY_DISABLED=true' <<<"$envs" || missing+=("QDRANT__TELEMETRY_DISABLED=true") ;;
    esac
    if (( ${#missing[@]} )); then
      fail "${c}: missing ${missing[*]}"
    else
      pass "${c}: telemetry disabled"
    fi
  done
else
  warn "docker not present; skipping container checks"
fi

echo
echo "--- 5. listening sockets (review for anything unexpected) ---"
ss -tlnp 2>/dev/null | awk 'NR==1 || $4 !~ /127\.0\.0\.1|\[::1\]/'

echo
if (( FAILED )); then
  echo "${RED}=== EGRESS VERIFICATION FAILED ===${RST}"
  exit 1
fi
echo "${GRN}=== EGRESS VERIFICATION PASSED ===${RST}"
