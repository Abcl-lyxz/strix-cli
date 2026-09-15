#!/bin/bash
set -e

configure_network_scope() {
  case "${STRIX_SANDBOX_PROFILE:-web}" in
    network|lan) ;;
    *) return 0 ;;
  esac

  if [ -z "${STRIX_SCOPE_CIDR:-}" ]; then
    echo "ERROR: network and lan profiles require STRIX_SCOPE_CIDR." >&2
    exit 1
  fi
  if ! command -v iptables >/dev/null 2>&1; then
    echo "ERROR: iptables is required to enforce the network scope." >&2
    exit 1
  fi

  iptables -F OUTPUT
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F OUTPUT
    ip6tables -P OUTPUT DROP
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  IFS=',' read -ra _scope_cidrs <<< "${STRIX_SCOPE_CIDR}"
  for _cidr in "${_scope_cidrs[@]}"; do
    _cidr="${_cidr//[[:space:]]/}"
    [ -n "${_cidr}" ] || continue
    if [[ "${_cidr}" == *:* ]]; then
      if ! command -v ip6tables >/dev/null 2>&1; then
        echo "ERROR: IPv6 CIDR supplied but ip6tables is unavailable." >&2
        exit 1
      fi
      _firewall=ip6tables
    else
      _firewall=iptables
    fi
    if [ -n "${STRIX_PACKET_RATE_LIMIT:-}" ]; then
      "${_firewall}" -A OUTPUT -d "${_cidr}" -m conntrack --ctstate NEW \
        -m limit --limit "${STRIX_PACKET_RATE_LIMIT}/second" \
        --limit-burst "${STRIX_PACKET_RATE_LIMIT}" -j ACCEPT
    else
      "${_firewall}" -A OUTPUT -d "${_cidr}" -j ACCEPT
    fi
  done
  iptables -A OUTPUT -j REJECT
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -A OUTPUT -j REJECT
  fi
  echo "Applied CIDR egress allowlist: ${STRIX_SCOPE_CIDR}"
}

if [ "${STRIX_HARDENED_SANDBOX:-0}" != "1" ] && [ -n "${STRIX_HOST_UID:-}" ] && [ "${STRIX_HOST_UID}" != "0" ] && [ "${STRIX_HOST_UID}" != "$(id -u)" ]; then
  exec sudo -E -- bash -c '
    set -e
    gid="${STRIX_HOST_GID:-$STRIX_HOST_UID}"
    old_uid="$1"
    old_gid="$2"
    export PATH="$3"
    shift 3
    sed -i "s|^pentester:x:${old_uid}:${old_gid}:|pentester:x:${STRIX_HOST_UID}:${gid}:|" /etc/passwd
    sed -i "s|^pentester:x:${old_gid}:|pentester:x:${gid}:|" /etc/group
    chown -R "${STRIX_HOST_UID}:${gid}" /home/pentester /app/certs
    chown "${STRIX_HOST_UID}:${gid}" /workspace
    exec setpriv --reuid "${STRIX_HOST_UID}" --regid "${gid}" --init-groups "$0" "$@"
  ' "$0" "$(id -u)" "$(id -g)" "$PATH" "$@"
fi

configure_network_scope

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

# Caido enforces a Host allowlist (DNS-rebinding protection) and rejects requests
# whose Host header is a hostname it doesn't recognize. To reach Caido over a
# hostname (rather than an IP literal), set STRIX_CAIDO_ALLOWED_DOMAINS to a
# comma-separated list of hostnames to allow. Unset by default.
# See https://docs.caido.io/app/guides/domain_allowlist
CAIDO_UI_DOMAIN_ARGS=()
if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then
  IFS=',' read -ra _caido_domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"
  for _d in "${_caido_domains[@]}"; do
    [ -n "$_d" ] && CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
  done
fi

caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          "${CAIDO_UI_DOMAIN_ARGS[@]}" \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Caido is up — host bootstraps the guest token + project via the Python SDK."

echo "Configuring system-wide proxy settings..."

if [ "${STRIX_HARDENED_SANDBOX:-0}" != "1" ]; then
cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=http://127.0.0.1:${CAIDO_PORT}
export https_proxy=http://127.0.0.1:${CAIDO_PORT}
export HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
export HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
export ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
export NO_PROXY=localhost,127.0.0.1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
NO_PROXY=localhost,127.0.0.1
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
EOF

# Use POSIX `.` (not the bashism `source`) so these lines are safe when the rc
# files are read by a POSIX shell (e.g. `sh -lc`), which otherwise fails with
# "source: not found". `.` is understood by bash, zsh, and dash alike.
echo ". /etc/profile.d/proxy.sh" >> ~/.bashrc
echo ". /etc/profile.d/proxy.sh" >> ~/.zshrc

. /etc/profile.d/proxy.sh
else
export HTTP_PROXY="${http_proxy:-http://127.0.0.1:${CAIDO_PORT}}"
export HTTPS_PROXY="${https_proxy:-http://127.0.0.1:${CAIDO_PORT}}"
export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1}"
fi

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
mkdir -p /home/pentester/.pki/nssdb
certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

mkdir -p /workspace/.agent-browser-screenshots

echo "✅ Container ready"

cd /workspace
exec "$@"
