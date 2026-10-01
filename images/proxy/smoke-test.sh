#!/usr/bin/env bash
# Starts the proxy image with no capabilities and a one-rule configuration,
# and checks that it listens, refuses a handshake for a name no rule allows,
# and refuses a request no rule allows. Usage: smoke-test.sh IMAGE
set -euo pipefail
image=${1:?usage: smoke-test.sh IMAGE}
runtime=${CONTAINER_RUNTIME:-docker}
curl_image=docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
dir=$(mktemp -d "${TMPDIR:-/tmp}/sealroom-smoke.XXXXXX")
name=sealroom-smoke-$$
trap '$runtime rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=sealroom smoke test" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
chmod 644 "$dir/ca.key"
cat > "$dir/proxy.json" <<'JSON'
{"placeholder": "sealroom-placeholder", "rules": [{"method": "GET", "host": "example.com", "path": "/allowed", "query": "", "headers": ["Accept"]}]}
JSON
$runtime run --detach --pull never --name "$name" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --mount "type=bind,src=$dir/proxy.json,dst=/etc/sealroom/proxy.json,readonly" \
  --mount "type=bind,src=$dir/ca.crt,dst=/etc/sealroom/ca.crt,readonly" \
  --mount "type=bind,src=$dir/ca.key,dst=/etc/sealroom/ca.key,readonly" \
  "$image" proxy --config /etc/sealroom/proxy.json --ca-cert /etc/sealroom/ca.crt --ca-key /etc/sealroom/ca.key --ip 127.0.0.1 >/dev/null
logs=
for _ in $(seq 20); do
  logs=$($runtime logs "$name" 2>&1)
  grep -q 'sealroom proxy listening' <<<"$logs" && break
  sleep 0.5
done
grep -q 'sealroom proxy listening' <<<"$logs" || { echo "the proxy did not start:"; echo "$logs"; exit 1; }
probe() {
  $runtime run --rm --pull never --network "container:$name" \
    --mount "type=bind,src=$dir/ca.crt,dst=/ca.crt,readonly" \
    "$curl_image" -s -o /dev/null -w '%{http_code}' --cacert /ca.crt --resolve "$1:443:127.0.0.1" "https://$1$2" || true
}
code=$(probe example.com /not-allowed)
[ "$code" = 403 ] || { echo "a request no rule allows was not refused: HTTP $code"; exit 1; }
code=$(probe evil.example /)
[ "$code" = 000 ] || { echo "a handshake for a name no rule allows was not refused: HTTP $code"; exit 1; }
echo "proxy image ok: listening, and refusing what no rule allows"
