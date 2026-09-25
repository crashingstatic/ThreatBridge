#!/usr/bin/env bash
# Verify a running ThreatBridge enforces mutual TLS.
#   tests/mtls_check.sh <base-url> <cert-dir> <client-name>
# Expects <cert-dir>/ca.crt and <cert-dir>/<client-name>.p12 (password $P12_PASS).
set -euo pipefail
BASE="$1" DIR="$2" CLIENT="$3"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
CURL=(curl -sS --noproxy '*' --max-time 10 --cacert "$DIR/ca.crt")

openssl pkcs12 -in "$DIR/$CLIENT.p12" -passin env:P12_PASS -nodes -out "$WORK/client.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /CN=rogue -keyout "$WORK/rogue.key" -out "$WORK/rogue.crt" 2>/dev/null

# The server must be up and accept a valid cert before rejections mean anything
# (a stopped server would otherwise "reject" everything).
echo "waiting for $BASE ..."
body=""
for _ in $(seq 1 30); do
  body="$("${CURL[@]}" --cert "$WORK/client.pem" "$BASE/healthz" 2>/dev/null)" && break
  sleep 1
done
if [[ "$body" == *'"status":"ok"'* ]]; then
  echo "ok: valid client certificate -> $body"
else
  echo "FAIL: server not reachable with a valid client certificate"; exit 1
fi

# A rejection must happen in TLS: curl exit 35 (handshake) or 56 (alert on read),
# not 7 (connection refused) or 0 (accepted).
expect_tls_reject() {
  local what="$1"; shift
  local rc=0
  "${CURL[@]}" "$@" "$BASE/healthz" >/dev/null 2>&1 || rc=$?
  if [[ $rc == 35 || $rc == 56 ]]; then echo "ok: $what -> rejected in TLS (curl $rc)"
  else echo "FAIL: $what -> curl exit $rc (expected TLS rejection 35/56)"; fail=1; fi
}

fail=0
expect_tls_reject "no client certificate"
expect_tls_reject "foreign-CA certificate" --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"

code="$("${CURL[@]}" --cert "$WORK/client.pem" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' -d '{"entry":"10.0.0.9"}' "$BASE/api/excludes")"
if [[ "$code" == 403 ]]; then echo "ok: write without X-ThreatBridge header -> 403"
else echo "FAIL: write without X-ThreatBridge header -> $code"; fail=1; fi

exit "$fail"
