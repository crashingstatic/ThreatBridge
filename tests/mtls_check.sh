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

echo "waiting for $BASE ..."
for _ in $(seq 1 30); do
  "${CURL[@]}" --cert "$WORK/client.pem" "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 1
done

fail=0
if "${CURL[@]}" "$BASE/healthz" >/dev/null 2>&1; then
  echo "FAIL: request without a client certificate was accepted"; fail=1
else echo "ok: no client certificate -> rejected"; fi

if "${CURL[@]}" --cert "$WORK/rogue.crt" --key "$WORK/rogue.key" "$BASE/healthz" >/dev/null 2>&1; then
  echo "FAIL: certificate from a foreign CA was accepted"; fail=1
else echo "ok: foreign-CA certificate -> rejected"; fi

if body="$("${CURL[@]}" --cert "$WORK/client.pem" "$BASE/healthz")" && [[ "$body" == *'"status":"ok"'* ]]; then
  echo "ok: valid client certificate -> $body"
else echo "FAIL: valid client certificate was not accepted"; fail=1; fi

code="$("${CURL[@]}" --cert "$WORK/client.pem" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' -d '{"entry":"10.0.0.9"}' "$BASE/api/excludes")"
if [[ "$code" == 403 ]]; then echo "ok: write without X-ThreatBridge header -> 403"
else echo "FAIL: write without X-ThreatBridge header -> $code"; fail=1; fi

exit "$fail"
