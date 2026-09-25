#!/usr/bin/env bash
# Private CA for ThreatBridge mutual TLS.
#   scripts/make-certs.sh ca                          # once
#   scripts/make-certs.sh server <dns-name> [ip ...]  # cert the browser sees
#   scripts/make-certs.sh client <analyst-name>       # one .p12 per analyst
# Output goes to $CERT_DIR (default ./certs). Keep ca.key offline if you can.
set -euo pipefail
DIR="${CERT_DIR:-./certs}"
DAYS_CA=3650 DAYS_LEAF=825
mkdir -p "$DIR" && chmod 700 "$DIR"
umask 077

die() { echo "error: $*" >&2; exit 1; }
need_ca() { [[ -f "$DIR/ca.key" && -f "$DIR/ca.crt" ]] || die "run '$0 ca' first"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "name must match [A-Za-z0-9._-]+"; }

cmd="${1:-}"; shift || true
case "$cmd" in
  ca)
    [[ -f "$DIR/ca.key" ]] && die "$DIR/ca.key already exists"
    openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/ca.key"
    openssl req -x509 -new -key "$DIR/ca.key" -sha256 -days "$DAYS_CA" \
      -subj "/CN=ThreatBridge CA" -out "$DIR/ca.crt" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "CA written to $DIR/ca.crt"
    ;;
  server)
    need_ca; name="${1:-}"; [[ -n "$name" ]] || die "usage: $0 server <dns-name> [ip ...]"; shift
    san="DNS:$name"; for ip in "$@"; do san="$san,IP:$ip"; done
    openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/server.key"
    openssl req -new -key "$DIR/server.key" -subj "/CN=$name" -out "$DIR/server.csr"
    openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
      -CAcreateserial -sha256 -days "$DAYS_LEAF" -out "$DIR/server.crt" \
      -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n" "$san")
    rm -f "$DIR/server.csr"
    echo "Server cert written to $DIR/server.crt (SAN: $san)"
    ;;
  client)
    need_ca; name="${1:-}"; [[ -n "$name" ]] || die "usage: $0 client <analyst-name>"; valid_name "$name"
    openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/$name.key"
    openssl req -new -key "$DIR/$name.key" -subj "/CN=$name/OU=ThreatBridge analysts" -out "$DIR/$name.csr"
    openssl x509 -req -in "$DIR/$name.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
      -CAcreateserial -sha256 -days "$DAYS_LEAF" -out "$DIR/$name.crt" \
      -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
    # Export password: from $P12_PASS if set, otherwise prompted.
    passout=(); [[ -n "${P12_PASS:-}" ]] && passout=(-passout env:P12_PASS)
    [[ ${#passout[@]} -eq 0 ]] && echo "Choose an export password for $name.p12 (entered on import):"
    openssl pkcs12 -export -inkey "$DIR/$name.key" -in "$DIR/$name.crt" -certfile "$DIR/ca.crt" \
      -name "ThreatBridge - $name" -out "$DIR/$name.p12" "${passout[@]}"
    rm -f "$DIR/$name.csr" "$DIR/$name.key"
    echo "Give $DIR/$name.p12 (and ca.crt, to trust the server) to $name."
    ;;
  *) die "usage: $0 {ca|server <dns-name> [ip ...]|client <name>}" ;;
esac
