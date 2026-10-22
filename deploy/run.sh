#!/usr/bin/env bash
# Run ThreatBridge on the Security Onion manager. Host networking lets it reach
# Elasticsearch on localhost:9200; it listens on TB_PORT (default 5443).
set -euo pipefail
cd "$(dirname "$0")/.."
SO_CA="${SO_CA:-/etc/pki/ca.crt}"   # verify this path on your manager
# The container runs as uid 10001: hand it the key (still 0600) and make sure
# the public certs are world-readable.
chown 10001 certs/server.key
chmod 644 certs/server.crt certs/ca.crt
docker build -t threatbridge:latest .
docker rm -f threatbridge 2>/dev/null || true
docker run -d --name threatbridge --restart unless-stopped --network host \
  --env-file deploy/threatbridge.env \
  -v "$PWD/certs/server.crt:/certs/server.crt:ro" \
  -v "$PWD/certs/server.key:/certs/server.key:ro" \
  -v "$PWD/certs/ca.crt:/certs/ca.crt:ro" \
  -v "$SO_CA:/so-ca/ca.crt:ro" \
  -v threatbridge-data:/data \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  threatbridge:latest
