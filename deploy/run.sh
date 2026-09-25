#!/usr/bin/env bash
# Run ThreatBridge on the Security Onion manager. Host networking lets it reach
# Elasticsearch on localhost:9200; it listens on TB_PORT (default 5443).
set -euo pipefail
cd "$(dirname "$0")/.."
SO_CA="${SO_CA:-/etc/pki/ca.crt}"   # verify this path on your manager
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
