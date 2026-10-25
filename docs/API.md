# ThreatBridge HTTP API

The map uses this API, and scripts can too. Every endpoint below is a stable interface (EXT-S2):
its paths, parameters and the fields listed stay as described. New endpoints, parameters and
response fields can be added; anything removed or changed in meaning is listed here first, with
the release that changes it.

## Conventions

- **Authentication** is mutual TLS (see the README): a client needs a certificate signed by the
  ThreatBridge CA. `python -m threatbridge` serves plain HTTP on 127.0.0.1 for local use only.
- **Times** are ISO-8601 UTC with milliseconds, e.g. `2024-05-01T12:00:00.000Z`. Times you send
  may also carry an offset (`+02:00`, converted to UTC), no zone (taken as UTC), or be epoch
  seconds or milliseconds (10 to 13 digits).
- **Windows** (`window`) are a number and a unit: `30m`, `24h`, `7d`, `2w` (`s`, `m`, `h`, `d`,
  `w`), at most `TB_MAX_WINDOW` (default `30d`). Default: `TB_WINDOW` (`24h`).
- **The time range** (`range_from`, `range_to`, optional, either end open) limits every query that
  takes it: only flows that started inside it count.
- **Hop limits** (`hops`) are 1 to 20. Default: `TB_THREAT_HOPS` (6).
- **Writes** (`POST`, `DELETE`) send a JSON object and need the header `X-ThreatBridge: 1`; without
  it the answer is 403. Browsers cannot add that header to a cross-site request, which is what
  stops other sites from writing through an analyst's certificate.
- **Errors** are JSON: `{"error": "invalid IP address: 'nope'"}`, with the status:

  | Status | When |
  |---|---|
  | 400 | A parameter or the body is invalid; the message says which |
  | 403 | A write without the `X-ThreatBridge` header |
  | 404 | No such saved map |
  | 409 | A map is already saved under that name |
  | 500 | A shared file (exclude list, compromised hosts, saved map) is not valid JSON; it is left as it is for someone to fix |
  | 501 | The endpoint needs another backend (threat lines and paths need the case backend; PCAP downloads need Security Onion and a SOC API client) |
  | 502 | Elasticsearch or SOC failed or answered unexpectedly |

## Status and settings

### `GET /healthz`

`{"status": "ok", "backend": "elastic" | "case" | "demo"}`.

### `GET /api/config`

What the map needs to know about this server:

| Field | |
|---|---|
| `backend` | `elastic`, `case` or `demo` |
| `default_window`, `max_window` | `TB_WINDOW`, `TB_MAX_WINDOW` |
| `default_limit`, `max_limit` | peers per expansion: `TB_LIMIT`, `TB_MAX_LIMIT` |
| `directions` | `{"in": "inbound-past", "out": "outbound-future"}` |
| `orders` | `["top", "bottom"]` |
| `rare_scan_cap` | `TB_RARE_SCAN_CAP` |
| `soc_pivots` | whether SOC pivots and PCAP links apply (not for the case backend) |
| `analysis` | whether threat lines and paths are available (case backend) |
| `threat_hops` | the default hop limit |
| `live_dns` | `TB_LIVE_DNS` |
| `pcap_download` | whether `POST /api/pcap` is available |
| `case` | case backend: `{"flows", "hosts", "start", "end", "dns_names"}` (`start`/`end` null for an empty case); otherwise null |

## Mapping connections

### `GET /api/resolve`

Checks an IP and settles the anchor time a map starts from.

| Parameter | |
|---|---|
| `ip` | required |
| `ts` | the IOC time; blank: see below |
| `direction` | `in` (default) or `out`: with no `ts`, inbound looks back from the end of what can be shown and outbound forward from its start (the time range, then the case's data), else now |
| `range_from`, `range_to` | the time range |

`{"ip": "10.0.0.9", "anchor": "2024-05-01T13:09:50.001Z"}`

### `GET /api/neighbors`

One hop: who connected to `ip` in the window before the anchor (`in`), or who it connected to in
the window after it (`out`).

| Parameter | |
|---|---|
| `ip` | required |
| `direction` | `in` (default) or `out` |
| `ts` | the anchor; blank: now |
| `window` | per hop |
| `limit` | peers to return, 1 to `max_limit` (larger values are capped) |
| `order` | `top` (most connections, default) or `bottom` (rarest) |
| `range_from`, `range_to` | the time range |

```json
{"ip": "10.0.0.9", "direction": "in", "order": "top", "anchor": "2024-05-01T13:00:00.000Z",
 "start": "2024-04-30T13:00:00.000Z", "end": "2024-05-01T13:00:00.000Z",
 "peers": [{"peer": "10.0.0.5", "count": 1, "first_seen": "2024-05-01T12:10:00.000Z",
            "last_seen": "2024-05-01T12:10:00.000Z", "ports": [445]}],
 "distinct_peers": 2, "truncated": false}
```

`ports` are the most used destination ports (up to 5). `distinct_peers` may be null (Elasticsearch
estimate unavailable). `truncated`: the rarest scan stopped at `rare_scan_cap` distinct peers, so
the bottom list may be incomplete. Hosts on the exclude list are left out. When the window and
the time range don't overlap, `start` is after `end` and `peers` is empty.

### `GET /api/flows`

One page of a connection's flows, oldest first.

| Parameter | |
|---|---|
| `src`, `dst` | required: initiator and responder |
| `from` | required: the start of the first flow wanted |
| `to` | the start of the last one; default `from` |
| `offset` | default 0 |
| `limit` | 1 to 500, default 50 |
| `range_from`, `range_to` | the time range |

```json
{"src": "10.0.0.5", "dst": "10.0.0.9", "start": "2024-05-01T12:10:00.000Z",
 "end": "2024-05-01T12:10:00.000Z", "offset": 0, "total": 1,
 "flows": [{"start": "2024-05-01T12:10:00.000Z", "duration": 0.001, "sport": 50001, "dport": 445,
            "proto": "tcp", "packets": 2, "bytes": 80}]}
```

`duration` is in seconds; any field but `start` may be null. Flows from Security Onion also have
`id` (the connection log's Elasticsearch ID, for `POST /api/pcap`) and `soc_pcap` (SOC's link
that has the sensor extract the flow's packets). Security Onion lists at most the first 10,000
flows of a connection (`offset + limit` past that is a 400); narrow the time range for later ones.

### `GET /api/pivot`

A Security Onion Dashboards filter (OQL) and its URL.

| Parameter | |
|---|---|
| `a` | required |
| `b` | with it: every conversation between `a` and `b`, either direction; without: everything to or from `a` |
| `until` | with `b`: no later than this (the IOC time) |
| `range_from`, `range_to` | the time range |

`{"query": "((source.ip:\"10.0.0.5\" AND destination.ip:\"10.0.0.9\") OR (...)) AND @timestamp:[* TO \"2024-05-01T12:00:00.000Z\"] | groupby source.ip destination.ip destination.port", "url": "https://securityonion/#/dashboards?q=..."}`

The time clause is left out with `TB_PIVOT_TIME_CLAUSE=false`.

### `POST /api/pcap`

The packets of one Security Onion flow, extracted by the sensor that saw it, through SOC's Connect
API. Needs a SOC API client (`TB_SOC_CLIENT_ID`, `TB_SOC_CLIENT_SECRET`; Security Onion Pro); else
501. The request waits for the sensor, up to `TB_PCAP_TIMEOUT` seconds.

Body: `{"id": "<the flow's id>", "time": "<the flow's start>"}`.

The answer is the PCAP file itself (`application/vnd.tcpdump.pcap`, as an attachment), or a 502
saying why the sensor could not provide it, with the SOC job's link where there is one.

## Threat lines and paths (case backend)

### `GET /api/threatline`

Everything time-consistent with the conversation `a` → `b`: who could have reached `a` before it,
and where `b` could have gone after it.

| Parameter | |
|---|---|
| `a`, `b` | required |
| `from` | required: the conversation's first flow |
| `to` | its last flow; default `from` |
| `window`, `hops` | per hop |
| `range_from`, `range_to` | the time range |

`{"a", "b", "nodes": [...], "edges": [...], "truncated": false}`. Each node is
`{"id", "role", "time", "hops"}`: `role` is `selected` (`a` and `b`), `up` (earlier), `down`
(later) or `both`; `time` is when the line reached it; `hops` how many it took. Each edge is
`{"source", "target", "role", "count", "first_seen", "last_seen", "ports"}` for the flows on that
host pair that fit the line. `truncated`: a direction stopped at `TB_THREAT_MAX_HOSTS` hosts.
A 400 says when there are no flows from `a` to `b` in that time.

### `GET /api/paths`

Without `src` and `dst`: the paths between each pair of compromised hosts, the first 10 per pair,
shortest first:

`{"pairs": [{"from": "203.0.113.66", "to": "10.0.0.20", "paths": [...], "truncated": false}]}`

With them: every path from `src` to `dst`, up to `TB_MAX_PATHS`:

| Parameter | |
|---|---|
| `src`, `dst` | the two hosts (both or neither) |
| `src_time`, `dst_time` | optional IOC times: the first hop leaves `src` within the window after `src_time`; the path reaches `dst` by `dst_time` |
| `window`, `hops` | per hop |
| `range_from`, `range_to` | the time range |

`{"src": "10.0.0.5", "dst": "10.0.0.20", "paths": [...], "truncated": false}`

A path is `{"hops": [{"source", "target", "start", "sport", "dport", "proto", "packets",
"bytes"}, ...]}`: one chain of flows that proves it. `truncated`: there are more than listed.

## Shared lists

### `GET /api/excludes`

`{"entries": ["10.0.0.0/24", "updates.example.com"], "resolved": {...}}`. For each domain name,
`resolved` gives `{"capture": [...], "dns": [...], "error": null}`: the addresses seen in DNS answers
in the evidence (pcaps, or Security Onion's DNS records), those from a live lookup, and what went
wrong, if anything.

### `POST /api/excludes`

Body `{"entry": "10.0.0.53" | "10.0.0.0/24" | "updates.example.com" | "*.example.com"}`. Answers
as `GET`, plus `entry`: the entry as stored (CIDRs normalised, names lower-cased).

### `DELETE /api/excludes`

Body `{"entry": ...}`. Answers as `GET`.

### `GET /api/compromised`

`{"hosts": [{"ip": "10.0.0.20", "time": "2024-05-01T13:00:00.000Z", "note": "EDR"}]}`; `time` is
null when unknown. Sorted by time, unknown first.

### `POST /api/compromised`

Body `{"ip", "time" (optional; blank or null: unknown), "note" (optional, up to 500 characters)}`.
Marking a host again replaces its entry. Answers as `GET`.

### `DELETE /api/compromised`

Body `{"ip"}`. Answers as `GET`.

## Saved maps

### `GET /api/sessions`

`{"sessions": [{"name": "incident 42", "saved": "2024-05-02T09:00:00.000Z"}]}`, the most recently
saved first. With `?name=`: that map, `{"name", "saved", "map"}`, or 404.

### `POST /api/sessions`

Body `{"name", "map", "overwrite" (optional)}`. `name`: 1 to 100 printable characters. `map`: a
JSON object of at most 2 MB, kept as it is (the map's own format, `version` 1). An existing name
is a 409 unless `overwrite` is `true`. Answers `{"name", "saved", "sessions"}`.

### `DELETE /api/sessions`

Body `{"name"}`. Answers `{"sessions"}`, or 404.
