# ThreatBridge HTTP API

The map uses this API, and scripts, MCP servers and data tools can too. API version **1**.
Every endpoint is a stable interface (EXT-S2): its paths, parameters and fields stay as they are
described. New endpoints, parameters and response fields can be added without changing the
version; anything removed or changed in meaning raises it and is listed here first. `api_version`
in `GET /healthz` and `GET /api/config` says which version a server speaks.

Every endpoint's parameters, request body and response fields are described in the OpenAPI 3.1
document, [`threatbridge/openapi.json`](../threatbridge/openapi.json), also served at
`GET /api/openapi.json` (D21). It is generated from the code (`python -m threatbridge.apidoc`,
which needs pydantic), and every response the API tests get is checked against it. This page has
what a schema can't say.

## Changes

- **Evidence and version (D31).** `GET /api/evidence` lists the case's evidence files with their
  SHA-256, hashed in the background on the first ask; `GET /api/config` has `version`, the
  tool's own. Additions, so `api_version` stays 1.
- **Accounts on flows (D28).** `GET`/`POST /api/accounts` lists the accounts that made a
  connection's flows. In the case backend each flow of `/api/flows` has `accounts`, each hop of a
  path `accounts`, each connection of a threat line `accounts` (with Windows events), and each
  export row `accounts`; the case summary has `logons`. Additions, so
  `api_version` stays 1.
- **Machines behind addresses (ING-9).** `GET /api/machines` lists every machine (MAC address,
  host name) that held an address, from DHCP; `POST /api/machines` gives, for each host, the one
  at its time and how many held the address in the time range. The case summary in
  `GET /api/config` has `leases`, and `limits.machines`. Additions, so `api_version` stays 1.
- **Beacons and long connections (ATK-12).** `GET`/`POST /api/flagged` lists them. Filters take
  two more words, `beacon` and `long` (`filter.flags` in `GET /api/config`). `GET /api/config`
  has `flagged`, `beacon_score`, `beacon_min`, `long_connection` and `limits.flagged`. Additions,
  so `api_version` stays 1.
- **Who talked to it (ATK-11).** `GET`/`POST /api/contacts`: the inside hosts that exchanged flows
  with an address, a network or a domain name. `GET /api/config` has `internal_nets` (the inside
  networks), `contacts` (whether the endpoint is available) and `limits.contacts`. Additions, so
  `api_version` stays 1.
- **Expansions either side of the anchor (ATK-10).** `GET`/`POST /api/neighbors` takes `time`
  (`before` or `after`; default `before` for `in`, `after` for `out`) and answers with it. A
  saved map's `expand` queries may carry it. An addition, so `api_version` stays 1.
- **Community ID (ING-8).** Each flow in `GET`/`POST /api/flows`, and each flow row of
  `POST /api/export`, has `community_id`: the flow's Community ID (version 1, seed 0), or null
  for ICMP and SCTP. An addition, so `api_version` stays 1.
- **Local mode's login and Host check (D23).** `python -m threatbridge` now needs its login token
  (401 without it) and a `Host` header naming it (421 otherwise). The container, behind mutual
  TLS, is unchanged. The endpoints and their answers are unchanged, so `api_version` stays 1.
- **Self-description (D20-D22).** `api_version` in `GET /healthz` and `GET /api/config`;
  `limits` and `filter` (the filter vocabulary) in `GET /api/config`; `GET`/`POST /api/protocols`;
  `GET /api/openapi.json`; the saved-map format (*The map document*, below).
- **Marks on flows (D15).** `GET /api/compromised` (and every answer about marks) lists in `hosts`
  every marked host, those marked through a marked flow too, each with `direct` and `count`, and
  `time` is when the host was reached. The hosts marked themselves, as before, are in `marked`.
  `DELETE /api/compromised` also removes the marked flows the host is an end of.
- **FTP data connections** carry the protocol `ftp`; Security Onion's `ftp-data` reads as `ftp`.

## Conventions

- **Authentication** in the container is mutual TLS (see the README): a client needs a
  certificate signed by the ThreatBridge CA. `python -m threatbridge` (local mode, plain HTTP)
  needs the login token it printed at start-up instead: send `Authorization: Bearer <token>`, or
  open the printed address once in a browser, which sets a cookie (`tb_token_<port>`). Without
  it the answer is 401. Local mode also answers only requests whose `Host` header names this
  server (`localhost`, `127.0.0.1`, `[::1]`, the listening address, `TB_ALLOWED_HOSTS`); any
  other gets 421 (D23).
- **Fields.** Every answer has exactly the fields its schema lists, those marked required always.
- **Times** in answers are ISO-8601 UTC with milliseconds, e.g. `2024-05-01T12:00:00.000Z`. Times
  you send may also carry an offset (`+02:00`, converted to UTC), no zone (taken as UTC), or be
  epoch seconds or milliseconds (10 to 13 digits).
- **Windows** (`window`) are a number and a unit: `30m`, `24h`, `7d`, `2w` (`s`, `m`, `h`, `d`,
  `w`), at most `max_window` (`TB_MAX_WINDOW`, default `30d`). Default: `default_window`
  (`TB_WINDOW`, `24h`).
- **The time range** (`range_from`, `range_to`, optional, either end open) limits every query that
  takes it: only flows that started inside it count.
- **Filters** (D17), on every query about flows: repeat `filter=` in a query string, or send
  `"filters": [...]` with a `POST`. A flow counts only if it matches every one, or is a marked
  flow. Up to `max_filters`, each up to `limits.filter_length` characters; an expression that
  can't be read is a 400 saying what and where (`GET /api/filter` checks one). Without filters,
  every flow counts.
- **Queries as POST.** Each query that takes filters can also be a `POST` with its parameters in a
  JSON object (text or numbers, the same names), plus `filters` and `marks`: marks to use instead
  of the shared ones (an opened map's own, D19), for what filters never hide and for attack paths
  and suspect connections.
- **Writes** (`POST`, `PUT`, `DELETE`) send a JSON object and need the header `X-ThreatBridge: 1`;
  without it the answer is 403. Browsers cannot add that header to a cross-site request, which is
  what stops other sites from writing through an analyst's certificate.
- **Errors** are JSON: `{"error": "invalid IP address: 'nope'"}`, with the status:

  | Status | When |
  |---|---|
  | 400 | A parameter or the body is invalid; the message says which |
  | 401 | Local mode: no valid login token |
  | 403 | A write without the `X-ThreatBridge` header |
  | 404 | No such saved map |
  | 409 | A map is already saved under that name |
  | 421 | Local mode: the `Host` header names an address this server doesn't answer to |
  | 500 | A shared file (exclude list, compromised hosts, saved map) is not valid JSON; it is left as it is for someone to fix |
  | 501 | The endpoint needs another backend (threat lines, paths and suspect connections need the case backend; PCAP downloads need Security Onion and a SOC API client) |
  | 502 | Elasticsearch or SOC failed or answered unexpectedly |

## Endpoints

Status and settings:

| Endpoint | Methods | |
|---|---|---|
| `/healthz` | GET | Is the service up, which backend, which API version |
| `/api/config` | GET | What a client needs to know: version, limits, filter vocabulary, defaults, what is available |
| `/api/openapi.json` | GET | The OpenAPI document |

Mapping connections:

| Endpoint | Methods | |
|---|---|---|
| `/api/resolve` | GET | Check an IP and settle the anchor time a map starts from |
| `/api/neighbors` | GET, POST | One hop: who connected to a host, or who it connected to, before or after the anchor |
| `/api/accounts` | GET, POST | The accounts that made a connection's flows, from Windows Security events (case backend) |
| `/api/evidence` | GET | The case's evidence files with their SHA-256, hashed in the background: ask until done (case backend) |
| `/api/machines` | GET, POST | Which machine held an address: every one (GET), or the one at each host's time (POST) (case backend) |
| `/api/flagged` | GET, POST | Beacons and long connections (case backend) |
| `/api/contacts` | GET, POST | The inside hosts that talked to an address, a network or a domain name (case backend) |
| `/api/flows` | GET, POST | One page of a connection's flows, oldest first |
| `/api/edge` | GET, POST | One connection, as it would be drawn |
| `/api/protocols` | GET, POST | How many flows carry each protocol in a time range |
| `/api/filter` | GET | Check one filter expression |
| `/api/pivot` | GET | A Security Onion Dashboards query and link |
| `/api/pcap` | POST | A Security Onion flow's packets, from its sensor through SOC |

Threat lines and paths (case backend):

| Endpoint | Methods | |
|---|---|---|
| `/api/threatline` | GET, POST | Hosts and hops time-consistent with a conversation |
| `/api/paths` | GET, POST | Every time-respecting path between two hosts, or between the marked hosts |
| `/api/suspect` | POST | What the marks keep of the drawn connections |
| `/api/export` | POST | The marked hosts, and the marked and suspect flows on the drawn connections |

Shared lists:

| Endpoint | Methods | |
|---|---|---|
| `/api/excludes` | GET, POST, DELETE | The exclude list: read it, add an entry, remove one |
| `/api/compromised` | GET, POST, DELETE, PUT | The marks: read them, mark a host, unmark one, replace them all |
| `/api/compromised/flows` | POST, DELETE | Mark a flow, unmark one |

Saved maps:

| Endpoint | Methods | |
|---|---|---|
| `/api/sessions` | GET, POST, DELETE | The saved maps (or one, by `name`): list, save, delete |

## The filter language

The language is D17 in the requirements. `filter` in `GET /api/config` gives its vocabulary,
taken from the parser itself: the fields with what they compare, the kinds of value, the
operators' spellings and the protocol names. Names are case-sensitive: fields in lower case,
protocols in capitals. The grammar:

```
expression  = disjunction ;
disjunction = conjunction , { ( "OR" | "||" ) , conjunction } ;
conjunction = negation , { ( "AND" | "&&" ) , negation } ;
negation    = ( "NOT" | "!" ) , negation | term ;
term        = "(" , disjunction , ")" | comparison | flag | protocol ;
flag        = "beacon" | "long" ;
comparison  = field , [ "==" | "!=" | "<" | ">" | "<=" | ">=" ] , value ;   (* none: == *)
value       = number | number , "-" , number | address | transport | time ;
protocol    = a name in "protocols", or another Zeek service in capitals ;
```

## Marks and suspect connections

The marks (D15) are shared by every analyst. A host is marked itself, with an optional time and
note, or through a marked flow it is an end of. `hosts` in every answer about marks lists every
marked host either way: its `count` is its own mark plus its marked flows, and its `time` is when
it was reached, the earliest known of its own mark's time and those flows' starts. `marked` lists
the hosts marked themselves. Unmarking a host also unmarks the flows it is an end of; marking a
host or flow again replaces its mark. `PUT /api/compromised` replaces every mark at once, or
nothing if any is invalid; the map does it to share an opened map's marks, after asking.
`version` changes whenever the marks do, so a client can poll for other analysts' changes.

`POST /api/suspect` says what the marks keep of the connections on a map (D16). Connections are
grouped into parts of the map, the hosts the connections sent join. In a part with no marked
host a connection is `unaffected`. In a part with marks, a flow is suspect when it lies on a
time-ordered line, by the rules of attack paths, that ends at a marked host (no later than it
was reached) or starts at one (within the window after). A connection that carries no marked or
suspect flow is `hidden`; one that does is `kept`, with the
counts, times, ports and protocols of those flows only, and `within`, the intervals they started
in, which `POST /api/flows` takes to list them. `POST /api/export` gives the same flows, and every
marked host, for a CSV export.

## The map document

What the map saves (D19, D22), with `POST /api/sessions` and in a file: a stable format,
`MapDocument` in the OpenAPI document. Version 2 holds the map's hosts where they were, its
connections with their counts as drawn, the highlights, the view, the toolbar and the paths
form, the filters, the map's own marks, and the queries it was built from, in order, so that it
can run them again with other filters. Version 1 was saved before filters and marks: it has no
filters, marks or queries, and opening it converts its hosts and connections into queries.

Opening a map reads only what it understands and leaves out what is malformed, so another tool
may write less than the schema allows; only the version, the hosts' ids and the connections'
ends are required. The server keeps a map as it is sent, without checking it against the schema.
