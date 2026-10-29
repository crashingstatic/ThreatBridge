"""The API described for programs (D21): the shape of every request and response as a pydantic
model, put together with the app's routes into an OpenAPI 3.1 document. Only for writing and
testing that document: the service serves the file this writes and never imports this module,
so it runs without pydantic.

    python -m threatbridge.apidoc        # writes threatbridge/openapi.json
"""
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Optional, Union, get_args

from pydantic import BaseModel, ConfigDict, Field, create_model
from pydantic.json_schema import GenerateJsonSchema, models_json_schema

from .app import API_VERSION, OPENAPI, create_app
from .backends import DemoBackend
from .config import Config as Settings


class _Schema(GenerateJsonSchema):
    """JSON Schema without pydantic's titles and defaults: the descriptions say what a default is."""

    def field_title_should_be_set(self, schema):
        return False

    def default_schema(self, schema):
        return self.generate_inner(schema["schema"])


class Shape(BaseModel):
    """An object with exactly the fields listed (no others allowed)."""
    model_config = ConfigDict(extra="forbid")


def example(doc):
    return ConfigDict(json_schema_extra={"examples": [doc]})


# ---- values ----------------------------------------------------------------------------------

Time = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")]   # as answers give it
Backend = Literal["elastic", "case", "demo"]
Direction = Literal["in", "out"]
Order = Literal["top", "bottom"]
Protocols = Annotated[list[str], Field(description=(
    "every protocol the flows carry, sorted: named as Zeek names its services (`dns`, `http`, `smb`, `ssl` "
    "for TLS, ...), plus `icmp`, and `unknown` for flows nothing identified. Security Onion gives Zeek's own; "
    "case files are identified from the payload, then by well-known port"))]
Ports = Annotated[list[int], Field(description="the most used destination ports, up to 5")]
Filters = Annotated[list[str], Field(description="filter expressions (D17), combined with AND")]
Value = Union[str, float]           # a query's parameter in a POST body: text or a number


# ---- status and settings ---------------------------------------------------------------------

class Error(Shape):
    """What went wrong; the status says what kind of error."""
    error: str = Field(description="e.g. invalid IP address: 'nope'")


class Health(Shape):
    status: Literal["ok"]
    backend: Backend
    api_version: int = Field(description="the API version this server speaks (D20)")


class Limits(Shape):
    """Every bound a request is held to, besides max_window, max_limit and max_filters."""
    hops: int = Field(description="hops in a threat line or path")
    threat_line_hosts: int = Field(description="hosts a threat line reaches in each direction (TB_THREAT_MAX_HOSTS)")
    paths: int = Field(description="paths between two hosts (TB_MAX_PATHS)")
    paths_per_pair: int = Field(description="attack paths per pair of marked hosts, without src and dst")
    flow_page: int = Field(description="flows in one page of a connection's flow list")
    connection_flows: Optional[int] = Field(description=(
        "Security Onion: how far into a connection's flows a page can reach (offset + limit); null: no bound"))
    filter_length: int = Field(description="characters in a filter expression")
    filter_depth: int = Field(description="nested parentheses or NOTs in a filter expression")
    edges: int = Field(description="drawn connections sent to /api/suspect or /api/export")
    within: int = Field(description="intervals in a flow list's within")
    export_flows: int = Field(description="flows in an export")
    marks: int = Field(description="hosts, and flows, in a list of marks")
    note: int = Field(description="characters in a mark's note")
    saved_maps: int = Field(description="saved maps")
    map_bytes: int = Field(description="bytes in a saved map")
    map_name: int = Field(description="characters in a saved map's name")


class FilterField(Shape):
    """A field a filter compares."""
    name: str
    kind: Literal["port", "count", "seconds", "address", "transport", "time"] = Field(
        description="what its values are (see kinds)")
    comparisons: list[Literal["==", "!=", "<", ">", "<=", ">="]]
    ranges: bool = Field(description="whether it takes a range, a-b")
    either_end: bool = Field(description="whether it tests both ends of a flow (port, host)")


class FilterKinds(Shape):
    """What each kind of value is."""
    port: str
    count: str
    seconds: str
    address: str
    transport: str
    time: str


class FilterOperators(Shape):
    """How each operator is spelt."""
    not_: list[str] = Field(alias="not")
    and_: list[str] = Field(alias="and")
    or_: list[str] = Field(alias="or")


class FilterVocabulary(Shape):
    """The filter language (D17), taken from the parser itself."""
    fields: list[FilterField]
    kinds: FilterKinds
    operators: FilterOperators
    protocols: list[str] = Field(description=(
        "the protocol names, as the map shows them; any other Zeek service in capitals works too"))
    grammar: str = Field(description="the grammar, in EBNF")


class CaseSummary(Shape):
    """The case's evidence."""
    flows: int
    hosts: int
    start: Optional[Time] = Field(description="the first flow's start; null for an empty case")
    end: Optional[Time] = Field(description="the last flow's start; null for an empty case")
    dns_names: int = Field(description="names in the evidence's DNS answers")


class Directions(Shape):
    in_: str = Field(alias="in")
    out: str


class Config(Shape):
    """What a client needs to know about this server (D20)."""
    api_version: int = Field(description="the API version this server speaks")
    limits: Limits
    filter: FilterVocabulary
    default_window: str = Field(description="a query's window when it gives none (TB_WINDOW)")
    max_window: str = Field(description="the longest window (TB_MAX_WINDOW)")
    default_limit: int = Field(description="peers per expansion when a query gives none (TB_LIMIT)")
    max_limit: int = Field(description="the most peers per expansion (TB_MAX_LIMIT); larger limits are capped")
    directions: Directions
    orders: list[Order]
    backend: Backend
    rare_scan_cap: int = Field(description="distinct peers the rarest scan looks at (TB_RARE_SCAN_CAP)")
    soc_pivots: bool = Field(description="whether SOC pivots and PCAP links apply (not for the case backend)")
    analysis: bool = Field(description="whether threat lines and paths are available (case backend)")
    threat_hops: int = Field(description="the default hop limit (TB_THREAT_HOPS)")
    suspects: bool = Field(description=(
        "whether marks hide what isn't on a line through them (POST /api/suspect; case backend)"))
    marks_poll: int = Field(description="seconds between the map's checks for other analysts' marks")
    protocol_names: dict[str, str] = Field(description=(
        'how the map names each protocol: {"ssl": "TLS", "krb": "Kerberos", ...}; others in capitals'))
    max_filters: int = Field(description="filters at once")
    live_dns: bool = Field(description="whether domain names on the exclude list are also looked up (TB_LIVE_DNS)")
    pcap_download: bool = Field(description="whether POST /api/pcap is available")
    case: Optional[CaseSummary] = Field(description="the case backend's evidence; otherwise null")


# ---- mapping connections ---------------------------------------------------------------------

class ProtocolCount(Shape):
    protocol: str = Field(description="Zeek's name, as in other answers")
    name: str = Field(description="what a filter writes")
    flows: int


class ProtocolCounts(Shape):
    model_config = example({"start": None, "end": None, "protocols": [
        {"protocol": "smb", "name": "SMB", "flows": 4}, {"protocol": "ssl", "name": "TLS", "flows": 1}]})
    start: Optional[Time] = Field(description="the start of the range counted; null: open")
    end: Optional[Time] = Field(description="its end; null: open")
    protocols: list[ProtocolCount] = Field(description="most flows first")


class Resolved(Shape):
    model_config = example({"ip": "10.0.0.9", "anchor": "2024-05-01T13:09:50.001Z"})
    ip: str
    anchor: Time = Field(description="the time the map starts from")


class Peer(Shape):
    peer: str
    count: int = Field(description="its flows")
    first_seen: Optional[Time]
    last_seen: Optional[Time]
    ports: Ports
    protocols: Protocols


class Neighbors(Shape):
    model_config = example({
        "ip": "10.0.0.9", "direction": "in", "order": "top", "anchor": "2024-05-01T13:00:00.000Z",
        "start": "2024-04-30T13:00:00.000Z", "end": "2024-05-01T13:00:00.000Z",
        "peers": [{"peer": "10.0.0.5", "count": 1, "first_seen": "2024-05-01T12:10:00.000Z",
                   "last_seen": "2024-05-01T12:10:00.000Z", "ports": [445], "protocols": ["smb"]}],
        "distinct_peers": 2, "truncated": False})
    ip: str
    direction: Direction
    order: Order
    anchor: Time
    start: Time = Field(description="the window's start; after end when the window and the time range don't overlap")
    end: Time
    peers: list[Peer]
    distinct_peers: Optional[int] = Field(description="null: Elasticsearch's estimate is unavailable")
    truncated: bool = Field(description=(
        "the rarest scan stopped at rare_scan_cap distinct peers, so the bottom list may be incomplete"))


class Flow(Shape):
    start: Time
    duration: Optional[float] = Field(description="seconds")
    sport: Optional[int]
    dport: Optional[int]
    proto: Optional[str]
    packets: Optional[int]
    bytes: Optional[int]
    protocols: Protocols
    id: str = Field(None, description="Security Onion: the connection log's Elasticsearch ID, for POST /api/pcap")
    soc_pcap: str = Field(None, description="Security Onion: SOC's link that has the sensor extract the flow's packets")


class Flows(Shape):
    model_config = example({
        "src": "10.0.0.5", "dst": "10.0.0.9", "start": "2024-05-01T12:10:00.000Z",
        "end": "2024-05-01T12:10:00.000Z", "offset": 0, "total": 1,
        "flows": [{"start": "2024-05-01T12:10:00.000Z", "duration": 0.001, "sport": 50001, "dport": 445,
                   "proto": "tcp", "packets": 2, "bytes": 80, "protocols": ["smb"]}]})
    src: str
    dst: str
    start: Time
    end: Time
    offset: int
    total: int = Field(description="the connection's flows in [start, end]")
    flows: list[Flow]


class Edge(Shape):
    """One connection, as the map draws it."""
    source: str
    target: str
    count: int = Field(description="its flows; 0 for none")
    first_seen: Optional[Time] = Field(description="null for no flows")
    last_seen: Optional[Time]
    ports: Ports
    protocols: Protocols


class CheckedFilter(Shape):
    model_config = example({"filter": "(SMB OR TLS) AND sport == 42000"})
    filter: str = Field(description="the expression's canonical form")


class Pivot(Shape):
    query: str = Field(description="the Dashboards filter, in OQL")
    url: str = Field(description="the Dashboards link")


class PcapRequest(Shape):
    id: str = Field(description="the flow's id, from its flow list")
    time: str = Field(description="the flow's start")


# ---- threat lines and paths ------------------------------------------------------------------

class LineNode(Shape):
    id: str
    role: Literal["selected", "up", "down", "both"] = Field(description="selected (a and b), up (earlier), down (later)")
    time: Time = Field(description="when the line reached it")
    hops: int = Field(description="how many hops it took")


class LineEdge(Edge):
    """A host pair's flows that fit the line."""
    role: Literal["selected", "up", "down"]


class ThreatLine(Shape):
    a: str
    b: str
    nodes: list[LineNode]
    edges: list[LineEdge]
    truncated: bool = Field(description="a direction stopped at limits.threat_line_hosts hosts")


class Hop(Shape):
    source: str
    target: str
    start: Time
    sport: Optional[int]
    dport: Optional[int]
    proto: str
    packets: Optional[int]
    bytes: Optional[int]
    protocols: Protocols


class Path(Shape):
    """One chain of flows that proves the path."""
    hops: list[Hop]


class PathsBetween(Shape):
    src: str
    dst: str
    paths: list[Path] = Field(description="shortest first")
    truncated: bool = Field(description="there are more than listed")


class PairPaths(Shape):
    from_: str = Field(alias="from")
    to: str
    paths: list[Path] = Field(description="shortest first")
    truncated: bool = Field(description="there are more than listed")


class AttackPaths(Shape):
    pairs: list[PairPaths] = Field(description="each pair of marked hosts with a path between them")


class DrawnEdge(Shape):
    """A connection on the map, with the span drawn."""
    source: str
    target: str
    from_: str = Field(alias="from")
    to: str = Field(None, description="default from")


class OtherEdge(Shape):
    source: str
    target: str
    status: Literal["unaffected", "hidden"] = Field(description=(
        "unaffected: no marked host is in its part of the map (hosts joined by the connections sent); "
        "hidden: in a part with marks, it carries no marked or suspect flow"))


class KeptEdge(Edge):
    """A connection that carries marked or suspect flows: the counts, times, ports and protocols are
    those flows' only."""
    status: Literal["kept"]
    marked: int = Field(description="its marked flows")
    suspect: int = Field(description="its suspect flows")
    within: list[tuple[Time, Time]] = Field(description="the intervals they started in, to list them (POST /api/flows)")


class Suspects(Shape):
    edges: list[Union[KeptEdge, OtherEdge]] = Field(description="one per connection sent")


class ExportHost(Shape):
    ip: str
    time: Optional[Time]
    note: str
    count: int
    marked: Literal["direct", "flows", "both"] = Field(description="marked itself, through marked flows, or both")


class ExportFlow(Shape):
    start: Time
    end: Optional[Time]
    src: str
    sport: Optional[int]
    dst: str
    dport: Optional[int]
    proto: Optional[str]
    protocols: Protocols
    packets: Optional[int]
    bytes: Optional[int]
    status: Literal["marked", "suspect"]


class Export(Shape):
    hosts: list[ExportHost] = Field(description="every marked host")
    flows: list[ExportFlow] = Field(description="each marked or suspect flow on the connections sent")
    truncated: bool = Field(description="there were more than limits.export_flows flows")


# ---- shared lists ----------------------------------------------------------------------------

class Resolution(Shape):
    capture: list[str] = Field(description="addresses in DNS answers in the evidence (pcaps, or Security Onion's DNS records)")
    dns: list[str] = Field(description="addresses from a live lookup")
    error: Optional[str] = Field(description="what went wrong, if anything")


class Excludes(Shape):
    entries: list[str]
    resolved: dict[str, Resolution] = Field(description="for each domain name on the list")
    entry: str = Field(None, description="adding one: the entry as stored (CIDRs normalised, names lower-cased)")


class ExcludeEntry(Shape):
    entry: str = Field(description="an IP, a CIDR, a domain name or *.domain")


class HostMark(Shape):
    ip: str
    time: Optional[Time]
    note: str


class FlowMark(Shape):
    src: str
    dst: str
    start: Time = Field(description="to the millisecond, as flow lists show it")
    sport: int
    dport: int
    proto: str
    note: str


class HostMarkIn(Shape):
    ip: str
    time: Union[str, float, None] = Field(None, description="ISO-8601 or epoch; blank or null: unknown")
    note: Optional[str] = Field(None, description="up to limits.note characters")


class FlowMarkIn(Shape):
    """A flow, as its connection's flow list gives it."""
    src: str
    dst: str
    start: Union[str, float] = Field(description="as the flow list shows it, to the millisecond")
    sport: int
    dport: int
    proto: str
    note: Optional[str] = Field(None, description="up to limits.note characters")


class Marks(Shape):
    """Marks to use instead of the shared ones (an opened map's own, D19)."""
    hosts: list[HostMarkIn] = None
    flows: list[FlowMarkIn] = None


class HostToUnmark(Shape):
    ip: str


class MarkedHost(Shape):
    ip: str
    time: Optional[Time] = Field(description=(
        "when it was reached: the earliest known of its own mark's time and its marked flows' starts; null: unknown"))
    note: str
    direct: bool = Field(description="it is marked itself")
    count: int = Field(description="its own mark, plus the marked flows it is an end of")


class MarksView(Shape):
    """The marks (D15), shared by every analyst."""
    model_config = example({
        "hosts": [{"ip": "10.0.0.20", "time": "2024-05-01T13:00:00.000Z", "note": "EDR", "direct": True, "count": 2}],
        "marked": [{"ip": "10.0.0.20", "time": "2024-05-01T13:00:00.000Z", "note": "EDR"}],
        "flows": [{"src": "10.0.0.9", "dst": "10.0.0.20", "start": "2024-05-01T13:20:00.000Z", "sport": 50001,
                   "dport": 3389, "proto": "tcp", "note": ""}],
        "version": "5f0c2a91d0e4b7c3"})
    hosts: list[MarkedHost] = Field(description=(
        "every marked host, those marked through a marked flow too, sorted by time, unknown first"))
    marked: list[HostMark] = Field(description="the hosts marked themselves")
    flows: list[FlowMark] = Field(description="the marked flows")
    version: str = Field(description="changes whenever the marks do")


# ---- saved maps ------------------------------------------------------------------------------

class Session(Shape):
    name: str
    saved: Time


class Sessions(Shape):
    sessions: list[Session] = Field(description="the most recently saved first")


class SavedMap(Shape):
    name: str
    saved: Time
    map: dict[str, Any] = Field(description="as it was saved; the map saves a MapDocument")


class SaveResult(Shape):
    name: str
    saved: Time
    sessions: list[Session]


class MapToSave(Shape):
    name: str = Field(description="1 to limits.map_name printable characters")
    map: dict[str, Any] = Field(description="up to limits.map_bytes, kept as it is; the map saves a MapDocument")
    overwrite: bool = Field(None, description="replace a map saved under that name; otherwise that is a 409")


class MapName(Shape):
    name: str


class Position(Shape):
    x: float
    y: float


class MapNode(Shape):
    """A host, where it was."""
    id: Annotated[str, Field(min_length=1)]
    position: Position = None
    classes: list[str] = Field(None, description=(
        "the highlights (up, down, line-selected, faded, attack, route), and other classes, which opening a map ignores"))
    anchor: str = None
    root: bool = None
    depth: float = None
    expandedIn: bool = None
    expandedOut: bool = None


class MapEdge(Shape):
    """A connection, as drawn."""
    source: str
    target: str
    direction: Direction = None
    count: float = None
    ports: list[int] = None
    protocols: list[str] = None
    classes: list[str] = None
    first_seen: str = None
    last_seen: str = None


class MapView(Shape):
    zoom: float
    pan: Position


class NodeData(Shape):
    anchor: str = None
    root: bool = None
    depth: float = None
    expandedIn: bool = None
    expandedOut: bool = None


class MapQuery(Shape):
    """A query the map was built from, with the fields that query took."""
    op: Literal["root", "expand", "threatline", "routes", "remove", "node", "edge"] = Field(description=(
        "node and edge: a version 1 map's hosts and connections, as converted"))
    ip: str = None
    ts: str = None
    direction: str = None
    window: str = None
    limit: str = None
    order: str = None
    a: str = None
    b: str = None
    from_: str = Field(None, alias="from")
    to: str = None
    src: str = None
    dst: str = None
    src_time: str = None
    dst_time: str = None
    id: str = None
    source: str = None
    target: str = None
    anchor: Optional[str] = None
    data: NodeData = None


Setting = Literal["ip", "ts", "direction", "window", "range-from", "range-to", "order", "limit", "route-src",
                  "route-src-time", "route-dst", "route-dst-time"]


class MapDocument(Shape):
    """A saved map (D19, D22): its hosts where they were, its connections with their counts as drawn,
    the highlights (classes), the view, the toolbar, the filters, its own marks and the queries it was
    built from, in order. The map reads only what it understands and leaves out what is malformed."""
    version: Literal[1, 2] = Field(description="1: saved before filters and marks; it has no filters, marks or queries")
    iocTime: Optional[str] = Field(None, description="the IOC host's anchor")
    settings: dict[Setting, str] = Field(None, description="the toolbar and the paths form: each field's text, by its element id")
    nodes: list[MapNode]
    edges: list[MapEdge]
    view: MapView = None
    filters: list[str] = None
    marks: Marks = None
    queries: list[MapQuery] = Field(None, description="in order, to run again with other filters")


# ---- query parameters ------------------------------------------------------------------------

RangeFrom = Annotated[str, Field(description="the start of the analyst's time range: only flows that started in it count")]
RangeTo = Annotated[str, Field(description="the end of the analyst's time range")]
Filter = Annotated[list[str], Field(description="a filter expression (D17); repeat for several, combined with AND")]
Window = Annotated[str, Field(pattern=r"^\s*\d+\s*[smhdwSMHDW]\s*$", description=(
    "per hop: a number and a unit (s, m, h, d, w), at most max_window; default default_window"))]
Hops = Annotated[int, Field(description="the hop limit, 1 to limits.hops; default threat_hops")]
From = Annotated[str, Field(alias="from", description="the start of the first flow wanted")]
To = Annotated[str, Field(description="the start of the last; default from")]


class ProtocolsQuery(BaseModel):
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class ResolveQuery(BaseModel):
    ip: str = Field(description="an IP address")
    ts: str = Field(None, description="the IOC time; blank: see direction")
    direction: Direction = Field(None, description=(
        "with no ts, in (the default) looks back from the end of what can be shown and out forward from its "
        "start: the time range, then the case's data, else now"))
    range_from: RangeFrom = None
    range_to: RangeTo = None


class NeighborsQuery(BaseModel):
    ip: str = Field(description="the host")
    direction: Direction = Field(None, description="in (the default): who connected to it before the anchor; out: who it connected to after")
    ts: str = Field(None, description="the anchor; blank: now")
    window: Window = None
    limit: int = Field(None, description="peers to return, 1 to max_limit (larger values are capped); default default_limit")
    order: Order = Field(None, description="top (most connections, the default) or bottom (rarest)")
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class FlowsQuery(BaseModel):
    src: str = Field(description="the initiator")
    dst: str = Field(description="the responder")
    from_: From
    to: To = None
    offset: int = Field(None, description="default 0")
    limit: int = Field(None, description="1 to limits.flow_page, default 50")
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class EdgeQuery(BaseModel):
    src: str = Field(description="the initiator")
    dst: str = Field(description="the responder")
    from_: From
    to: To = None
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class FilterQuery(BaseModel):
    filter: str = Field(description="the expression")


class PivotQuery(BaseModel):
    a: str = Field(description="a host")
    b: str = Field(None, description="the other host: every conversation between the two, either direction")
    until: str = Field(None, description="with b: the IOC time; the query ends there")
    range_from: RangeFrom = None
    range_to: RangeTo = None


class ThreatLineQuery(BaseModel):
    a: str = Field(description="the conversation's initiator")
    b: str = Field(description="its responder")
    from_: Annotated[str, Field(alias="from", description="the conversation's first flow")]
    to: Annotated[str, Field(description="its last flow; default from")] = None
    window: Window = None
    hops: Hops = None
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class PathsQuery(BaseModel):
    src: str = Field(None, description="from this host; with neither src nor dst, the paths between the marked hosts")
    dst: str = Field(None, description="to this host")
    src_time: str = Field(None, description="src's IOC time: the first hop leaves src within the window after it")
    dst_time: str = Field(None, description="dst's IOC time: the path reaches dst by then")
    window: Window = None
    hops: Hops = None
    range_from: RangeFrom = None
    range_to: RangeTo = None
    filter: Filter = None


class SessionsQuery(BaseModel):
    name: str = Field(None, description="a saved map's name: that map")


class MarkedQuery(Shape):
    """The connections drawn, and the query's other parameters (text or numbers)."""
    edges: list[DrawnEdge] = Field(description="up to limits.edges")
    window: Value = None
    hops: Value = None
    range_from: Value = None
    range_to: Value = None
    filters: Filters = None
    marks: Marks = None


# ---- the endpoints ---------------------------------------------------------------------------

PCAP = "application/vnd.tcpdump.pcap"


@dataclass(frozen=True)
class Endpoint:
    """What one view (by its name in the app) takes and answers. A view serving GET and POST
    takes `query` as parameters, and in a POST as a JSON object with filters and marks."""
    summary: str
    ok: Any                     # a model, a Union of models, or (media type, schema)
    query: type = None
    body: type = None           # a write's JSON body
    errors: tuple = ()
    description: str = None
    post_extra: dict = None     # the POST form's other fields: {name: (type, Field)}


ENDPOINTS = {
    "healthz": Endpoint("Is the service up", Health),
    "api_config": Endpoint("What a client needs to know about this server (D20)", Config),
    "api_openapi": Endpoint("This document", ("application/json", {"type": "object"})),
    "api_protocols": Endpoint(
        "How many flows carry each protocol in a time range (D20)", ProtocolCounts, ProtocolsQuery,
        errors=(400, 500, 502), description=(
            "Of the flows that started in the time range and pass the filters. Without a time range: a "
            "case's whole span; Security Onion's last max_window. A Security Onion record naming several "
            "protocols counts for each.")),
    "api_resolve": Endpoint("Check an IP and settle the anchor time a map starts from", Resolved, ResolveQuery,
                            errors=(400,)),
    "api_neighbors": Endpoint(
        "One hop: who connected to a host before the anchor, or who it connected to after", Neighbors,
        NeighborsQuery, errors=(400, 500, 502), description=(
            "Who connected to ip in the window before the anchor (in), or who it connected to in the window "
            "after it (out). Hosts on the exclude list are left out. When the window and the time range "
            "don't overlap, start is after end and peers is empty. With filters, counts, times, ports and "
            "protocols are those of the flows that pass.")),
    "api_flows": Endpoint(
        "One page of a connection's flows, oldest first", Flows, FlowsQuery, errors=(400, 500, 502),
        description=(
            "The flows src -> dst that started in [from, to]. Security Onion lists at most the first "
            "limits.connection_flows of a connection (offset + limit past that is a 400); narrow the time "
            "range for later ones."),
        post_extra={"within": (list[tuple[str, str]], Field(None, description=(
            "intervals [from, to] from POST /api/suspect (up to limits.within), to list only a kept "
            "connection's marked and suspect flows (case backend)")))}),
    "api_edge": Endpoint(
        "One connection, as it would be drawn", Edge, EdgeQuery, errors=(400, 500, 502), description=(
            "The count, times, ports and protocols of the flows src -> dst that started in [from, to] and "
            "pass the filters. With none, count is 0 and the times null.")),
    "api_filter": Endpoint(
        "Check one filter expression", CheckedFilter, FilterQuery, errors=(400,), description=(
            "Its canonical form, or a 400 saying what is wrong and where, e.g. \"at character 1: protocol "
            "names are case-sensitive: write SMB\". GET /api/config's filter gives the vocabulary and grammar.")),
    "api_pivot": Endpoint(
        "A Security Onion Dashboards query and link", Pivot, PivotQuery, errors=(400,), description=(
            "With b: every conversation between a and b, either direction, up to until; without: everything "
            "to or from a. The time clause is left out with TB_PIVOT_TIME_CLAUSE=false.")),
    "api_pcap": Endpoint(
        "A Security Onion flow's packets, from its sensor through SOC",
        (PCAP, {"type": "string", "contentMediaType": PCAP}), body=PcapRequest, errors=(400, 501, 502),
        description=(
            "The PCAP file, as an attachment, extracted by the sensor that saw the flow, through SOC's "
            "Connect API. Needs a SOC API client (TB_SOC_CLIENT_ID, TB_SOC_CLIENT_SECRET; Security Onion "
            "Pro), else 501. The request waits for the sensor, up to TB_PCAP_TIMEOUT seconds; a 502 says why "
            "the sensor could not provide it, with the SOC job's link where there is one.")),
    "api_threatline": Endpoint(
        "Hosts and hops time-consistent with a conversation (case backend)", ThreatLine, ThreatLineQuery,
        errors=(400, 500, 501), description=(
            "Who could have reached a before the conversation a -> b, and where b could have gone after it. "
            "A 400 says when there are no flows from a to b in that time.")),
    "api_paths": Endpoint(
        "Every time-respecting path between two hosts, or between the marked hosts (case backend)",
        Union[PathsBetween, AttackPaths], PathsQuery, errors=(400, 500, 501), description=(
            "With src and dst: every path from src to dst, up to limits.paths. With neither: the paths "
            "between each pair of marked hosts, each reached when GET /api/compromised says (in a POST, "
            "those of its marks), the first limits.paths_per_pair per pair.")),
    "api_suspect": Endpoint(
        "What the marks keep of the drawn connections (D16, case backend)", Suspects, body=MarkedQuery,
        errors=(400, 500, 501)),
    "api_export": Endpoint(
        "The marked hosts, and the marked and suspect flows on the drawn connections", Export,
        body=MarkedQuery, errors=(400, 500, 502), description=(
            "For a CSV export. Without the case backend, the marked flows only.")),
    "api_excludes": Endpoint("The shared exclude list", Excludes, errors=(500,)),
    "api_excludes_add": Endpoint("Add an IP, CIDR or domain name", Excludes, body=ExcludeEntry, errors=(400, 500)),
    "api_excludes_remove": Endpoint("Remove one", Excludes, body=ExcludeEntry, errors=(400, 500)),
    "api_compromised": Endpoint("The shared marks (D15)", MarksView, errors=(500,)),
    "api_compromised_mark": Endpoint("Mark a host compromised", MarksView, body=HostMarkIn, errors=(400, 500),
                                     description="Marking a host again replaces its own mark."),
    "api_compromised_unmark": Endpoint("Unmark a host, with the marked flows it is an end of", MarksView,
                                       body=HostToUnmark, errors=(400, 500)),
    "api_compromised_replace": Endpoint(
        "Replace every shared mark (Share)", MarksView, body=Marks, errors=(400, 500), description=(
            "Any invalid mark is a 400 and nothing changes. The map does it to share an opened map's marks, "
            "after asking.")),
    "api_compromised_mark_flow": Endpoint("Mark a flow compromised", MarksView, body=FlowMarkIn, errors=(400, 500),
                                          description="Marking it again replaces its note."),
    "api_compromised_unmark_flow": Endpoint("Unmark a flow", MarksView, body=FlowMarkIn, errors=(400, 500)),
    "api_sessions": Endpoint("The saved maps, or with name the one saved under it", Union[Sessions, SavedMap],
                             SessionsQuery, errors=(400, 404, 500)),
    "api_sessions_save": Endpoint("Save a map for every analyst", SaveResult, body=MapToSave, errors=(400, 409, 500)),
    "api_sessions_delete": Endpoint("Delete a saved map", Sessions, body=MapName, errors=(400, 404, 500)),
}

ERRORS = {
    400: "a parameter or the body is invalid; the message says which",
    403: "a write without the X-ThreatBridge header",
    404: "no such saved map",
    409: "a map is already saved under that name",
    500: "a shared file (exclude list, marks, saved map) is not valid JSON; it is left for someone to fix",
    501: ("this needs another backend (threat lines, paths and suspect connections: the case backend; PCAP "
          "downloads: Security Onion with a SOC API client)"),
    502: "Elasticsearch or SOC failed or answered unexpectedly",
}

WRITE = {"name": "X-ThreatBridge", "in": "header", "required": True, "schema": {"const": "1"},
         "description": "required on every write: browsers can't add it to a cross-site request"}


# ---- the document ----------------------------------------------------------------------------

class Undescribed(Exception):
    """A route with no Endpoint, or an Endpoint with no route."""


def routes():
    """{(METHOD, path): view name} for every API route of the app."""
    with tempfile.TemporaryDirectory() as d:
        cfg = Settings(backend="demo", live_dns=False, exclude_file=os.path.join(d, "ex.json"),
                       compromised_file=os.path.join(d, "c.json"), sessions_dir=os.path.join(d, "maps"))
        app = create_app(cfg, DemoBackend(cfg))
    return {(m, r.rule): r.endpoint for r in app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"}
            if r.endpoint not in ("static", "index")}


def _post_form(query, extra):
    """The JSON body that sends a query's parameters (text or numbers) as a POST."""
    fields = {name: (Value, Field(None, alias=f.alias)) for name, f in query.model_fields.items() if name != "filter"}
    return create_model(query.__name__ + "Body", __base__=Shape, __doc__=(
        "The query's parameters as a JSON object (text or numbers), plus filters and marks."),
        **fields, filters=(Filters, None), marks=(Marks, None), **(extra or {}))


def _parameters(query):
    out = []
    schema = query.model_json_schema(schema_generator=_Schema)
    for name, prop in schema["properties"].items():
        param = {"name": name, "in": "query"}
        if "description" in prop:
            param["description"] = prop.pop("description")
        if name in schema.get("required", ()):
            param["required"] = True
        param["schema"] = prop
        if prop.get("type") == "array":          # filter=...&filter=...
            param.update(style="form", explode=True)
        out.append(param)
    return out


def _members(ok):
    """The models an Endpoint answers with: one, a Union's, or none for (media type, schema)."""
    return [] if isinstance(ok, tuple) else list(get_args(ok) or (ok,))


def _operations(routes):
    """[(METHOD, path, Endpoint, body model or None)]; Undescribed unless every route has its
    Endpoint and every Endpoint its route."""
    problems = [f"no Endpoint for {m} {p} ({v})" for (m, p), v in sorted(routes.items()) if v not in ENDPOINTS]
    problems += [f"no route for {v}" for v in sorted(set(ENDPOINTS) - set(routes.values()))]
    if problems:
        raise Undescribed("; ".join(problems))
    out = []
    for (m, p), v in sorted(routes.items()):
        e = ENDPOINTS[v]
        out.append((m, p, e, _post_form(e.query, e.post_extra) if m == "POST" and e.query else e.body))
    return out


def _content(ok, refs):
    if isinstance(ok, tuple):
        media, schema = ok
        return {media: {"schema": schema}}
    found = [refs[m] for m in _members(ok)]
    return {"application/json": {"schema": found[0] if len(found) == 1 else {"anyOf": found}}}


def _operation(method, e, body, refs):
    op = {"summary": e.summary, **({"description": e.description} if e.description else {})}
    if body:
        op["parameters"] = [{"$ref": "#/components/parameters/write"}]
        op["requestBody"] = {"required": True, "content": {"application/json": {"schema": refs[body]}}}
    elif e.query:
        op["parameters"] = _parameters(e.query)
    errors = sorted(set(e.errors) | ({403} if method != "GET" else set()))
    op["responses"] = {"200": {"description": "OK", "content": _content(e.ok, refs)},
                       **{str(s): {"$ref": f"#/components/responses/E{s}"} for s in errors}}
    return op


def build(routes):
    """The OpenAPI document for `routes` ({(METHOD, path): view name})."""
    operations = _operations(routes)
    models = [Error, MapDocument] + [m for _, _, e, body in operations for m in _members(e.ok) + [body] if m]
    keys, defs = models_json_schema([(m, "validation") for m in dict.fromkeys(models)], schema_generator=_Schema,
                                    ref_template="#/components/schemas/{model}")
    refs = {m: ref for (m, _), ref in keys.items()}
    schemas = defs["$defs"]
    for schema in schemas.values():
        schema.pop("title", None)
    paths = {}
    for method, path, e, body in operations:
        paths.setdefault(path, {})[method.lower()] = _operation(method, e, body, refs)
    error = {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "ThreatBridge", "version": str(API_VERSION), "description": (
            "The HTTP API of ThreatBridge's map. docs/API.md has the conventions (times, windows, the time "
            "range, filters, queries as POST, writes, errors), the filter grammar and what marks mean. Every "
            "response here lists every field it has.")},
        "security": [{"mutualTLS": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"mutualTLS": {"type": "mutualTLS", "description": (
                "a client certificate signed by the ThreatBridge CA (python -m threatbridge serves plain HTTP "
                "locally)")}},
            "parameters": {"write": WRITE},
            "responses": {f"E{s}": {"description": d, "content": error} for s, d in ERRORS.items()},
            "schemas": schemas,
        },
    }


def text():
    """The document as openapi.json holds it."""
    return json.dumps(build(routes()), indent=1, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    with open(OPENAPI, "w", encoding="utf-8") as fh:
        fh.write(text())
    print(f"wrote {OPENAPI}")
