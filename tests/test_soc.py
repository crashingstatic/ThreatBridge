"""A flow's PCAP from its sensor, through SOC's Connect API (against a fake SOC)."""
import pytest
import requests

from threatbridge.app import create_app
from threatbridge.backends import DemoBackend
from threatbridge.config import Config
from threatbridge.excludes import ExcludeStore
from threatbridge.soc import SocClient, SocError

DOC, WHEN = "P5mgnpEB0JpjNDZz1bIN", "2024-05-01T12:00:00.123Z"
WRITE = {"X-ThreatBridge": "1"}


class Resp:
    def __init__(self, status=200, body=None, headers=None, content=b""):
        self.status_code, self.body, self.headers, self.content = status, body, headers or {}, content

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body

    def iter_content(self, size):
        return (self.content[i:i + size] for i in range(0, len(self.content), size))


class FakeSoc:
    """SOC's token, job lookup, job and stream endpoints. `statuses`: what each look at the job
    says, in turn; the last one repeats."""

    def __init__(self, statuses=(0, 0, 1), failure="", token_status=200, lookup=None, job_body=None,
                 expired_once=False, error=None, stream_status=200):
        self.statuses, self.failure, self.token_status = list(statuses), failure, token_status
        self.lookup = lookup or Resp(302, headers={"Location": "https://so/#/job/1004"})
        self.job_body, self.expired_once, self.error = job_body, expired_once, error
        self.stream_status = stream_status
        self.calls, self.tokens, self.timeouts = [], 0, set()
        self.verify = None
        self.token_body = {"expires_in": 3599}

    def post(self, url, auth, data, timeout):
        self.calls.append(("token", url, auth, data))
        self.timeouts.add(timeout)
        self.tokens += 1
        return Resp(self.token_status, dict(self.token_body, access_token=f"t{self.tokens}"))

    def request(self, method, url, timeout, headers, **kw):
        if self.error:
            raise self.error
        self.timeouts.add(timeout)
        path = url.split("https://so", 1)[1]
        self.calls.append((method, path, headers["Authorization"], kw))
        if self.expired_once and headers["Authorization"] == "Bearer t1":
            return Resp(401)
        if path == "/connect/joblookup/":
            return self.lookup
        if path == "/connect/job/1004":
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return Resp(200, self.job_body or {"id": 1004, "status": status, "failure": self.failure})
        if path == "/connect/stream/1004":
            return Resp(self.stream_status, content=b"\xd4\xc3\xb2\xa1" + b"\0" * 100_000)
        return Resp(404)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def client_for(session, clock=None, soc_url_override=None, **cfg):
    clock = clock or Clock()
    config = Config(backend="elastic", soc_url=soc_url_override or "https://so", soc_client_id="tb",
                    soc_client_secret="s3cret", es_ca="/etc/pki/ca.crt", **cfg)
    return SocClient(config, session=session, clock=clock, sleep=clock.sleep)


def test_a_pcap_from_the_sensor():
    soc = FakeSoc(statuses=(0, 0, 1))
    pcap = b"".join(client_for(soc).pcap(DOC, WHEN))
    assert pcap.startswith(b"\xd4\xc3\xb2\xa1") and len(pcap) == 100_004
    token, lookup, *polls, stream = soc.calls
    assert token == ("token", "https://so/oauth2/token", ("tb", "s3cret"), {"grant_type": "client_credentials"})
    assert lookup == ("get", "/connect/joblookup/", "Bearer t1",
                      {"params": {"esid": DOC, "time": WHEN}, "allow_redirects": False})
    assert [c[:3] for c in polls] == [("get", "/connect/job/1004", "Bearer t1")] * 3
    assert stream == ("get", "/connect/stream/1004", "Bearer t1", {"params": {"ext": "pcap"}, "stream": True})
    assert soc.verify == "/etc/pki/ca.crt"
    assert soc.timeouts == {30}                                       # TB_ES_TIMEOUT, per request


def test_a_soc_url_with_a_trailing_slash():
    soc = FakeSoc(statuses=(1,))
    assert b"".join(client_for(soc, soc_url_override="https://so/").pcap(DOC, WHEN))
    assert soc.calls[0][1] == "https://so/oauth2/token" and soc.calls[1][1] == "/connect/joblookup/"


def test_tokens_are_reused_until_they_expire_and_renewed_when_refused():
    soc, clock = FakeSoc(statuses=(1,)), Clock()
    client = client_for(soc, clock)
    list(client.pcap(DOC, WHEN))
    list(client.pcap(DOC, WHEN))
    assert soc.tokens == 1
    clock.now += 3599 - 60                                     # within a minute of expiry: renewed
    list(client.pcap(DOC, WHEN))
    assert soc.tokens == 2
    soc = FakeSoc(statuses=(1,), expired_once=True)            # SOC says the token has expired
    assert b"".join(client_for(soc).pcap(DOC, WHEN))
    assert soc.tokens == 2
    soc, clock = FakeSoc(statuses=(1,)), Clock()                 # no expires_in: an hour
    soc.token_body = {}
    client = client_for(soc, clock)
    list(client.pcap(DOC, WHEN))
    clock.now += 3600 - 60 - 0.5
    list(client.pcap(DOC, WHEN))
    assert soc.tokens == 1
    clock.now += 0.5
    list(client.pcap(DOC, WHEN))
    assert soc.tokens == 2


def test_a_token_refused_twice_is_an_error():
    class Refusing(FakeSoc):
        def request(self, method, url, timeout, headers, **kw):
            self.calls.append(headers["Authorization"])
            return Resp(401)
    soc = Refusing()
    with pytest.raises(SocError, match="SOC returned HTTP 401"):
        list(client_for(soc).pcap(DOC, WHEN))
    assert soc.tokens == 2 and [c for c in soc.calls if isinstance(c, str)] == ["Bearer t1", "Bearer t2"]


def test_the_ca_for_soc_and_falling_back_to_elasticsearch_s():
    assert client_for(FakeSoc(), soc_ca="/soc/ca.crt").session.verify == "/soc/ca.crt"
    soc = FakeSoc()
    SocClient(Config(soc_client_id="a", soc_client_secret="b", es_verify=False), session=soc)
    assert soc.verify is False


@pytest.mark.parametrize("soc,message", [
    (FakeSoc(token_status=401), "SOC refused the API client credentials \\(HTTP 401\\)"),
    (FakeSoc(lookup=Resp(404)), "SOC returned HTTP 404"),
    (FakeSoc(lookup=Resp(200)), "SOC did not create a PCAP job \\(HTTP 200\\)"),
    (FakeSoc(lookup=Resp(302, headers={"Location": "https://so/#/hunt"})), "did not create a PCAP job"),
    (FakeSoc(lookup=Resp(403)), "lacks a permission it needs \\(events/read, jobs/read, jobs/write\\)"),
    (FakeSoc(statuses=(0, 2), failure="No matching packets found"),
     "could not extract the packets: No matching packets found \\(SOC job https://so/#/job/1004\\)"),
    (FakeSoc(statuses=(3,)), "could not extract the packets: deleted"),
    (FakeSoc(statuses=(2,), failure=""), "could not extract the packets: no reason given"),
    (FakeSoc(job_body=ValueError("not json")), "unexpected answer from SOC about job 1004"),
    (FakeSoc(job_body=["a list"]), "unexpected answer from SOC about job 1004"),
    (FakeSoc(statuses=(0,)), "has not finished after 90 s; the job may still complete in SOC: https://so/#/job/1004"),
    (FakeSoc(error=requests.ConnectionError("down")), "SOC request failed: ConnectionError"),
    (FakeSoc(stream_status=404), "SOC returned HTTP 404"),
])
def test_what_goes_wrong_is_said(soc, message):
    with pytest.raises(SocError, match=message):
        list(client_for(soc).pcap(DOC, WHEN))


def test_waiting_for_the_sensor_gives_up_at_the_timeout():
    soc, clock = FakeSoc(statuses=(0,)), Clock()
    with pytest.raises(SocError, match="has not finished after 10 s"):
        list(client_for(soc, clock, pcap_timeout=10).pcap(DOC, WHEN))
    polls = [c for c in soc.calls if c[1] == "/connect/job/1004"]
    assert len(polls) == 6 and clock.now == 10                  # at 0, 2, ..., 10 s


def test_a_token_answer_that_is_not_a_token():
    class Odd(FakeSoc):
        def post(self, url, auth, data, timeout):
            return Resp(200, {"token_type": "bearer"})
    with pytest.raises(SocError, match="token answer is not what the Connect API sends"):
        list(client_for(Odd()).pcap(DOC, WHEN))

    class Down(FakeSoc):
        def post(self, url, auth, data, timeout):
            raise requests.Timeout()
    with pytest.raises(SocError, match="SOC request failed: Timeout"):
        list(client_for(Down()).pcap(DOC, WHEN))


# ---- the API ------------------------------------------------------------------------------

def app_client(tmp_path, soc=None, **cfg):
    config = Config(backend="demo", live_dns=False, compromised_file=str(tmp_path / "c.json"), **cfg)
    return create_app(config, DemoBackend(config), ExcludeStore(str(tmp_path / "ex.json")), soc=soc).test_client()


def test_pcap_download_through_the_api(tmp_path):
    soc = FakeSoc(statuses=(0, 1))
    c = app_client(tmp_path, soc=client_for(soc))
    assert c.get("/api/config").get_json()["pcap_download"] is True
    assert c.post("/api/pcap", json={"id": DOC, "time": WHEN}).status_code == 403          # CSRF header
    r = c.post("/api/pcap", json={"id": DOC, "time": "2024-05-01T14:00:00.123+02:00"}, headers=WRITE)
    assert r.status_code == 200 and r.mimetype == "application/vnd.tcpdump.pcap"
    assert r.headers["Content-Disposition"] == f'attachment; filename="threatbridge-{DOC}.pcap"'
    assert len(r.data) == 100_004
    assert soc.calls[1][3]["params"] == {"esid": DOC, "time": WHEN}                         # as UTC


@pytest.mark.parametrize("body,status,message", [
    ({"id": "x y", "time": WHEN}, 400, "invalid document ID"),
    ({"time": WHEN}, 400, "invalid document ID: None"),
    ({"id": DOC}, 400, "time (the flow's start) is required"),
    ({"id": DOC, "time": " "}, 400, "time (the flow's start) is required"),
    ({"id": DOC, "time": "soon"}, 400, "invalid timestamp"),
])
def test_pcap_requests_are_checked(tmp_path, body, status, message):
    r = app_client(tmp_path, soc=client_for(FakeSoc())).post("/api/pcap", json=body, headers=WRITE)
    assert r.status_code == status and message in r.get_json()["error"]


def test_pcap_errors_and_the_unconfigured_case(tmp_path):
    c = app_client(tmp_path, soc=client_for(FakeSoc(statuses=(2,), failure="No data")))
    r = c.post("/api/pcap", json={"id": DOC, "time": WHEN}, headers=WRITE)
    assert r.status_code == 502 and "could not extract the packets: No data" in r.get_json()["error"]
    c = app_client(tmp_path)
    assert c.get("/api/config").get_json()["pcap_download"] is False
    r = c.post("/api/pcap", json={"id": DOC, "time": WHEN}, headers=WRITE)
    assert r.status_code == 501 and "TB_SOC_CLIENT_ID" in r.get_json()["error"]


def test_the_client_is_made_only_for_security_onion_with_credentials(tmp_path):
    def config(**kw):
        return Config(live_dns=False, exclude_file=str(tmp_path / "ex.json"),
                      compromised_file=str(tmp_path / "c.json"), soc_url="https://so", **kw)
    with_both = config(backend="elastic", soc_client_id="a", soc_client_secret="b")
    assert create_app(with_both).test_client().get("/api/config").get_json()["pcap_download"] is True
    for cfg in (config(backend="elastic", soc_client_id="a"),
                config(backend="demo", soc_client_id="a", soc_client_secret="b")):
        assert create_app(cfg).test_client().get("/api/config").get_json()["pcap_download"] is False
