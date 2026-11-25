"""Security Onion Console's Connect API: a connection log's PCAP, from the sensor that saw it.

Needs a Security Onion Pro licence with the API feature (2.4.120 or later), Hydra enabled, and
an API client (SOC > Administration > API Clients) with events/read, jobs/read and jobs/write.
SOC itself picks the sensor, ports and time window for the job, as its own PCAP action does.
"""
import re
import time

import requests

from .backends import BackendError

TOKEN_MARGIN = 60   # seconds before a token's expiry to get a new one
POLL_EVERY = 2.0    # seconds between looks at a pending job
CHUNK = 1 << 16

# SOC job status: 0 pending, 1 completed, 2 incomplete (failed), 3 deleted.
PENDING, COMPLETED, INCOMPLETE, DELETED = 0, 1, 2, 3
_JOB_RE = re.compile(r"#/job/(\d+)")


class SocError(BackendError):
    pass


class SocClient:
    def __init__(self, cfg, session=None, clock=time.monotonic, sleep=time.sleep):
        self.url = cfg.soc_url.rstrip("/")
        self.client = (cfg.soc_client_id, cfg.soc_client_secret)
        self.timeout, self.request_timeout = cfg.pcap_timeout, cfg.es_timeout
        self.session = session or requests.Session()
        self.session.verify = cfg.soc_ca or cfg.es_ca or cfg.es_verify
        self.clock, self.sleep = clock, sleep
        self._token, self._expires = None, 0.0

    def job_url(self, job_id):
        return f"{self.url}/#/job/{job_id}"

    def pcap(self, doc_id, time_text):
        """An iterator over the PCAP of the connection log `doc_id` (seen at `time_text`)."""
        job_id = self._create_job(doc_id, time_text)
        self._wait(job_id)
        resp = self._call("get", f"/connect/stream/{job_id}", params={"ext": "pcap"}, stream=True)
        return resp.iter_content(CHUNK)

    # ---- the steps ------------------------------------------------------------------------

    def _create_job(self, doc_id, time_text):
        resp = self._call("get", "/connect/joblookup/", params={"esid": doc_id, "time": time_text},
                          allow_redirects=False)
        found = _JOB_RE.search(resp.headers.get("Location", "")) if resp.status_code == 302 else None
        if not found:
            raise SocError(f"SOC did not create a PCAP job (HTTP {resp.status_code}); "
                           "is the connection log still in Elasticsearch?")
        return int(found.group(1))

    def _wait(self, job_id):
        """Look at the job every POLL_EVERY seconds until it completes; SocError if it fails, is
        deleted, says something unexpected, or is still pending after `timeout` seconds."""
        deadline = self.clock() + self.timeout
        while True:
            job = self._job(job_id)
            status = job.get("status")
            if status == COMPLETED:
                return
            if status in (INCOMPLETE, DELETED):
                reason = job.get("failure") or ("deleted" if status == DELETED else "no reason given")
                raise SocError(f"the sensor could not extract the packets: {reason} "
                               f"(SOC job {self.job_url(job_id)})")
            if status != PENDING:
                raise SocError(f"unexpected answer from SOC about job {job_id}")
            if self.clock() >= deadline:
                raise SocError(f"the sensor has not finished after {self.timeout} s; the job may "
                               f"still complete in SOC: {self.job_url(job_id)}")
            self.sleep(POLL_EVERY)

    def _job(self, job_id):
        """The job as SOC describes it; {} if the answer is not a JSON object."""
        try:
            job = self._call("get", f"/connect/job/{job_id}").json()
        except ValueError:
            return {}
        return job if isinstance(job, dict) else {}

    # ---- talking to SOC -------------------------------------------------------------------

    def _bearer(self, renew=False):
        """An access token for the API client: the one held, unless it is about to expire or
        `renew` is asked (SOC refused it); else a new one from SOC's OAuth2 endpoint."""
        if renew or not self._token or self.clock() >= self._expires:
            try:
                resp = self.session.post(f"{self.url}/oauth2/token", auth=self.client,
                                         data={"grant_type": "client_credentials"},
                                         timeout=self.request_timeout)
            except requests.RequestException as e:
                raise SocError(f"SOC request failed: {e.__class__.__name__}")
            if resp.status_code != 200:
                raise SocError(f"SOC refused the API client credentials (HTTP {resp.status_code})")
            try:
                body = resp.json()
                self._token = body["access_token"]
                self._expires = self.clock() + float(body.get("expires_in", 3600)) - TOKEN_MARGIN
            except (ValueError, KeyError, TypeError):
                raise SocError("SOC's token answer is not what the Connect API sends")
        return self._token

    def _call(self, method, path, **kw):
        for renew in (False, True):          # an expired token is renewed once
            try:
                resp = self.session.request(method, self.url + path, timeout=self.request_timeout,
                                            headers={"Authorization": f"Bearer {self._bearer(renew)}"},
                                            **kw)
            except requests.RequestException as e:
                raise SocError(f"SOC request failed: {e.__class__.__name__}")
            if resp.status_code != 401:
                break
        if resp.status_code == 403:
            raise SocError("the SOC API client lacks a permission it needs "
                           "(events/read, jobs/read, jobs/write)")
        if resp.status_code not in (200, 302):
            raise SocError(f"SOC returned HTTP {resp.status_code}")
        return resp
