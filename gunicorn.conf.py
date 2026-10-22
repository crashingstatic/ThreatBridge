"""gunicorn config: HTTPS with mandatory client certificates (mutual TLS)."""
import os
import ssl

bind = f"0.0.0.0:{os.environ.get('TB_PORT', '5443')}"
workers = int(os.environ.get("TB_WORKERS", "2"))
threads = 4
timeout = 120  # exact rarest-peer scans can take a while on busy hosts
wsgi_app = "threatbridge.app:create_app()"
accesslog = "-"

certfile = os.environ.get("TB_TLS_CERT", "/certs/server.crt")
keyfile = os.environ.get("TB_TLS_KEY", "/certs/server.key")
ca_certs = os.environ.get("TB_TLS_CLIENT_CA", "/certs/ca.crt")
cert_reqs = ssl.CERT_REQUIRED  # no valid client cert -> TLS handshake fails
