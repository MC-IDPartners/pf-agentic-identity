"""Publishes an Entity Configuration over HTTPS, so PingFederate can resolve its trust chain (OIDFED §9, §10): the
workload's own, or - `workload.py entity-host` - the federated attested client's, with its SPIFFE bindings.

With no trust_chain in the client assertion, PingFederate resolves the chain from the client_id: it GETs
<ENTITY_ID>/.well-known/openid-federation, follows its authority_hints to Raidiam, and validates up to the
pinned trust anchor. This serves that first document over HTTPS, signed afresh on every request (an Entity
Configuration expires), under a self-signed certificate for ENTITY_ID's host - PingFederate is told not to
check it (OIDF_FEDERATION_IGNORE_SSL_ERRORS, a development setting).

ENTITY_LISTEN_PORT is the port inside the container (default: ENTITY_ID's port); publish it on the host so
PingFederate reaches it as host.docker.internal.
"""
import datetime
import ipaddress
import os
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

WELL_KNOWN = "/.well-known/openid-federation"


def _self_signed(host: str):
    """A throwaway TLS key and certificate naming host, written to temp files for ssl.load_cert_chain."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cert_path, key_path = os.path.join(d, "tls.crt"), os.path.join(d, "tls.key")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


def serve(entity_id: str, sign_entity_configuration) -> ThreadingHTTPServer:
    """Starts serving in a daemon thread; sign_entity_configuration() returns a freshly signed JWT."""
    parts = urlsplit(entity_id)
    path = parts.path.rstrip("/") + WELL_KNOWN
    port = int(os.environ.get("ENTITY_LISTEN_PORT") or parts.port or 443)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0] != path:
                self.send_error(404)
                return
            body = sign_entity_configuration().encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/entity-statement+jwt")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            print(f"entity host: {self.address_string()} {fmt % args}", flush=True)

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ENTITY_TLS_CERT/KEY: a certificate the fetcher trusts (the rig's runtime CA issues one); else a throwaway.
    if os.environ.get("ENTITY_TLS_CERT") and os.environ.get("ENTITY_TLS_KEY"):
        context.load_cert_chain(os.environ["ENTITY_TLS_CERT"], os.environ["ENTITY_TLS_KEY"])
    else:
        context.load_cert_chain(*_self_signed(parts.hostname))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"entity host: serving https://{parts.hostname}:{port}{path} (listening on :{port})", flush=True)
    return server
