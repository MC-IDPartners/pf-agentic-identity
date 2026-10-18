"""Principal versions the provider hosts on the marketplace's word - each a Raidiam software statement of its own, at
<provider>/agent/<slot>, deployed while the provider runs (../marketplace, the control centre).

Two ways to hold the versions' bridge keys (BRIDGE_BACKING):

  config (default)  PingFederate reads its bridge keys once, at start-up (OIDF_BRIDGE_SIGNING_KEYS), so the versions use
                    slots made in advance: PRINCIPAL_SLOTS (principal-1 .. principal-4), each with an entity key and a
                    bridge key under PRINCIPALS_DIR/<slot>/ (PRINCIPAL=<slot> ../raidiam/attested-client.sh keys; up.sh
                    makes them and renders the bridge keys for PingFederate).
  vault             The bridge keys live in OpenBao (OPENBAO_ADDR, OPENBAO_TOKEN_FILE: the provider's token, which may
                    create bridge-* keys and get their CSRs, never sign with them - ../openbao/setup.py). PingFederate
                    finds each version's key by name (the bridge template, bridge-<name>), so there is no limit: a deploy
                    takes a free version or enrols the next principal-N, creates bridge-<name> in the vault, and has the
                    vault make its CSR. The private half of a bridge key exists only in the vault.

A deploy claims a version. The entity key's private half never leaves the provider: the marketplace gets CSRs, for the
statement it created, and uploads those.

The admin API is plain HTTP on PRINCIPAL_ADMIN_PORT (8091), inside the compose network only - the provider's gateway
(Kong, 8443) does not route to it:

  GET  /admin/versions                     every slot: free, claimed, hosted or withdrawn, with its identifiers
  POST /admin/versions/claim               {name, version} -> the first free slot: {slot, entity_id, spiffe_id}
  POST /admin/versions/<slot>/csr          {softwareStatementId, organisationId} -> {entity, bridge} CSRs (PEM)
  POST /admin/versions/<slot>/host         publish its Entity Configuration and register it at PingFederate
  GET  /admin/versions/<slot>/status       hosted; whether Raidiam vouches for its keys yet; the kids it publishes
  GET  /admin/versions/<slot>/keys         the public halves of its entity and bridge keys
  POST /admin/versions/<slot>/withdraw     stop publishing it (its Entity Configuration is gone; chains break)
  POST /admin/versions/<slot>/release      free the slot (its Raidiam statement is the marketplace's to retire)
"""
import base64
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import requests

import federation


class Versions:
    def __init__(self, provider_id: str, authority: str, issuer: str, signer, agents: list, hosted: list,
                 bindings):
        self.provider, self.authority, self.issuer = provider_id.rstrip("/"), authority, issuer
        self.signer, self.agents, self.hosted, self.bindings = signer, agents, hosted, bindings
        self.root = os.environ.get("PRINCIPALS_DIR", "/principals")
        self.configured_slots = os.environ.get("PRINCIPAL_SLOTS", "principal-1 principal-2 principal-3 principal-4").replace(",", " ").split()
        self.vault = os.environ.get("BRIDGE_BACKING", "config") == "vault"
        self.vault_addr = os.environ.get("OPENBAO_ADDR", "http://openbao:8200").rstrip("/")
        self.vault_token_file = os.environ.get("OPENBAO_TOKEN_FILE", "/openbao/provider.token")
        self.trust_domain = os.environ.get("TRUST_DOMAIN", "example.org")
        self.server = None
        self.lock = threading.Lock()
        self.wake = threading.Event()  # the entity host's registration loop: register a newly hosted version now

    @property
    def slots(self) -> list:
        """The versions there are: the configured slots, or - with the bridge keys in the vault - every version enrolled."""
        if not self.vault:
            return self.configured_slots
        found = [d for d in os.listdir(self.root) if os.path.isdir(self._dir(d))] if os.path.isdir(self.root) else []
        return sorted(found, key=lambda n: (len(n), n))

    # ── the vault (BRIDGE_BACKING=vault) ─────────────────────────────────────────────────────────────────────────

    def _bao(self, method, path, body=None, ok=(200, 204)):
        with open(self.vault_token_file) as f:
            token = f.read().strip()
        r = requests.request(method, self.vault_addr + path, json=body, timeout=15, headers={"X-Vault-Token": token})
        if r.status_code not in ok:
            raise RuntimeError(f"OpenBao {method} {path}: {r.status_code} {r.text[:200]}")
        return r.status_code, (r.json() if r.text else {})

    def _bridge_name(self, slot):
        return f"bridge-{slot}"

    def _vault_bridge_key(self, slot, create=False):
        """The version's bridge key in the vault - its public half as an RSA public key - created when asked."""
        status, body = self._bao("GET", f"/v1/transit/keys/{self._bridge_name(slot)}", ok=(200, 404))
        if status == 404:
            if not create:
                return None
            self._bao("POST", f"/v1/transit/keys/{self._bridge_name(slot)}", {"type": "rsa-2048", "exportable": False})
            print(f"entity host: created {self._bridge_name(slot)} in OpenBao (rsa-2048, not exportable)", flush=True)
            status, body = self._bao("GET", f"/v1/transit/keys/{self._bridge_name(slot)}")
        latest = body["data"]["keys"][str(body["data"]["latest_version"])]
        return serialization.load_pem_public_key(latest["public_key"].encode())

    def _bridge_public_jwks(self, slot) -> dict:
        if not self.vault:
            with open(os.path.join(self._dir(slot), "bridge.public.jwks.json")) as f:
                return json.load(f)
        pub = self._vault_bridge_key(slot)
        if pub is None:
            raise RuntimeError(f"no {self._bridge_name(slot)} in OpenBao")
        n = pub.public_numbers()
        b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
        jwk = {"kty": "RSA", "n": b64(n.n), "e": b64(n.e)}
        thumb = hashlib.sha256(json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":")).encode()).digest()
        return {"keys": [{**jwk, "kid": base64.urlsafe_b64encode(thumb).rstrip(b"=").decode(), "use": "sig", "alg": "PS256"}]}

    # ── state ────────────────────────────────────────────────────────────────────────────────────────────────────

    def _dir(self, slot):
        return os.path.join(self.root, slot)

    def _state(self, slot) -> dict:
        try:
            with open(os.path.join(self._dir(slot), "deployed.json")) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save(self, slot, state: dict):
        path = os.path.join(self._dir(slot), "deployed.json")
        if state:
            with open(path, "w") as f:
                json.dump(state, f, indent=2)
        elif os.path.exists(path):
            os.remove(path)

    def entity_id(self, slot):
        return f"{self.provider}/agent/{slot}"

    def spiffe_id(self, slot):
        return f"spiffe://{self.trust_domain}/{slot}"

    def _ready(self, slot) -> bool:
        d = self._dir(slot)
        if self.vault:  # the bridge key is created in the vault at the deploy
            return os.path.exists(os.path.join(d, "entity.private.jwk.json"))
        return all(os.path.exists(os.path.join(d, f)) for f in
                   ("entity.private.jwk.json", "entity.key.pem", "bridge.public.jwks.json", "bridge.key.pem"))

    def describe(self, slot) -> dict:
        state = self._state(slot)
        return {"slot": slot, "entity_id": self.entity_id(slot), "spiffe_id": self.spiffe_id(slot),
                "keys": self._ready(slot), "state": state.get("state", "free"), **{k: v for k, v in state.items() if k != "state"}}

    # ── hosting ──────────────────────────────────────────────────────────────────────────────────────────────────

    def _agent(self, slot) -> dict:
        state = self._state(slot)
        private, public = federation.load_or_create_key(os.path.join(self._dir(slot), "entity.private.jwk.json"))
        client_jwks = self._bridge_public_jwks(slot)
        agent_id = self.entity_id(slot)
        return {"id": agent_id, "private": private, "public": public, "client_jwks": client_jwks,
                "name": state.get("name") or f"Principal Agent ({slot})",
                "bindings": self.bindings(agent_id, self.issuer, self.provider, self.spiffe_id(slot)),
                "resource": None, "slot": slot}

    def _host(self, slot) -> dict:
        ag = self._agent(slot)
        self.agents[:] = [a for a in self.agents if a["id"] != ag["id"]] + [ag]
        self.hosted[:] = [h for h in self.hosted if h[0] != ag["id"]] + [(ag["id"], ag["bindings"])]
        if self.server:
            self.server.add(ag["id"], self.signer(ag))
        self.wake.set()
        return ag

    def _unhost(self, slot):
        agent_id = self.entity_id(slot)
        self.agents[:] = [a for a in self.agents if a["id"] != agent_id]
        self.hosted[:] = [h for h in self.hosted if h[0] != agent_id]
        if self.server:
            self.server.remove(agent_id)

    def load(self) -> list:
        """The versions deployed before this start, hosted again."""
        out = []
        for slot in self.slots:
            if self._state(slot).get("state") == "hosted" and self._ready(slot):
                out.append(self._host(slot))
                print(f"entity host: Principal version {slot} ({self._state(slot).get('name')}) hosted", flush=True)
        return out

    # ── actions ──────────────────────────────────────────────────────────────────────────────────────────────────

    def claim(self, request: dict):
        with self.lock:
            free = next((s for s in self.slots if self._ready(s) and not self._state(s)), None)
            if not free and self.vault:  # no limit: enrol the next version, its entity key made here and now
                taken = {int(n.split("-")[-1]) for n in self.slots if n.startswith("principal-") and n.split("-")[-1].isdigit()}
                free = f"principal-{max(taken | {0}) + 1}"
                os.makedirs(self._dir(free), exist_ok=True)
                federation.load_or_create_key(os.path.join(self._dir(free), "entity.private.jwk.json"))
                print(f"entity host: enrolled {free} (entity key made here; its bridge key is made in OpenBao at the deploy)", flush=True)
            if not free:
                return 409, {"error": "no_free_slot", "error_description":
                             f"every Principal slot is in use ({', '.join(self.slots)}): release one, or add slots "
                             "(PRINCIPAL_SLOTS, then up.sh renders their bridge keys for PingFederate)"}
            self._save(free, {"state": "claimed", "name": request.get("name") or "", "version": request.get("version") or "",
                              "claimedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        print(f"entity host: slot {free} claimed for {request.get('name')} {request.get('version')}", flush=True)
        return 200, self.describe(free)

    def csr(self, slot, request: dict):
        ssid, org = request.get("softwareStatementId"), request.get("organisationId")
        if not ssid or not org:
            return 400, {"error": "invalid_request", "error_description": "softwareStatementId and organisationId are required"}
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.get("organisation") or "CBA Trust Framework"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, ssid)])
        out = {}
        entity, _ = federation.load_or_create_key(os.path.join(self._dir(slot), "entity.private.jwk.json"))
        out["entity"] = (x509.CertificateSigningRequestBuilder().subject_name(subject).sign(entity, hashes.SHA256())
                         .public_bytes(serialization.Encoding.PEM).decode())
        if self.vault:
            # The vault makes the bridge key's CSR and signs it with the key it holds: the subject comes from a template
            # signed by a throwaway key, which the vault replaces with its own.
            self._vault_bridge_key(slot, create=True)
            template = (x509.CertificateSigningRequestBuilder().subject_name(subject)
                        .sign(rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256())
                        .public_bytes(serialization.Encoding.PEM).decode())
            _, made = self._bao("POST", f"/v1/transit/keys/{self._bridge_name(slot)}/csr", {"csr": template})
            out["bridge"] = made["data"]["csr"]
        else:
            with open(os.path.join(self._dir(slot), "bridge.key.pem"), "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            out["bridge"] = (x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
                             .public_bytes(serialization.Encoding.PEM).decode())
        state = self._state(slot)
        self._save(slot, {**state, "softwareStatementId": ssid, "organisationId": org})
        print(f"entity host: CSRs for {slot} (statement {ssid}): entity and bridge keys, the private halves kept here", flush=True)
        return 200, out

    def host(self, slot, request: dict):
        state = self._state(slot)
        if not state:
            return 409, {"error": "not_claimed", "error_description": f"{slot} is free: claim it first"}
        self._save(slot, {**state, "state": "hosted", "name": request.get("name") or state.get("name"),
                          "hostedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        self._host(slot)
        print(f"entity host: Principal version {slot} hosted at {self.entity_id(slot)}", flush=True)
        return 200, self.describe(slot)

    def status(self, slot):
        out = self.describe(slot)
        ag = next((a for a in self.agents if a["id"] == self.entity_id(slot)), None)
        out["hosted"] = bool(ag)
        out["pingfederate"] = {"registered_until": (ag or {}).get("registered_until"),
                               "error": (ag or {}).get("registration_error")}
        try:
            about = federation.subordinate_statement(self.authority, self.entity_id(slot))
            keys = federation._claims(about).get("jwks", {}).get("keys", [])
            mine = {}
            for name, key in self.keys(slot)[1].items():
                mine[name] = next((k.get("kid") for k in keys if k.get("n") == key["n"]), None)
            out["raidiam"] = {"vouches": bool(mine["entity"]), "kids": mine}
        except Exception as e:
            out["raidiam"] = {"vouches": False, "error": str(e)[:200]}
        return 200, out

    def keys(self, slot):
        """The public halves of the slot's entity and bridge keys - to find their certificates in Raidiam."""
        with open(os.path.join(self._dir(slot), "entity.private.jwk.json")) as f:
            jwk = json.load(f)
        out = {"entity": {k: jwk[k] for k in ("kty", "n", "e")}}
        try:
            bridge = self._bridge_public_jwks(slot)["keys"][0]
            out["bridge"] = {k: bridge[k] for k in ("kty", "n", "e")}
        except (OSError, RuntimeError):
            out["bridge"] = {"kty": "RSA", "n": None, "e": None}  # not made yet
        return 200, out

    def withdraw(self, slot):
        state = self._state(slot)
        if not state:
            return 409, {"error": "not_claimed", "error_description": f"{slot} is free"}
        self._unhost(slot)
        self._save(slot, {**state, "state": "withdrawn", "withdrawnAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        return 200, self.describe(slot)

    def release(self, slot):
        if self._state(slot).get("state") == "hosted":
            return 409, {"error": "hosted", "error_description": f"withdraw {slot} before releasing it"}
        self._save(slot, {})
        return 200, self.describe(slot)

    # ── the admin server ─────────────────────────────────────────────────────────────────────────────────────────

    def serve_admin(self, server):
        self.server = server
        versions = self
        port = int(os.environ.get("PRINCIPAL_ADMIN_PORT", "8091"))

        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _route(self, method):
                parts = [p for p in self.path.split("?")[0].split("/") if p]
                if parts[:2] != ["admin", "versions"]:
                    return 404, {"error": "not_found"}
                if method == "GET" and len(parts) == 2:
                    return 200, {"provider": versions.provider, "versions": [versions.describe(s) for s in versions.slots]}
                if method == "POST" and parts[2:] == ["claim"]:
                    return versions.claim(self._json())
                if len(parts) == 4 and parts[2] in versions.slots:
                    slot, action = parts[2], parts[3]
                    if method == "GET" and action == "status":
                        return versions.status(slot)
                    if method == "GET" and action == "keys":
                        return versions.keys(slot)
                    if method == "POST" and action == "csr":
                        return versions.csr(slot, self._json())
                    if method == "POST" and action == "host":
                        return versions.host(slot, self._json())
                    if method == "POST" and action == "withdraw":
                        return versions.withdraw(slot)
                    if method == "POST" and action == "release":
                        return versions.release(slot)
                return 404, {"error": "not_found"}

            def _json(self):
                length = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(length) or b"{}") if length else {}

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def _handle(self, method):
                try:
                    self._send(*self._route(method))
                except Exception as e:
                    self._send(500, {"error": "server_error", "error_description": str(e)[:300]})

            def log_message(self, fmt, *args):
                print(f"provider admin: {fmt % args}", flush=True)

        admin = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=admin.serve_forever, daemon=True).start()
        print(f"entity host: Principal versions admin on :{port} (slots {', '.join(versions.slots)})", flush=True)
