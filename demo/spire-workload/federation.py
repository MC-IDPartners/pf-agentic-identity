"""Raidiam directory lookup and OpenID Federation automatic registration (OIDFED §12.1) at PingFederate.

Directory: GET <DIRECTORY_URL>/participants is public. The authorisation server is picked by
AUTHORISATION_SERVER_ID (stable) or, failing that, by CustomerFriendlyName (AUTHORISATION_SERVER_NAME).

Federation: the workload is its own federation leaf. It signs its Entity Configuration with ENTITY_KEY_FILE,
fetches the Subordinate Statements above it from Raidiam, and presents the whole chain in the trust_chain
header of a private_key_jwt client_assertion. PingFederate's TokenEndpointAutoRegistrationFilter validates
the chain to its pinned trust anchor, registers the client with the LEAF'S OWN jwks, and lets the same
request through to be authenticated against that key - so the key that signs the assertion must be the
leaf's entity key, and Raidiam's Subordinate Statement must carry it too.
"""
import base64
import hashlib
import json
import os
import time
import uuid
from urllib.parse import quote, urlsplit, urlunsplit

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ENTITY_STATEMENT_TYP = "entity-statement+jwt"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _strip(url: str) -> str:
    return url.rstrip("/")


def reachable(url: str) -> str:
    """The URL with its host replaced by ISSUER_HOST_OVERRIDE, e.g. host.docker.internal:9031.

    PingFederate's issuer is a public tunnel name, but this container reaches PingFederate directly on the
    Docker host. Identifiers (aud, issuer) keep the published value; only the connection uses this. An
    override with a port replaces the port too; one without keeps the issuer's.
    """
    host = os.environ.get("ISSUER_HOST_OVERRIDE")
    if not host:
        return url
    parts = urlsplit(url)
    netloc = host if ":" in host else host + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


def pf_verify():
    """TLS verification for calls to PingFederate: its self-signed certificate, else the system store."""
    return os.environ.get("PF_CA_FILE") or os.environ.get("SSL_CERT_FILE") or True


# ── Raidiam directory ──────────────────────────────────────────────────────────────────────────────

def find_authorisation_server(directory_url: str, server_id: str = None, server_name: str = None) -> dict:
    # The participants export is public and rate-limited (429): back off and try again rather than fail - a
    # container that crashes on it restarts straight into the limit again.
    # A connection or TLS failure is retried too: one network blip should not end a run.
    for attempt in range(6):
        try:
            resp = requests.get(_strip(directory_url) + "/participants", timeout=15)
        except requests.RequestException as e:
            if attempt == 5:
                raise
            print(f"directory: {type(e).__name__}, retrying in {2 ** attempt} s", flush=True)
            time.sleep(2 ** attempt)
            continue
        if resp.status_code != 429:
            break
        wait = int(resp.headers.get("Retry-After") or 0) or min(5 * 2 ** attempt, 60)
        print(f"directory: rate-limited (429), retrying in {wait} s", flush=True)
        time.sleep(wait)
    resp.raise_for_status()
    candidates = []
    for org in resp.json():
        for server in org.get("AuthorisationServers") or []:
            if server_id and server.get("AuthorisationServerId") == server_id:
                candidates.append(server)
            elif not server_id and server_name and server.get("CustomerFriendlyName") == server_name:
                candidates.append(server)
    wanted = server_id or server_name
    if not candidates:
        raise RuntimeError(f"directory lists no authorisation server {wanted!r}")
    if len(candidates) > 1:
        raise RuntimeError(f"directory lists {len(candidates)} authorisation servers named {wanted!r}; "
                           "set AUTHORISATION_SERVER_ID instead")
    server = candidates[0]
    if server.get("Status") != "Active":
        raise RuntimeError(f"authorisation server {wanted!r} is {server.get('Status')}, not Active")
    if not server.get("Issuer"):
        raise RuntimeError(f"authorisation server {wanted!r} has no Issuer in the directory yet")
    return server


def discover(server: dict) -> dict:
    """The AS's OpenID discovery document, fetched over the reachable URL."""
    url = server.get("OpenIDDiscoveryDocument") or _strip(server["Issuer"]) + "/.well-known/openid-configuration"
    resp = requests.get(reachable(url), timeout=15, verify=pf_verify())
    resp.raise_for_status()
    doc = resp.json()
    if _strip(doc.get("issuer", "")) != _strip(server["Issuer"]):
        raise RuntimeError(f"discovery issuer {doc.get('issuer')!r} is not the directory's {server['Issuer']!r}")
    return doc


# ── Entity key ─────────────────────────────────────────────────────────────────────────────────────

# Per key type: the JWK members that identify the key (RFC 7638) and the algorithm it signs with.
# RSA is what Raidiam certifies for rtssigning (a 2048-bit CSR), signing PS256; EC P-256 signs ES256.
_KEY_MEMBERS = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y")}
_KEY_ALG = {"RSA": "PS256", "EC": "ES256"}
_KEY_CODEC = {"RSA": RSAAlgorithm, "EC": ECAlgorithm}


def load_or_create_key(path: str, kty: str = "RSA"):
    """The workload's federation entity key as (private key, public JWK). Created on first run as kty;
    an existing file keeps whatever type it holds."""
    if os.path.exists(path):
        with open(path) as f:
            jwk = json.load(f)
        kty = jwk["kty"]
        private = _KEY_CODEC[kty].from_jwk(json.dumps(jwk))
    else:
        if kty == "RSA":
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            private = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(_KEY_CODEC[kty].to_jwk(private))
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(jwk, f)
        os.chmod(path, 0o600)
    public = json.loads(_KEY_CODEC[kty].to_jwk(private.public_key()))
    public.update({"kid": jwk.get("kid") or _thumbprint(public), "use": "sig", "alg": _KEY_ALG[kty]})
    return private, public


def _thumbprint(public_jwk: dict) -> str:
    """RFC 7638 JWK thumbprint, the kid when the stored key names none."""
    members = json.dumps({k: public_jwk[k] for k in _KEY_MEMBERS[public_jwk["kty"]]}, separators=(",", ":"),
                         sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(members.encode()).digest()).rstrip(b"=").decode()


def certificate_request(private_key, subject: str) -> bytes:
    """A PEM CSR for the entity key, subject in openssl's /C=../O=../OU=../CN=.. form."""
    oids = {"C": NameOID.COUNTRY_NAME, "O": NameOID.ORGANIZATION_NAME, "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "CN": NameOID.COMMON_NAME}
    names = [x509.NameAttribute(oids[k], v) for k, v in (p.split("=", 1) for p in subject.strip("/").split("/"))]
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(names)).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


# ── Trust chain ────────────────────────────────────────────────────────────────────────────────────

def entity_configuration(entity_id: str, private_key, public_jwk: dict, authority: str, client_name: str,
                         audience: str = None, client_jwks: dict = None, extra_claims: dict = None,
                         extra_metadata: dict = None) -> str:
    """The workload's own Entity Configuration: self-issued, self-signed, naming its superior. With an audience
    (the OP's Entity Identifier) it is an explicit registration request (OIDFED §12.2.1).

    client_jwks: the keys the client authenticates with, when they are not the entity key (an attested client's
    are its bridge key's). extra_claims: top-level claims beside the protocol's, such as spiffe_client_bindings."""
    now = int(time.time())
    client_jwks = client_jwks or {"keys": [public_jwk]}
    claims = {
        "iss": entity_id,
        "sub": entity_id,
        "iat": now,
        "exp": now + 3600,
        "jwks": {"keys": [public_jwk]},
        "authority_hints": [authority],
        "metadata": {
            "openid_relying_party": {
                "client_name": client_name,
                "client_registration_types": ["automatic", "explicit"],
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": client_jwks["keys"][0].get("alg", public_jwk["alg"]),
                "jwks": client_jwks,
            }
        },
    }
    claims["metadata"].update(extra_metadata or {})
    claims.update(extra_claims or {})
    if audience:
        claims["aud"] = audience
    return jwt.encode(claims, private_key, algorithm=public_jwk["alg"],
                      headers={"typ": ENTITY_STATEMENT_TYP, "kid": public_jwk["kid"]})


def _get_statement(url: str) -> str:
    resp = requests.get(url, timeout=15, headers={"Accept": "application/entity-statement+jwt"})
    if resp.status_code != 200:
        raise RuntimeError(f"GET {url} answered {resp.status_code}: {resp.text[:300]}")
    return resp.text.strip()


def _claims(statement: str) -> dict:
    return jwt.decode(statement, options={"verify_signature": False})


def _fetch_endpoint(entity: str) -> str:
    """The superior's federation_fetch_endpoint, from its own Entity Configuration."""
    ec_claims = _claims(_get_statement(_strip(entity) + "/.well-known/openid-federation"))
    endpoint = ec_claims.get("metadata", {}).get("federation_entity", {}).get("federation_fetch_endpoint")
    if not endpoint:
        raise RuntimeError(f"{entity} publishes no federation_fetch_endpoint")
    return endpoint


def subordinate_statement(superior: str, subject: str) -> str:
    return _get_statement(f"{_fetch_endpoint(superior)}?sub={quote(subject, safe='')}")


def vouched_kid(about_leaf: str, public_jwk: dict) -> str:
    """The kid the superior publishes for this workload's key, matched on the key itself.

    Raidiam names a key it certified with its own kid, not the RFC 7638 thumbprint the workload would
    use, and PingFederate looks the assertion's kid up in the keys the chain vouches for - so the
    workload signs under Raidiam's kid.
    """
    for key in _claims(about_leaf).get("jwks", {}).get("keys", []):
        if all(key.get(m) == public_jwk[m] for m in _KEY_MEMBERS[public_jwk["kty"]]):
            return key.get("kid") or public_jwk["kid"]
    raise RuntimeError(
        f"{_claims(about_leaf).get('iss')} vouches for {_claims(about_leaf).get('sub')} but not for this "
        f"workload's key ({public_jwk['kid'][:16]}...): add it to the software statement in Raidiam")


def trust_chain(leaf_ec: str, about_leaf: str, authority: str, trust_anchor: str) -> list:
    """[leaf EC, authority about leaf, (anchor about authority,) anchor EC] - OIDFED §4 order."""
    chain = [leaf_ec, about_leaf]
    if _strip(authority) != _strip(trust_anchor):
        chain.append(subordinate_statement(trust_anchor, authority))
    chain.append(_get_statement(_strip(trust_anchor) + "/.well-known/openid-federation"))
    return chain


# ── Token ──────────────────────────────────────────────────────────────────────────────────────────

def client_assertion(entity_id: str, private_key, public_jwk: dict, audience: str, chain: list = None) -> str:
    """A private_key_jwt. With a chain, it rides in the trust_chain header; without one, PingFederate (0.3.0+)
    resolves the chain itself by discovery, starting from <sub>/.well-known/openid-federation."""
    now = int(time.time())
    claims = {"iss": entity_id, "sub": entity_id, "aud": audience, "iat": now, "exp": now + 60,
              "jti": str(uuid.uuid4())}
    headers = {"kid": public_jwk["kid"]}
    if chain:
        headers["trust_chain"] = chain
    return jwt.encode(claims, private_key, algorithm=public_jwk["alg"], headers=headers)


def registration_endpoint(issuer: str) -> str:
    """The OP's federation_registration_endpoint, from its own Entity Configuration."""
    resp = requests.get(reachable(_strip(issuer) + "/.well-known/openid-federation"), timeout=15, verify=pf_verify())
    resp.raise_for_status()
    endpoint = _claims(resp.text.strip()).get("metadata", {}).get("openid_provider", {}).get(
        "federation_registration_endpoint")
    if not endpoint:
        raise RuntimeError(f"{issuer} publishes no federation_registration_endpoint")
    return endpoint


def explicit_register(endpoint: str, entity_configuration_jwt: str) -> dict:
    """POST only the Entity Configuration (no chain): the OP resolves the trust chain itself from authority_hints
    (OIDFED §12.2.1) and answers with an explicit-registration-response+jwt. Returns its (unverified) claims."""
    resp = requests.post(reachable(endpoint), data=entity_configuration_jwt, timeout=60, verify=pf_verify(),
                         headers={"Content-Type": "application/entity-statement+jwt",
                                  "Accept": "application/explicit-registration-response+jwt"})
    if resp.status_code != 200:
        raise RuntimeError(f"registration endpoint answered {resp.status_code}: {resp.text[:500]}")
    return _claims(resp.text.strip())


def request_token(discovery: dict, entity_id: str, assertion: str, authorization_details=None, scope=None) -> dict:
    form = {
        "grant_type": "client_credentials",
        "client_id": entity_id,
        "client_assertion_type": JWT_BEARER,
        "client_assertion": assertion,
    }
    if authorization_details:
        form["authorization_details"] = json.dumps(authorization_details)
    if scope:
        form["scope"] = scope
    resp = requests.post(reachable(discovery["token_endpoint"]), data=form, timeout=30, verify=pf_verify(),
                         headers={"Accept": "application/json"})
    if resp.status_code != 200:
        raise RuntimeError(f"token endpoint answered {resp.status_code}: {resp.text[:500]}")
    return resp.json()
