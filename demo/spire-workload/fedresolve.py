"""Trust chain resolution done by the caller, for entities the federation's resolver cannot reach (OIDFED §10).

Raidiam's authority resolves an entity at /resolve by fetching the entity's own Entity Configuration, so it
fails for anything inside a protected network - the bank's resource servers, its agents, its provider. Its
/fetch still answers: the authority's signed statement about the entity, which needs nothing from the entity
itself. So a party inside the network resolves the chain on its own: the leaf's Entity Configuration from the
leaf, each superior's statement about its subordinate from that superior's fetch endpoint, every signature
checked downwards from the trust anchor's PINNED keys, and the superiors' metadata_policy applied to the leaf's
metadata. Trust is still entirely the federation's; only the leaf's document comes from inside.

resolve(entity_id) -> {"metadata": {...resolved...}, "trust_marks": [...], "chain": [jwt, ...], "exp": int}
"""
import base64
import json
import os
import time
from urllib.parse import quote

import jwt
import requests
from jwt import PyJWKSet

import federation

WELL_KNOWN = "/.well-known/openid-federation"


def _claims(statement: str) -> dict:
    payload = statement.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _verify(statement: str, jwks: dict) -> dict:
    """The statement's claims, if a key in jwks signed it (matched by kid, else any)."""
    header = jwt.get_unverified_header(statement)
    keys = [k for k in PyJWKSet.from_dict(jwks).keys if not header.get("kid") or k.key_id == header.get("kid")]
    for key in keys:
        try:
            return jwt.decode(statement, key.key, algorithms=[header["alg"]],
                              options={"verify_aud": False, "verify_iat": False})
        except jwt.PyJWTError:
            continue
    raise ValueError(f"{_claims(statement).get('iss')}'s statement about {_claims(statement).get('sub')} is not "
                     f"signed by a key its superior vouches for (kid {header.get('kid')})")


def pinned_anchor_jwks() -> dict:
    """The anchor's keys, pinned: TRUST_ANCHOR_JWKS, or OIDF_FEDERATION_TRUST_ANCHOR_JWKS in TRUST_ANCHOR_ENV_FILE
    (the rig's vars.raidiam.env, so the pin is written down once)."""
    if os.environ.get("TRUST_ANCHOR_JWKS"):
        return json.loads(os.environ["TRUST_ANCHOR_JWKS"])
    with open(os.environ["TRUST_ANCHOR_ENV_FILE"]) as f:
        for line in f:
            if line.startswith("OIDF_FEDERATION_TRUST_ANCHOR_JWKS="):
                return json.loads(line.split("=", 1)[1])
    raise RuntimeError("no pinned trust anchor keys: set TRUST_ANCHOR_JWKS or TRUST_ANCHOR_ENV_FILE")


class Resolver:
    """fetch(url) -> requests.Response; reachable(url) -> the URL to connect to for an entity's own document."""

    def __init__(self, trust_anchor: str, anchor_jwks: dict, verify, reachable=lambda u: u):
        self.trust_anchor, self.anchor_jwks, self.verify, self.reachable = trust_anchor, anchor_jwks, verify, reachable

    def _get(self, url: str) -> str:
        resp = federation.get(url, timeout=20, verify=self.verify)  # a network or TLS blip is retried, a 404 is not
        resp.raise_for_status()
        return resp.text.strip()

    def entity_configuration(self, entity_id: str) -> str:
        return self._get(self.reachable(entity_id.rstrip("/") + WELL_KNOWN))

    def subordinate_statement(self, superior: str, subject: str) -> str:
        fetch = _claims(self.entity_configuration(superior))["metadata"]["federation_entity"]["federation_fetch_endpoint"]
        return self._get(f"{fetch}?sub={quote(subject, safe='')}")

    def resolve(self, entity_id: str, entity_type: str = None) -> dict:
        """Walks up authority_hints from the leaf to the anchor, then verifies down from the pinned keys."""
        leaf = self.entity_configuration(entity_id)
        leaf_claims = _claims(leaf)
        if leaf_claims.get("iss") != entity_id.rstrip("/") and leaf_claims.get("iss") != entity_id:
            raise ValueError(f"{entity_id} served an Entity Configuration for {leaf_claims.get('iss')}")
        # Upwards: (superior, its statement about the subject), one authority hint at a time.
        statements, subject, superiors = [], entity_id, leaf_claims.get("authority_hints") or []
        while subject != self.trust_anchor:
            if not superiors:
                raise ValueError(f"{subject} names no superior and is not the trust anchor")
            superior = superiors[0]
            statements.append(self.subordinate_statement(superior, subject))
            subject = superior
            if subject != self.trust_anchor:
                superiors = _claims(self.entity_configuration(subject)).get("authority_hints") or []
        # Downwards: each statement verified with the keys the one above it vouches for.
        jwks, policies, exp = self.anchor_jwks, [], []
        for statement in reversed(statements):
            claims = _verify(statement, jwks)
            jwks = claims["jwks"]
            policies.append(claims.get("metadata_policy") or {})
            exp.append(claims["exp"])
        leaf_verified = _verify(leaf, jwks)
        exp.append(leaf_verified["exp"])
        metadata = leaf_verified.get("metadata") or {}
        # The anchor's policy first, then each superior's below it (OIDFED §6.1.4.1, the operators used here).
        for policy in policies:
            for etype, rules in policy.items():
                if etype in metadata or any("value" in r or "default" in r for r in rules.values()):
                    metadata[etype] = apply_policy(metadata.get(etype, {}), rules, f"{entity_id} {etype}")
        if entity_type and entity_type not in metadata:
            raise ValueError(f"{entity_id} has no {entity_type} metadata")
        if min(exp) < time.time():
            raise ValueError(f"the chain for {entity_id} has expired")
        return {"metadata": metadata, "trust_marks": leaf_verified.get("trust_marks") or [],
                "chain": [leaf, *statements], "exp": min(exp), "jwks": leaf_verified.get("jwks")}


def apply_policy(metadata: dict, rules: dict, where: str) -> dict:
    out = dict(metadata)
    for name, rule in rules.items():
        if "value" in rule:
            out[name] = rule["value"]
            continue
        if "add" in rule:
            add = rule["add"] if isinstance(rule["add"], list) else [rule["add"]]
            out[name] = list(dict.fromkeys([*(out.get(name) or []), *add]))
        if "default" in rule and name not in out:
            out[name] = rule["default"]
        if "subset_of" in rule and name in out:
            out[name] = [v for v in out[name] if v in rule["subset_of"]]
        if "one_of" in rule and name in out and out[name] not in rule["one_of"]:
            raise ValueError(f"{where}: {name}={out[name]!r} is not one of {rule['one_of']}")
        if "superset_of" in rule and name in out and not set(rule["superset_of"]) <= set(out[name]):
            raise ValueError(f"{where}: {name} must include {rule['superset_of']}")
        if rule.get("essential") and name not in out:
            raise ValueError(f"{where}: {name} is essential and missing")
    return out


def ca_bundle(extra: str = None) -> str:
    """A CA file trusting the public roots (Raidiam) and the protected network's own CA (extra, e.g. the rig's)."""
    import certifi
    if not extra:
        return certifi.where()
    path = "/tmp/fedresolve-ca.pem"
    with open(path, "w") as out, open(certifi.where()) as public, open(extra) as private:
        out.write(public.read() + "\n" + private.read())
    return path
