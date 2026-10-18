"""OpenBao for the rig's bridge keys: initialise (once), unseal, enable transit, write the two policies and their tokens,
and import the bridge keys already in use - so PingFederate can sign each attested client's bridge assertion in the
vault (OIDF_BRIDGE_SIGNER_BACKING=vault) and the provider can enrol new agents there.

    python3 openbao/setup.py            idempotent: initialises only an uninitialised vault, imports only missing keys

Writes, under keys/openbao/ (git-ignored, 0600): init.json (the unseal key and root token), pf-bridge.token (PingFederate:
read and sign bridge-* keys), provider/provider.token (the agent provider: create bridge-* keys and their CSRs - never sign, export,
back up or delete them). Imports, as RSA transit keys, the bridge keys the rig's existing clients are certified with:
bridge-spire-workload, bridge-spire-client, bridge-accounts-agent, bridge-payments-agent and each deployed Principal
version's (bridge-principal-N) - from keys/raidiam/... - so Raidiam's certificates stay valid. Nothing is printed but
names; the key files are left where they are.

OPENBAO_ADDR (default http://localhost:8200).
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.dirname(HERE)
KEYS = os.path.join(DEMO, "keys")
OUT = os.path.join(KEYS, "openbao")
ADDR = os.environ.get("OPENBAO_ADDR", "http://localhost:8200").rstrip("/")

PF_POLICY = """
# PingFederate's bridge signer: describe and sign with bridge keys, nothing else.
path "transit/keys/bridge-*" { capabilities = ["read"] }
path "transit/sign/bridge-*" { capabilities = ["update"] }
"""
PROVIDER_POLICY = """
# The agent provider enrols agents: it creates their bridge keys and has the vault make their CSRs. OpenBao counts
# creating a key as an update, and a deny on a key's /config cannot outrank this glob, so the provider can also change a
# bridge key's settings (make it exportable, rotate it) - it could disrupt an agent, as it can already through the
# agent's entity key it holds. It cannot sign with a bridge key (it would then be every agent's bridge), export, back up
# or delete one: no rule here grants those paths.
path "transit/keys/bridge-*" { capabilities = ["create", "read", "update"] }
path "transit/sign/*" { capabilities = ["deny"] }
path "transit/export/*" { capabilities = ["deny"] }
path "transit/backup/*" { capabilities = ["deny"] }
"""


def call(method, path, body=None, token=None, ok=(200, 204)):
    req = urllib.request.Request(ADDR + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"X-Vault-Token": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode()
            return r.status, json.loads(text) if text else {}
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        if e.code in ok:
            return e.code, json.loads(text) if text else {}
        raise RuntimeError(f"{method} {path}: {e.code} {text[:200]}") from None


def save(name, content):
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o600)
    return path


def wait():
    for _ in range(60):
        try:
            call("GET", "/v1/sys/health", ok=(200, 429, 472, 473, 501, 503))
            return
        except Exception:
            time.sleep(1)
    sys.exit(f"OpenBao does not answer at {ADDR}")


def init_and_unseal():
    _, st = call("GET", "/v1/sys/init")
    if not st.get("initialized"):
        _, init = call("PUT", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        save("init.json", json.dumps({"unseal_key": init["keys_base64"][0], "root_token": init["root_token"]}))
        print("initialised  keys/openbao/init.json (the unseal key and root token)")
    with open(os.path.join(OUT, "init.json")) as f:
        init = json.load(f)
    _, seal = call("GET", "/v1/sys/seal-status")
    if seal.get("sealed"):
        call("PUT", "/v1/sys/unseal", {"key": init["unseal_key"]})
        print("unsealed")
    return init["root_token"]


def configure(root):
    _, mounts = call("GET", "/v1/sys/mounts", token=root)
    if "transit/" not in (mounts.get("data") or mounts):
        call("POST", "/v1/sys/mounts/transit", {"type": "transit"}, token=root)
        print("enabled      transit")
    for name, policy in (("pf-bridge", PF_POLICY), ("provider", PROVIDER_POLICY)):
        call("PUT", f"/v1/sys/policies/acl/{name}", {"policy": policy}, token=root)
    # The provider's token in a directory of its own: the provider mounts that, and so never sees PingFederate's token
    # or the root token beside it.
    for name, policy in (("pf-bridge", "pf-bridge"), ("provider/provider", "provider")):
        path = os.path.join(OUT, f"{name}.token")
        if os.path.exists(path):
            with open(path) as f:
                tok = f.read().strip()
            try:
                call("GET", "/v1/auth/token/lookup-self", token=tok)
                continue
            except RuntimeError:
                pass
        _, made = call("POST", "/v1/auth/token/create-orphan", {"policies": [policy], "period": "768h",
                                                                 "display_name": policy, "no_default_policy": False},
                       token=root)
        save(f"{name}.token", made["auth"]["client_token"])
        print(f"token        keys/openbao/{name}.token ({policy} policy, renewable)")


def import_key(root, name, private, source):
    status, _ = call("GET", f"/v1/transit/keys/{name}", token=root, ok=(200, 404))
    if status == 200:
        print(f"kept         {name}")
        return
    der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    _, wrapping = call("GET", "/v1/transit/wrapping_key", token=root)
    wrapping_key = serialization.load_pem_public_key(wrapping["data"]["public_key"].encode())
    ephemeral = os.urandom(32)
    wrapped_ephemeral = wrapping_key.encrypt(ephemeral, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
    ciphertext = base64.b64encode(wrapped_ephemeral + aes_key_wrap_with_padding(ephemeral, der)).decode()
    if isinstance(private, rsa.RSAPrivateKey):
        key_type = f"rsa-{private.key_size}"
    else:
        key_type = {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384", "secp521r1": "ecdsa-p521"}[private.curve.name]
    call("POST", f"/v1/transit/keys/{name}/import", {"ciphertext": ciphertext, "type": key_type,
                                                      "hash_function": "SHA256", "exportable": False}, token=root)
    print(f"imported     {name} ({key_type}, from {source}; not exportable)")


def import_existing(root):
    """The bridge keys the rig's clients are already certified with, under the names the bridge file gives them."""
    raidiam = os.path.join(KEYS, "raidiam")
    plain = os.path.join(raidiam, "bridge-spire-workload.private.jwk.json")
    if os.path.exists(plain):  # the plain attestation client keeps its key as a JWK only (EC P-256)
        import jwt
        with open(plain) as f:
            import_key(root, "bridge-spire-workload", jwt.PyJWK(json.load(f)).key, os.path.relpath(plain, DEMO))
    sources = [("bridge-spire-client", os.path.join(raidiam, "attested-client", "bridge.key.pem"))]
    agents = os.path.join(raidiam, "agents")
    for name in sorted(os.listdir(agents)) if os.path.isdir(agents) else []:
        sources.append((f"bridge-{name}", os.path.join(agents, name, "bridge.key.pem")))
    principals = os.path.join(raidiam, "principals")
    for name in sorted(os.listdir(principals)) if os.path.isdir(principals) else []:
        state = os.path.join(principals, name, "deployed.json")
        if os.path.exists(state):  # only versions Raidiam has certified a bridge key for
            sources.append((f"bridge-{name}", os.path.join(principals, name, "bridge.key.pem")))
    for name, pem in sources:
        if os.path.exists(pem):
            with open(pem, "rb") as f:
                import_key(root, name, serialization.load_pem_private_key(f.read(), password=None), os.path.relpath(pem, DEMO))


def main():
    wait()
    root = init_and_unseal()
    configure(root)
    import_existing(root)
    print(f"OpenBao ready at {ADDR}")


if __name__ == "__main__":
    main()
