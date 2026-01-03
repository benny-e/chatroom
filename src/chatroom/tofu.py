import hashlib
import json
import os
from pathlib import Path

def pubkey_fingerprint(pubkey_pem: bytes) -> str:
    # SHA-256 fingerprint of the PEM bytes
    return hashlib.sha256(pubkey_pem).hexdigest()

def known_servers_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    d = Path(base) / "chatroom"
    d.mkdir(parents=True, exist_ok=True)
    return d / "known_servers.json"

def load_known_servers() -> dict:
    p = known_servers_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}

def save_known_servers(data: dict) -> None:
    p = known_servers_path()
    p.write_text(json.dumps(data, indent=2))

#TOFU
#If we have not seen this server, pin its fingerprint
#If we have, reject the fingerprint if it has been changed
def verify_or_pin_server(host: str, port: int, pubkey_pem: bytes) -> None:
    fp = pubkey_fingerprint(pubkey_pem)
    server_id = f"{host}:{port}"

    known = load_known_servers()

    if server_id not in known:
        known[server_id] = fp
        save_known_servers(known)
        print(f"[TOFU] Pinned server key for {server_id}: {fp[:16]}...")
        return

    if known[server_id] != fp:
        raise RuntimeError(
            f"[TOFU] SERVER KEY CHANGED for {server_id}!\n"
            f"Known: {known[server_id]}\n"
            f"Got:   {fp}\n"
            "Refusing to connect (possible MITM or server key rotation)."
        )

