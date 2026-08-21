#!/usr/bin/env python3
"""
Activation key system.
Key = HMAC-SHA256(machine_id + expiry, master_secret)[:24].hex()
"""

import hmac
import hashlib
import os
from datetime import datetime, timedelta

MASTER_SECRET_PATH = "/var/lib/leaktrace/activation.secret"
ACTIVATION_KEY_PATH = "/var/lib/leaktrace/activation.key"


def _get_machine_id() -> str:
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        if os.path.exists(path):
            with open(path) as f:
                mid = f.read().strip()
                if mid:
                    return mid
    import socket
    return socket.gethostname()


def _load_or_create_secret() -> bytes:
    os.makedirs(os.path.dirname(MASTER_SECRET_PATH), exist_ok=True)
    if os.path.exists(MASTER_SECRET_PATH):
        with open(MASTER_SECRET_PATH, "rb") as f:
            return f.read().strip()
    secret = os.urandom(32).hex().encode()
    with open(MASTER_SECRET_PATH, "wb") as f:
        f.write(secret)
    os.chmod(MASTER_SECRET_PATH, 0o600)
    return secret


def _compute_sig(machine_id: str, expiry_str: str) -> str:
    secret = _load_or_create_secret()
    payload = f"{machine_id}:{expiry_str}".encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()[:24]


def generate_key(machine_id: str = None, valid_days: int = 365) -> str:
    if not machine_id:
        machine_id = _get_machine_id()
    expiry = (datetime.utcnow() + timedelta(days=valid_days)).strftime("%Y%m%d")
    sig = _compute_sig(machine_id, expiry)
    return f"LT-{sig[:8]}-{sig[8:16]}-{sig[16:24]}-{expiry}"


def verify_key(key: str) -> tuple[bool, str]:
    try:
        parts = key.strip().split("-")
        if len(parts) != 5 or parts[0] != "LT":
            return False, "Invalid key format."

        expiry_str = parts[4]
        expiry = datetime.strptime(expiry_str, "%Y%m%d")
        if datetime.utcnow() > expiry:
            return False, f"Key expired on {expiry.strftime('%Y-%m-%d')}."

        machine_id = _get_machine_id()
        sig = _compute_sig(machine_id, expiry_str)
        expected_key = f"LT-{sig[:8]}-{sig[8:16]}-{sig[16:24]}-{expiry_str}"

        if not hmac.compare_digest(key.strip(), expected_key):
            return False, "Key is not valid for this machine."

        return True, f"Valid until {expiry.strftime('%Y-%m-%d')}."

    except Exception as e:
        return False, f"Key verification error: {e}"


def activate(key: str) -> bool:
    valid, reason = verify_key(key)
    if not valid:
        print(f"[!] Activation failed: {reason}")
        return False
    os.makedirs(os.path.dirname(ACTIVATION_KEY_PATH), exist_ok=True)
    with open(ACTIVATION_KEY_PATH, "w") as f:
        f.write(key.strip())
    os.chmod(ACTIVATION_KEY_PATH, 0o644)
    print(f"[✓] Activated successfully. {reason}")
    return True


def check_activated() -> tuple[bool, str]:
    if not os.path.exists(ACTIVATION_KEY_PATH):
        return False, "Not activated. Run: leaktrace activate <key>"
    with open(ACTIVATION_KEY_PATH) as f:
        key = f.read().strip()
    return verify_key(key)
