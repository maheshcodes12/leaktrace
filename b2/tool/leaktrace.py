#!/usr/bin/env python3
"""
LeakTrace CLI
Usage:
  leaktrace activate <key>        - Activate this installation
  leaktrace decrypt  <file>       - Decrypt an encrypted PDF
  leaktrace verify   <file>       - Full forensic verification
  leaktrace verify-text <file>    - Verify plain .txt file (copy-paste demo)
  leaktrace genkey  [machine_id]  - (Admin) Generate activation key
  leaktrace whoami                - Show activation status
"""

import sys
import os
import hashlib
import pathlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

from core.crypto import decrypt, load_master_password
from core.watermark import extract_all_layers
from core.stego import extract_text as stego_extract_text
from core.logger import lookup, log_access, get_access_log, _sha256
from core.config import MASTER_KEY_PATH
from keys.activation import activate, check_activated, generate_key, _get_machine_id


def require_activation():
    valid, reason = check_activated()
    if not valid:
        print(f"[!] {reason}")
        sys.exit(1)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cmd_activate(args):
    if not args:
        print("Usage: leaktrace activate <KEY>")
        sys.exit(1)
    activate(args[0])


def cmd_genkey(args):
    machine_id = args[0] if args else None
    days = int(args[1]) if len(args) > 1 else 365
    key = generate_key(machine_id, days)
    mid = machine_id or _get_machine_id()
    print(f"Machine ID : {mid}")
    print(f"Valid days : {days}")
    print(f"Key        : {key}")


def cmd_whoami(_):
    valid, reason = check_activated()
    status = "✓ Activated" if valid else "✗ Not activated"
    print(f"Machine ID : {_get_machine_id()}")
    print(f"Status     : {status}")
    print(f"Details    : {reason}")


def cmd_decrypt(args):
    require_activation()
    if not args:
        print("Usage: leaktrace decrypt <file>")
        sys.exit(1)

    path = args[0]
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    password = load_master_password(MASTER_KEY_PATH)
    with open(path, "rb") as f:
        data = f.read()

    try:
        decrypted = decrypt(data, password)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    p = pathlib.Path(path)
    stem = p.stem if p.suffix != ".pdf" else p.with_suffix("").stem
    out_path = str(p.parent / (stem + "_decrypted.pdf"))
    with open(out_path, "wb") as f:
        f.write(decrypted)

    doc_id = extract_all_layers(decrypted)['doc_id']
    if doc_id:
        log_access(doc_id, "decrypt")

    print(f"[✓] Decrypted → {out_path}")


def _print_layer_status(layers: dict):
    """Print which watermark layers were found."""
    print(f"\n  ── WATERMARK LAYERS ────────────────")
    icons = {True: "✓", False: "✗"}
    print(f"  Layer 1 (PDF Metadata)   : {icons[bool(layers['layer1'])]} {'found: ' + layers['layer1'][:8] + '...' if layers['layer1'] else 'not found'}")
    print(f"  Layer 2 (EOF Comment)    : {icons[bool(layers['layer2'])]} {'found: ' + layers['layer2'][:8] + '...' if layers['layer2'] else 'not found'}")
    print(f"  Layer 3 (Homoglyphs)     : {icons[bool(layers['layer3'])]} {'found: ' + layers['layer3'][:8] + '...' if layers['layer3'] else 'not found'}")

    # Consistency check
    found = [v for v in [layers['layer1'], layers['layer2'], layers['layer3']] if v]
    if len(set(found)) > 1:
        print(f"  ⚠ WARNING: layers disagree — possible partial tampering")
    elif len(found) == 0:
        print(f"  ✗ No watermark found in any layer")
    else:
        print(f"  Watermark ID  : {layers['doc_id']}")


def cmd_verify(args):
    require_activation()
    if not args:
        print("Usage: leaktrace verify <file>")
        sys.exit(1)

    path = args[0]
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    with open(path, "rb") as f:
        data = f.read()

    password = load_master_password(MASTER_KEY_PATH)

    # Determine if encrypted
    is_encrypted = False
    try:
        pdf_bytes = decrypt(data, password)
        is_encrypted = True
    except Exception:
        pdf_bytes = data

    print(f"\n{'='*44}")
    print(f"  LEAKTRACE VERIFICATION REPORT")
    print(f"{'='*44}")
    print(f"  File          : {os.path.basename(path)}")
    print(f"  Encrypted     : {'Yes' if is_encrypted else 'No'}")

    # Extract all layers
    layers = extract_all_layers(pdf_bytes)
    _print_layer_status(layers)

    doc_id = layers['doc_id']
    if not doc_id:
        print(f"\n  [!] No watermark found. File may not be LeakTrace-protected.")
        print(f"{'='*44}\n")
        sys.exit(1)

    log_access(doc_id, "verify")

    # Origin lookup
    record = lookup(doc_id)
    if record:
        print(f"\n  ── ORIGIN ──────────────────────────")
        print(f"  Printed By    : {record['user']}")
        print(f"  Hostname      : {record['hostname']}")
        print(f"  Timestamp     : {record['timestamp']} UTC")
        print(f"  Document      : {record['title']}")
        print(f"  Saved At      : {record['output_path']}")

        # Tamper detection
        print(f"\n  ── TAMPER CHECK ────────────────────")
        original_hash = record["file_hash"]

        if original_hash == "unknown":
            print(f"  Status        : ⚠ No hash on record (old log entry)")

        elif not is_encrypted:
            # File is plaintext — could be a decrypted copy or copy-pasted content
            # Hash WILL differ from encrypted spool — explain this clearly
            saved_path = record["output_path"]
            if os.path.exists(saved_path):
                spool_hash = _sha256(saved_path)
                if spool_hash == original_hash:
                    print(f"  Status        : ✓ Spool file UNTAMPERED")
                    print(f"  Note          : You are verifying a decrypted copy.")
                    print(f"                  Hash check performed on original spool file.")
                else:
                    print(f"  Status        : ✗ Spool file TAMPERED — encrypted file was modified!")
                    print(f"  Original Hash : {original_hash}")
                    print(f"  Current Hash  : {spool_hash}")
            else:
                print(f"  Status        : ⚠ Spool file not found at {saved_path}")
                print(f"  Note          : Cannot verify — original encrypted file missing.")
                print(f"  Tip           : Watermark identity still confirmed above.")

        else:
            # File is encrypted — hash must match directly
            saved_path = record["output_path"]
            if os.path.exists(saved_path):
                spool_hash = _sha256(saved_path)
                if spool_hash == original_hash:
                    print(f"  Status        : ✓ UNTAMPERED — matches original print")
                else:
                    print(f"  Status        : ✗ TAMPERED — file modified after printing!")
                    print(f"  Original Hash : {original_hash}")
                    print(f"  Current Hash  : {spool_hash}")
            else:
                current_hash = _sha256_bytes(data)
                if current_hash == original_hash:
                    print(f"  Status        : ✓ UNTAMPERED")
                else:
                    print(f"  Status        : ✗ TAMPERED")
                    print(f"  Original Hash : {original_hash}")
                    print(f"  Current Hash  : {current_hash}")

        # Access log
        access_entries = get_access_log(doc_id)
        print(f"\n  ── ACCESS LOG ──────────────────────")
        if access_entries:
            for entry in access_entries:
                icon = "🔓" if entry["action"] == "decrypt" else "🔍"
                print(f"  {icon} {entry['action'].upper():<8} {entry['user']}@{entry['hostname']} — {entry['timestamp']} UTC")
        else:
            print(f"  (no actions recorded yet)")

    else:
        print(f"\n  ── ORIGIN ──────────────────────────")
        print(f"  ⚠ Watermark found but no matching DB record.")
        print(f"  This file was printed on a different machine")
        print(f"  or the database has been cleared.")

    print(f"{'='*44}\n")


def cmd_verify_text(args):
    """Verify a plain text file — for copy-paste demo using Layer 3."""
    require_activation()
    if not args:
        print("Usage: leaktrace verify-text <file.txt>")
        sys.exit(1)

    path = args[0]
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    print(f"\n{'='*44}")
    print(f"  LEAKTRACE TEXT VERIFICATION")
    print(f"{'='*44}")
    print(f"  File          : {os.path.basename(path)}")
    print(f"  Mode          : Plain text / Layer 3 only")

    doc_id, strategy = stego_extract_text(text)

    print(f"\n  ── WATERMARK LAYERS ────────────────")
    print(f"  Layer 1 (PDF Metadata)   : — not applicable for plain text")
    print(f"  Layer 2 (EOF Comment)    : — not applicable for plain text")
    print(f"  Layer 3 (Homoglyphs/ZW)  : {'✓ found via ' + strategy + ': ' + doc_id[:8] + '...' if doc_id else '✗ not found'}")

    if not doc_id:
        print(f"\n  [!] No homoglyph watermark found.")
        print(f"  Tip: Make sure you copied from a LeakTrace-processed PDF.")
        print(f"{'='*44}\n")
        sys.exit(1)

    log_access(doc_id, "verify-text")

    print(f"  Watermark ID  : {doc_id}")

    record = lookup(doc_id)
    if record:
        print(f"\n  ── ORIGIN ──────────────────────────")
        print(f"  Printed By    : {record['user']}")
        print(f"  Hostname      : {record['hostname']}")
        print(f"  Timestamp     : {record['timestamp']} UTC")
        print(f"  Document      : {record['title']}")
        print(f"\n  ── TAMPER CHECK ────────────────────")
        print(f"  Status        : ⚠ Hash check not possible on plain text")
        print(f"                  Identity confirmed via homoglyph watermark")

        access_entries = get_access_log(doc_id)
        print(f"\n  ── ACCESS LOG ──────────────────────")
        if access_entries:
            for entry in access_entries:
                icon = "🔓" if entry["action"] == "decrypt" else "🔍"
                print(f"  {icon} {entry['action'].upper():<10} {entry['user']}@{entry['hostname']} — {entry['timestamp']} UTC")
        else:
            print(f"  (no actions recorded yet)")
    else:
        print(f"\n  ⚠ Watermark found but no DB record on this machine.")

    print(f"{'='*44}\n")


COMMANDS = {
    "activate":    cmd_activate,
    "decrypt":     cmd_decrypt,
    "verify":      cmd_verify,
    "verify-text": cmd_verify_text,
    "genkey":      cmd_genkey,
    "whoami":      cmd_whoami,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(0)
    COMMANDS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()