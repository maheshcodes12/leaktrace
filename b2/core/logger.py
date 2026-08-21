import sqlite3
import socket
import hashlib
from datetime import datetime
from .config import DB_PATH


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS print_jobs (
            doc_id      TEXT PRIMARY KEY,
            user        TEXT,
            hostname    TEXT,
            timestamp   TEXT,
            title       TEXT,
            file_hash   TEXT,
            output_path TEXT
        )
    """)
    # Track every decrypt/verify access
    con.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id      TEXT,
            action      TEXT,
            user        TEXT,
            hostname    TEXT,
            timestamp   TEXT
        )
    """)
    con.commit()
    con.close()


def log_job(doc_id: str, user: str, title: str, file_path: str):
    init_db()
    file_hash = _sha256(file_path)
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO print_jobs VALUES (?,?,?,?,?,?,?)",
        (doc_id, user, socket.gethostname(), datetime.utcnow().isoformat(), title, file_hash, file_path)
    )
    con.commit()
    con.close()


def log_access(doc_id: str, action: str, user: str = None):
    """Log every decrypt or verify action against a doc_id."""
    init_db()
    import os, pwd
    if user is None:
        try:
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = str(os.getuid())
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO access_log (doc_id, action, user, hostname, timestamp) VALUES (?,?,?,?,?)",
        (doc_id, action, user, socket.gethostname(), datetime.utcnow().isoformat())
    )
    con.commit()
    con.close()


def get_access_log(doc_id: str) -> list[dict]:
    init_db()
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT action, user, hostname, timestamp FROM access_log WHERE doc_id=? ORDER BY timestamp",
        (doc_id,)
    ).fetchall()
    con.close()
    return [dict(zip(["action", "user", "hostname", "timestamp"], r)) for r in rows]


def lookup(doc_id: str) -> dict | None:
    init_db()
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT * FROM print_jobs WHERE doc_id=?", (doc_id,)).fetchone()
    con.close()
    if not row:
        return None
    keys = ["doc_id", "user", "hostname", "timestamp", "title", "file_hash", "output_path"]
    return dict(zip(keys, row))


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        return "unknown"
    return h.hexdigest()