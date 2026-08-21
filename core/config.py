import os

# Directories
SPOOL_DIR = "/var/spool/virtprinter"
LEAKTRACE_DIR = "/var/lib/leaktrace"
DB_PATH = os.path.join(LEAKTRACE_DIR, "leaktrace.db")
MASTER_KEY_PATH = os.path.join(LEAKTRACE_DIR, "master.key")

# Watermark marker (hidden in PDF metadata)
WATERMARK_KEY = "LeakTrace-ID"

os.makedirs(LEAKTRACE_DIR, exist_ok=True)
os.makedirs(SPOOL_DIR, exist_ok=True)
