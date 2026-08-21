#!/usr/bin/env python3
"""
Called by vpfilter.c:
  python3 process_job.py <input_pdf> <output_pdf> <job_id> <user> <title>

Watermarks + encrypts the PDF and logs to DB.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from core.watermark import generate_doc_id, embed
from core.crypto import encrypt, load_master_password
from core.logger import log_job
from core.config import MASTER_KEY_PATH


def main():
    if len(sys.argv) < 6:
        print("Usage: process_job.py <input> <output> <job_id> <user> <title>", file=sys.stderr)
        sys.exit(1)

    input_pdf  = sys.argv[1]
    output_pdf = sys.argv[2]
    job_id     = sys.argv[3]
    user       = sys.argv[4]
    title      = sys.argv[5]

    # Read original PDF
    with open(input_pdf, "rb") as f:
        pdf_bytes = f.read()

    # Step 1: Watermark
    doc_id = generate_doc_id()
    watermarked = embed(pdf_bytes, doc_id)

    # Step 2: Encrypt
    password = load_master_password(MASTER_KEY_PATH)
    encrypted = encrypt(watermarked, password)

    # Step 3: Write output
    with open(output_pdf, "wb") as f:
        f.write(encrypted)

    # Step 4: Log (pass actual output path so hash is computed correctly)
    log_job(doc_id, user, title, output_pdf)

    print(f"[LeakTrace] doc_id={doc_id}", file=sys.stderr)
    print(f"[LeakTrace] Encrypted PDF → {output_pdf}", file=sys.stderr)


if __name__ == "__main__":
    main()