"""
Watermark strategy:
  1. Embed doc_id in PDF /Keywords via pypdf (works on compressed PDFs)
  2. Append hidden comment before %%EOF (raw bytes fallback layer)
"""

import uuid
import re
import io
from .config import WATERMARK_KEY

try:
    from pypdf import PdfReader, PdfWriter
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False


def generate_doc_id() -> str:
    return str(uuid.uuid4())


def embed(pdf_bytes: bytes, doc_id: str) -> bytes:
    # Layer 1: pypdf metadata injection (survives compression)
    if HAS_PYPDF:
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            existing = reader.metadata or {}
            existing_kw = existing.get("/Keywords", "")
            writer.add_metadata({
                "/Keywords": f"{existing_kw} [LT:{doc_id}]".strip(),
                f"/{WATERMARK_KEY}": doc_id,
            })
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes = buf.getvalue()
        except Exception:
            pass  # fall through to raw layer

    # Layer 2: raw comment before %%EOF (always applied)
    eof_marker = b"%%EOF"
    if eof_marker in pdf_bytes:
        idx = pdf_bytes.rfind(eof_marker)
        pdf_bytes = pdf_bytes[:idx] + b"% LEAKTRACE:" + doc_id.encode() + b"\n" + pdf_bytes[idx:]
    else:
        pdf_bytes = pdf_bytes + b"\n% LEAKTRACE:" + doc_id.encode() + b"\n"

    return pdf_bytes


def extract(pdf_bytes: bytes) -> str | None:
    # Try raw comment layer first (fastest)
    m = re.search(rb"% LEAKTRACE:([a-f0-9\-]{36})", pdf_bytes)
    if m:
        return m.group(1).decode()

    # Try pypdf metadata
    if HAS_PYPDF:
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            meta = reader.metadata or {}
            for key in (f"/{WATERMARK_KEY}", "/Keywords"):
                val = meta.get(key, "")
                if val:
                    m2 = re.search(r"\[LT:([a-f0-9\-]{36})\]", val)
                    if m2:
                        return m2.group(1)
                    m3 = re.search(r"^[a-f0-9\-]{36}$", val.strip())
                    if m3:
                        return m3.group(0)
        except Exception:
            pass

    # Raw keyword fallback
    m = re.search(rb"\[LT:([a-f0-9\-]{36})\]", pdf_bytes)
    if m:
        return m.group(1).decode()

    return None
