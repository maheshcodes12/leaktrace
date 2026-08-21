"""
Watermark — 3 independent layers:
  Layer 1: PDF /Keywords metadata
  Layer 2: Hidden EOF comment in PDF bytes  
  Layer 3: Unicode homoglyph substitution (encodes stripped UUID = 32 hex chars = 128 bits)
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


# Homoglyph map — Latin → visually identical Unicode
HOMOGLYPH_MAP = {
    'a': '\u0430', 'e': '\u0435', 'o': '\u043e',
    'p': '\u0440', 'c': '\u0441', 'x': '\u0445',
    'i': '\u0456',  'y': '\u0443',
}
REVERSE_MAP = {v: k for k, v in HOMOGLYPH_MAP.items()}
ENCODABLE = set(HOMOGLYPH_MAP.keys())


def generate_doc_id() -> str:
    return str(uuid.uuid4())


def _id_to_bits(doc_id: str) -> list[int]:
    """Encode only the 32 hex chars of UUID (strip hyphens) → 128 bits."""
    stripped = doc_id.replace('-', '')  # 32 hex chars
    bits = []
    for ch in stripped:
        val = int(ch, 16)
        for i in range(3, -1, -1):
            bits.append((val >> i) & 1)
    return bits  # 128 bits


def _bits_to_id(bits: list[int]) -> str | None:
    """Decode 128 bits → UUID string."""
    if len(bits) < 128:
        return None
    hex_chars = []
    for i in range(0, 128, 4):
        val = (bits[i] << 3) | (bits[i+1] << 2) | (bits[i+2] << 1) | bits[i+3]
        hex_chars.append(f'{val:x}')
    h = ''.join(hex_chars)  # 32 hex chars
    # Reformat as UUID
    candidate = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', candidate):
        return candidate
    return None


def _embed_homoglyphs(text: str, doc_id: str) -> str:
    bits = _id_to_bits(doc_id)
    result = []
    bit_idx = 0
    for ch in text:
        if bit_idx < len(bits) and ch in ENCODABLE:
            result.append(HOMOGLYPH_MAP[ch] if bits[bit_idx] == 1 else ch)
            bit_idx += 1
        else:
            result.append(ch)
    return ''.join(result)


def _extract_homoglyphs(text: str) -> str | None:
    bits = []
    for ch in text:
        if ch in ENCODABLE:
            bits.append(0)
        elif ch in REVERSE_MAP:
            bits.append(1)
    if len(bits) < 128:
        return None
    return _bits_to_id(bits[:128])


def embed_text(text: str, doc_id: str) -> str:
    """Embed doc_id into plain text via homoglyphs. For demo use."""
    return _embed_homoglyphs(text, doc_id)


def extract_text(text: str) -> str | None:
    """Extract doc_id from plain text with homoglyphs."""
    return _extract_homoglyphs(text)


def embed(pdf_bytes: bytes, doc_id: str) -> bytes:
    """Apply all 3 watermark layers to PDF bytes."""

    # Layer 1: pypdf metadata
    if HAS_PYPDF:
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            existing_kw = (reader.metadata or {}).get("/Keywords", "")
            writer.add_metadata({
                "/Keywords": f"{existing_kw} [LT:{doc_id}]".strip(),
                f"/{WATERMARK_KEY}": doc_id,
            })
            buf = io.BytesIO()
            writer.write(buf)
            pdf_bytes = buf.getvalue()
        except Exception:
            pass

    # Layer 2: raw EOF comment
    eof = b"%%EOF"
    if eof in pdf_bytes:
        idx = pdf_bytes.rfind(eof)
        pdf_bytes = pdf_bytes[:idx] + b"% LEAKTRACE:" + doc_id.encode() + b"\n" + pdf_bytes[idx:]
    else:
        pdf_bytes += b"\n% LEAKTRACE:" + doc_id.encode() + b"\n"

    # Layer 3: steganographic encoding stored in /LT3 metadata field
    if HAS_PYPDF:
        try:
            from .stego import embed_text as stego_embed
            reader = PdfReader(io.BytesIO(pdf_bytes))
            full_text = ""
            for page in reader.pages:
                full_text += (page.extract_text() or "")
            if full_text.strip():
                encoded_text, strategy = stego_embed(full_text, doc_id)
                writer2 = PdfWriter()
                for page in reader.pages:
                    writer2.add_page(page)
                meta = dict(reader.metadata or {})
                meta["/LT3"] = encoded_text
                meta["/LT3Strategy"] = strategy
                writer2.add_metadata(meta)
                buf2 = io.BytesIO()
                writer2.write(buf2)
                pdf_bytes = buf2.getvalue()
        except Exception:
            pass

    return pdf_bytes


def extract_all_layers(pdf_bytes: bytes) -> dict:
    """Try all 3 layers. Returns per-layer results + resolved doc_id."""
    result = {'layer1': None, 'layer2': None, 'layer3': None, 'doc_id': None}

    # Layer 2: raw bytes scan
    m = re.search(rb"% LEAKTRACE:([a-f0-9\-]{36})", pdf_bytes)
    if m:
        result['layer2'] = m.group(1).decode()

    if HAS_PYPDF:
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            meta = reader.metadata or {}

            # Layer 1: metadata fields
            for key in (f"/{WATERMARK_KEY}", "/Keywords"):
                val = meta.get(key, "")
                if val:
                    m2 = re.search(r"\[LT:([a-f0-9\-]{36})\]", val)
                    if m2:
                        result['layer1'] = m2.group(1)
                        break
                    if re.match(r"^[a-f0-9\-]{36}$", val.strip()):
                        result['layer1'] = val.strip()
                        break

            # Layer 3: stego from /LT3 field
            lt3 = meta.get("/LT3", "")
            if lt3:
                from .stego import extract_text as stego_extract
                found, _ = stego_extract(lt3)
                result['layer3'] = found

        except Exception:
            pass

    # Raw fallback for layer1
    if not result['layer1']:
        m = re.search(rb"\[LT:([a-f0-9\-]{36})\]", pdf_bytes)
        if m:
            result['layer1'] = m.group(1).decode()

    result['doc_id'] = result['layer2'] or result['layer1'] or result['layer3']
    return result


def extract(pdf_bytes: bytes) -> str | None:
    return extract_all_layers(pdf_bytes)['doc_id']