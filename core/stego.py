"""
Layer 3 steganography — two encoding strategies:

Strategy A (homoglyph): replaces Latin chars with Unicode lookalikes
  - needs 128 encodable positions
  - works on rich text (articles, reports)

Strategy B (zero-width): inserts invisible zero-width chars between words
  - works on ANY text regardless of content
  - encodes doc_id in binary using ZWSP (0) and ZWNJ (1)

verify-text tries both strategies.
"""

import re

# Strategy A — homoglyphs
HOMOGLYPH_MAP = {
    'a': '\u0430', 'e': '\u0435', 'o': '\u043e',
    'p': '\u0440', 'c': '\u0441', 'x': '\u0445',
    'i': '\u0456',  'y': '\u0443',
}
REVERSE_MAP = {v: k for k, v in HOMOGLYPH_MAP.items()}
ENCODABLE = set(HOMOGLYPH_MAP.keys())

# Strategy B — zero-width chars (invisible)
ZW_ZERO = '\u200b'   # Zero Width Space = bit 0
ZW_ONE  = '\u200c'   # Zero Width Non-Joiner = bit 1
ZW_SEP  = '\u200d'   # Zero Width Joiner = separator (marks start/end)


def _id_to_bits(doc_id: str) -> list[int]:
    """32 hex chars → 128 bits."""
    stripped = doc_id.replace('-', '')
    bits = []
    for ch in stripped:
        val = int(ch, 16)
        for i in range(3, -1, -1):
            bits.append((val >> i) & 1)
    return bits


def _bits_to_id(bits: list[int]) -> str | None:
    if len(bits) < 128:
        return None
    hex_chars = []
    for i in range(0, 128, 4):
        val = (bits[i]<<3)|(bits[i+1]<<2)|(bits[i+2]<<1)|bits[i+3]
        hex_chars.append(f'{val:x}')
    h = ''.join(hex_chars)
    c = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', c):
        return c
    return None


# ── Strategy A: Homoglyphs ───────────────────────────────────────────────

def embed_homoglyph(text: str, doc_id: str) -> tuple[str, bool]:
    """Returns (encoded_text, success)."""
    bits = _id_to_bits(doc_id)
    encodable_count = sum(1 for c in text if c in ENCODABLE)
    if encodable_count < 128:
        return text, False  # not enough room

    result = []
    bit_idx = 0
    for ch in text:
        if bit_idx < len(bits) and ch in ENCODABLE:
            result.append(HOMOGLYPH_MAP[ch] if bits[bit_idx] == 1 else ch)
            bit_idx += 1
        else:
            result.append(ch)
    return ''.join(result), True


def extract_homoglyph(text: str) -> str | None:
    bits = []
    for ch in text:
        if ch in ENCODABLE:
            bits.append(0)
        elif ch in REVERSE_MAP:
            bits.append(1)
    return _bits_to_id(bits[:128]) if len(bits) >= 128 else None


# ── Strategy B: Zero-width chars ────────────────────────────────────────

def embed_zerowidth(text: str, doc_id: str) -> str:
    """Insert invisible zero-width chars between words to encode doc_id."""
    bits = _id_to_bits(doc_id)
    words = text.split(' ')

    if len(words) < len(bits) + 2:
        # Pad with space insertions between chars instead
        pass

    # Insert ZW_SEP as start marker, then bits between word gaps
    encoded_bits = ZW_SEP  # start marker
    for bit in bits:
        encoded_bits += (ZW_ONE if bit == 1 else ZW_ZERO)
    encoded_bits += ZW_SEP  # end marker

    # Insert after the first word
    if words:
        words[0] = words[0] + encoded_bits
    else:
        return encoded_bits + text

    return ' '.join(words)


def extract_zerowidth(text: str) -> str | None:
    """Extract doc_id from zero-width encoded text."""
    # Find content between SEP markers
    pattern = ZW_SEP + f'([{ZW_ZERO}{ZW_ONE}]+)' + ZW_SEP
    m = re.search(pattern, text)
    if not m:
        return None
    bits_str = m.group(1)
    bits = [1 if ch == ZW_ONE else 0 for ch in bits_str]
    return _bits_to_id(bits)


# ── Combined embed/extract ───────────────────────────────────────────────

def embed_text(text: str, doc_id: str) -> tuple[str, str]:
    """
    Try homoglyph first, fallback to zero-width.
    Returns (encoded_text, strategy_used)
    """
    encoded, ok = embed_homoglyph(text, doc_id)
    if ok:
        return encoded, 'homoglyph'
    encoded = embed_zerowidth(text, doc_id)
    return encoded, 'zerowidth'


def extract_text(text: str) -> tuple[str | None, str]:
    """
    Try both strategies.
    Returns (doc_id or None, strategy_name)
    """
    # Try homoglyph
    result = extract_homoglyph(text)
    if result:
        return result, 'homoglyph'

    # Try zero-width
    result = extract_zerowidth(text)
    if result:
        return result, 'zerowidth'

    return None, 'none'