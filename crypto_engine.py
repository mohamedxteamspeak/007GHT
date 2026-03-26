# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║  NEW UPDATE — crypto_engine.py                       ║
║  AES-CBC + HMAC + XOR + Protobuf (encode/decode)     ║
╚══════════════════════════════════════════════════════╝
"""
import hmac
import hashlib
import struct
import codecs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from config import AES_KEY, AES_IV, HMAC_SECRET_BYTES, XOR_KEYSTREAM

# ═══════════════════════════════════════════════════════════════════════
#  AES-128-CBC
# ═══════════════════════════════════════════════════════════════════════

def aes_encrypt(data: bytes) -> bytes:
    """Encrypt with AES-128-CBC + PKCS7 padding."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def aes_encrypt_hex(hex_plaintext: str) -> str:
    """Encrypt hex-encoded plaintext. Returns hex ciphertext."""
    return aes_encrypt(bytes.fromhex(hex_plaintext)).hex()


def aes_decrypt(data: bytes) -> bytes | None:
    """Decrypt AES-128-CBC with PKCS7 unpadding."""
    if not data or len(data) % AES.block_size != 0:
        return None
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(data)
        p = decrypted[-1]
        if 0 < p <= AES.block_size and decrypted[-p:] == bytes([p]) * p:
            return decrypted[:-p]
        return decrypted
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
#  HMAC-SHA256
# ═══════════════════════════════════════════════════════════════════════

def hmac_sign(message: str) -> str:
    """HMAC-SHA256 sign a message. Returns hex digest."""
    return hmac.new(HMAC_SECRET_BYTES, message.encode("utf-8"), hashlib.sha256).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
#  XOR Open-ID Encoding (for MajorRegister)
# ═══════════════════════════════════════════════════════════════════════

def xor_encode_open_id(original: str) -> bytes:
    """XOR-encode an open_id for the field14 in MajorRegister."""
    encoded = ""
    for i, ch in enumerate(original):
        encoded += chr(ord(ch) ^ XOR_KEYSTREAM[i % len(XOR_KEYSTREAM)])
    escaped = "".join(
        c if 32 <= ord(c) <= 126 else f"\\u{ord(c):04x}" for c in encoded
    )
    return codecs.decode(escaped, "unicode_escape").encode("latin1")


# ═══════════════════════════════════════════════════════════════════════
#  Protobuf — Encoder (hand-rolled, no .proto)
# ═══════════════════════════════════════════════════════════════════════

def _encode_varint(n: int) -> bytes:
    if n < 0:
        return b""
    parts = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        parts.append(byte)
        if not n:
            break
    return bytes(parts)


def _make_varint_field(field_number: int, value: int) -> bytes:
    header = (field_number << 3) | 0
    return _encode_varint(header) + _encode_varint(value)


def _make_length_field(field_number: int, value) -> bytes:
    header = (field_number << 3) | 2
    raw = value.encode() if isinstance(value, str) else value
    return _encode_varint(header) + _encode_varint(len(raw)) + raw


def build_protobuf(fields: dict) -> bytes:
    """Build protobuf packet from {field_num: value} dict."""
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = build_protobuf(value)
            packet.extend(_make_length_field(field, nested))
        elif isinstance(value, int):
            packet.extend(_make_varint_field(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(_make_length_field(field, value))
    return bytes(packet)


# ═══════════════════════════════════════════════════════════════════════
#  Protobuf — Decoder (raw wire-format, no .proto)
# ═══════════════════════════════════════════════════════════════════════

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    raise ValueError("Truncated varint")


def decode_protobuf(data: bytes) -> dict:
    """Decode raw Protobuf bytes into {field_number: value}."""
    if not data:
        return {}
    fields = {}
    pos = 0
    try:
        while pos < len(data):
            tag, pos = _read_varint(data, pos)
            fn = tag >> 3
            wt = tag & 0x07
            if wt == 0:
                value, pos = _read_varint(data, pos)
                fields[fn] = value
            elif wt == 1:
                if pos + 8 > len(data): break
                value = struct.unpack_from("<Q", data, pos)[0]
                pos += 8
                fields[fn] = value
            elif wt == 2:
                length, pos = _read_varint(data, pos)
                if pos + length > len(data): break
                raw = data[pos:pos + length]
                pos += length
                try:
                    text = raw.decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in text):
                        fields[fn] = text
                    else:
                        raise UnicodeDecodeError("", b"", 0, 0, "")
                except (UnicodeDecodeError, ValueError):
                    try:
                        nested = decode_protobuf(raw)
                        fields[fn] = nested if nested else raw.hex()
                    except Exception:
                        fields[fn] = raw.hex()
            elif wt == 5:
                if pos + 4 > len(data): break
                value = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                fields[fn] = value
            else:
                break
    except (ValueError, IndexError, struct.error):
        pass
    return fields


# ═══════════════════════════════════════════════════════════════════════
#  Quick Self-Test
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test AES round-trip
    test_data = b"Hello Koolchi!"
    encrypted = aes_encrypt(test_data)
    decrypted = aes_decrypt(encrypted)
    assert decrypted == test_data, "AES round-trip failed!"
    print("✅ AES round-trip: OK")

    # Test REAL captured payloads from koolchi (2026-03-24)
    # Event 87: 1-spin Unlimited Gacha (ME)
    ev87 = aes_decrypt(bytes.fromhex("fe3f6c2debdd84504d1b1b806210f01f"))
    f87 = decode_protobuf(ev87)
    assert f87.get(1) == 87, f"Event 87 wrong: {f87}"
    assert f87.get(3) == 526, f"Box 87 wrong: {f87}"
    assert f87.get(4) == 5, f"Currency 87 wrong: {f87}"
    print(f"✅ Event 87 (Unlimited Gacha): {f87}")

    # Event 93: 2-spin Chest Wheel
    ev93 = aes_decrypt(bytes.fromhex("ffa1f00b0204c6301c025261692cd59b"))
    f93 = decode_protobuf(ev93)
    assert f93.get(1) == 93, f"Event 93 wrong: {f93}"
    assert f93.get(3) == 471, f"Box 93 wrong: {f93}"
    assert f93.get(4) == 2, f"Currency 93 wrong: {f93}"
    assert f93.get(10) == 10, f"Field 10 wrong: {f93}"
    print(f"✅ Event 93 (Chest Wheel): {f93}")

    # Event 5: 1-spin Gold Chest
    ev5 = aes_decrypt(bytes.fromhex("016c892d4d1e11432229bc62b557906f"))
    f5 = decode_protobuf(ev5)
    assert f5.get(1) == 5, f"Event 5 wrong: {f5}"
    assert f5.get(3) == 521, f"Box 5 wrong: {f5}"
    assert f5.get(4) == 1, f"Currency 5 wrong: {f5}"
    assert f5.get(12) == 300, f"Field 12 wrong: {f5}"
    print(f"✅ Event 5 (Gold Chest): {f5}")

    # Test Protobuf build with extra_fields (like Event 93)
    built = build_protobuf({1: 93, 2: 2, 3: 471, 4: 2, 10: 10, 13: 2})
    decoded = decode_protobuf(built)
    assert decoded[1] == 93 and decoded[3] == 471 and decoded[10] == 10
    print(f"✅ Protobuf build (Event 93): {decoded}")

    print("\n🎉 All crypto_engine tests passed!")
