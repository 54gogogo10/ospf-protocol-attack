"""Unit tests for OSPF authentication module (auth.py)."""

import struct
import pytest
from ospf_attack.core.auth import (
    AUTH_NONE, AUTH_PLAIN, AUTH_MD5,
    _pad_key, build_ospf_auth, auth_type_name, _MD5_TRAILER_LEN,
)


# ---------------------------------------------------------------------------
# _pad_key
# ---------------------------------------------------------------------------

def test_pad_key_exact():
    assert _pad_key(b"password") == b"password"

def test_pad_key_short():
    assert _pad_key(b"abc") == b"abc\x00\x00\x00\x00\x00"

def test_pad_key_long_truncates():
    assert _pad_key(b"toolongpassword") == b"toolongp"

def test_pad_key_empty():
    assert _pad_key(b"") == b"\x00" * 8


# ---------------------------------------------------------------------------
# build_ospf_auth — Type 0 (none)
# ---------------------------------------------------------------------------

def test_auth_none():
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)  # minimal OSPF header
    auth_field, trailer = build_ospf_auth(ospf, AUTH_NONE)
    assert auth_field == b"\x00" * 8
    assert trailer is None


# ---------------------------------------------------------------------------
# build_ospf_auth — Type 1 (plaintext)
# ---------------------------------------------------------------------------

def test_auth_plain():
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    auth_field, trailer = build_ospf_auth(ospf, AUTH_PLAIN, b"secret")
    assert auth_field == b"secret\x00\x00"
    assert trailer is None

def test_auth_plain_pads_to_8():
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    auth_field, _ = build_ospf_auth(ospf, AUTH_PLAIN, b"pw")
    assert len(auth_field) == 8
    assert auth_field[:2] == b"pw"
    assert auth_field[2:] == b"\x00" * 6


# ---------------------------------------------------------------------------
# build_ospf_auth — Type 2 (MD5)
# ---------------------------------------------------------------------------

def test_auth_md5_basic():
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    auth_field, trailer = build_ospf_auth(ospf, AUTH_MD5, b"mykey", crypto_seq=1)
    assert len(auth_field) == 8
    assert len(trailer) == _MD5_TRAILER_LEN  # 16 bytes
    # First 2 bytes of auth field are reserved (0)
    assert auth_field[0] == 0
    # Byte 2 is Key ID (default 1 from RFC — but our helper sets keyid=1)
    # This is raw auth — keyid/authdatalen/seq are embedded by the callers

def test_auth_md5_deterministic():
    """Same input produces same MD5 digest."""
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    _, t1 = build_ospf_auth(ospf, AUTH_MD5, b"key", crypto_seq=1)
    _, t2 = build_ospf_auth(ospf, AUTH_MD5, b"key", crypto_seq=1)
    assert t1 == t2

def test_auth_md5_differs_by_seq():
    """Different crypto_seq produces different digest."""
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    _, t1 = build_ospf_auth(ospf, AUTH_MD5, b"key", crypto_seq=1)
    _, t2 = build_ospf_auth(ospf, AUTH_MD5, b"key", crypto_seq=2)
    assert t1 != t2

def test_auth_md5_differs_by_key():
    """Different key produces different digest."""
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    _, t1 = build_ospf_auth(ospf, AUTH_MD5, b"key_a", crypto_seq=1)
    _, t2 = build_ospf_auth(ospf, AUTH_MD5, b"key_b", crypto_seq=1)
    assert t1 != t2

def test_auth_md5_differs_by_packet():
    """Different packet content produces different digest."""
    ospf1 = b"\x02\x01" + struct.pack("!H", 24) + b"AAAA" + bytes(16)
    ospf2 = b"\x02\x01" + struct.pack("!H", 24) + b"BBBB" + bytes(16)
    _, t1 = build_ospf_auth(ospf1, AUTH_MD5, b"key", crypto_seq=1)
    _, t2 = build_ospf_auth(ospf2, AUTH_MD5, b"key", crypto_seq=1)
    assert t1 != t2

def test_auth_md5_auth_field_format():
    """Auth field for MD5 follows RFC 2328 D.3 layout."""
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    auth_field, _ = build_ospf_auth(ospf, AUTH_MD5, b"key", crypto_seq=0x12345678)
    # RFC D.3: byte0=reserved(0), byte1=KeyID, bytes2-3=AuthDataLen(16), bytes4-7=seq
    assert auth_field[0] == 0          # Reserved
    assert auth_field[1] == 1          # Key ID
    assert struct.unpack("!H", auth_field[2:4])[0] == 16  # Auth Data Len
    seq = struct.unpack("!I", auth_field[4:8])[0]
    assert seq == 0x12345678


# ---------------------------------------------------------------------------
# Invalid auth type
# ---------------------------------------------------------------------------

def test_invalid_auth_type_raises():
    ospf = b"\x02\x01" + struct.pack("!H", 24) + bytes(20)
    with pytest.raises(ValueError, match="Unsupported auth_type"):
        build_ospf_auth(ospf, 99)


# ---------------------------------------------------------------------------
# auth_type_name
# ---------------------------------------------------------------------------

def test_auth_type_name():
    assert auth_type_name(0) == "none"
    assert auth_type_name(1) == "plain"
    assert auth_type_name(2) == "md5"
    assert "unknown" in auth_type_name(99)
