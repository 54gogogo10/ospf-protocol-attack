"""OSPF authentication (RFC 2328 Appendix D).

Supports Type 0 (null), Type 1 (plaintext), Type 2 (MD5).
Plain Python — no platform dependencies, Windows 7+ compatible.
"""

import hashlib
import hmac
import struct


AUTH_NONE = 0
AUTH_PLAIN = 1
AUTH_MD5 = 2

_AUTH_FIELD_LEN = 8          # 64-bit OSPF auth field in header
_MD5_TRAILER_LEN = 16        # 128-bit MD5 digest appended after packet


def _pad_key(key: bytes) -> bytes:
    """Pad or truncate key to 8 bytes for Type 1. Zero-pad if short."""
    if len(key) >= _AUTH_FIELD_LEN:
        return key[:_AUTH_FIELD_LEN]
    return key + b"\x00" * (_AUTH_FIELD_LEN - len(key))


def _compute_md5_auth(ospf_packet: bytes, key: bytes, crypto_seq: int) -> bytes:
    """Compute MD5 auth field + trailer for Type 2.

    Returns (auth_field_8_bytes, trailer_16_bytes).

    RFC 2328 D.3 — auth field layout (8 bytes):
        0: Reserved (0)
        1: Key ID
        2-3: Auth Data Len (= 16 for MD5)
        4-7: Cryptographic sequence number (non-decreasing)
    """
    auth_field = (
        b"\x00\x01"
        + struct.pack("!H", _MD5_TRAILER_LEN)
        + struct.pack("!I", crypto_seq)
    )

    # Zero out the 8-byte auth field in the packet, then compute HMAC-MD5
    data = ospf_packet[:16] + auth_field + ospf_packet[24:]
    md5 = hmac.HMAC(key, data, hashlib.md5).digest()
    return auth_field, md5


def build_ospf_auth(
    ospf_packet: bytes,
    auth_type: int,
    auth_key: bytes = b"",
    crypto_seq: int = 1,
):
    """Compute auth field and optional trailer for an OSPF packet.

    Args:
        ospf_packet: Full OSPF packet bytes (header + body).
        auth_type: 0 (none), 1 (plaintext), or 2 (MD5).
        auth_key: Key/password bytes.
        crypto_seq: Non-decreasing sequence number (MD5 only).

    Returns:
        (auth_field: bytes(8), trailer: bytes | None)
    """
    if auth_type == AUTH_NONE:
        return b"\x00" * _AUTH_FIELD_LEN, None

    if auth_type == AUTH_PLAIN:
        return _pad_key(auth_key), None

    if auth_type == AUTH_MD5:
        return _compute_md5_auth(ospf_packet, auth_key, crypto_seq)

    raise ValueError(f"Unsupported auth_type: {auth_type}")


def auth_type_name(t: int) -> str:
    return {AUTH_NONE: "none", AUTH_PLAIN: "plain", AUTH_MD5: "md5"}.get(t, f"unknown({t})")
