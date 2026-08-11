"""Independent UMP/1 vector verifier.

This module intentionally does not import the Rust workspace.  It implements
the small, frozen vector surface with Python's ``cryptography`` package and
checks the published JSON byte-for-byte.  It is a conformance consumer, not a
replacement UMP implementation.
"""

import hashlib
import hmac
import json
import struct
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


VECTOR_PATH = Path(__file__).resolve().parents[1] / "vectors" / "ump1-v0.1.json"


def hx(value: str) -> bytes:
    return bytes.fromhex(value)


def hex_of(value: bytes) -> str:
    return value.hex()


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError("{} mismatch: expected {!r}, got {!r}".format(label, expected, actual))


def blake2s(value: bytes) -> bytes:
    return hashlib.blake2s(value, digest_size=32).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # UMP/1 uses RFC-2104 HMAC-BLAKE2s rather than SHA-256 HKDF.
    return hmac.new(salt, ikm, hashlib.blake2s).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.blake2s
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def expand_label(secret: bytes, label: bytes, context: bytes = b"", length: int = 32) -> bytes:
    info = (
        length.to_bytes(2, "big")
        + b"ump v1 "
        + label
        + len(context).to_bytes(2, "big")
        + context
    )
    return hkdf_expand(secret, info, length)


def varint(value: int) -> bytes:
    if value <= 63:
        return bytes((value,))
    if value <= 16_383:
        return ((value | 0x4000).to_bytes(2, "big"))
    if value <= 1_073_741_823:
        return ((value | 0x80000000).to_bytes(4, "big"))
    if value <= 4_611_686_018_427_387_903:
        return ((value | 0xC000000000000000).to_bytes(8, "big"))
    raise ValueError("varint out of range")


def packet_keys(secret: bytes) -> Dict[str, bytes]:
    return {
        "packet_key": expand_label(secret, b"packet key"),
        "packet_iv": expand_label(secret, b"packet iv", length=12),
        "header_protection_key": expand_label(secret, b"header protection"),
    }


def nonce(iv: bytes, packet_number: int) -> bytes:
    encoded = packet_number.to_bytes(8, "big")
    result = bytearray(iv)
    for index, value in enumerate(encoded):
        result[len(result) - len(encoded) + index] ^= value
    return bytes(result)


def header_mask(key: bytes, sample: bytes) -> bytes:
    sample = sample[:16].ljust(16, b"\0")
    counter = struct.unpack("<I", sample[:4])[0]
    chacha_nonce = struct.pack("<I", counter) + sample[4:]
    cipher = Cipher(algorithms.ChaCha20(key, chacha_nonce), mode=None)
    return cipher.encryptor().update(b"\0" * 5)


def protect_short_packet(
    keys: Dict[str, bytes], dcid: bytes, path_id: int, packet_number: int, payload: bytes
) -> bytes:
    first = 0x04  # SessionData, 16-bit packet number.
    pn = packet_number.to_bytes(2, "big")
    header = bytes((first,)) + dcid + varint(path_id)
    ciphertext = ChaCha20Poly1305(keys["packet_key"]).encrypt(
        nonce(keys["packet_iv"], packet_number), payload, header + pn
    )
    mask = header_mask(keys["header_protection_key"], ciphertext[:16])
    protected_first = first ^ (mask[4] & 0x10)
    protected_pn = bytes(value ^ mask[index] for index, value in enumerate(pn))
    return bytes((protected_first,)) + dcid + varint(path_id) + protected_pn + ciphertext


def parse_varint(data: bytes, offset: int) -> tuple:
    first = data[offset]
    width = 1 << (first >> 6)
    raw = bytearray(data[offset : offset + width])
    raw[0] &= 0x3F
    return int.from_bytes(raw, "big"), width


def parse_short_packet(keys: Dict[str, bytes], packet: bytes) -> bytes:
    if len(packet) < 1 + 8 + 1 + 2 + 16:
        raise ValueError("short packet truncated")
    protected_first = packet[0]
    dcid = packet[1:9]
    path_id, path_width = parse_varint(packet, 9)
    del path_id
    pn_offset = 9 + path_width
    protected_pn = packet[pn_offset : pn_offset + 2]
    ciphertext = packet[pn_offset + 2 :]
    mask = header_mask(keys["header_protection_key"], ciphertext[:16])
    first = protected_first ^ (mask[4] & 0x10)
    pn = bytes(value ^ mask[index] for index, value in enumerate(protected_pn))
    packet_number = int.from_bytes(pn, "big")
    aad = bytes((first,)) + dcid + packet[9 : 9 + path_width] + pn
    return ChaCha20Poly1305(keys["packet_key"]).decrypt(
        nonce(keys["packet_iv"], packet_number), ciphertext, aad
    )


def canonical_message(message_type: int, body: bytes) -> bytes:
    return varint(message_type) + varint(len(body)) + body


def verify_vectors(path: Optional[Path] = None) -> None:
    vector_path = path or VECTOR_PATH
    vectors: Dict[str, Any] = json.loads(vector_path.read_text(encoding="utf-8"))
    identity = vectors["identity"]
    identity_private = ed25519.Ed25519PrivateKey.from_private_bytes(hx(identity["ed25519_seed"]))
    identity_public = identity_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    require_equal(hex_of(identity_public), identity["public_key"], "identity public key")
    endpoint = blake2s(b"UMP-ENDPOINT-ID-v1" + identity_public)
    require_equal(hex_of(endpoint), identity["endpoint_id"], "endpoint id")

    x_values = vectors["x25519"]
    static_private = x25519.X25519PrivateKey.from_private_bytes(hx(x_values["static_seed"]))
    peer_private = x25519.X25519PrivateKey.from_private_bytes(hx(x_values["peer_seed"]))
    static_public = static_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    peer_public = peer_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    require_equal(hex_of(static_public), x_values["static_public"], "static X25519 public key")
    require_equal(hex_of(peer_public), x_values["peer_public"], "peer X25519 public key")
    require_equal(
        hex_of(static_private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))),
        x_values["diffie_hellman"],
        "X25519 shared secret",
    )

    initial = vectors["initial_keys"]
    initial_salt = b"UMP-1-INITIAL-SALT".ljust(32, b"\0")
    initial_secret = hkdf_extract(initial_salt, hx(initial["destination_connection_id"]))
    client_secret = expand_label(initial_secret, b"client initial")
    server_secret = expand_label(initial_secret, b"server initial")
    client_keys = packet_keys(client_secret)
    server_keys = packet_keys(server_secret)
    require_equal(hex_of(client_keys["packet_key"]), initial["client_key"], "client packet key")
    require_equal(hex_of(client_keys["packet_iv"]), initial["client_iv"], "client packet IV")
    require_equal(
        hex_of(client_keys["header_protection_key"]),
        initial["client_header_protection_key"],
        "client header-protection key",
    )
    require_equal(hex_of(server_keys["packet_key"]), initial["server_key"], "server packet key")

    binding = vectors["identity_binding"]
    signed_bytes = (
        b"\x01"
        + endpoint
        + identity_public
        + static_public
        + (0).to_bytes(8, "big")
        + ((1 << 64) - 1).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + bytes(32)
    )
    signed_message = blake2s(b"UMP-IDENTITY-BINDING-v1" + signed_bytes)
    signature = identity_private.sign(signed_message)
    require_equal(hex_of(signed_message), binding["signed_message_digest"], "binding digest")
    require_equal(hex_of(signature), binding["signature"], "binding signature")
    identity_private.public_key().verify(signature, signed_message)

    transcript = vectors["handshake_transcript"]
    current = blake2s(
        b"UMP-HANDSHAKE-v1"
        + transcript["mode"].encode()
        + transcript["crypto_profile"].encode()
        + transcript["carrier_binding"].encode()
    )
    require_equal(hex_of(current), transcript["initial_hash"], "transcript initial hash")
    for message in transcript["messages"]:
        body = hx(message["body"])
        encoded = canonical_message(message["type"], body)
        require_equal(hex_of(encoded), message["encoded"], "canonical transcript message")
        current = blake2s(current + encoded)
        require_equal(hex_of(current), message["hash"], "transcript message hash")

    finished = vectors["finished_mac"]
    require_equal(
        hex_of(hmac.new(hx(finished["key"]), hx(finished["transcript_hash"]), hashlib.blake2s).digest()),
        finished["tag"],
        "Finished HMAC-BLAKE2s",
    )

    session = vectors["session_packet"]
    traffic_secret = hx(session["traffic_secret"])
    keys = packet_keys(traffic_secret)
    for name in ("packet_key", "packet_iv", "header_protection_key"):
        require_equal(hex_of(keys[name]), session[name], "session {}".format(name))
    packet = protect_short_packet(
        keys,
        hx(session["destination_connection_id"]),
        session["path_id"],
        session["packet_number"],
        hx(session["plaintext_payload"]),
    )
    require_equal(hex_of(packet), session["protected_packet"], "protected short packet")
    require_equal(
        parse_short_packet(keys, packet), hx(session["plaintext_payload"]), "decrypted payload"
    )
    tampered = bytearray(packet)
    tampered[-1] ^= 1
    try:
        parse_short_packet(keys, bytes(tampered))
    except Exception:
        pass
    else:
        raise AssertionError("tampered protected packet was accepted")


if __name__ == "__main__":
    verify_vectors()
    print("independent UMP/1 vectors: PASS")
