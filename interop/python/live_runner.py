"""Independent live UMP/1 peer for the carrier interoperability gate.

The peer intentionally uses only Python's standard library plus
``cryptography``.  It speaks enough of the frozen UMP/1 profile to exercise a
real daemon over TCP, UDP, or the experimental TLS stream carrier: protected
Initial/Handshake exchange, XX authentication, protected stream/datagram
traffic, version-negotiation refusal, and restart against the same store.
"""

import argparse
import hashlib
import hmac
import json
import os
import signal
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

from verify_vectors import expand_label, hkdf_extract, header_mask, nonce, packet_keys


PROTOCOL_VERSION = 1
CRYPTO_PROFILE = b"UMP-CRYPTO-1"
MODE_XX = b"XX"
CLIENT_HELLO = 0
SERVER_HELLO = 1
CLIENT_AUTH = 2
SERVER_FINISHED = 3
CLIENT_FINISHED = 4
WELL_KNOWN_APP = b"org.umc.app/1"
MAX_PACKET = 65_535


def varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative varint")
    if value <= 63:
        return bytes((value,))
    if value <= 16_383:
        return (value | 0x4000).to_bytes(2, "big")
    if value <= 1_073_741_823:
        return (value | 0x80000000).to_bytes(4, "big")
    if value <= 4_611_686_018_427_387_903:
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("varint too large")


def read_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    first = data[offset]
    width = 1 << (first >> 6)
    end = offset + width
    if end > len(data):
        raise ValueError("truncated varint")
    raw = bytearray(data[offset:end])
    raw[0] &= 0x3F
    value = int.from_bytes(raw, "big")
    limits = {1: 63, 2: 16_383, 4: 1_073_741_823, 8: 4_611_686_018_427_387_903}
    if value > limits[width]:
        raise ValueError("non-canonical varint")
    if width > 1 and value <= limits[width // 2]:
        raise ValueError("non-canonical varint")
    return value, end


def bytes_field(value: bytes, limit: int) -> bytes:
    if len(value) > limit:
        raise ValueError("field exceeds limit")
    return varint(len(value)) + value


def read_bytes(data: bytes, offset: int, limit: int) -> Tuple[bytes, int]:
    length, offset = read_varint(data, offset)
    if length > limit or offset + length > len(data):
        raise ValueError("invalid byte field")
    return data[offset : offset + length], offset + length


def blake2s(value: bytes) -> bytes:
    return hashlib.blake2s(value, digest_size=32).digest()


def endpoint_id(identity_public: bytes) -> bytes:
    return blake2s(b"UMP-ENDPOINT-ID-v1" + identity_public)


def capabilities_hash(minimum_privacy: bytes = b"p0") -> bytes:
    ids = [b"stream", b"datagram", b"relay", b"bundle", b"route", b"mobility", b"privacy=p3"]
    out = b"UMP-CAPABILITIES-v1" + varint(len(ids) + 1)
    out += b"".join(bytes_field(identifier, 64) for identifier in ids)
    out += bytes_field(b"privacy-min=" + minimum_privacy, 64)
    return blake2s(out)


def build_client_hello(
    client_random: bytes,
    client_ephemeral_public_key: bytes,
    supported_versions: List[int],
    minimum_privacy: bytes = b"p0",
    retry_token: bytes = b"",
) -> bytes:
    if len(client_random) != 32 or len(client_ephemeral_public_key) != 32:
        raise ValueError("hello key material must be 32 bytes")
    out = varint(PROTOCOL_VERSION) + client_random + client_ephemeral_public_key
    out += varint(1) + bytes_field(CRYPTO_PROFILE, 64)
    out += varint(1) + bytes_field(MODE_XX, 64)
    out += varint(len(supported_versions)) + b"".join(varint(v) for v in supported_versions)
    out += capabilities_hash(minimum_privacy)
    out += bytes_field(minimum_privacy, 8)
    out += bytes_field(b"", 512)
    out += bytes_field(retry_token, 1_024)
    out += bytes_field(b"", 64)
    out += bytes_field(bytes(64), 4_096)
    return out


def parse_client_hello(data: bytes) -> Dict[str, Any]:
    offset = 0
    version, offset = read_varint(data, offset)
    client_random = data[offset : offset + 32]
    offset += 32
    ephemeral = data[offset : offset + 32]
    offset += 32
    profile_count, offset = read_varint(data, offset)
    profiles = []
    for _ in range(profile_count):
        value, offset = read_bytes(data, offset, 64)
        profiles.append(value)
    mode_count, offset = read_varint(data, offset)
    modes = []
    for _ in range(mode_count):
        value, offset = read_bytes(data, offset, 64)
        modes.append(value)
    version_count, offset = read_varint(data, offset)
    versions = []
    for _ in range(version_count):
        value, offset = read_varint(data, offset)
        versions.append(value)
    capabilities = data[offset : offset + 32]
    offset += 32
    minimum_privacy, offset = read_bytes(data, offset, 8)
    destination_hint, offset = read_bytes(data, offset, 512)
    retry_token, offset = read_bytes(data, offset, 1_024)
    invitation, offset = read_bytes(data, offset, 64)
    padding, offset = read_bytes(data, offset, 4_096)
    if offset != len(data):
        raise ValueError("trailing ClientHello bytes")
    return {
        "version": version,
        "client_random": client_random,
        "client_ephemeral_public_key": ephemeral,
        "supported_crypto_profiles": profiles,
        "supported_handshake_modes": modes,
        "supported_protocol_versions": versions,
        "capabilities_hash": capabilities,
        "minimum_privacy": minimum_privacy,
        "destination_hint": destination_hint,
        "retry_token": retry_token,
        "invitation_authenticator": invitation,
        "padding": padding,
    }


def canonical_message(message_type: int, body: bytes) -> bytes:
    return varint(message_type) + varint(len(body)) + body


def transcript_start(carrier_type: bytes) -> bytes:
    return blake2s(b"UMP-HANDSHAKE-v1" + MODE_XX + CRYPTO_PROFILE + carrier_type)


def transcript_update(current: bytes, message_type: int, body: bytes) -> bytes:
    return blake2s(current + canonical_message(message_type, body))


def identity_binding(identity: ed25519.Ed25519PrivateKey, static_public: bytes) -> Tuple[bytes, bytes]:
    public = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signed = (
        b"\x01"
        + endpoint_id(public)
        + public
        + static_public
        + (0).to_bytes(8, "big")
        + ((1 << 64) - 1).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + bytes(32)
    )
    return signed, identity.sign(blake2s(b"UMP-IDENTITY-BINDING-v1" + signed))


def aead_seal(secret: bytes, packet_number: int, aad: bytes, plaintext: bytes) -> bytes:
    keys = packet_keys(secret)
    return ChaCha20Poly1305(keys["packet_key"]).encrypt(nonce(keys["packet_iv"], packet_number), plaintext, aad)


def aead_open(secret: bytes, packet_number: int, aad: bytes, ciphertext: bytes) -> bytes:
    keys = packet_keys(secret)
    return ChaCha20Poly1305(keys["packet_key"]).decrypt(nonce(keys["packet_iv"], packet_number), ciphertext, aad)


def long_header(ptype: int, dcid: bytes, scid: bytes, payload_len: int) -> bytes:
    if len(dcid) > 20 or len(scid) > 20:
        raise ValueError("connection id too long")
    return (
        bytes((0x80 | ((ptype & 3) << 5),))
        + PROTOCOL_VERSION.to_bytes(4, "big")
        + bytes((len(dcid),))
        + dcid
        + bytes((len(scid),))
        + scid
        + varint(0)
        + varint(payload_len)
    )


def protect_long_packet(header: bytes, ciphertext: bytes, secret: bytes, packet_number: int) -> bytes:
    pn = packet_number.to_bytes(1, "big")
    first = header[0]
    mask = header_mask(packet_keys(secret)["header_protection_key"], ciphertext[:16])
    return bytes((first ^ (mask[4] & 0x10),)) + header[1:] + bytes((pn[0] ^ mask[0],)) + ciphertext


def build_initial_packet(dcid: bytes, scid: bytes, payload: bytes) -> bytes:
    padded = payload
    while True:
        header = long_header(0, dcid, scid, len(padded) + 16)
        if len(header) + 1 + len(padded) + 16 >= 1_200:
            ciphertext = aead_seal(packet_keys_initial(dcid, True), 0, header + b"\x00", padded)
            return protect_long_packet(header, ciphertext, packet_keys_initial(dcid, True), 0)
        padded += b"\x00"


def packet_keys_initial(dcid: bytes, client: bool) -> bytes:
    initial_secret = hkdf_extract(b"UMP-1-INITIAL-SALT".ljust(32, b"\x00"), dcid)
    return expand_label(initial_secret, b"client initial" if client else b"server initial")


def parse_long_packet(packet: bytes, secret: bytes, expected_payload_includes_pn: bool) -> Tuple[bytes, bytes, bytes]:
    if len(packet) < 20 or not (packet[0] & 0x80):
        raise ValueError("not a long packet")
    offset = 5
    dcid_len = packet[offset]
    offset += 1
    dcid = packet[offset : offset + dcid_len]
    offset += dcid_len
    scid_len = packet[offset]
    offset += 1
    scid = packet[offset : offset + scid_len]
    offset += scid_len
    token_len, offset = read_varint(packet, offset)
    offset += token_len
    payload_len, offset = read_varint(packet, offset)
    pn_offset = offset
    if expected_payload_includes_pn:
        if payload_len < 1:
            raise ValueError("invalid handshake payload length")
        ciphertext_len = payload_len - 1
    else:
        ciphertext_len = payload_len
    ciphertext = packet[pn_offset + 1 : pn_offset + 1 + ciphertext_len]
    if len(ciphertext) != ciphertext_len or pn_offset + 1 + ciphertext_len != len(packet):
        raise ValueError("long packet length mismatch")
    mask = header_mask(packet_keys(secret)["header_protection_key"], ciphertext[:16])
    first = packet[0] ^ (mask[4] & 0x10)
    pn = packet[pn_offset] ^ mask[0]
    aad = bytearray(packet[: pn_offset + 1])
    aad[0] = first
    aad[-1] = pn
    plaintext = aead_open(secret, pn, bytes(aad), ciphertext)
    return dcid, scid, plaintext


def build_handshake_packet(dcid: bytes, scid: bytes, packet_number: int, payload: bytes, secret: bytes) -> bytes:
    ciphertext_len = len(payload) + 16
    header = long_header(2, dcid, scid, 1 + ciphertext_len)
    ciphertext = aead_seal(secret, packet_number, header + packet_number.to_bytes(1, "big"), payload)
    return protect_long_packet(header, ciphertext, secret, packet_number)


def parse_server_hello(data: bytes) -> Dict[str, Any]:
    offset = 0
    server_random = data[offset : offset + 32]
    offset += 32
    server_ephemeral = data[offset : offset + 32]
    offset += 32
    selected_version, offset = read_varint(data, offset)
    profile, offset = read_bytes(data, offset, 64)
    mode, offset = read_bytes(data, offset, 64)
    encrypted_auth, offset = read_bytes(data, offset, 8_192)
    padding, offset = read_bytes(data, offset, 4_096)
    # The live Initial builder appends wire PADDING bytes after the encoded
    # SERVER_HELLO to satisfy the 1,200-byte minimum.  They are authenticated
    # packet padding, not part of the hello message.
    if any(data[offset:]):
        raise ValueError("trailing ServerHello bytes")
    return {
        "server_random": server_random,
        "server_ephemeral_public_key": server_ephemeral,
        "selected_protocol_version": selected_version,
        "selected_crypto_profile": profile,
        "selected_handshake_mode": mode,
        "encrypted_server_authentication": encrypted_auth,
        "padding": padding,
        # Preserve the canonical message body separately from authenticated
        # packet padding appended by the Initial builder.
        "encoded": data[:offset],
    }


def build_client_auth(
    identity: ed25519.Ed25519PrivateKey,
    static: x25519.X25519PrivateKey,
    ephemeral: x25519.X25519PrivateKey,
    hello_bytes: bytes,
    server_hello_bytes: bytes,
    server_hello: Dict[str, Any],
    carrier_type: bytes,
) -> Dict[str, Any]:
    transcript = transcript_update(transcript_start(carrier_type), CLIENT_HELLO, hello_bytes)
    server_auth_transcript = transcript
    server_ephemeral = x25519.X25519PublicKey.from_public_bytes(
        server_hello["server_ephemeral_public_key"]
    )
    dh_ee = ephemeral.exchange(server_ephemeral)
    extract1 = hkdf_extract(bytes(32), dh_ee)
    server_auth_key = expand_label(extract1, b"server hello key", server_auth_transcript)
    aad = (
        server_auth_transcript
        + server_hello["server_random"]
        + server_hello["server_ephemeral_public_key"]
        + server_hello["selected_crypto_profile"]
    )
    block = aead_open(
        server_auth_key,
        0,
        aad,
        server_hello["encrypted_server_authentication"],
    )
    server_static_public = block[:32]
    server_binding = block[32:]
    if len(server_binding) < 97:
        raise ValueError("server binding truncated")
    server_identity_public = server_binding[33:65]
    server_eid = endpoint_id(server_identity_public)
    transcript = transcript_update(transcript, SERVER_HELLO, server_hello["encoded"])
    server_static = x25519.X25519PublicKey.from_public_bytes(server_static_public)
    secret2 = hkdf_extract(extract1, ephemeral.exchange(server_static))
    secret3 = hkdf_extract(secret2, dh_ee)
    secret4 = hkdf_extract(secret3, ephemeral.exchange(server_static))
    transcript_hash = transcript
    client_public = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    client_static_public = static.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    client_eid = endpoint_id(client_public)
    sig_input = blake2s(
        b"UMP-CLIENT-AUTH-v1"
        + transcript_hash
        + client_eid
        + server_eid
        + client_static_public
        + server_static_public
    )
    binding_signed, binding_signature = identity_binding(identity, client_static_public)
    plaintext = client_static_public + binding_signed + binding_signature + identity.sign(sig_input)
    client_auth_key = expand_label(secret3, b"client auth key", transcript_hash)
    ciphertext = aead_seal(client_auth_key, 0, transcript_hash, plaintext)
    auth_body = bytes_field(ciphertext, 16_384)
    auth_frame = canonical_message(CLIENT_AUTH, auth_body)
    auth_secret = expand_label(secret3, b"client handshake traffic", transcript_hash)
    auth_packet = build_handshake_packet(b"\x01" * 8, b"\x02" * 8, 0, auth_frame, auth_secret)
    session_transcript = transcript_hash
    session_secrets = derive_session_secrets(secret4, session_transcript)
    return {
        "auth_body": auth_body,
        "auth_packet": auth_packet,
        "secret3": secret3,
        "secret4": secret4,
        "transcript_hash": transcript_hash,
        "client_endpoint_id": client_eid,
        "server_endpoint_id": server_eid,
        "server_identity_public": server_identity_public,
        "server_static_public": server_static_public,
        "client_static_public": client_static_public,
        "session_client": session_secrets[0],
        "session_server": session_secrets[1],
    }


def derive_session_secrets(secret4: bytes, transcript: bytes) -> Tuple[bytes, bytes]:
    derived = expand_label(secret4, b"derived", transcript)
    master = hkdf_extract(derived, bytes(32))
    client = expand_label(master, b"client session traffic", transcript)
    server = expand_label(master, b"server session traffic", transcript)
    return client, server


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()


def finish_client_handshake(context: Dict[str, Any], server_finished: bytes) -> bytes:
    if len(server_finished) != 96:
        raise ValueError("SERVER_FINISHED length")
    transcript = transcript_update(context["transcript_hash"], CLIENT_AUTH, context["auth_body"])
    server_finished_transcript = transcript
    server_finished_key = expand_label(context["secret4"], b"server finished", transcript)
    if hmac_blake2s(server_finished_key, transcript) != server_finished[64:]:
        raise ValueError("SERVER_FINISHED MAC mismatch")
    signature_input = blake2s(
        b"UMP-SERVER-AUTH-v1"
        + transcript
        + context["server_endpoint_id"]
        + context["client_endpoint_id"]
        + context["server_static_public"]
        + context["client_static_public"]
    )
    ed25519.Ed25519PublicKey.from_public_bytes(context["server_identity_public"]).verify(
        server_finished[:64], signature_input
    )
    transcript = transcript_update(transcript, SERVER_FINISHED, server_finished)
    client_finished_key = expand_label(context["secret4"], b"client finished", server_finished_transcript)
    confirmation = hmac_blake2s(client_finished_key, transcript)
    frame = canonical_message(CLIENT_FINISHED, confirmation)
    client_secret = expand_label(context["secret3"], b"client handshake traffic", context["transcript_hash"])
    return build_handshake_packet(b"\x01" * 8, b"\x02" * 8, 1, frame, client_secret)


def protect_short_packet(secret: bytes, dcid: bytes, packet_number: int, payload: bytes) -> bytes:
    first = 0x04  # SessionData with a 16-bit packet number.
    path = varint(0)
    pn = packet_number.to_bytes(2, "big")
    header = bytes((first,)) + dcid + path
    ciphertext = aead_seal(secret, packet_number, header + pn, payload)
    mask = header_mask(packet_keys(secret)["header_protection_key"], ciphertext[:16])
    return bytes((first ^ (mask[4] & 0x10),)) + dcid + path + bytes(
        value ^ mask[index] for index, value in enumerate(pn)
    ) + ciphertext


def parse_short_packet(secret: bytes, packet: bytes) -> Tuple[int, bytes]:
    if len(packet) < 1 + 8 + 1 + 2 + 16:
        raise ValueError("short packet truncated")
    protected_first = packet[0]
    dcid = packet[1:9]
    path_id, path_end = read_varint(packet, 9)
    del path_id
    pn_offset = path_end
    protected_pn = packet[pn_offset : pn_offset + 2]
    ciphertext = packet[pn_offset + 2 :]
    mask = header_mask(packet_keys(secret)["header_protection_key"], ciphertext[:16])
    first = protected_first ^ (mask[4] & 0x10)
    pn_bytes = bytes(value ^ mask[index] for index, value in enumerate(protected_pn))
    packet_number = int.from_bytes(pn_bytes, "big")
    aad = bytes((first,)) + dcid + packet[9:pn_offset] + pn_bytes
    return packet_number, aead_open(secret, packet_number, aad, ciphertext)


def stream_frame(stream_id: int, data: bytes, fin: bool, protocol_id: bytes) -> bytes:
    flags = 0x04 | 0x08 | (0x01 if fin else 0)
    return (
        varint(0x10)
        + varint(stream_id)
        + bytes((flags,))
        + varint(len(data))
        + data
        + bytes_field(protocol_id, 255)
        + bytes_field(b"", 4_096)
    )


def datagram_frame(data: bytes, context_id: int = 0) -> bytes:
    return varint(0x28) + varint(context_id) + b"\x01" + varint(len(data)) + data


def ack_frame(largest: int) -> bytes:
    return varint(0x08) + varint(largest) + varint(0) + varint(1) + varint(1)


def parse_frames(payload: bytes) -> List[Tuple[str, Any]]:
    frames = []
    offset = 0
    while offset < len(payload):
        frame_type, offset = read_varint(payload, offset)
        if frame_type == 0:
            frames.append(("padding", None))
        elif frame_type == 4:
            frames.append(("ping", None))
        elif frame_type == 8:
            largest, offset = read_varint(payload, offset)
            _delay, offset = read_varint(payload, offset)
            count, offset = read_varint(payload, offset)
            first, offset = read_varint(payload, offset)
            for _ in range(max(0, count - 1)):
                _gap, offset = read_varint(payload, offset)
                _length, offset = read_varint(payload, offset)
            frames.append(("ack", largest))
        elif frame_type == 0x10:
            stream_id, offset = read_varint(payload, offset)
            flags = payload[offset]
            offset += 1
            if flags & 0xE0:
                raise ValueError("reserved STREAM flags")
            stream_offset = 0
            if flags & 0x02:
                stream_offset, offset = read_varint(payload, offset)
            if flags & 0x04:
                data_len, offset = read_varint(payload, offset)
            else:
                data_len = len(payload) - offset
            data = payload[offset : offset + data_len]
            offset += data_len
            if flags & 0x08:
                _protocol, offset = read_bytes(payload, offset, 255)
                _metadata, offset = read_bytes(payload, offset, 4_096)
            frames.append(("stream", (stream_id, stream_offset, bool(flags & 1), data)))
        elif frame_type == 0x28:
            context_id, offset = read_varint(payload, offset)
            flags = payload[offset]
            offset += 1
            if flags & 0x04:
                _expiration, offset = read_varint(payload, offset)
            data_len, offset = read_varint(payload, offset)
            data = payload[offset : offset + data_len]
            offset += data_len
            frames.append(("datagram", (context_id, data)))
        elif frame_type == 0x20:
            _stream_id, offset = read_varint(payload, offset)
            _maximum, offset = read_varint(payload, offset)
        elif frame_type == 0x1C:
            _maximum, offset = read_varint(payload, offset)
        else:
            raise ValueError("unsupported response frame 0x{:x}".format(frame_type))
    return frames


class CarrierConnection:
    def __init__(
        self, carrier: str, address: Tuple[str, int], tls_ca_file: Optional[Path] = None
    ):
        self.carrier = carrier
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if carrier == "udp" else socket.SOCK_STREAM)
        self.sock.settimeout(0.2)
        if carrier == "udp":
            self.sock.connect(address)
            self.buffer = b""
        else:
            self.sock.connect(address)
            if carrier == "tls":
                if tls_ca_file is None:
                    raise ValueError("TLS carrier requires a trust root")
                context = ssl.create_default_context(cafile=str(tls_ca_file))
                raw = self.sock
                self.sock = context.wrap_socket(raw, server_hostname="localhost")
            self.buffer = b""

    def send_packet(self, packet: bytes) -> None:
        if self.carrier == "udp":
            self.sock.send(packet)
        else:
            self.sock.sendall(varint(len(packet)) + packet)

    def recv_packet(self, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self.carrier == "udp":
                    return self.sock.recv(65_535)
                chunk = self.sock.recv(65_535)
                if not chunk:
                    raise RuntimeError("carrier closed")
                self.buffer += chunk
                length, prefix_end = read_varint(self.buffer, 0)
                if length > MAX_PACKET:
                    raise RuntimeError("carrier packet exceeds limit")
                if len(self.buffer) >= prefix_end + length:
                    packet = self.buffer[prefix_end : prefix_end + length]
                    self.buffer = self.buffer[prefix_end + length :]
                    return packet
            except socket.timeout:
                continue
        raise TimeoutError("timed out waiting for carrier packet")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Daemon:
    def __init__(self, binary: Path, carrier: str):
        self.binary = binary
        self.carrier = carrier
        self.directory = Path(tempfile.mkdtemp(prefix="umc-interop-"))
        self.port = free_port("udp" if carrier == "udp" else "tcp")
        carrier_type = {"tcp": "ump.tcp/1", "udp": "ump.udp/1", "tls": "ump.tls-stream/1"}[carrier]
        listen_key = {"tcp": "tcp_listen", "udp": "udp_listen", "tls": "tls_listen"}[carrier]
        self.config = {
            "data_dir": str(self.directory / "data"),
            "control_socket": str(self.directory / "umc.sock"),
            "carriers": [carrier_type],
            listen_key: "127.0.0.1:{}".format(self.port),
        }
        if carrier == "tls":
            certificate, private_key, trust_root = make_tls_material(self.directory)
            self.tls_trust_root = trust_root
            self.config.update(
                {
                    "tls_certificate": str(certificate),
                    "tls_private_key": str(private_key),
                    "tls_trust_roots": [str(certificate)],
                    "tls_server_name": "localhost",
                }
            )
        else:
            self.tls_trust_root = None
        self.config_path = self.directory / "node.json"
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.process = None
        self.log = None

    def start(self) -> None:
        self.log = open(self.directory / "umcd.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "--config", str(self.config_path)], stdout=self.log, stderr=self.log
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("umcd exited during startup; see {}".format(self.directory / "umcd.log"))
            if (self.directory / "umc.sock").exists():
                return
            time.sleep(0.05)
        raise TimeoutError("umcd control socket did not appear")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()
        self.process = None


def free_port(kind: str) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def make_tls_material(directory: Path) -> Tuple[Path, Path, Path]:
    """Create test-only DER certificate/key material for the TLS carrier."""
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = directory / "tls-cert.der"
    private_key_path = directory / "tls-key.der"
    trust_root_path = directory / "tls-root.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    trust_root_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, private_key_path, trust_root_path


def make_client_keys() -> Tuple[ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey, x25519.X25519PrivateKey]:
    return (
        ed25519.Ed25519PrivateKey.generate(),
        x25519.X25519PrivateKey.generate(),
        x25519.X25519PrivateKey.generate(),
    )


def run_version_refusal(daemon: Daemon) -> None:
    carrier = CarrierConnection(
        daemon.carrier, ("127.0.0.1", daemon.port), daemon.tls_trust_root
    )
    try:
        _identity, _static, ephemeral = make_client_keys()
        ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        dcid = os.urandom(8)
        scid = os.urandom(8)
        hello = build_client_hello(os.urandom(32), ephemeral_public, [99])
        carrier.send_packet(build_initial_packet(dcid, scid, hello))
        response = carrier.recv_packet()
        if len(response) < 14 or response[0] != 0xE0 or response[1:5] != bytes(4):
            raise AssertionError("unsupported version did not receive Version-Negotiation")
        response_dcid_len = response[5]
        response_dcid = response[6 : 6 + response_dcid_len]
        if response_dcid != scid:
            raise AssertionError("Version-Negotiation DCID echo mismatch")
        offset = 6 + response_dcid_len
        response_scid_len = response[offset]
        offset += 1 + response_scid_len
        count, offset = read_varint(response, offset)
        versions = []
        for _ in range(count):
            versions.append(int.from_bytes(response[offset : offset + 4], "big"))
            offset += 4
        if PROTOCOL_VERSION not in versions:
            raise AssertionError("Version-Negotiation omitted supported version")
    finally:
        carrier.close()


def run_handshake_and_data(daemon: Daemon) -> bytes:
    carrier_type = {"tcp": b"ump.tcp/1", "udp": b"ump.udp/1", "tls": b"ump.tls-stream/1"}[daemon.carrier]
    carrier = CarrierConnection(
        daemon.carrier, ("127.0.0.1", daemon.port), daemon.tls_trust_root
    )
    try:
        identity, static, ephemeral = make_client_keys()
        ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        dcid = os.urandom(8)
        scid = os.urandom(8)
        hello_bytes = build_client_hello(os.urandom(32), ephemeral_public, [1])
        carrier.send_packet(build_initial_packet(dcid, scid, hello_bytes))
        initial_keys = packet_keys_initial(dcid, False)
        _server_dcid, _server_scid, server_hello_bytes = parse_long_packet(
            carrier.recv_packet(), initial_keys, False
        )
        server_hello = parse_server_hello(server_hello_bytes)
        if server_hello["selected_protocol_version"] != 1 or server_hello["selected_handshake_mode"] != MODE_XX:
            raise AssertionError("daemon selected unexpected handshake parameters")
        context = build_client_auth(
            identity, static, ephemeral, hello_bytes, server_hello_bytes, server_hello, carrier_type
        )
        carrier.send_packet(context["auth_packet"])
        handshake_secret_server = expand_label(
            context["secret3"], b"server handshake traffic", context["transcript_hash"]
        )
        _dcid, _scid, finished_frame = parse_long_packet(
            carrier.recv_packet(), handshake_secret_server, True
        )
        message_type, offset = read_varint(finished_frame, 0)
        message_len, offset = read_varint(finished_frame, offset)
        if message_type != SERVER_FINISHED or message_len != len(finished_frame) - offset:
            raise AssertionError("invalid SERVER_FINISHED envelope")
        client_finished_secret = finish_client_handshake(context, finished_frame[offset:])
        carrier.send_packet(client_finished_secret)
        server_session_secret = context["session_server"]
        client_session_secret = context["session_client"]
        client_pn = 0

        stream_payload = stream_frame(0, b"python-independent-stream", True, WELL_KNOWN_APP)
        carrier.send_packet(protect_short_packet(client_session_secret, dcid, client_pn, stream_payload))
        client_pn += 1
        echoed = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            server_pn, payload = parse_short_packet(server_session_secret, carrier.recv_packet(1.0))
            frames = parse_frames(payload)
            carrier.send_packet(protect_short_packet(client_session_secret, dcid, client_pn, ack_frame(server_pn)))
            client_pn += 1
            for kind, value in frames:
                if kind == "stream" and value[3] == b"python-independent-stream":
                    echoed = True
            if echoed:
                break
        if not echoed:
            raise AssertionError("daemon did not echo independent stream data")

        datagram_payload = datagram_frame(b"python-independent-datagram", context_id=7)
        sent_datagram_pn = client_pn
        carrier.send_packet(protect_short_packet(client_session_secret, dcid, sent_datagram_pn, datagram_payload))
        client_pn += 1
        acknowledged = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            server_pn, payload = parse_short_packet(server_session_secret, carrier.recv_packet(1.0))
            frames = parse_frames(payload)
            carrier.send_packet(protect_short_packet(client_session_secret, dcid, client_pn, ack_frame(server_pn)))
            client_pn += 1
            for kind, value in frames:
                if kind == "ack" and value >= sent_datagram_pn:
                    acknowledged = True
            if acknowledged:
                break
        if not acknowledged:
            raise AssertionError("daemon did not acknowledge independent datagram traffic")
        return context["server_endpoint_id"]
    finally:
        carrier.close()


def run(carrier: str, binary: Path, result_path: Optional[Path]) -> Dict[str, Any]:
    daemon = Daemon(binary, carrier)
    carrier_type = {"tcp": "ump.tcp/1", "udp": "ump.udp/1", "tls": "ump.tls-stream/1"}[carrier]
    try:
        daemon.start()
        run_version_refusal(daemon)
        first_endpoint = run_handshake_and_data(daemon)
        daemon.stop()
        daemon.start()
        second_endpoint = run_handshake_and_data(daemon)
        if first_endpoint != second_endpoint:
            raise AssertionError("daemon endpoint identity changed across restart")
        report = {
            "status": "pass",
            "implementation": "python-independent-peer/0.1",
            "protocol": "UMP/1",
            "storage": "SQLite schema v2",
            "vector": "ump-independent-vectors/0.1",
            "carrier": carrier_type,
            "scenarios": [
                "unsupported-version-refusal",
                "xx-authenticated-session",
                "stream-echo",
                "datagram-acknowledgement",
                "restart-with-persistent-identity",
            ],
            "failure_classifications": {
                "unsupported-version": "VERSION_NEGOTIATION",
                "carrier-close": "LINK_FAILED",
                "authentication": "AUTHENTICATION_FAILED",
            },
        }
    except Exception as error:
        raise RuntimeError("{} (daemon diagnostics: {})".format(error, daemon.directory)) from error
    finally:
        daemon.stop()
    if result_path is not None:
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--carrier", choices=("tcp", "udp", "tls"), required=True)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/umcd"))
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        report = run(args.carrier, args.binary, args.result)
    except Exception as error:
        report = {
            "status": "fail",
            "implementation": "python-independent-peer/0.1",
            "carrier": args.carrier,
            "failure": type(error).__name__ + ": " + str(error),
        }
        print(json.dumps(report, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
