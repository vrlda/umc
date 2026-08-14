"""Small, dependency-free subset of the UMC protobuf API.

The reference daemon uses protobuf on a length-prefixed Unix socket.  The
official schema remains ``api/umc.proto``; this module intentionally contains
only the messages needed by the stdlib client so Python users do not need the
``protobuf`` or ``grpcio`` wheels just to perform control-plane requests.
"""

from __future__ import annotations


def _varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ValueError("truncated protobuf varint")


def _signed64(value: int) -> int:
    return value - (1 << 64) if value & (1 << 63) else value


def _fields(data: bytes):
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, offset = _read_varint(data, offset)
        elif wire == 2:
            length, offset = _read_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("truncated protobuf bytes field")
            value, offset = data[offset:end], end
        elif wire == 1:
            end = offset + 8
            if end > len(data):
                raise ValueError("truncated protobuf fixed64 field")
            value, offset = data[offset:end], end
        elif wire == 5:
            end = offset + 4
            if end > len(data):
                raise ValueError("truncated protobuf fixed32 field")
            value, offset = data[offset:end], end
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield number, wire, value


def _tag(number: int, wire: int) -> bytes:
    return _varint((number << 3) | wire)


def _put_varint(out: bytearray, number: int, value: int, *, include_zero: bool = False) -> None:
    if value or include_zero:
        out.extend(_tag(number, 0))
        out.extend(_varint(value))


def _put_bytes(out: bytearray, number: int, value: bytes | bytearray | None) -> None:
    if value:
        value = bytes(value)
        out.extend(_tag(number, 2))
        out.extend(_varint(len(value)))
        out.extend(value)


def _put_string(out: bytearray, number: int, value: str | None) -> None:
    if value:
        _put_bytes(out, number, value.encode("utf-8"))


def _put_message(out: bytearray, number: int, value: "Message | None") -> None:
    if value is not None:
        _put_bytes(out, number, value.SerializeToString())


class Message:
    """Minimal protobuf-message interface compatible with generated classes."""

    def SerializeToString(self) -> bytes:
        return self._encode()

    def ParseFromString(self, data: bytes) -> None:
        parsed = type(self).FromString(data)
        self.__dict__.update(parsed.__dict__)

    @classmethod
    def FromString(cls, data: bytes):
        return cls._decode(bytes(data))

    def _encode(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def _decode(cls, data: bytes):
        raise NotImplementedError


class ApiVersion(Message):
    def __init__(self, major: int = 0, minor: int = 0):
        self.major, self.minor = major, minor

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.major)
        _put_varint(out, 2, self.minor)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if wire == 0 and number == 1:
                result.major = value
            elif wire == 0 and number == 2:
                result.minor = value
        return result


class ClientHello(Message):
    def __init__(
        self,
        supported_versions: list[ApiVersion] | None = None,
        client_name: str = "",
        client_instance_id: bytes = b"",
        client_kind: int = 0,
        authentication: "ClientAuthentication | None" = None,
        requested_envelope_size: int = 0,
        requested_features: list[str] | None = None,
    ):
        self.supported_versions = list(supported_versions or [])
        self.client_name = client_name
        self.client_instance_id = bytes(client_instance_id)
        self.client_kind = client_kind
        self.authentication = authentication
        self.requested_envelope_size = requested_envelope_size
        self.requested_features = list(requested_features or [])

    def _encode(self) -> bytes:
        out = bytearray()
        for version in self.supported_versions:
            _put_message(out, 1, version)
        _put_string(out, 2, self.client_name)
        _put_bytes(out, 3, self.client_instance_id)
        _put_varint(out, 4, self.client_kind)
        _put_message(out, 5, self.authentication)
        _put_varint(out, 6, self.requested_envelope_size)
        for feature in self.requested_features:
            _put_string(out, 7, feature)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.supported_versions.append(ApiVersion.FromString(value))
            elif number == 2 and wire == 2:
                result.client_name = value.decode("utf-8")
            elif number == 3 and wire == 2:
                result.client_instance_id = value
            elif number == 4 and wire == 0:
                result.client_kind = value
            elif number == 5 and wire == 2:
                result.authentication = ClientAuthentication.FromString(value)
            elif number == 6 and wire == 0:
                result.requested_envelope_size = value
            elif number == 7 and wire == 2:
                result.requested_features.append(value.decode("utf-8"))
        return result


class ClientAuthentication(Message):
    def __init__(self, development: bytes = b"", bearer: bytes = b""):
        self.development = bytes(development)
        self.bearer = bytes(bearer)

    def _encode(self) -> bytes:
        out = bytearray()
        if self.development:
            _put_message(out, 3, _Token(self.development))
        if self.bearer:
            _put_message(out, 2, _Token(self.bearer))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number in (2, 3) and wire == 2:
                token = _Token.FromString(value).value
                if number == 2:
                    result.bearer = token
                else:
                    result.development = token
        return result


class _Token(Message):
    def __init__(self, value: bytes = b""):
        self.value = bytes(value)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.value)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.value = value
        return result


class CapabilityGrant(Message):
    def __init__(self, capability: int = 0, scope: str = ""):
        self.capability, self.scope = capability, scope

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.capability)
        _put_string(out, 2, self.scope)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.capability = value
            elif number == 2 and wire == 2:
                result.scope = value.decode("utf-8")
        return result


class OpaqueHandle(Message):
    def __init__(self, value: bytes = b""):
        self.value = bytes(value)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.value)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.value = value
        return result


class ListIdentitiesRequest(Message):
    def _encode(self) -> bytes:
        return b""


class IdentitySummary(Message):
    def __init__(self):
        self.identity_handle = None
        self.endpoint_id = b""
        self.kind = 0
        self.label = ""
        self.binding_sequence = 0
        self.binding_not_after_unix_ms = 0
        self.secret_available = False

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.identity_handle)
        _put_bytes(out, 2, self.endpoint_id)
        _put_varint(out, 3, self.kind)
        _put_string(out, 4, self.label)
        _put_varint(out, 5, self.binding_sequence)
        _put_varint(out, 6, self.binding_not_after_unix_ms)
        _put_varint(out, 7, int(self.secret_available))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.identity_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.endpoint_id = value
            elif number == 3 and wire == 0:
                result.kind = value
            elif number == 4 and wire == 2:
                result.label = value.decode("utf-8")
            elif number == 5 and wire == 0:
                result.binding_sequence = value
            elif number == 6 and wire == 0:
                result.binding_not_after_unix_ms = _signed64(value)
            elif number == 7 and wire == 0:
                result.secret_available = bool(value)
        return result


class ListIdentitiesResponse(Message):
    def __init__(self):
        self.identities = []

    def _encode(self) -> bytes:
        out = bytearray()
        for identity in self.identities:
            _put_message(out, 1, identity)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.identities.append(IdentitySummary.FromString(value))
        return result


class CreateDelegationRequest(Message):
    def __init__(self, identity_handle=None, delegated_public_key: bytes = b"", allowed_capabilities=None, expires_at_unix_ms: int = 0, root_capabilities=None):
        self.identity_handle = identity_handle
        self.delegated_public_key = bytes(delegated_public_key)
        self.allowed_capabilities = list(allowed_capabilities or [])
        self.expires_at_unix_ms = expires_at_unix_ms
        self.root_capabilities = list(root_capabilities or [])

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.identity_handle)
        _put_bytes(out, 2, self.delegated_public_key)
        for capability in self.allowed_capabilities:
            _put_bytes(out, 3, capability)
        _put_varint(out, 4, self.expires_at_unix_ms)
        for capability in self.root_capabilities:
            _put_bytes(out, 5, capability)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.identity_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.delegated_public_key = value
            elif number == 3 and wire == 2:
                result.allowed_capabilities.append(value)
            elif number == 4 and wire == 0:
                result.expires_at_unix_ms = _signed64(value)
            elif number == 5 and wire == 2:
                result.root_capabilities.append(value)
        return result


class CreateDelegationResponse(Message):
    def __init__(self):
        self.certificate = b""
        self.delegation_chain = b""
        self.root_public_key = b""

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.certificate = value
            elif number == 2 and wire == 2:
                result.delegation_chain = value
            elif number == 3 and wire == 2:
                result.root_public_key = value
        return result


class ImportDelegationRequest(Message):
    def __init__(self, root_public_key: bytes = b"", root_capabilities=None, delegation_chain: bytes = b""):
        self.root_public_key = bytes(root_public_key)
        self.root_capabilities = list(root_capabilities or [])
        self.delegation_chain = bytes(delegation_chain)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.root_public_key)
        for capability in self.root_capabilities:
            _put_bytes(out, 2, capability)
        _put_bytes(out, 3, self.delegation_chain)
        return bytes(out)


class ImportDelegationResponse(Message):
    def __init__(self):
        self.delegated_public_key = b""
        self.delegation_chain = b""

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.delegated_public_key = value
            elif number == 2 and wire == 2:
                result.delegation_chain = value
        return result


class ListDelegationsRequest(Message):
    def _encode(self) -> bytes:
        return b""


class DelegationSummary(Message):
    def __init__(self):
        self.root_public_key = b""
        self.delegated_public_key = b""
        self.depth = 0
        self.sequence = 0
        self.expires_at_unix_ms = 0
        self.capabilities = []

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.root_public_key)
        _put_bytes(out, 2, self.delegated_public_key)
        _put_varint(out, 3, self.depth)
        _put_varint(out, 4, self.sequence)
        _put_varint(out, 5, self.expires_at_unix_ms)
        for capability in self.capabilities:
            _put_bytes(out, 6, capability)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.root_public_key = value
            elif number == 2 and wire == 2:
                result.delegated_public_key = value
            elif number == 3 and wire == 0:
                result.depth = value
            elif number == 4 and wire == 0:
                result.sequence = value
            elif number == 5 and wire == 0:
                result.expires_at_unix_ms = value
            elif number == 6 and wire == 2:
                result.capabilities.append(value)
        return result


class ListDelegationsResponse(Message):
    def __init__(self):
        self.delegations = []

    def _encode(self) -> bytes:
        out = bytearray()
        for delegation in self.delegations:
            _put_message(out, 1, delegation)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.delegations.append(DelegationSummary.FromString(value))
        return result


class RevokeDelegationRequest(Message):
    def __init__(self, identity_handle=None, delegated_public_key: bytes = b"", sequence: int = 0, expires_at_unix_ms: int = 0, reason: str = ""):
        self.identity_handle = identity_handle
        self.delegated_public_key = bytes(delegated_public_key)
        self.sequence = sequence
        self.expires_at_unix_ms = expires_at_unix_ms
        self.reason = reason

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.identity_handle)
        _put_bytes(out, 2, self.delegated_public_key)
        _put_varint(out, 3, self.sequence)
        _put_varint(out, 4, self.expires_at_unix_ms)
        _put_string(out, 5, self.reason)
        return bytes(out)


class RevokeDelegationResponse(Message):
    def _encode(self) -> bytes:
        return b""


class RegisterApplicationRequest(Message):
    def __init__(self, application_name: str = "", application_instance_id: bytes = b"", requested_protocol_ids: list[str] | None = None, resumable: bool = False):
        self.application_name = application_name
        self.application_instance_id = bytes(application_instance_id)
        self.requested_protocol_ids = list(requested_protocol_ids or [])
        self.resumable = resumable

    def _encode(self) -> bytes:
        out = bytearray()
        _put_string(out, 1, self.application_name)
        _put_bytes(out, 2, self.application_instance_id)
        for protocol in self.requested_protocol_ids:
            _put_string(out, 4, protocol)
        _put_varint(out, 6, int(self.resumable))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.application_name = value.decode("utf-8")
            elif number == 2 and wire == 2:
                result.application_instance_id = value
            elif number == 4 and wire == 2:
                result.requested_protocol_ids.append(value.decode("utf-8"))
            elif number == 6 and wire == 0:
                result.resumable = bool(value)
        return result


class RegisterApplicationResponse(Message):
    def __init__(self):
        self.application_handle = None
        self.effective_grants = []
        self.resume_token = b""

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        for grant in self.effective_grants:
            _put_message(out, 2, grant)
        _put_bytes(out, 3, self.resume_token)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.application_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.effective_grants.append(CapabilityGrant.FromString(value))
            elif number == 3 and wire == 2:
                result.resume_token = value
        return result


class UnregisterApplicationRequest(Message):
    def __init__(self, application_handle=None, close_owned_sessions: bool = False):
        self.application_handle = application_handle
        self.close_owned_sessions = close_owned_sessions

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_varint(out, 2, int(self.close_owned_sessions))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.application_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 0:
                result.close_owned_sessions = bool(value)
        return result


class ConnectRequest(Message):
    def __init__(self, application_handle=None, local_endpoint_id: bytes = b"", destination_hint: bytes = b"", protocol_id: str = "", return_operation: bool = False):
        self.application_handle = application_handle
        self.local_endpoint_id = bytes(local_endpoint_id)
        self.destination_hint = bytes(destination_hint)
        self.protocol_id = protocol_id
        self.return_operation = return_operation

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_bytes(out, 2, self.local_endpoint_id)
        _put_bytes(out, 3, self.destination_hint)
        _put_string(out, 4, self.protocol_id)
        _put_varint(out, 6, int(self.return_operation))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.application_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.local_endpoint_id = value
            elif number == 3 and wire == 2:
                result.destination_hint = value
            elif number == 4 and wire == 2:
                result.protocol_id = value.decode("utf-8")
            elif number == 6 and wire == 0:
                result.return_operation = bool(value)
        return result


class ConnectResponse(Message):
    def __init__(self):
        self.session_handle = None
        self.operation_handle = None

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.session_handle)
        _put_message(out, 2, self.operation_handle)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.session_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.operation_handle = OpaqueHandle.FromString(value)
        return result


class AcceptIncomingSessionRequest(Message):
    def __init__(self, application_handle=None, pending_session_handle=None):
        self.application_handle = application_handle
        self.pending_session_handle = pending_session_handle

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_message(out, 2, self.pending_session_handle)
        return bytes(out)


class RejectIncomingSessionRequest(Message):
    def __init__(self, application_handle=None, pending_session_handle=None, application_error_code: int = 0, reason: str = ""):
        self.application_handle = application_handle
        self.pending_session_handle = pending_session_handle
        self.application_error_code = application_error_code
        self.reason = reason

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_message(out, 2, self.pending_session_handle)
        _put_varint(out, 3, self.application_error_code)
        _put_string(out, 4, self.reason)
        return bytes(out)


class AcceptIncomingSessionResponse(Message):
    def __init__(self):
        self.session_handle = None

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.session_handle = OpaqueHandle.FromString(value)
        return result


class OpenListenerRequest(Message):
    def __init__(self, application_handle=None, endpoint_id: bytes = b"", protocol_id: str = ""):
        self.application_handle = application_handle
        self.endpoint_id = bytes(endpoint_id)
        self.protocol_id = protocol_id

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_bytes(out, 2, self.endpoint_id)
        _put_string(out, 3, self.protocol_id)
        return bytes(out)


class ListCandidatesRequest(Message):
    def __init__(self):
        pass

    def _encode(self) -> bytes:
        return b""

    @classmethod
    def _decode(cls, data: bytes):
        return cls()


class CandidateSummary(Message):
    def __init__(self, candidate_id: int = 0, carrier_type: str = "", expires_at_ms: int = 0, public: bool = False):
        self.candidate_id = candidate_id
        self.carrier_type = carrier_type
        self.expires_at_ms = expires_at_ms
        self.public = public

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.candidate_id)
        _put_string(out, 2, self.carrier_type)
        _put_varint(out, 3, self.expires_at_ms)
        _put_varint(out, 4, int(self.public))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.candidate_id = value
            elif number == 2 and wire == 2:
                result.carrier_type = value.decode("utf-8")
            elif number == 3 and wire == 0:
                result.expires_at_ms = value
            elif number == 4 and wire == 0:
                result.public = bool(value)
        return result


class ListCandidatesResponse(Message):
    def __init__(self):
        self.candidates = []
        self.total = 0

    def _encode(self) -> bytes:
        out = bytearray()
        for candidate in self.candidates:
            _put_message(out, 1, candidate)
        _put_varint(out, 2, self.total)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.candidates.append(CandidateSummary.FromString(value))
            elif number == 2 and wire == 0:
                result.total = value
        return result


class ServiceHintSummary(Message):
    def __init__(self, peer_endpoint_id: bytes = b"", protocol_id: str = "", endpoint_hint: bytes = b"", metadata: bytes = b"", expires_at_unix_ms: int = 0, signature: bytes = b"", public: bool = False):
        self.peer_endpoint_id = bytes(peer_endpoint_id)
        self.protocol_id = protocol_id
        self.endpoint_hint = bytes(endpoint_hint)
        self.metadata = bytes(metadata)
        self.expires_at_unix_ms = expires_at_unix_ms
        self.signature = bytes(signature)
        self.public = public

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.peer_endpoint_id)
        _put_string(out, 2, self.protocol_id)
        _put_bytes(out, 3, self.endpoint_hint)
        _put_bytes(out, 4, self.metadata)
        _put_varint(out, 5, self.expires_at_unix_ms)
        _put_bytes(out, 6, self.signature)
        _put_varint(out, 7, int(self.public))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.peer_endpoint_id = value
            elif number == 2 and wire == 2:
                result.protocol_id = value.decode("utf-8")
            elif number == 3 and wire == 2:
                result.endpoint_hint = value
            elif number == 4 and wire == 2:
                result.metadata = value
            elif number == 5 and wire == 0:
                result.expires_at_unix_ms = _signed64(value)
            elif number == 6 and wire == 2:
                result.signature = value
            elif number == 7 and wire == 0:
                result.public = bool(value)
        return result


class PublishServiceHintRequest(Message):
    def __init__(self, protocol_id: str = "", endpoint_hint: bytes = b"", metadata: bytes = b"", expires_at_unix_ms: int = 0, public: bool = False):
        self.protocol_id = protocol_id
        self.endpoint_hint = bytes(endpoint_hint)
        self.metadata = bytes(metadata)
        self.expires_at_unix_ms = expires_at_unix_ms
        self.public = public

    def _encode(self) -> bytes:
        out = bytearray()
        _put_string(out, 1, self.protocol_id)
        _put_bytes(out, 2, self.endpoint_hint)
        _put_bytes(out, 3, self.metadata)
        _put_varint(out, 4, self.expires_at_unix_ms)
        _put_varint(out, 5, int(self.public))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.protocol_id = value.decode("utf-8")
            elif number == 2 and wire == 2:
                result.endpoint_hint = value
            elif number == 3 and wire == 2:
                result.metadata = value
            elif number == 4 and wire == 0:
                result.expires_at_unix_ms = _signed64(value)
            elif number == 5 and wire == 0:
                result.public = bool(value)
        return result


class PublishServiceHintResponse(Message):
    def __init__(self, hint=None):
        self.hint = hint

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.hint)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.hint = ServiceHintSummary.FromString(value)
        return result


class DiscoverServicesRequest(Message):
    def __init__(self, protocol_id: str = ""):
        self.protocol_id = protocol_id

    def _encode(self) -> bytes:
        out = bytearray()
        _put_string(out, 1, self.protocol_id)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.protocol_id = value.decode("utf-8")
        return result


class DiscoverServicesResponse(Message):
    def __init__(self, hints=None):
        self.hints = list(hints or [])

    def _encode(self) -> bytes:
        out = bytearray()
        for hint in self.hints:
            _put_message(out, 1, hint)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.hints.append(ServiceHintSummary.FromString(value))
        return result


class OpenListenerResponse(Message):
    def __init__(self):
        self.listener_handle = None

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.listener_handle = OpaqueHandle.FromString(value)
        return result

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.listener_handle)
        return bytes(out)


class CloseListenerRequest(Message):
    def __init__(self, listener_handle=None, close_owned_sessions: bool = False):
        self.listener_handle = listener_handle
        self.close_owned_sessions = close_owned_sessions

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.listener_handle)
        _put_varint(out, 2, int(self.close_owned_sessions))
        return bytes(out)


class OpenStreamRequest(Message):
    def __init__(self, application_handle=None, session_handle=None, unidirectional: bool = False, initial_metadata: bytes = b""):
        self.application_handle = application_handle
        self.session_handle = session_handle
        self.unidirectional = unidirectional
        self.initial_metadata = bytes(initial_metadata)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_message(out, 2, self.session_handle)
        _put_varint(out, 3, int(self.unidirectional))
        _put_bytes(out, 4, self.initial_metadata)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.application_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 2:
                result.session_handle = OpaqueHandle.FromString(value)
            elif number == 3 and wire == 0:
                result.unidirectional = bool(value)
            elif number == 4 and wire == 2:
                result.initial_metadata = value
        return result


class OpenStreamResponse(Message):
    def __init__(self):
        self.stream_handle = None

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.stream_handle)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.stream_handle = OpaqueHandle.FromString(value)
        return result


class AcceptStreamRequest(Message):
    def __init__(self, application_handle=None, pending_stream_handle=None):
        self.application_handle = application_handle
        self.pending_stream_handle = pending_stream_handle

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_message(out, 2, self.pending_stream_handle)
        return bytes(out)


class RejectStreamRequest(Message):
    def __init__(self, pending_stream_handle=None, application_error_code: int = 0):
        self.pending_stream_handle = pending_stream_handle
        self.application_error_code = application_error_code

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.pending_stream_handle)
        _put_varint(out, 2, self.application_error_code)
        return bytes(out)


class AcceptStreamResponse(Message):
    def __init__(self):
        self.stream_handle = None

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.stream_handle = OpaqueHandle.FromString(value)
        return result


class WriteStreamRequest(Message):
    def __init__(self, stream_handle=None, data: bytes = b"", fin: bool = False):
        self.stream_handle = stream_handle
        self.data = bytes(data)
        self.fin = fin

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.stream_handle)
        _put_bytes(out, 2, self.data)
        _put_varint(out, 3, int(self.fin))
        return bytes(out)


class WriteStreamResponse(Message):
    def __init__(self):
        self.accepted_bytes = 0
        self.fin_accepted = False

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.accepted_bytes = value
            elif number == 2 and wire == 0:
                result.fin_accepted = bool(value)
        return result

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.accepted_bytes)
        _put_varint(out, 2, int(self.fin_accepted))
        return bytes(out)


class CloseStreamSendRequest(Message):
    def __init__(self, stream_handle=None):
        self.stream_handle = stream_handle

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.stream_handle)
        return bytes(out)


class ResetStreamRequest(Message):
    def __init__(self, stream_handle=None, application_error_code: int = 0):
        self.stream_handle = stream_handle
        self.application_error_code = application_error_code

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.stream_handle)
        _put_varint(out, 2, self.application_error_code)
        return bytes(out)


class StopStreamRequest(ResetStreamRequest):
    pass


class SendDatagramRequest(Message):
    def __init__(self, session_handle=None, context_id: int = 0, data: bytes = b"", lifetime_ms: int = 0, request_ack: bool = False):
        self.session_handle = session_handle
        self.context_id = context_id
        self.data = bytes(data)
        self.lifetime_ms = lifetime_ms
        self.request_ack = request_ack

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.session_handle)
        _put_varint(out, 2, self.context_id)
        _put_bytes(out, 3, self.data)
        _put_varint(out, 4, self.lifetime_ms)
        _put_varint(out, 5, int(self.request_ack))
        return bytes(out)


class SendDatagramResponse(Message):
    def __init__(self):
        self.local_datagram_id = 0

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.local_datagram_id = value
        return result

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.local_datagram_id)
        return bytes(out)


class ReceiveDatagramRequest(Message):
    def __init__(self, application_handle=None, session_handle=None, maximum_bytes: int = 0, wait_for_data: bool = False):
        self.application_handle = application_handle
        self.session_handle = session_handle
        self.maximum_bytes = maximum_bytes
        self.wait_for_data = wait_for_data

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.application_handle)
        _put_message(out, 2, self.session_handle)
        _put_varint(out, 3, self.maximum_bytes)
        _put_varint(out, 4, int(self.wait_for_data))
        return bytes(out)


class ReceiveDatagramResponse(Message):
    def __init__(self):
        self.session_handle = None
        self.context_id = 0
        self.data = b""
        self.expired = False

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.session_handle = OpaqueHandle.FromString(value)
            elif number == 2 and wire == 0:
                result.context_id = value
            elif number == 3 and wire == 2:
                result.data = value
            elif number == 4 and wire == 0:
                result.expired = bool(value)
        return result


class ReadStreamRequest(Message):
    def __init__(self, stream_handle=None, maximum_bytes: int = 0, wait_for_data: bool = False):
        self.stream_handle = stream_handle
        self.maximum_bytes = maximum_bytes
        self.wait_for_data = wait_for_data

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.stream_handle)
        _put_varint(out, 2, self.maximum_bytes)
        _put_varint(out, 3, int(self.wait_for_data))
        return bytes(out)


class ReadStreamResponse(Message):
    def __init__(self):
        self.data = b""
        self.eof = False
        self.reset = False
        self.application_error_code = 0

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.data = value
            elif number == 2 and wire == 0:
                result.eof = bool(value)
            elif number == 3 and wire == 0:
                result.reset = bool(value)
            elif number == 4 and wire == 0:
                result.application_error_code = value
        return result

    def _encode(self) -> bytes:
        out = bytearray()
        _put_bytes(out, 1, self.data)
        _put_varint(out, 2, int(self.eof))
        _put_varint(out, 3, int(self.reset))
        _put_varint(out, 4, self.application_error_code)
        return bytes(out)


class ConnectionLimits(Message):
    def __init__(self, **kwargs: int):
        names = (
            "maximum_envelope_size",
            "maximum_concurrent_requests",
            "maximum_queued_requests",
            "maximum_event_streams",
            "maximum_event_backlog",
            "maximum_event_backlog_bytes",
        )
        for name in names:
            setattr(self, name, int(kwargs.get(name, 0)))

    def _encode(self) -> bytes:
        out = bytearray()
        for number, name in enumerate(
            (
                "maximum_envelope_size",
                "maximum_concurrent_requests",
                "maximum_queued_requests",
                "maximum_event_streams",
                "maximum_event_backlog",
                "maximum_event_backlog_bytes",
            ),
            1,
        ):
            _put_varint(out, number, getattr(self, name))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        names = (
            "maximum_envelope_size",
            "maximum_concurrent_requests",
            "maximum_queued_requests",
            "maximum_event_streams",
            "maximum_event_backlog",
            "maximum_event_backlog_bytes",
        )
        for number, wire, value in _fields(data):
            if wire == 0 and 1 <= number <= len(names):
                setattr(result, names[number - 1], value)
        return result


class ServerHello(Message):
    def __init__(self):
        self.selected_version: ApiVersion | None = None
        self.server_instance_id = b""
        self.node_state = 0
        self.connection_id = b""
        self.principal_id = b""
        self.granted_capabilities: list[CapabilityGrant] = []
        self.negotiated_envelope_size = 0
        self.enabled_features: list[str] = []
        self.limits: ConnectionLimits | None = None

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.selected_version)
        _put_bytes(out, 2, self.server_instance_id)
        _put_varint(out, 3, self.node_state)
        _put_bytes(out, 4, self.connection_id)
        _put_bytes(out, 5, self.principal_id)
        for grant in self.granted_capabilities:
            _put_message(out, 6, grant)
        _put_varint(out, 7, self.negotiated_envelope_size)
        for feature in self.enabled_features:
            _put_string(out, 8, feature)
        _put_message(out, 9, self.limits)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.selected_version = ApiVersion.FromString(value)
            elif number == 2 and wire == 2:
                result.server_instance_id = value
            elif number == 3 and wire == 0:
                result.node_state = value
            elif number == 4 and wire == 2:
                result.connection_id = value
            elif number == 5 and wire == 2:
                result.principal_id = value
            elif number == 6 and wire == 2:
                result.granted_capabilities.append(CapabilityGrant.FromString(value))
            elif number == 7 and wire == 0:
                result.negotiated_envelope_size = value
            elif number == 8 and wire == 2:
                result.enabled_features.append(value.decode("utf-8"))
            elif number == 9 and wire == 2:
                result.limits = ConnectionLimits.FromString(value)
        return result


class Request(Message):
    def __init__(
        self,
        request_id: int = 0,
        service: str = "",
        method: str = "",
        deadline_unix_ms: int = 0,
        idempotency_key: bytes = b"",
        payload: bytes = b"",
    ):
        self.request_id, self.service, self.method = request_id, service, method
        self.deadline_unix_ms = deadline_unix_ms
        self.idempotency_key, self.payload = bytes(idempotency_key), bytes(payload)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.request_id)
        _put_string(out, 2, self.service)
        _put_string(out, 3, self.method)
        _put_varint(out, 4, self.deadline_unix_ms)
        _put_bytes(out, 5, self.idempotency_key)
        _put_bytes(out, 6, self.payload)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.request_id = value
            elif number == 2 and wire == 2:
                result.service = value.decode("utf-8")
            elif number == 3 and wire == 2:
                result.method = value.decode("utf-8")
            elif number == 4 and wire == 0:
                result.deadline_unix_ms = _signed64(value)
            elif number == 5 and wire == 2:
                result.idempotency_key = value
            elif number == 6 and wire == 2:
                result.payload = value
        return result


class StatusDetail(Message):
    def __init__(self, type: str = "", value: bytes = b""):
        self.type, self.value = type, bytes(value)

    def _encode(self) -> bytes:
        out = bytearray()
        _put_string(out, 1, self.type)
        _put_bytes(out, 2, self.value)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.type = value.decode("utf-8")
            elif number == 2 and wire == 2:
                result.value = value
        return result


class Status(Message):
    def __init__(
        self,
        code: int = 0,
        message: str = "",
        details: list[StatusDetail] | None = None,
        retry_after_ms: int = 0,
    ):
        self.code, self.message = code, message
        self.details = list(details or [])
        self.retry_after_ms = retry_after_ms

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.code)
        _put_string(out, 2, self.message)
        for detail in self.details:
            _put_message(out, 3, detail)
        _put_varint(out, 4, self.retry_after_ms)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.code = value
            elif number == 2 and wire == 2:
                result.message = value.decode("utf-8")
            elif number == 3 and wire == 2:
                result.details.append(StatusDetail.FromString(value))
            elif number == 4 and wire == 0:
                result.retry_after_ms = value
        return result


class Response(Message):
    def __init__(self, request_id: int = 0, status: Status | None = None, payload: bytes = b"", completed_at_unix_ms: int = 0):
        self.request_id = request_id
        self.status = status
        self.payload = bytes(payload)
        self.completed_at_unix_ms = completed_at_unix_ms

    def _encode(self) -> bytes:
        out = bytearray()
        _put_varint(out, 1, self.request_id)
        _put_message(out, 2, self.status)
        _put_bytes(out, 3, self.payload)
        _put_varint(out, 4, self.completed_at_unix_ms)
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 0:
                result.request_id = value
            elif number == 2 and wire == 2:
                result.status = Status.FromString(value)
            elif number == 3 and wire == 2:
                result.payload = value
            elif number == 4 and wire == 0:
                result.completed_at_unix_ms = _signed64(value)
        return result


class Envelope(Message):
    def __init__(
        self,
        api_version: ApiVersion | None = None,
        sequence: int = 0,
        client_hello: ClientHello | None = None,
        server_hello: ServerHello | None = None,
        request: Request | None = None,
        response: Response | None = None,
    ):
        self.api_version, self.sequence = api_version, sequence
        self.client_hello = client_hello
        self.server_hello = server_hello
        self.request = request
        self.response = response

    def WhichOneof(self, _name: str) -> str | None:
        for name in ("client_hello", "server_hello", "request", "response"):
            if getattr(self, name) is not None:
                return name
        return None

    def _encode(self) -> bytes:
        out = bytearray()
        _put_message(out, 1, self.api_version)
        _put_varint(out, 2, self.sequence)
        for number, name in ((10, "client_hello"), (11, "server_hello"), (12, "request"), (13, "response")):
            _put_message(out, number, getattr(self, name))
        return bytes(out)

    @classmethod
    def _decode(cls, data: bytes):
        result = cls()
        for number, wire, value in _fields(data):
            if number == 1 and wire == 2:
                result.api_version = ApiVersion.FromString(value)
            elif number == 2 and wire == 0:
                result.sequence = value
            elif number == 10 and wire == 2:
                result.client_hello = ClientHello.FromString(value)
            elif number == 11 and wire == 2:
                result.server_hello = ServerHello.FromString(value)
            elif number == 12 and wire == 2:
                result.request = Request.FromString(value)
            elif number == 13 and wire == 2:
                result.response = Response.FromString(value)
        return result


class StatusCode:
    OK = 0
    CANCELLED = 1
    UNKNOWN = 2
    INVALID_ARGUMENT = 3
    DEADLINE_EXCEEDED = 4
    NOT_FOUND = 5
    ALREADY_EXISTS = 6
    PERMISSION_DENIED = 7
    UNAUTHENTICATED = 8
    RESOURCE_EXHAUSTED = 9
    FAILED_PRECONDITION = 10
    ABORTED = 11
    OUT_OF_RANGE = 12
    UNIMPLEMENTED = 13
    INTERNAL = 14
    UNAVAILABLE = 15
    DATA_LOSS = 16
    CONFLICT = 17
    IDEMPOTENCY_CONFLICT = 18


__all__ = [
    "AcceptIncomingSessionRequest",
    "AcceptIncomingSessionResponse",
    "AcceptStreamRequest",
    "AcceptStreamResponse",
    "ApiVersion",
    "CapabilityGrant",
    "CandidateSummary",
    "CloseStreamSendRequest",
    "ClientAuthentication",
    "ClientHello",
    "ConnectionLimits",
    "Envelope",
    "Message",
    "ConnectRequest",
    "ConnectResponse",
    "CreateDelegationRequest",
    "CreateDelegationResponse",
    "DelegationSummary",
    "ImportDelegationRequest",
    "ImportDelegationResponse",
    "ListDelegationsRequest",
    "ListDelegationsResponse",
    "ListCandidatesRequest",
    "ListCandidatesResponse",
    "ServiceHintSummary",
    "PublishServiceHintRequest",
    "PublishServiceHintResponse",
    "DiscoverServicesRequest",
    "DiscoverServicesResponse",
    "ListIdentitiesRequest",
    "ListIdentitiesResponse",
    "IdentitySummary",
    "Request",
    "OpaqueHandle",
    "OpenStreamRequest",
    "OpenStreamResponse",
    "ReadStreamRequest",
    "ReadStreamResponse",
    "ReceiveDatagramRequest",
    "ReceiveDatagramResponse",
    "RegisterApplicationRequest",
    "RegisterApplicationResponse",
    "RejectIncomingSessionRequest",
    "RejectStreamRequest",
    "ResetStreamRequest",
    "RevokeDelegationRequest",
    "RevokeDelegationResponse",
    "Response",
    "SendDatagramRequest",
    "SendDatagramResponse",
    "ServerHello",
    "Status",
    "StatusCode",
    "StatusDetail",
    "StopStreamRequest",
    "UnregisterApplicationRequest",
    "WriteStreamRequest",
    "WriteStreamResponse",
]
