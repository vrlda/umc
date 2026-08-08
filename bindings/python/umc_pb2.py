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
    "ApiVersion",
    "CapabilityGrant",
    "ClientAuthentication",
    "ClientHello",
    "ConnectionLimits",
    "Envelope",
    "Message",
    "Request",
    "Response",
    "ServerHello",
    "Status",
    "StatusCode",
    "StatusDetail",
]
