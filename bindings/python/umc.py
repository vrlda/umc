"""Pure-stdlib asynchronous client for the UMC local Control API.

Unix endpoints use a local stream socket. On Windows, endpoints in the
``\\\\.\\pipe\\`` namespace use the daemon's raw byte-mode named pipe.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import struct
from typing import Optional

from . import umc_pb2 as api


MAX_ENVELOPE = 4 * 1024 * 1024


class UMCError(Exception):
    """Base class for transport, framing, and daemon status errors."""


class FramingError(UMCError):
    """The daemon sent an invalid or oversized length-prefixed envelope."""


class StatusError(UMCError):
    """The daemon returned a non-OK status."""

    def __init__(self, status: api.Status):
        super().__init__(f"{status.code}: {status.message}")
        self.status = status


class StreamWriteResult:
    def __init__(self, accepted_bytes: int, fin_accepted: bool):
        self.accepted_bytes = accepted_bytes
        self.fin_accepted = fin_accepted


class StreamReadResult:
    def __init__(self, data: bytes, eof: bool, reset: bool, application_error_code: int):
        self.data = data
        self.eof = eof
        self.reset = reset
        self.application_error_code = application_error_code


class Datagram:
    def __init__(self, session_handle: bytes, context_id: int, data: bytes, expired: bool):
        self.session_handle = bytes(session_handle)
        self.context_id = context_id
        self.data = bytes(data)
        self.expired = expired


class Endpoint:
    def __init__(self, client: "Client", handle: bytes, endpoint_id: bytes, label: str, kind: int):
        self._client = client
        self.handle = bytes(handle)
        self.endpoint_id = bytes(endpoint_id)
        self.label = label
        self.kind = kind


class Delegation:
    def __init__(self, certificate: bytes, delegation_chain: bytes, root_public_key: bytes):
        self.certificate = bytes(certificate)
        self.delegation_chain = bytes(delegation_chain)
        self.root_public_key = bytes(root_public_key)


class DelegationSummary:
    def __init__(self, summary: api.DelegationSummary):
        self.root_public_key = bytes(summary.root_public_key)
        self.delegated_public_key = bytes(summary.delegated_public_key)
        self.depth = summary.depth
        self.sequence = summary.sequence
        self.expires_at_unix_ms = summary.expires_at_unix_ms
        self.capabilities = tuple(bytes(value) for value in summary.capabilities)


class Application:
    def __init__(self, client: "Client", handle: bytes, grants, resume_token: bytes):
        self._client = client
        self.handle = bytes(handle)
        self.grants = tuple(grants)
        self.resume_token = bytes(resume_token)

    async def connect(self, destination_hint: bytes, protocol_id: str, *, deadline_unix_ms: Optional[int] = None) -> "Session":
        request = api.ConnectRequest(
            application_handle=api.OpaqueHandle(self.handle),
            destination_hint=destination_hint,
            protocol_id=protocol_id,
        )
        response = await self._client.request_checked(
            "ApplicationService", "Connect", request.SerializeToString(), deadline_unix_ms=deadline_unix_ms
        )
        decoded = api.ConnectResponse.FromString(response.payload)
        if decoded.session_handle is None:
            raise UMCError("daemon returned no session handle")
        return Session(self, decoded.session_handle.value)

    async def connect_from_endpoint(self, local_endpoint: Endpoint, destination_hint: bytes, protocol_id: str, *, deadline_unix_ms: Optional[int] = None) -> "Session":
        request = api.ConnectRequest(
            application_handle=api.OpaqueHandle(self.handle),
            local_endpoint_id=local_endpoint.endpoint_id,
            destination_hint=destination_hint,
            protocol_id=protocol_id,
        )
        response = await self._client.request_checked(
            "ApplicationService", "Connect", request.SerializeToString(), deadline_unix_ms=deadline_unix_ms
        )
        decoded = api.ConnectResponse.FromString(response.payload)
        if decoded.session_handle is None:
            raise UMCError("daemon returned no session handle")
        return Session(self, decoded.session_handle.value)

    async def listen(self, protocol_id: str, *, endpoint_id: bytes = b"", deadline_unix_ms: Optional[int] = None) -> "Listener":
        request = api.OpenListenerRequest(
            application_handle=api.OpaqueHandle(self.handle),
            endpoint_id=endpoint_id,
            protocol_id=protocol_id,
        )
        response = await self._client.request_checked(
            "ApplicationService", "OpenListener", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.OpenListenerResponse.FromString(response.payload)
        if decoded.listener_handle is None:
            raise UMCError("daemon returned no listener handle")
        return Listener(self, decoded.listener_handle.value)

    async def accept_session(self, pending_session_handle: bytes, *, deadline_unix_ms: Optional[int] = None) -> "Session":
        request = api.AcceptIncomingSessionRequest(
            application_handle=api.OpaqueHandle(self.handle),
            pending_session_handle=api.OpaqueHandle(pending_session_handle),
        )
        response = await self._client.request_checked(
            "ApplicationService", "AcceptIncomingSession", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.AcceptIncomingSessionResponse.FromString(response.payload)
        if decoded.session_handle is None:
            raise UMCError("daemon returned no accepted session handle")
        return Session(self, decoded.session_handle.value)

    async def reject_session(
        self,
        pending_session_handle: bytes,
        application_error_code: int = 0,
        reason: str = "",
        *,
        deadline_unix_ms: Optional[int] = None,
    ) -> None:
        request = api.RejectIncomingSessionRequest(
            application_handle=api.OpaqueHandle(self.handle),
            pending_session_handle=api.OpaqueHandle(pending_session_handle),
            application_error_code=application_error_code,
            reason=reason,
        )
        await self._client.request_checked(
            "ApplicationService", "RejectIncomingSession", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )

    async def accept_stream(self, pending_stream_handle: bytes, *, deadline_unix_ms: Optional[int] = None) -> "Stream":
        request = api.AcceptStreamRequest(
            application_handle=api.OpaqueHandle(self.handle),
            pending_stream_handle=api.OpaqueHandle(pending_stream_handle),
        )
        response = await self._client.request_checked(
            "ApplicationService", "AcceptStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.AcceptStreamResponse.FromString(response.payload)
        if decoded.stream_handle is None:
            raise UMCError("daemon returned no accepted stream handle")
        return Stream(None, decoded.stream_handle.value, self)

    async def reject_stream(
        self,
        pending_stream_handle: bytes,
        application_error_code: int = 0,
        *,
        deadline_unix_ms: Optional[int] = None,
    ) -> None:
        request = api.RejectStreamRequest(
            pending_stream_handle=api.OpaqueHandle(pending_stream_handle),
            application_error_code=application_error_code,
        )
        await self._client.request_checked(
            "ApplicationService", "RejectStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )

    async def close(self, *, close_owned_sessions: bool = True, deadline_unix_ms: Optional[int] = None) -> None:
        request = api.UnregisterApplicationRequest(
            application_handle=api.OpaqueHandle(self.handle),
            close_owned_sessions=close_owned_sessions,
        )
        await self._client.request_checked(
            "ApplicationService", "UnregisterApplication", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )


class Session:
    def __init__(self, application: Application, handle: bytes):
        self.application = application
        self.handle = bytes(handle)

    async def open_stream(
        self, *, unidirectional: bool = False, initial_metadata: bytes = b"",
        deadline_unix_ms: Optional[int] = None,
    ) -> "Stream":
        request = api.OpenStreamRequest(
            application_handle=api.OpaqueHandle(self.application.handle),
            session_handle=api.OpaqueHandle(self.handle),
            unidirectional=unidirectional,
            initial_metadata=initial_metadata,
        )
        response = await self.application._client.request_checked(
            "ApplicationService", "OpenStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.OpenStreamResponse.FromString(response.payload)
        if decoded.stream_handle is None:
            raise UMCError("daemon returned no stream handle")
        return Stream(self, decoded.stream_handle.value)

    async def send_datagram(
        self, context_id: int, data: bytes, *, lifetime_ms: int = 0,
        request_ack: bool = False, deadline_unix_ms: Optional[int] = None,
    ) -> int:
        request = api.SendDatagramRequest(
            session_handle=api.OpaqueHandle(self.handle),
            context_id=context_id,
            data=data,
            lifetime_ms=lifetime_ms,
            request_ack=request_ack,
        )
        response = await self.application._client.request_checked(
            "ApplicationService", "SendDatagram", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        return api.SendDatagramResponse.FromString(response.payload).local_datagram_id

    async def receive_datagram(
        self, maximum_bytes: int = 256 * 1024, *, wait_for_data: bool = True,
        deadline_unix_ms: Optional[int] = None,
    ) -> Datagram:
        request = api.ReceiveDatagramRequest(
            application_handle=api.OpaqueHandle(self.application.handle),
            session_handle=api.OpaqueHandle(self.handle),
            maximum_bytes=maximum_bytes,
            wait_for_data=wait_for_data,
        )
        response = await self.application._client.request_checked(
            "ApplicationService", "ReceiveDatagram", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.ReceiveDatagramResponse.FromString(response.payload)
        if decoded.session_handle is None:
            raise UMCError("daemon returned no datagram session handle")
        return Datagram(decoded.session_handle.value, decoded.context_id, decoded.data, decoded.expired)


class Listener:
    def __init__(self, application: Application, handle: bytes):
        self.application = application
        self.handle = bytes(handle)

    async def close(self, *, close_owned_sessions: bool = False, deadline_unix_ms: Optional[int] = None) -> None:
        request = api.CloseListenerRequest(
            listener_handle=api.OpaqueHandle(self.handle),
            close_owned_sessions=close_owned_sessions,
        )
        await self.application._client.request_checked(
            "ApplicationService", "CloseListener", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )


class Stream:
    def __init__(self, session: Optional[Session], handle: bytes, application: Optional[Application] = None):
        self.session = session
        self.application = application or session.application
        self.handle = bytes(handle)

    async def write(self, data: bytes, *, fin: bool = False, deadline_unix_ms: Optional[int] = None) -> StreamWriteResult:
        request = api.WriteStreamRequest(
            stream_handle=api.OpaqueHandle(self.handle), data=data, fin=fin
        )
        response = await self.application._client.request_checked(
            "ApplicationService", "WriteStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.WriteStreamResponse.FromString(response.payload)
        return StreamWriteResult(decoded.accepted_bytes, decoded.fin_accepted)

    async def read(
        self, maximum_bytes: int = 64 * 1024, *, wait_for_data: bool = True,
        deadline_unix_ms: Optional[int] = None,
    ) -> StreamReadResult:
        request = api.ReadStreamRequest(
            stream_handle=api.OpaqueHandle(self.handle),
            maximum_bytes=maximum_bytes,
            wait_for_data=wait_for_data,
        )
        response = await self.application._client.request_checked(
            "ApplicationService", "ReadStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        decoded = api.ReadStreamResponse.FromString(response.payload)
        return StreamReadResult(decoded.data, decoded.eof, decoded.reset, decoded.application_error_code)

    async def close_send(self, *, deadline_unix_ms: Optional[int] = None) -> None:
        request = api.CloseStreamSendRequest(stream_handle=api.OpaqueHandle(self.handle))
        await self.application._client.request_checked(
            "ApplicationService", "CloseStreamSend", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )

    async def reset(self, application_error_code: int = 0, *, deadline_unix_ms: Optional[int] = None) -> None:
        request = api.ResetStreamRequest(
            stream_handle=api.OpaqueHandle(self.handle),
            application_error_code=application_error_code,
        )
        await self.application._client.request_checked(
            "ApplicationService", "ResetStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )

    async def stop(self, application_error_code: int = 0, *, deadline_unix_ms: Optional[int] = None) -> None:
        request = api.StopStreamRequest(
            stream_handle=api.OpaqueHandle(self.handle),
            application_error_code=application_error_code,
        )
        await self.application._client.request_checked(
            "ApplicationService", "StopStream", request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )


class _StreamTransport:
    """Small transport adapter shared by asyncio streams and named pipes."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    async def sendall(self, payload: bytes) -> None:
        self._writer.write(payload)
        await self._writer.drain()

    async def recv_exactly(self, size: int) -> bytes:
        return await self._reader.readexactly(size)

    async def close(self) -> None:
        if not self._writer.is_closing():
            self._writer.close()
            await self._writer.wait_closed()


if os.name == "nt":
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _ERROR_PIPE_BUSY = 231
    _KERNEL32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _KERNEL32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _KERNEL32.ReadFile.restype = wintypes.BOOL
    _KERNEL32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _KERNEL32.WriteFile.restype = wintypes.BOOL
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL


class _NamedPipeTransport:
    """Async adapter for a byte-mode Windows named-pipe handle.

    The daemon uses Tokio's byte-mode named pipe, so this deliberately uses
    the raw Win32 ReadFile/WriteFile calls rather than multiprocessing's
    message-oriented authentication protocol.
    """

    def __init__(self, handle):
        self._handle = handle
        self._closed = False

    def _write(self, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = ctypes.c_ulong(0)
            chunk = payload[offset:]
            buffer = ctypes.create_string_buffer(chunk)
            ok = _KERNEL32.WriteFile(
                self._handle, buffer, len(chunk), ctypes.byref(written), None
            )
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            if written.value == 0:
                raise OSError("named pipe write made no progress")
            offset += written.value

    def _read_exactly(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk_size = size - len(result)
            buffer = ctypes.create_string_buffer(chunk_size)
            read = ctypes.c_ulong(0)
            ok = _KERNEL32.ReadFile(
                self._handle, buffer, chunk_size, ctypes.byref(read), None
            )
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            if read.value == 0:
                raise EOFError("named pipe closed")
            result.extend(buffer.raw[: read.value])
        return bytes(result)

    async def sendall(self, payload: bytes) -> None:
        if self._closed:
            raise ConnectionError("named pipe is closed")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._write, payload)

    async def recv_exactly(self, size: int) -> bytes:
        if self._closed:
            raise ConnectionError("named pipe is closed")
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_exactly, size)

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _KERNEL32.CloseHandle, self._handle)


def _open_named_pipe_sync(endpoint: str):
    if os.name != "nt":
        raise OSError("Windows named pipes are only available on Windows")
    handle = _KERNEL32.CreateFileW(
        endpoint,
        _GENERIC_READ | _GENERIC_WRITE,
        0,
        None,
        _OPEN_EXISTING,
        0,
        None,
    )
    handle_value = handle.value if hasattr(handle, "value") else handle
    if handle_value == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error == _ERROR_PIPE_BUSY:
            raise TimeoutError("UMC control pipe is busy")
        raise ctypes.WinError(error)
    return _NamedPipeTransport(handle)


async def _open_named_pipe(endpoint: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _open_named_pipe_sync, endpoint)


async def _open_transport(endpoint: str):
    if os.name == "nt" and endpoint.lower().startswith("\\\\.\\pipe\\"):
        return await _open_named_pipe(endpoint)
    reader, writer = await asyncio.open_unix_connection(endpoint)
    return _StreamTransport(reader, writer)


class Client:
    """Connected UMC client.

    Use ``await Client.connect(path)`` and close it with ``await close()`` or
    an async context manager. Requests return decoded ``Response`` objects;
    ``request_checked`` raises :class:`StatusError` for non-OK responses.
    """

    def __init__(self, transport):
        self._transport = transport
        self._request_lock = asyncio.Lock()
        self._sequence = 1
        self._request_id = 0
        self.envelope_max = MAX_ENVELOPE

    @classmethod
    async def connect(cls, socket_path: str, client_name: str = "umc-python") -> "Client":
        """Connect to a Unix socket or Windows ``\\\\.\\pipe\\`` endpoint."""
        client = cls(await _open_transport(socket_path))
        hello = api.Envelope(
            api_version=api.ApiVersion(major=1, minor=0),
            sequence=client._next_sequence(),
            client_hello=api.ClientHello(
                supported_versions=[api.ApiVersion(major=1, minor=0)],
                client_name=client_name,
            ),
        )
        await client._send(hello)
        reply = await client._receive()
        if reply.server_hello is None or reply.server_hello.selected_version is None:
            await client.close()
            raise UMCError("control API hello was not accepted")
        if reply.server_hello.selected_version.major != 1:
            await client.close()
            raise UMCError("unsupported control API version")
        negotiated = reply.server_hello.negotiated_envelope_size
        if negotiated:
            client.envelope_max = min(MAX_ENVELOPE, max(1024, negotiated))
        return client

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    def _next_sequence(self) -> int:
        sequence = self._sequence
        self._sequence += 1
        return sequence

    async def _send(self, envelope: api.Envelope) -> None:
        payload = envelope.SerializeToString()
        if not payload or len(payload) > self.envelope_max:
            raise FramingError("invalid envelope size")
        await self._transport.sendall(struct.pack(">I", len(payload)) + payload)

    async def _receive(self) -> api.Envelope:
        prefix = await self._transport.recv_exactly(4)
        length = struct.unpack(">I", prefix)[0]
        if length == 0 or length > self.envelope_max:
            raise FramingError("invalid envelope length")
        payload = await self._transport.recv_exactly(length)
        try:
            return api.Envelope.FromString(payload)
        except ValueError as exc:
            raise FramingError(str(exc)) from exc

    async def request(
        self,
        service: str,
        method: str,
        payload: bytes = b"",
        *,
        deadline_unix_ms: Optional[int] = None,
        idempotency_key: bytes = b"",
    ) -> api.Response:
        async with self._request_lock:
            self._request_id += 1
            request_id = self._request_id
            request = api.Request(
                request_id=request_id,
                service=service,
                method=method,
                deadline_unix_ms=deadline_unix_ms or 0,
                idempotency_key=idempotency_key,
                payload=payload,
            )
            await self._send(
                api.Envelope(
                    api_version=api.ApiVersion(major=1, minor=0),
                    sequence=self._next_sequence(),
                    request=request,
                )
            )
            while True:
                reply = await self._receive()
                if reply.response is not None and reply.response.request_id == request_id:
                    return reply.response

    async def request_checked(self, *args, **kwargs) -> api.Response:
        response = await self.request(*args, **kwargs)
        if response.status is not None and response.status.code != api.StatusCode.OK:
            raise StatusError(response.status)
        return response

    async def register_application(
        self,
        application_name: str,
        protocol_ids: list[str],
        *,
        application_instance_id: bytes = b"",
        resumable: bool = False,
    ) -> Application:
        request = api.RegisterApplicationRequest(
            application_name=application_name,
            application_instance_id=application_instance_id,
            requested_protocol_ids=protocol_ids,
            resumable=resumable,
        )
        response = await self.request_checked(
            "ApplicationService", "RegisterApplication", request.SerializeToString()
        )
        decoded = api.RegisterApplicationResponse.FromString(response.payload)
        if decoded.application_handle is None:
            raise UMCError("daemon returned no application handle")
        return Application(self, decoded.application_handle.value, decoded.effective_grants, decoded.resume_token)

    async def list_endpoints(self, *, deadline_unix_ms: Optional[int] = None) -> list[Endpoint]:
        response = await self.request_checked(
            "IdentityService", "ListIdentities", api.ListIdentitiesRequest().SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        listed = api.ListIdentitiesResponse.FromString(response.payload)
        return [
            Endpoint(self, item.identity_handle.value, item.endpoint_id, item.label, item.kind)
            for item in listed.identities
            if item.identity_handle is not None
        ]

    async def create_delegation(
        self, identity_handle: bytes, delegated_public_key: bytes, allowed_capabilities: list[bytes],
        root_capabilities: list[bytes], expires_at_unix_ms: int, *, deadline_unix_ms: Optional[int] = None,
    ) -> Delegation:
        request = api.CreateDelegationRequest(
            identity_handle=api.OpaqueHandle(identity_handle),
            delegated_public_key=delegated_public_key,
            allowed_capabilities=allowed_capabilities,
            expires_at_unix_ms=expires_at_unix_ms,
            root_capabilities=root_capabilities,
        )
        response = await self.request_checked(
            "IdentityService", "CreateDelegation", request.SerializeToString(), deadline_unix_ms=deadline_unix_ms,
        )
        created = api.CreateDelegationResponse.FromString(response.payload)
        return Delegation(created.certificate, created.delegation_chain, created.root_public_key)

    async def import_delegation(
        self, root_public_key: bytes, root_capabilities: list[bytes], delegation_chain: bytes, *, deadline_unix_ms: Optional[int] = None,
    ) -> bytes:
        request = api.ImportDelegationRequest(
            root_public_key=root_public_key, root_capabilities=root_capabilities, delegation_chain=delegation_chain,
        )
        response = await self.request_checked(
            "IdentityService", "ImportDelegation", request.SerializeToString(), deadline_unix_ms=deadline_unix_ms,
        )
        return api.ImportDelegationResponse.FromString(response.payload).delegated_public_key

    async def list_delegations(self, *, deadline_unix_ms: Optional[int] = None) -> list[DelegationSummary]:
        response = await self.request_checked(
            "IdentityService", "ListDelegations", api.ListDelegationsRequest().SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        return [DelegationSummary(item) for item in api.ListDelegationsResponse.FromString(response.payload).delegations]

    async def revoke_delegation(
        self, identity_handle: bytes, delegated_public_key: bytes, sequence: int, expires_at_unix_ms: int,
        reason: str = "", *, deadline_unix_ms: Optional[int] = None,
    ) -> None:
        request = api.RevokeDelegationRequest(
            identity_handle=api.OpaqueHandle(identity_handle), delegated_public_key=delegated_public_key,
            sequence=sequence, expires_at_unix_ms=expires_at_unix_ms, reason=reason,
        )
        await self.request_checked(
            "IdentityService", "RevokeDelegation", request.SerializeToString(), deadline_unix_ms=deadline_unix_ms,
        )

    async def list_discovery_candidates(self, *, deadline_unix_ms: Optional[int] = None):
        """List bounded, non-secret discovery candidates known to the daemon."""
        response = await self.request_checked(
            "DiscoveryService",
            "ListCandidates",
            api.ListCandidatesRequest().SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        return api.ListCandidatesResponse.FromString(response.payload).candidates

    async def publish_service_hint(
        self,
        protocol_id: str,
        endpoint_hint: bytes,
        metadata: bytes = b"",
        expires_at_unix_ms: int = 0,
        public: bool = True,
        *,
        deadline_unix_ms: Optional[int] = None,
    ):
        """Publish one bounded opaque application service hint."""
        request = api.PublishServiceHintRequest(
            protocol_id=protocol_id,
            endpoint_hint=endpoint_hint,
            metadata=metadata,
            expires_at_unix_ms=expires_at_unix_ms,
            public=public,
        )
        response = await self.request_checked(
            "DiscoveryService",
            "PublishServiceHint",
            request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        return api.PublishServiceHintResponse.FromString(response.payload).hint

    async def discover_services(
        self,
        protocol_id: str = "",
        *,
        deadline_unix_ms: Optional[int] = None,
    ):
        """Discover active public hints, optionally filtered by protocol."""
        request = api.DiscoverServicesRequest(protocol_id=protocol_id)
        response = await self.request_checked(
            "DiscoveryService",
            "DiscoverServices",
            request.SerializeToString(),
            deadline_unix_ms=deadline_unix_ms,
        )
        return api.DiscoverServicesResponse.FromString(response.payload).hints

    async def get_status(self) -> bytes:
        return (await self.request_checked("NodeAdmin", "GetStatus")).payload

    async def get_config(self, keys: bytes = b"") -> bytes:
        return (await self.request_checked("NodeAdmin", "GetConfig", keys)).payload

    async def get_events(self) -> bytes:
        return (await self.request_checked("NodeAdmin", "GetEvents")).payload

    async def close(self) -> None:
        await self._transport.close()


__all__ = [
    "Application",
    "Client",
    "Delegation",
    "DelegationSummary",
    "Datagram",
    "Endpoint",
    "FramingError",
    "Listener",
    "Session",
    "StatusError",
    "Stream",
    "UMCError",
]
