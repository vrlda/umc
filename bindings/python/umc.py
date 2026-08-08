"""Pure-stdlib asynchronous client for the UMC local Control API."""

from __future__ import annotations

import asyncio
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


class Client:
    """Connected UMC client.

    Use ``await Client.connect(path)`` and close it with ``await close()`` or
    an async context manager. Requests return decoded ``Response`` objects;
    ``request_checked`` raises :class:`StatusError` for non-OK responses.
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._sequence = 1
        self._request_id = 0
        self.envelope_max = MAX_ENVELOPE

    @classmethod
    async def connect(cls, socket_path: str, client_name: str = "umc-python") -> "Client":
        reader, writer = await asyncio.open_unix_connection(socket_path)
        client = cls(reader, writer)
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
        self._writer.write(struct.pack(">I", len(payload)) + payload)
        await self._writer.drain()

    async def _receive(self) -> api.Envelope:
        prefix = await self._reader.readexactly(4)
        length = struct.unpack(">I", prefix)[0]
        if length == 0 or length > self.envelope_max:
            raise FramingError("invalid envelope length")
        payload = await self._reader.readexactly(length)
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
        self._request_id += 1
        request = api.Request(
            request_id=self._request_id,
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
            if reply.response is not None and reply.response.request_id in (0, self._request_id):
                return reply.response

    async def request_checked(self, *args, **kwargs) -> api.Response:
        response = await self.request(*args, **kwargs)
        if response.status is not None and response.status.code != api.StatusCode.OK:
            raise StatusError(response.status)
        return response

    async def get_status(self) -> bytes:
        return (await self.request_checked("NodeAdmin", "GetStatus")).payload

    async def get_config(self, keys: bytes = b"") -> bytes:
        return (await self.request_checked("NodeAdmin", "GetConfig", keys)).payload

    async def get_events(self) -> bytes:
        return (await self.request_checked("NodeAdmin", "GetEvents")).payload

    async def close(self) -> None:
        if not self._writer.is_closing():
            self._writer.close()
            await self._writer.wait_closed()


__all__ = ["Client", "FramingError", "StatusError", "UMCError"]
