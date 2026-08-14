import asyncio
import os
import tempfile
import unittest
from unittest import mock

from bindings.python import umc_pb2 as api
from bindings.python import umc
from bindings.python.umc import Client


class ClientTest(unittest.TestCase):
    def test_hello_and_request_round_trip(self):
        asyncio.run(self._round_trip())

    async def _round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "umc.sock")

            async def serve(reader, writer):
                async def receive():
                    length = int.from_bytes(await reader.readexactly(4), "big")
                    return api.Envelope.FromString(await reader.readexactly(length))

                async def send(envelope):
                    payload = envelope.SerializeToString()
                    writer.write(len(payload).to_bytes(4, "big") + payload)
                    await writer.drain()

                hello = await receive()
                self.assertEqual(hello.client_hello.client_name, "test")
                server_hello = api.ServerHello()
                server_hello.selected_version = api.ApiVersion(1, 0)
                await send(
                    api.Envelope(
                        api_version=api.ApiVersion(1, 0),
                        sequence=2,
                        server_hello=server_hello,
                    )
                )
                request = await receive()
                self.assertEqual(request.request.service, "NodeAdmin")
                await send(
                    api.Envelope(
                        sequence=3,
                        response=api.Response(
                            request_id=request.request.request_id,
                            status=api.Status(),
                            payload=b"ok",
                        ),
                    )
                )
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_unix_server(serve, path=socket_path)
            async with server:
                async with await Client.connect(socket_path, "test") as client:
                    response = await client.request("NodeAdmin", "GetStatus")
                    self.assertEqual(response.payload, b"ok")
            server.close()
            await server.wait_closed()

    def test_named_pipe_endpoint_uses_named_pipe_transport(self):
        asyncio.run(self._named_pipe_transport_selection())

    async def _named_pipe_transport_selection(self):
        transport = _MemoryTransport()
        transport.queue(_server_hello())
        opened = []

        async def open_pipe(endpoint):
            opened.append(endpoint)
            return transport

        with mock.patch.object(umc.os, "name", "nt"), mock.patch.object(
            umc, "_open_named_pipe", new=open_pipe
        ) as open_pipe_mock:
            client = await Client.connect(r"\\.\pipe\umc", "test")
            self.assertEqual(opened, [r"\\.\pipe\umc"])
            await client.close()

    def test_high_level_application_stream_and_datagram_surface(self):
        asyncio.run(self._high_level_round_trip())

    def test_discovery_candidate_listing_surface(self):
        asyncio.run(self._discovery_round_trip())

    def test_service_hint_publish_and_discover_surface(self):
        asyncio.run(self._service_hint_round_trip())

    def test_inbound_accept_reject_and_datagram_receive_surface(self):
        asyncio.run(self._inbound_round_trip())

    def test_python_delegation_and_endpoint_selection_surface(self):
        asyncio.run(self._delegation_round_trip())

    async def _delegation_round_trip(self):
        transport = _MemoryTransport()
        client = Client(transport)
        endpoint_summary = api.IdentitySummary()
        endpoint_summary.identity_handle = api.OpaqueHandle(b"node-identity")
        endpoint_summary.endpoint_id = b"e" * 32
        endpoint_summary.label = "primary"
        identities = api.ListIdentitiesResponse()
        identities.identities.append(endpoint_summary)
        transport.queue(api.Envelope(response=api.Response(
            request_id=1, status=api.Status(), payload=identities.SerializeToString(),
        )))
        endpoints = await client.list_endpoints()
        self.assertEqual(endpoints[0].endpoint_id, b"e" * 32)

        transport.queue(api.Envelope(response=api.Response(
            request_id=2, status=api.Status(), payload=_delegation_payload(),
        )))
        delegation = await client.create_delegation(
            b"node-identity", b"d" * 32, [b"chat"], [b"chat"], 1234,
        )
        self.assertEqual(delegation.delegation_chain, b"chain")

        transport.queue(api.Envelope(response=api.Response(
            request_id=3, status=api.Status(), payload=_bytes_field(1, b"d" * 32),
        )))
        self.assertEqual(await client.import_delegation(b"r" * 32, [b"chat"], b"chain"), b"d" * 32)

        summaries = api.ListDelegationsResponse()
        summary = api.DelegationSummary()
        summary.delegated_public_key = b"d" * 32
        summaries.delegations.append(summary)
        transport.queue(api.Envelope(response=api.Response(
            request_id=4, status=api.Status(), payload=summaries.SerializeToString(),
        )))
        self.assertEqual((await client.list_delegations())[0].delegated_public_key, b"d" * 32)

        transport.queue(api.Envelope(response=api.Response(
            request_id=5, status=api.Status(), payload=b"",
        )))
        await client.revoke_delegation(b"node-identity", b"d" * 32, 1, 1234, "retired")

        app = umc.Application(client, b"app", [], b"")
        transport.queue(api.Envelope(response=api.Response(
            request_id=6, status=api.Status(), payload=_handle_payload(b"session"),
        )))
        await app.connect_from_endpoint(endpoints[0], b"destination", "org.example.chat/1")
        self.assertEqual(api.ConnectRequest.FromString(_request_payload(transport.sent[-1])).local_endpoint_id, b"e" * 32)

    async def _inbound_round_trip(self):
        transport = _MemoryTransport()
        client = Client(transport)
        app = umc.Application(client, b"app", [], b"")
        transport.queue(api.Envelope(response=api.Response(
            request_id=1, status=api.Status(),
            payload=_handle_payload(b"accepted-session"),
        )))
        accepted = await app.accept_session(b"pending")
        self.assertEqual(accepted.handle, b"accepted-session")

        transport.queue(api.Envelope(response=api.Response(
            request_id=2, status=api.Status(), payload=b"",
        )))
        await app.reject_session(b"pending", 9, "busy", deadline_unix_ms=123)

        transport.queue(api.Envelope(response=api.Response(
            request_id=3, status=api.Status(),
            payload=_handle_payload(b"accepted-stream"),
        )))
        stream = await app.accept_stream(b"pending-stream")
        self.assertEqual(stream.handle, b"accepted-stream")

        transport.queue(api.Envelope(response=api.Response(
            request_id=4, status=api.Status(), payload=b"",
        )))
        await app.reject_stream(b"pending-stream", 10)

        transport.queue(api.Envelope(response=api.Response(
            request_id=5, status=api.Status(),
            payload=_handle_payload(b"session") + _varint_field(2, 4) + _bytes_field(3, b"ping"),
        )))
        datagram = await umc.Session(app, b"session").receive_datagram(64, wait_for_data=False)
        self.assertEqual(datagram.data, b"ping")
        self.assertEqual(datagram.context_id, 4)

    async def _discovery_round_trip(self):
        transport = _MemoryTransport()
        transport.queue(_server_hello())
        client = Client(transport)
        await client._receive()
        candidate = api.CandidateSummary(7, "ump.tcp/1", 123, True)
        payload = api.ListCandidatesResponse()
        payload.candidates.append(candidate)
        payload.total = 1
        response = api.Envelope(
            response=api.Response(request_id=1, status=api.Status(), payload=payload.SerializeToString())
        )
        transport.queue(response)
        listed = await client.list_discovery_candidates()
        self.assertEqual(listed[0].candidate_id, 7)
        self.assertEqual(listed[0].carrier_type, "ump.tcp/1")

    async def _service_hint_round_trip(self):
        transport = _MemoryTransport()
        transport.queue(_server_hello())
        client = Client(transport)
        await client._receive()
        hint = api.ServiceHintSummary(
            peer_endpoint_id=b"e" * 32,
            protocol_id="org.example.chat/1",
            endpoint_hint=b"chat.example.invalid",
            metadata=b'{"region":"test"}',
            expires_at_unix_ms=1_700_000_000_000,
            signature=b"s" * 64,
            public=True,
        )
        transport.queue(api.Envelope(response=api.Response(
            request_id=1,
            status=api.Status(),
            payload=api.PublishServiceHintResponse(hint=hint).SerializeToString(),
        )))
        published = await client.publish_service_hint(
            "org.example.chat/1",
            b"chat.example.invalid",
            b'{"region":"test"}',
            1_700_000_000_000,
            True,
        )
        self.assertEqual(published.protocol_id, "org.example.chat/1")
        self.assertEqual(published.signature, b"s" * 64)
        sent_publish = api.PublishServiceHintRequest.FromString(_request_payload(transport.sent[-1]))
        self.assertEqual(sent_publish.endpoint_hint, b"chat.example.invalid")

        transport.queue(api.Envelope(response=api.Response(
            request_id=2,
            status=api.Status(),
            payload=api.DiscoverServicesResponse(hints=[hint]).SerializeToString(),
        )))
        discovered = await client.discover_services("org.example.chat/1")
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].peer_endpoint_id, b"e" * 32)
        sent_discover = api.DiscoverServicesRequest.FromString(_request_payload(transport.sent[-1]))
        self.assertEqual(sent_discover.protocol_id, "org.example.chat/1")

    async def _high_level_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, "umc.sock")
            requests = []

            async def serve(reader, writer):
                async def receive():
                    length = int.from_bytes(await reader.readexactly(4), "big")
                    return api.Envelope.FromString(await reader.readexactly(length))

                async def send(envelope):
                    payload = envelope.SerializeToString()
                    writer.write(len(payload).to_bytes(4, "big") + payload)
                    await writer.drain()

                await receive()
                hello = api.ServerHello()
                hello.selected_version = api.ApiVersion(1, 0)
                await send(api.Envelope(sequence=2, server_hello=hello))
                for _ in range(5):
                    envelope = await receive()
                    requests.append(envelope.request)
                    method = envelope.request.method
                    if method == "RegisterApplication":
                        payload = _handle_payload(b"app")
                    elif method == "Connect":
                        payload = _handle_payload(b"session")
                    elif method == "OpenStream":
                        payload = _handle_payload(b"stream")
                    elif method == "WriteStream":
                        payload = _varint_field(1, len(b"hello")) + _varint_field(2, 1)
                    elif method == "SendDatagram":
                        payload = _varint_field(1, 7)
                    else:
                        raise AssertionError(method)
                    await send(api.Envelope(sequence=3 + len(requests), response=api.Response(
                        request_id=envelope.request.request_id,
                        status=api.Status(),
                        payload=payload,
                    )))

            server = await asyncio.start_unix_server(serve, path=socket_path)
            async with server:
                async with await Client.connect(socket_path, "test") as client:
                    app = await client.register_application("chat", ["org.example.chat/1"])
                    session = await app.connect(b"destination", "org.example.chat/1")
                    stream = await session.open_stream()
                    result = await stream.write(b"hello", fin=True)
                    datagram_id = await session.send_datagram(3, b"ping", request_ack=True)
                    self.assertEqual(result.accepted_bytes, 5)
                    self.assertTrue(result.fin_accepted)
                    self.assertEqual(datagram_id, 7)
            server.close()
            await server.wait_closed()
            self.assertEqual(
                [request.method for request in requests],
                ["RegisterApplication", "Connect", "OpenStream", "WriteStream", "SendDatagram"],
            )


def _server_hello():
    server_hello = api.ServerHello()
    server_hello.selected_version = api.ApiVersion(1, 0)
    return api.Envelope(
        api_version=api.ApiVersion(1, 0),
        sequence=2,
        server_hello=server_hello,
    )


class _MemoryTransport:
    def __init__(self):
        self.incoming = []
        self.sent = []

    def queue(self, envelope):
        payload = envelope.SerializeToString()
        self.incoming.append(len(payload).to_bytes(4, "big") + payload)

    async def sendall(self, payload):
        self.sent.append(payload)

    async def recv_exactly(self, size):
        while not self.incoming:
            await asyncio.sleep(0)
        payload = self.incoming[0]
        result, remainder = payload[:size], payload[size:]
        if remainder:
            self.incoming[0] = remainder
        else:
            self.incoming.pop(0)
        return result

    async def close(self):
        return None


def _varint_field(number, value):
    out = bytearray()
    out.extend(umc_pb_tag(number, 0))
    out.extend(umc_varint(value))
    return bytes(out)


def _bytes_field(number, value):
    return umc_pb_tag(number, 2) + umc_varint(len(value)) + value


def _handle_payload(value):
    return umc_pb_tag(1, 2) + umc_varint(len(value) + 2) + umc_pb_tag(1, 2) + umc_varint(len(value)) + value


def _delegation_payload():
    return _bytes_field(1, b"cert") + _bytes_field(2, b"chain") + _bytes_field(3, b"r" * 32)


def _request_payload(framed):
    length = int.from_bytes(framed[:4], "big")
    return api.Envelope.FromString(framed[4:4 + length]).request.payload


def umc_varint(value):
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def umc_pb_tag(number, wire):
    return umc_varint((number << 3) | wire)


if __name__ == "__main__":
    unittest.main()
