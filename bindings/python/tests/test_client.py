import asyncio
import os
import tempfile
import unittest

from bindings.python import umc_pb2 as api
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


if __name__ == "__main__":
    unittest.main()
