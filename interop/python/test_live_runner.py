import hashlib
import hmac
import unittest

from live_runner import (
    build_client_hello,
    datagram_frame,
    hmac_blake2s,
    parse_client_hello,
    stream_frame,
)


class LiveRunnerEncodingTests(unittest.TestCase):
    def test_client_hello_round_trip(self):
        hello = build_client_hello(
            client_random=bytes(range(32)),
            client_ephemeral_public_key=bytes(range(32, 64)),
            supported_versions=[1],
        )
        parsed = parse_client_hello(hello)
        self.assertEqual(parsed["client_random"], bytes(range(32)))
        self.assertEqual(parsed["client_ephemeral_public_key"], bytes(range(32, 64)))
        self.assertEqual(parsed["supported_protocol_versions"], [1])
        self.assertEqual(parsed["minimum_privacy"], b"p0")

    def test_stream_and_datagram_frames_are_canonical(self):
        stream = stream_frame(0, b"hello", fin=True, protocol_id=b"org.umc.app/1")
        self.assertEqual(stream[:1], b"\x10")
        self.assertIn(b"hello", stream)
        datagram = datagram_frame(b"ping", context_id=7)
        self.assertEqual(datagram[:1], b"\x28")
        self.assertIn(b"ping", datagram)

    def test_finished_mac_uses_rfc2104_hmac_blake2s(self):
        key = bytes(range(32))
        transcript = bytes(range(32, 64))
        self.assertEqual(
            hmac_blake2s(key, transcript),
            hmac.new(key, transcript, hashlib.blake2s).digest(),
        )


if __name__ == "__main__":
    unittest.main()
