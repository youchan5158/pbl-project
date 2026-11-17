import io
import struct
import unittest

from lab.integration_stream import Reader, exit_code, send_frame
from lab.integration_live import execution_errors
from lab.integration_scenarios import definitions


class Socket:
    def __init__(self, data=b""):
        self.input, self.output = io.BytesIO(data), b""

    def recv(self, count):
        return self.input.read(min(count, 3))  # fragmented network delivery

    def settimeout(self, _):
        pass

    def sendall(self, data):
        self.output += data


class StreamingEvidenceTests(unittest.TestCase):
    def test_frame_lengths_and_fragmented_delivery(self):
        payload = b"x" * 180
        frame = b"\x82\x7e" + struct.pack("!H", len(payload)) + payload
        self.assertEqual(Reader(Socket(frame)).frame(), (True, 2, payload))
        with self.assertRaises(EOFError):
            Reader(Socket(frame[:-1])).frame()

    def test_server_masking_rejected_and_client_masked(self):
        with self.assertRaises(ValueError):
            Reader(Socket(b"\x82\x80")).frame()
        sock = Socket()
        send_frame(sock, 10, b"ping")
        mask = sock.output[2:6]
        self.assertEqual(sock.output[:2], b"\x8a\x84")
        self.assertEqual(bytes(c ^ mask[i % 4] for i, c in enumerate(sock.output[6:])), b"ping")

    def test_exit_status_must_be_explicit(self):
        self.assertEqual(exit_code({"status": "Success"}), 0)
        self.assertEqual(exit_code({"status": "Failure", "reason": "NonZeroExitCode",
            "details": {"causes": [{"reason": "ExitCode", "message": "7"}]}}), 7)
        self.assertIsNone(exit_code({}))
        self.assertIsNone(exit_code({"status": "Failure", "reason": "InternalError"}))

    def test_http_upgrade_without_execution_is_invalid(self):
        case = next(c for c in definitions() if c["id"] == "X01")
        proof = {"exec": {"http_code": 101, "closed": True}, "pod": {}}
        self.assertIn("exec_success_not_proven", execution_errors(case, proof))
        self.assertIn("container_running_not_proven", execution_errors(case, proof))

    def test_permission_change_requires_real_object_and_identity(self):
        case = next(c for c in definitions() if c["id"] == "R02")
        self.assertIn("permission_effect_not_proven", execution_errors(case,
            {"codes": [403, 201, 200], "same_subject_credential": True, "object_verified": False}))


if __name__ == "__main__":
    unittest.main()
