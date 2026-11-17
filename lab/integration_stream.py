"""Small bounded Kubernetes WebSocket exec client (no interactive stdin).

Implements RFC 6455 framing and Kubernetes v4/v5 channel exit status. TLS is
verified using the lab API client's CA. Never treats HTTP 101 alone as success.
References: kubernetes/client-go tools/remotecommand/{websocket,v4}.go.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import time
import uuid
from urllib.parse import urlsplit

LIMIT = 1024 * 1024


def exit_code(status):
    if status.get("status") == "Success":
        return 0
    if status.get("reason") == "NonZeroExitCode":
        for cause in status.get("details", {}).get("causes", []):
            if cause.get("reason") == "ExitCode":
                value = int(cause["message"])
                if 0 <= value <= 255:
                    return value
    return None


def send_frame(sock, opcode, payload=b""):
    if len(payload) > 125:
        raise ValueError("only short client control frames are supported")
    mask = os.urandom(4)
    sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask +
                 bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


class Reader:
    def __init__(self, sock, initial=b"", deadline=None):
        self.sock, self.buffer = sock, initial
        self.deadline = deadline or time.monotonic() + 60

    def read(self, count):
        while len(self.buffer) < count:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("exec stream deadline exceeded")
            self.sock.settimeout(remaining)
            part = self.sock.recv(min(65536, count - len(self.buffer)))
            if not part:
                raise EOFError("exec stream disconnected before close")
            self.buffer += part
        value, self.buffer = self.buffer[:count], self.buffer[count:]
        return value

    def frame(self):
        a, b = self.read(2)
        if a & 0x70 or b & 0x80:
            raise ValueError("unsupported masked/compressed server frame")
        size = b & 127
        if size == 126:
            size = struct.unpack("!H", self.read(2))[0]
        elif size == 127:
            size = struct.unpack("!Q", self.read(8))[0]
        opcode = a & 15
        if size > LIMIT or (opcode >= 8 and (size > 125 or not a & 0x80)):
            raise ValueError("invalid/oversized WebSocket frame")
        return bool(a & 0x80), opcode, self.read(size)


def execute(api, path, timeout=60):
    parsed = urlsplit(api.server)
    if not path.startswith("/api/v1/namespaces/") or "/exec?" not in path or "\r" in path or "\n" in path:
        raise ValueError("only lab Pod exec paths are supported")
    nonce = base64.b64encode(os.urandom(16)).decode()
    correlation = "auditguard-integration/1.0 request/" + str(uuid.uuid4())
    headers = ["GET " + path + " HTTP/1.1", "Host: " + parsed.netloc,
               "User-Agent: " + correlation, "Connection: Upgrade", "Upgrade: websocket",
               "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: " + nonce,
               "Sec-WebSocket-Protocol: v5.channel.k8s.io, v4.channel.k8s.io"]
    if api.token:
        headers.append("Authorization: Bearer " + api.token)
    result = {"http_code": None, "audit_id": "", "stdout": "", "stderr": "", "exit_code": None,
              "protocol": "", "closed": False, "status": None, "correlation_user_agent": correlation,
              "response_audit_id": ""}
    deadline = time.monotonic() + timeout
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as raw:
        with api.context.wrap_socket(raw, server_hostname=parsed.hostname) as sock:
            sock.settimeout(timeout)
            sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            received = b""
            while b"\r\n\r\n" not in received:
                part = sock.recv(8192)
                if not part or len(received) > 65536:
                    raise ValueError("invalid WebSocket upgrade response")
                received += part
            head, rest = received.split(b"\r\n\r\n", 1)
            lines = head.decode("iso-8859-1").split("\r\n")
            code = int(lines[0].split()[1])
            fields = {k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:])}
            result.update(http_code=code, audit_id=fields.get("audit-id", ""))
            result["response_audit_id"] = result["audit_id"]
            if code != 101:
                return result
            expected = base64.b64encode(hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            protocol = fields.get("sec-websocket-protocol", "")
            if fields.get("sec-websocket-accept") != expected or protocol not in {"v4.channel.k8s.io", "v5.channel.k8s.io"}:
                raise ValueError("invalid exec WebSocket negotiation")
            result["protocol"] = protocol
            reader = Reader(sock, rest, deadline)
            channels, fragmented, total = {1: bytearray(), 2: bytearray(), 3: bytearray()}, None, 0
            while True:
                final, opcode, payload = reader.frame()
                total += len(payload)
                if total > LIMIT:
                    raise ValueError("exec output limit exceeded")
                if opcode == 8:
                    result["closed"] = True
                    send_frame(sock, 8, payload)
                    break
                if opcode == 9:
                    send_frame(sock, 10, payload)
                    continue
                if opcode == 10:
                    continue
                if opcode == 2:
                    if fragmented is not None:
                        raise ValueError("unexpected nested fragmented message")
                    fragmented = bytearray(payload)
                elif opcode == 0 and fragmented is not None:
                    fragmented.extend(payload)
                else:
                    raise ValueError("unexpected exec WebSocket opcode")
                if not final:
                    continue
                data, fragmented = bytes(fragmented), None
                if data and data[0] in channels:
                    channels[data[0]].extend(data[1:])
                elif data and data[0] != 255:
                    raise ValueError("unexpected exec channel")
            result["stdout"] = channels[1].decode("utf-8", errors="replace")
            result["stderr"] = channels[2].decode("utf-8", errors="replace")
            if channels[3]:
                result["status"] = json.loads(channels[3])
                result["exit_code"] = exit_code(result["status"])
    return result
