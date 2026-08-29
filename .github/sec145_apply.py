from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
rpc_path = ROOT / "rpc.py"
text = rpc_path.read_text(encoding="utf-8")

anchor = '''def _require_rpc_int(value, label):
    if type(value) is not int:
        raise RPCError(f"{label} must be integer")
    return value
'''
replacement = '''def _require_rpc_request_framing(headers):
    # The RPC server accepts one fixed-length JSON body only.  Reject HTTP
    # framing aliases before reading a body so duplicate lengths or transfer
    # codings cannot create parser/proxy disagreement around operator calls.
    transfer_values = headers.get_all("Transfer-Encoding") or []
    if transfer_values:
        raise RPCError("transfer encoding not supported")

    content_types = headers.get_all("Content-Type") or []
    if len(content_types) != 1:
        raise RPCError("invalid content type header")
    media_type = content_types[0].split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise RPCError("content type must be application/json")

    lengths = headers.get_all("Content-Length") or []
    if len(lengths) != 1:
        raise RPCError("invalid content length header")
    length_text = lengths[0].strip()
    if (
        not length_text
        or len(length_text) > 10
        or not length_text.isascii()
        or not length_text.isdigit()
    ):
        raise RPCError("invalid request size")

    n = int(length_text)
    if n <= 0 or n > MAX_RPC_REQUEST_BYTES:
        raise RPCError("invalid request size")
    return n


def _require_rpc_int(value, label):
    if type(value) is not int:
        raise RPCError(f"{label} must be integer")
    return value
'''
if text.count(anchor) != 1:
    raise SystemExit("SEC-145 helper anchor mismatch")
text = text.replace(anchor, replacement, 1)

old = '''                _require_safe_rpc_host(self.headers)
                content_type = self.headers.get("Content-Type", "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type != "application/json":
                    raise RPCError("content type must be application/json")

                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > MAX_RPC_REQUEST_BYTES:
                    raise RPCError("invalid request size")
                raw_request = self.rfile.read(n)
'''
new = '''                _require_safe_rpc_host(self.headers)
                n = _require_rpc_request_framing(self.headers)
                raw_request = self.rfile.read(n)
'''
if text.count(old) != 1:
    raise SystemExit("SEC-145 do_POST anchor mismatch")
text = text.replace(old, new, 1)
rpc_path.write_text(text, encoding="utf-8", newline="")

spec = r'''#!/usr/bin/env python3
"""SEC-145 rejects ambiguous RPC HTTP request framing before dispatch."""

import json
import socket
from pathlib import Path

import rpc


class ProbeCore:
    def __init__(self):
        self.status_calls = 0
        self.stop_calls = 0

    def status(self):
        self.status_calls += 1
        return {"probe": "ok"}

    def request_shutdown(self):
        self.stop_calls += 1
        return {"stopping": True}


def raw_post(address, header_lines, body):
    request = b"POST / HTTP/1.1\r\n"
    for name, value in header_lines:
        request += name.encode("ascii") + b": " + value.encode("ascii") + b"\r\n"
    request += b"Connection: close\r\n\r\n" + body

    sock = socket.create_connection(address, timeout=2.0)
    try:
        sock.settimeout(2.0)
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        sock.close()


def status(response):
    return int(response.split(b" ", 2)[1])


def headers(address, body, *extra, content_type="application/json", length=None):
    port = address[1]
    out = [("Host", f"127.0.0.1:{port}")]
    if content_type is not None:
        out.append(("Content-Type", content_type))
    if length is not None:
        out.append(("Content-Length", str(length)))
    out.extend(extra)
    return out


def main():
    core = ProbeCore()
    server = rpc.RPCServer(core, port=0).start()
    checks = 0
    try:
        body = json.dumps({"method": "get_status", "params": {}}).encode()

        response = raw_post(
            server.address,
            headers(server.address, body, length=len(body)),
            body,
        )
        assert status(response) == 200
        assert core.status_calls == 1
        checks += 1
        print("[GREEN] canonical fixed-length JSON request preserved")

        response = raw_post(
            server.address,
            headers(
                server.address,
                body,
                length=len(body),
                content_type="application/json; charset=utf-8",
            ),
            body,
        )
        assert status(response) == 200
        assert core.status_calls == 2
        checks += 1
        print("[GREEN] canonical JSON charset content type preserved")

        duplicate_same = headers(
            server.address,
            body,
            ("Content-Length", str(len(body))),
            length=len(body),
        )
        response = raw_post(server.address, duplicate_same, body)
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] duplicate identical Content-Length rejected pre-dispatch")

        duplicate_different = headers(
            server.address,
            body,
            ("Content-Length", str(len(body) + 1)),
            length=len(body),
        )
        response = raw_post(server.address, duplicate_different, body)
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] conflicting Content-Length rejected pre-dispatch")

        response = raw_post(
            server.address,
            headers(server.address, body, length=None),
            body,
        )
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] missing Content-Length rejected pre-dispatch")

        response = raw_post(
            server.address,
            headers(
                server.address,
                body,
                ("Transfer-Encoding", "chunked"),
                length=len(body),
            ),
            body,
        )
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] Content-Length plus chunked transfer coding rejected")

        response = raw_post(
            server.address,
            headers(
                server.address,
                body,
                ("Transfer-Encoding", "chunked"),
                length=None,
            ),
            body,
        )
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] transfer-coded request without Content-Length rejected")

        response = raw_post(
            server.address,
            headers(
                server.address,
                body,
                ("Transfer-Encoding", "identity"),
                length=len(body),
            ),
            body,
        )
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] any Transfer-Encoding header is unsupported")

        duplicate_type = headers(
            server.address,
            body,
            ("Content-Type", "application/json"),
            length=len(body),
        )
        response = raw_post(server.address, duplicate_type, body)
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] duplicate Content-Type rejected pre-dispatch")

        response = raw_post(
            server.address,
            headers(server.address, body, content_type=None, length=len(body)),
            body,
        )
        assert status(response) == 400 and core.status_calls == 2
        checks += 1
        print("[GREEN] missing Content-Type remains rejected")

        for bad in (
            f"+{len(body)}",
            f"{len(body)}_0",
            "-1",
            "not-a-number",
            "00000000001",
            str(rpc.MAX_RPC_REQUEST_BYTES + 1),
        ):
            response = raw_post(
                server.address,
                headers(server.address, body, length=bad),
                body,
            )
            assert status(response) == 400 and core.status_calls == 2, bad
            checks += 1
            print(f"[GREEN] ambiguous/invalid Content-Length rejected: {bad!r}")

        stop_body = json.dumps({"method": "stop", "params": {}}).encode()
        response = raw_post(
            server.address,
            headers(
                server.address,
                stop_body,
                ("Content-Length", str(len(stop_body))),
                length=len(stop_body),
            ),
            stop_body,
        )
        assert status(response) == 400
        assert core.stop_calls == 0
        checks += 1
        print("[GREEN] ambiguous operator request blocked before dispatch")

        source = Path(__file__).with_name("rpc.py").read_text(encoding="utf-8")
        assert 'headers.get_all("Content-Length")' in source
        assert 'headers.get_all("Content-Type")' in source
        assert 'headers.get_all("Transfer-Encoding")' in source
        assert 'int(self.headers.get("Content-Length"' not in source
        assert "n = _require_rpc_request_framing(self.headers)" in source
        checks += 1
        print("[GREEN] production framing parser is duplicate-aware and fail-closed")

        assert checks == 18, checks
        print("SEC-145 RPC request framing: 18/18 GREEN")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
'''
spec_path = ROOT / "security_sec145_rpc_request_framing_spec.py"
spec_path.write_text(spec, encoding="utf-8", newline="")

manifest_path = ROOT / "release_manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for rel in ("rpc.py", "security_sec145_rpc_request_framing_spec.py"):
    data = (ROOT / rel).read_bytes()
    manifest["files"][rel] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
    newline="",
)
