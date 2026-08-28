#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

p2p_path = Path("p2p.py")
source = p2p_path.read_text(encoding="utf-8")

old_constants = '''MAX_INBOUND_PEERS = 32\nMAX_SYNC_BLOCKS = 128\n'''
new_constants = '''MAX_INBOUND_PEERS = 32\nMAX_INBOUND_PEERS_PER_HOST = 4\nMAX_SYNC_BLOCKS = 128\n'''
if source.count(old_constants) != 1:
    raise SystemExit("SEC-105 constants target mismatch")
source = source.replace(old_constants, new_constants)

old_init = '''        self._sock=None; self._thread=None; self._stop=threading.Event()\n        self._clients=set(); self._lock=threading.Lock()\n'''
new_init = '''        self._sock=None; self._thread=None; self._stop=threading.Event()\n        self._clients=set(); self._client_hosts={}; self._lock=threading.Lock()\n'''
if source.count(old_init) != 1:
    raise SystemExit("SEC-105 init target mismatch")
source = source.replace(old_init, new_init)

old_accept = '''                try: c,_=sock.accept()\n                except socket.timeout: continue\n                except OSError: break\n                c.settimeout(INBOUND_PEER_TIMEOUT)\n                with self._lock:\n                    if len(self._clients) >= MAX_INBOUND_PEERS:\n                        reject = True\n                    else:\n                        self._clients.add(c)\n                        reject = False\n                if reject:\n                    try:\n                        c.close()\n                    except OSError:\n                        pass\n                    continue\n                def worker(client=c):\n                    try: serve_connection(client,self.session)\n                    finally:\n                        with self._lock:self._clients.discard(client)\n                threading.Thread(target=worker,daemon=True).start()\n'''
new_accept = '''                try: c,remote=sock.accept()\n                except socket.timeout: continue\n                except OSError: break\n                c.settimeout(INBOUND_PEER_TIMEOUT)\n                remote_host=remote[0]\n                with self._lock:\n                    host_count=sum(\n                        1 for host in self._client_hosts.values()\n                        if host == remote_host\n                    )\n                    if (\n                        len(self._clients) >= MAX_INBOUND_PEERS\n                        or host_count >= MAX_INBOUND_PEERS_PER_HOST\n                    ):\n                        reject = True\n                    else:\n                        self._clients.add(c)\n                        self._client_hosts[c]=remote_host\n                        reject = False\n                if reject:\n                    try:\n                        c.close()\n                    except OSError:\n                        pass\n                    continue\n                def worker(client=c):\n                    try: serve_connection(client,self.session)\n                    finally:\n                        with self._lock:\n                            self._clients.discard(client)\n                            self._client_hosts.pop(client,None)\n                threading.Thread(target=worker,daemon=True).start()\n'''
if source.count(old_accept) != 1:
    raise SystemExit("SEC-105 accept target mismatch")
source = source.replace(old_accept, new_accept)

p2p_path.write_text(source, encoding="utf-8", newline="\n")

spec = '''#!/usr/bin/env python3
"""SEC-105 per-source inbound P2P connection quota contract."""

import socket
import time

import p2p


ATTEMPTED_LOCAL_CONNECTIONS = 12


def snapshot(server):
    with server._lock:
        return len(server._clients), dict(server._client_hosts)


def wait_until(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def main():
    assert p2p.MAX_INBOUND_PEERS == 32
    assert p2p.MAX_INBOUND_PEERS_PER_HOST == 4
    print("[GREEN] global and per-host inbound quotas pinned")

    server = p2p.NodeServer().start()
    clients = []
    try:
        for _ in range(ATTEMPTED_LOCAL_CONNECTIONS):
            try:
                client = socket.create_connection(server.address, timeout=1.0)
                client.settimeout(1.0)
                clients.append(client)
            except OSError:
                pass

        assert wait_until(
            lambda: snapshot(server)[0] >= p2p.MAX_INBOUND_PEERS_PER_HOST,
            timeout=2.0,
        ), "server did not retain expected local peer quota"

        count, hosts = snapshot(server)
        local_host = server.address[0]
        local_count = sum(1 for host in hosts.values() if host == local_host)

        assert count <= p2p.MAX_INBOUND_PEERS, (
            f"global inbound quota exceeded: {count}"
        )
        assert local_count <= p2p.MAX_INBOUND_PEERS_PER_HOST, (
            f"single source retained {local_count} inbound slots"
        )
        assert count == len(hosts), "client/source accounting diverged"
        print(
            f"[GREEN] one source bounded at "
            f"{local_count}/{p2p.MAX_INBOUND_PEERS_PER_HOST} slots"
        )

        assert server._thread is not None and server._thread.is_alive()
        print("[GREEN] listener survives per-host quota saturation")

        for client in clients:
            try:
                client.close()
            except OSError:
                pass
        clients.clear()

        assert wait_until(lambda: snapshot(server)[0] == 0, timeout=2.0), (
            "closed clients did not release per-host slots"
        )
        print("[GREEN] closed clients release per-host quota accounting")

        fresh = socket.create_connection(server.address, timeout=1.0)
        fresh.settimeout(1.0)
        clients.append(fresh)
        assert wait_until(lambda: snapshot(server)[0] == 1, timeout=1.0)
        print("[GREEN] released source slot is reusable")

        print("SEC-105 inbound P2P per-host quota: 5/5 GREEN")
    finally:
        for client in clients:
            try:
                client.close()
            except OSError:
                pass
        server.stop()


if __name__ == "__main__":
    main()
'''
spec_path = Path("security_sec105_p2p_inbound_per_host_bounds_spec.py")
spec_path.write_text(spec, encoding="utf-8", newline="\n")

manifest_path = Path("release_manifest.json")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name in ("p2p.py", spec_path.name):
    data = Path(name).read_bytes()
    manifest["files"][name] = {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
manifest["files"] = dict(sorted(manifest["files"].items()))
manifest_path.write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
    newline="\n",
)
