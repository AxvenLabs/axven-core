#!/usr/bin/env python3
from pathlib import Path


def replace_once(text, old, new, label):
    count=text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old,new,1)


p2p_path=Path("p2p.py")
p2p=p2p_path.read_text(encoding="utf-8")
p2p=replace_once(
    p2p,
    '''def connect_with_identity(address,timeout=3.0):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    deadline=(None if timeout is None else time.monotonic()+timeout)
    try:
        peer=handshake(s,deadline=deadline)
        identity={
            key:peer[key]
            for key in (
                "protocol_version","chain_id","config_fingerprint","genesis_hash"
            )
        }
    except Exception:
        try:s.close()
        except OSError:pass
        raise
    s.settimeout(timeout)
    return s,identity

def connect(address,timeout=3.0):
    s,_identity=connect_with_identity(address,timeout=timeout)
    return s
''',
    '''def _apply_remote_host_gate(sock,remote_host_gate):
    """Expose the kernel-connected remote IP before any peer handshake work."""
    if remote_host_gate is None:
        return None
    try:
        peername=sock.getpeername()
    except (OSError,AttributeError) as exc:
        raise ProtocolError("remote peer endpoint unavailable") from exc
    if (
        type(peername) not in (tuple,list)
        or not peername
        or type(peername[0]) is not str
        or not peername[0]
    ):
        raise ProtocolError("invalid remote peer endpoint")
    remote_host=peername[0]
    if remote_host_gate(remote_host) is not True:
        raise ProtocolError("outbound peer resolved diversity limit exceeded")
    return remote_host


def connect_with_identity(address,timeout=3.0,remote_host_gate=None):
    s=socket.create_connection(address,timeout=timeout)
    s.settimeout(timeout)
    deadline=(None if timeout is None else time.monotonic()+timeout)
    try:
        _apply_remote_host_gate(s,remote_host_gate)
        peer=handshake(s,deadline=deadline)
        identity={
            key:peer[key]
            for key in (
                "protocol_version","chain_id","config_fingerprint","genesis_hash"
            )
        }
    except Exception:
        try:s.close()
        except OSError:pass
        raise
    s.settimeout(timeout)
    return s,identity

def connect(address,timeout=3.0,remote_host_gate=None):
    if remote_host_gate is None:
        s,_identity=connect_with_identity(address,timeout=timeout)
    else:
        s,_identity=connect_with_identity(
            address,timeout=timeout,remote_host_gate=remote_host_gate
        )
    return s
''',
    "p2p connect gate",
)
p2p=replace_once(
    p2p,
    '''def sync_to_peer(
    address, session, limit=128, max_rounds=100,
    block_work_gate=None, block_signature_work_gate=None,
):
    """Reconnect-friendly catch-up until empty reply or local work budget."""
    total=0
    sock=connect(address)
''',
    '''def sync_to_peer(
    address, session, limit=128, max_rounds=100,
    block_work_gate=None, block_signature_work_gate=None,
    remote_host_gate=None,
):
    """Reconnect-friendly catch-up until empty reply or local work budget."""
    total=0
    if remote_host_gate is None:
        sock=connect(address)
    else:
        sock=connect(address,remote_host_gate=remote_host_gate)
''',
    "p2p sync gate",
)
p2p_path.write_text(p2p,encoding="utf-8")


core_path=Path("core.py")
core=core_path.read_text(encoding="utf-8")
core=replace_once(
    core,
    '''        self.p2p_server = None
        self._peer_lock = threading.RLock()
        # Persist automatic configured-peer work budgets on the core, not
''',
    '''        self.p2p_server = None
        self._peer_lock = threading.RLock()
        # SEC-199: remember the actual kernel-connected IP for each configured
        # peer so DNS aliases cannot mint independent diversity/work identities.
        self.peer_resolved_hosts = {}
        # Persist automatic configured-peer work budgets on the core, not
''',
    "core resolved state",
)
core=replace_once(
    core,
    '''        return normalized

    @staticmethod
    def _peer_health_timestamp():
''',
    '''        return normalized

    @staticmethod
    def _canonical_resolved_peer_host(remote_host):
        """Canonicalize a kernel-reported connected peer host as an IP."""
        if type(remote_host) is not str or not remote_host:
            raise ValueError("invalid resolved peer host")
        host=remote_host
        if host.startswith("[") and host.endswith("]"):
            host=host[1:-1]
        try:
            return str(ipaddress.ip_address(host))
        except ValueError as exc:
            raise ValueError("resolved peer host must be IP address") from exc

    def _admit_resolved_peer_host(self, peer, remote_host):
        """Bind a configured peer to its actual IP and enforce resolved diversity."""
        addr=self._parse_peer(peer)
        remote_host=self._canonical_resolved_peer_host(remote_host)
        group=self._peer_diversity_group(remote_host)
        with _peer_guard(self):
            if addr not in self.outbound_peers:
                return True
            if group is not None:
                count=0
                for other_addr,other_host in self.peer_resolved_hosts.items():
                    if other_addr == addr or other_addr not in self.outbound_peers:
                        continue
                    if self._peer_diversity_group(other_host) == group:
                        count += 1
                if count >= self.MAX_CONFIGURED_PEERS_PER_DIVERSITY_GROUP:
                    return False
            self.peer_resolved_hosts[addr]=remote_host
            return True

    @staticmethod
    def _peer_health_timestamp():
''',
    "core resolved admission helper",
)
core=replace_once(
    core,
    '''        self.peer_last_success_at.pop(addr,None)
        self.peer_last_failure_at.pop(addr,None)
        self.peer_health_current_state.pop(addr,None)
''',
    '''        self.peer_last_success_at.pop(addr,None)
        self.peer_last_failure_at.pop(addr,None)
        self.peer_resolved_hosts.pop(addr,None)
        self.peer_health_current_state.pop(addr,None)
''',
    "core resolved removal",
)
core=replace_once(
    core,
    '''    def sync_outbound_peer(self, peer):
        """Synchronize one configured outbound peer and update its health."""
        addr=self._parse_peer(peer)
        try:
            source_host=addr[0]
            block_gate=lambda: (
                self._outbound_sync_block_work_limiter.consume(source_host)
            )
            signature_gate=lambda cost: (
                self._outbound_sync_block_signature_work_limiter.consume(
                    source_host,cost
                )
            )
            accepted=p2p.sync_to_peer(
                addr,p2p.PeerSession(self.chain,self.mempool),limit=128,
                block_work_gate=block_gate,
                block_signature_work_gate=signature_gate,
            )
''',
    '''    def sync_outbound_peer(self, peer):
        """Synchronize one configured outbound peer and update its health."""
        addr=self._parse_peer(peer)
        try:
            source_host=addr[0]
            def remote_host_gate(remote_host):
                nonlocal source_host
                source_host=self._canonical_resolved_peer_host(remote_host)
                return self._admit_resolved_peer_host(addr,source_host)
            block_gate=lambda: (
                self._outbound_sync_block_work_limiter.consume(source_host)
            )
            signature_gate=lambda cost: (
                self._outbound_sync_block_signature_work_limiter.consume(
                    source_host,cost
                )
            )
            accepted=p2p.sync_to_peer(
                addr,p2p.PeerSession(self.chain,self.mempool),limit=128,
                block_work_gate=block_gate,
                block_signature_work_gate=signature_gate,
                remote_host_gate=remote_host_gate,
            )
''',
    "core configured sync resolved gate",
)
core=replace_once(
    core,
    '''    def sync_peer(self, host, port, batch=128):
        batch=self._validate_service_int(batch,"sync batch",1,128)
        addr = self._parse_peer((host, port))
        source_host=addr[0]
        block_gate=lambda: (
            self._outbound_sync_block_work_limiter.consume(source_host)
        )
        signature_gate=lambda cost: (
            self._outbound_sync_block_signature_work_limiter.consume(
                source_host,cost
            )
        )
        return p2p.sync_to_peer(
            addr, p2p.PeerSession(self.chain, self.mempool),
            limit=batch,
            block_work_gate=block_gate,
            block_signature_work_gate=signature_gate,
        )
''',
    '''    def sync_peer(self, host, port, batch=128):
        batch=self._validate_service_int(batch,"sync batch",1,128)
        addr = self._parse_peer((host, port))
        source_host=addr[0]
        def remote_host_gate(remote_host):
            nonlocal source_host
            source_host=self._canonical_resolved_peer_host(remote_host)
            return True
        block_gate=lambda: (
            self._outbound_sync_block_work_limiter.consume(source_host)
        )
        signature_gate=lambda cost: (
            self._outbound_sync_block_signature_work_limiter.consume(
                source_host,cost
            )
        )
        return p2p.sync_to_peer(
            addr, p2p.PeerSession(self.chain, self.mempool),
            limit=batch,
            block_work_gate=block_gate,
            block_signature_work_gate=signature_gate,
            remote_host_gate=remote_host_gate,
        )
''',
    "core manual sync resolved gate",
)
core_path.write_text(core,encoding="utf-8")
print("SEC-199 production patch applied")
