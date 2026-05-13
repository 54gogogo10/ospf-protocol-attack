import threading
import time
from dataclasses import dataclass, field
from typing import List, Tuple

try:
    import pcap
    HAS_PCAP = True
except (ImportError, OSError):
    HAS_PCAP = False

_MAX_PACKETS = 10000


@dataclass
class LsaSummary:
    lsa_type: int
    link_state_id: str
    advertising_router: str
    sequence: int
    age: int


@dataclass
class TopologyModel:
    router_ids: List[str] = field(default_factory=list)
    area_ids: List[str] = field(default_factory=list)
    dr_bdr_map: dict = field(default_factory=dict)
    lsa_summary: List[LsaSummary] = field(default_factory=list)

    def add_router(self, router_id: str, area_id: str) -> None:
        if router_id not in self.router_ids:
            self.router_ids.append(router_id)
        if area_id not in self.area_ids:
            self.area_ids.append(area_id)

    def add_hello(self, router_id: str, area_id: str,
                  dr: str, bdr: str, priority: int) -> None:
        self.add_router(router_id, area_id)
        if dr != "0.0.0.0" or bdr != "0.0.0.0":
            self.dr_bdr_map[area_id] = (dr, bdr)

    def add_lsa(self, lsa_type: int, link_state_id: str,
                advertising_router: str, sequence: int, age: int) -> None:
        self.lsa_summary.append(LsaSummary(
            lsa_type=lsa_type, link_state_id=link_state_id,
            advertising_router=advertising_router,
            sequence=sequence, age=age,
        ))

    def get_dr_bdr(self, area_id: str) -> Tuple[str, str]:
        return self.dr_bdr_map.get(area_id, ("0.0.0.0", "0.0.0.0"))


class Sniffer:
    def __init__(self, iface: str):
        self.iface = iface
        self.available = HAS_PCAP
        self._sniffer = None
        self._stop_event = threading.Event()
        self._packets = []
        self._topology = TopologyModel()

    def start(self, timeout: int = 30) -> None:
        if not self.available:
            return
        self._stop_event.clear()
        self._packets = []

        def _capture():
            sniffer = pcap.pcap(name=self.iface, promisc=True, immediate=True)
            sniffer.setfilter("proto 89")
            deadline = time.monotonic() + timeout
            try:
                for _ts, pkt in sniffer:
                    if time.monotonic() > deadline or self._stop_event.is_set():
                        break
                    if len(self._packets) < _MAX_PACKETS:
                        self._packets.append(pkt)
            except Exception:
                pass

        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        self._sniffer = t

    def stop(self):
        self._stop_event.set()
        return self._packets

    @property
    def packets(self):
        return self._packets

    @property
    def topology(self):
        return self._topology
