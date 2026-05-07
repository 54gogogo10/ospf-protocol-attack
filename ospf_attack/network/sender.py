import time
import socket
import threading
from scapy.all import send, sendp


class PacketSender:
    def __init__(self, iface: str, packet_rate: int = 10, max_packets: int = 0):
        self.iface = iface
        self.packet_rate = packet_rate
        self.max_packets = max_packets
        self._sent_count = 0
        self._lock = threading.Lock()
        self._start_time = time.monotonic()
        self._packet_interval = 1.0 / packet_rate if packet_rate > 0 else 0

    def send_raw(self, data) -> bool:
        if not self._can_send():
            return False
        try:
            send(data, iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def send_l2(self, packet) -> bool:
        if not self._can_send():
            return False
        try:
            sendp(packet, iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def send_raw_socket(self, data: bytes, dst_ip: str) -> bool:
        if not self._can_send():
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(data, (dst_ip, 0))
            sock.close()
            self._inc_count()
            return True
        except Exception:
            return False

    def _can_send(self) -> bool:
        if self.max_packets > 0 and self._sent_count >= self.max_packets:
            return False
        if self._packet_interval > 0:
            time.sleep(self._packet_interval)
        return True

    def _inc_count(self):
        with self._lock:
            self._sent_count += 1

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time
