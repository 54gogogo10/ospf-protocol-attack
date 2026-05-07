# tests/unit/test_config_types.py
import pytest
from ospf_attack.config.types import (
    AttackMode, SniffMode, AttackCategory, AttackResult,
    AttackConfig, HelloInjectionConfig, LSAConfig, DoSConfig, MITMConfig, ReplayConfig,
)


class TestAttackMode:
    def test_passive_value(self):
        assert AttackMode.PASSIVE.value == "passive"

    def test_active_value(self):
        assert AttackMode.ACTIVE.value == "active"


class TestSniffMode:
    def test_hub_value(self):
        assert SniffMode.HUB.value == "hub"

    def test_arp_spoof_value(self):
        assert SniffMode.ARP_SPOOF.value == "arp_spoof"


class TestAttackCategory:
    def test_four_categories(self):
        values = [c.value for c in AttackCategory]
        assert sorted(values) == sorted(["adjacency", "lsa", "dos", "protocol"])


class TestAttackResult:
    def test_defaults(self):
        r = AttackResult(success=False, packets_sent=0, target_affected=False, details="")
        assert r.success is False
        assert r.packets_sent == 0
        assert r.target_affected is False
        assert r.evidence == {}

    def test_success_result(self):
        r = AttackResult(success=True, packets_sent=50, target_affected=True, details="注入成功")
        assert r.success is True
        assert r.packets_sent == 50
        assert r.target_affected is True


class TestAttackConfig:
    def test_default_values(self):
        c = AttackConfig(iface="eth0", target="10.0.0.1")
        assert c.mode == AttackMode.PASSIVE
        assert c.sniff_mode == SniffMode.HUB
        assert c.router_id == "1.1.1.1"
        assert c.area_id == "0.0.0.0"
        assert c.sniff_duration == 30
        assert c.packet_rate == 10
        assert c.max_packets == 0

    def test_custom_values(self):
        c = AttackConfig(
            iface="eth1", target="192.168.1.0/24",
            mode=AttackMode.ACTIVE, sniff_mode=SniffMode.ARP_SPOOF,
            router_id="2.2.2.2", area_id="0.0.0.1",
            sniff_duration=60, packet_rate=100, max_packets=500,
            arp_target_a="10.0.0.1", arp_target_b="10.0.0.2", arp_interval=5,
            verbose=True, pcap_output="out.pcap",
        )
        assert c.mode == AttackMode.ACTIVE
        assert c.sniff_mode == SniffMode.ARP_SPOOF
        assert c.arp_target_a == "10.0.0.1"
        assert c.arp_target_b == "10.0.0.2"
        assert c.arp_interval == 5
        assert c.verbose is True
        assert c.pcap_output == "out.pcap"


class TestHelloInjectionConfig:
    def test_defaults(self):
        c = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        assert c.hello_interval == 10
        assert c.router_dead_interval == 40
        assert c.router_priority == 255
        assert c.auth_type == "none"
        assert c.auth_key == ""
        assert c.subnet_mask == "255.255.255.0"

    def test_with_auth(self):
        c = HelloInjectionConfig(iface="eth0", target="10.0.0.1",
                                 auth_type="md5", auth_key="secret")
        assert c.auth_type == "md5"
        assert c.auth_key == "secret"


class TestLSAConfig:
    def test_defaults(self):
        c = LSAConfig(iface="eth0", target="224.0.0.5")
        assert c.lsa_type == 5
        assert c.sequence_number == 0x80000001
        assert c.age == 0
        assert c.metric == 1
        assert c.external_routes == []

    def test_max_age_config(self):
        c = LSAConfig(iface="eth0", target="224.0.0.5", age=3600, lsa_type=1)
        assert c.age == 3600
        assert c.lsa_type == 1


class TestDoSConfig:
    def test_defaults(self):
        c = DoSConfig(iface="eth0", target="224.0.0.5")
        assert c.duration == 60
        assert c.thread_count == 1
        assert c.lsa_change_interval == 2
        assert c.lsa_count == 1000


class TestMITMConfig:
    def test_defaults(self):
        c = MITMConfig(iface="eth0", target="10.0.0.0/24")
        assert c.action == "modify"
        assert c.modify_rules == []


class TestReplayConfig:
    def test_defaults(self):
        c = ReplayConfig(iface="eth0", target="224.0.0.5")
        assert c.replay_loop is False
        assert c.replay_interval == 5
        assert c.capture_file == ""
        assert c.modify_fields == {}
