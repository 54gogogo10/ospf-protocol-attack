from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.dr_bdr_hijack import DRBDRHijackAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestDRBDRHijackAttack:
    def test_name(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1", router_priority=255)
        attack = DRBDRHijackAttack(config)
        assert attack.name == "dr-bdr-hijack"
        assert attack.config.router_priority == 255
