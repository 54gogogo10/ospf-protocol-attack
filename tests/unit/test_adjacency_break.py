from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestAdjacencyBreakAttack:
    def test_name(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        attack = AdjacencyBreakAttack(config)
        assert attack.name == "adjacency-break"
