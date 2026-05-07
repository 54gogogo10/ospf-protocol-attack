from unittest.mock import patch, MagicMock
from ospf_attack.core.arp_spoof import ArpSpoofEngine


class TestArpSpoofEngine:
    def test_init(self):
        engine = ArpSpoofEngine(
            iface="eth0",
            target_a="10.0.0.1", target_b="10.0.0.2",
            interval=2,
        )
        assert engine.target_a == "10.0.0.1"
        assert engine.target_b == "10.0.0.2"
        assert engine.interval == 2
        assert not engine._running

    def test_validate_targets_empty(self):
        engine = ArpSpoofEngine(iface="eth0", target_a="", target_b="")
        assert not engine.validate_targets()

    def test_validate_targets_valid(self):
        engine = ArpSpoofEngine(iface="eth0", target_a="10.0.0.1", target_b="10.0.0.2")
        assert engine.validate_targets()
