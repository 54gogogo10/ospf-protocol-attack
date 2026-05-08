from ospf_attack.attacks.protocol.mitm import MITMAttack
from ospf_attack.attacks.protocol.replay import ReplayAttack
from ospf_attack.config.types import MITMConfig, ReplayConfig


class TestProtocolAttacks:
    def test_mitm_name(self):
        config = MITMConfig(iface="eth0", target="10.0.0.0/24")
        assert MITMAttack(config).name == "mitm"

    def test_replay_name(self):
        config = ReplayConfig(iface="eth0", target="224.0.0.5")
        assert ReplayAttack(config).name == "replay"

    def test_replay_requires_capture(self):
        config = ReplayConfig(iface="eth0", target="224.0.0.5")
        attack = ReplayAttack(config)
        result = attack.launch()
        assert result.success is False
