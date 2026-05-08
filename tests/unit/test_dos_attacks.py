from ospf_attack.attacks.dos.flood import FloodAttack
from ospf_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from ospf_attack.attacks.dos.db_overflow import DBOverflowAttack
from ospf_attack.config.types import DoSConfig


class TestDoSAttacks:
    def test_names(self):
        config = DoSConfig(iface="eth0", target="224.0.0.5")
        assert FloodAttack(config).name == "flood"
        assert SPFRecalcAttack(config).name == "spf-recalc"
        assert DBOverflowAttack(config).name == "db-overflow"

    def test_thread_count(self):
        config = DoSConfig(iface="eth0", target="224.0.0.5", thread_count=4)
        attack = FloodAttack(config)
        assert attack.config.thread_count == 4
