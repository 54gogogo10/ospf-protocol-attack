from ospf_attack.attacks.lsa.route_inject import RouteInjectAttack
from ospf_attack.attacks.lsa.max_seq import MaxSeqAttack
from ospf_attack.attacks.lsa.max_age import MaxAgeAttack
from ospf_attack.attacks.lsa.fight_back import FightBackAttack
from ospf_attack.config.types import LSAConfig


class TestLSAttacks:
    def test_names(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5")
        assert RouteInjectAttack(config).name == "route-inject"
        assert MaxSeqAttack(config).name == "max-seq"
        assert MaxAgeAttack(config).name == "max-age"
        assert FightBackAttack(config).name == "fight-back"

    def test_max_age_uses_3600(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5", age=3600)
        attack = MaxAgeAttack(config)
        assert attack.config.age == 3600
