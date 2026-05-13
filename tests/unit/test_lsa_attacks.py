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

    def test_auth_defaults_to_none(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5")
        assert config.auth_type == "none"
        assert config.auth_key == ""

    def test_auth_plain_setup(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5",
                           auth_type="plain", auth_key="secret")
        assert config.auth_type == "plain"
        assert config.auth_key == "secret"
        attack = RouteInjectAttack(config)
        attack.setup()
        assert attack._sender is not None

    def test_auth_md5_setup(self):
        config = LSAConfig(iface="eth0", target="224.0.0.5",
                           auth_type="md5", auth_key="mykey")
        assert config.auth_type == "md5"
        attack = MaxSeqAttack(config)
        attack.setup()
        assert attack._sender is not None
