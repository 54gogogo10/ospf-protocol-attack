from unittest.mock import MagicMock
from ospf_attack.attacks.base import BaseAttack, AttackResult, AttackMode, AttackCategory, SniffMode


class _TestAttack(BaseAttack):
    name = "test_attack"
    description = "用于测试的攻击"
    category = AttackCategory.ADJACENCY
    default_mode = AttackMode.PASSIVE

    def setup(self):
        self._setup_called = True

    def launch(self) -> AttackResult:
        return AttackResult(success=True, packets_sent=1, target_affected=False, details="ok")

    def verify(self) -> bool:
        return True

    def teardown(self):
        self._teardown_called = True


class TestAttackRunner:
    def test_run_calls_all_phases(self):
        from ospf_attack.config.types import AttackConfig
        config = AttackConfig(iface="lo", target="127.0.0.1")
        attack = _TestAttack(config)
        result = attack.run()
        assert result.success is True
        assert attack._setup_called is True
        assert attack._teardown_called is True
