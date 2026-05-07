from abc import ABC, abstractmethod
from ospf_attack.config.types import AttackResult, AttackMode, AttackCategory, SniffMode


class BaseAttack(ABC):
    name: str = ""
    description: str = ""
    category: AttackCategory
    default_mode: AttackMode = AttackMode.PASSIVE

    def __init__(self, config):
        self.config = config
        self._sniffer = None
        self._sender = None

    @abstractmethod
    def setup(self) -> None:
        """阶段一：初始化"""

    @abstractmethod
    def launch(self) -> AttackResult:
        """阶段二：执行攻击"""

    @abstractmethod
    def verify(self) -> bool:
        """阶段三：验证攻击效果"""

    @abstractmethod
    def teardown(self) -> None:
        """阶段四：清理资源"""

    def run(self) -> AttackResult:
        try:
            self.setup()
            result = self.launch()
            result.target_affected = self.verify()
            return result
        finally:
            self.teardown()
