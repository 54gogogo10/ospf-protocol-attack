import threading
import time
from abc import ABC, abstractmethod
from ospf_attack.config.types import AttackResult, AttackMode, AttackCategory, SniffMode


class BaseAttack(ABC):
    name: str = ""
    description: str = ""
    category: AttackCategory
    default_mode: AttackMode = AttackMode.PASSIVE
    needs_repeated: bool = False

    def __init__(self, config, stop_event: threading.Event | None = None):
        self.config = config
        self._sniffer = None
        self._sender = None
        self._stop_event = stop_event or threading.Event()

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

    def send_one_round(self) -> bool:
        """Override in subclasses for repeated attacks. Returns True if successful."""
        return False

    def run(self) -> AttackResult:
        result = None
        try:
            self.setup()
            if self.needs_repeated:
                result = self._run_repeated()
            else:
                result = self.launch()
                result.target_affected = self.verify()
        except Exception as e:
            result = AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details=f"攻击执行失败: {e}",
            )
        finally:
            try:
                self.teardown()
            except Exception as e:
                if result is not None:
                    result.details += f" (teardown 异常: {e})"
        return result

    def _run_repeated(self) -> AttackResult:
        deadline = time.time() + self.config.sniff_duration
        rounds = 0
        while time.time() < deadline and not self._stop_event.is_set():
            if self.send_one_round():
                rounds += 1
            time.sleep(1.0 / max(getattr(self.config, 'packet_rate', 1), 1))

        total_sent = self._sender.sent_count if self._sender else 0
        return AttackResult(
            success=rounds > 0,
            packets_sent=total_sent,
            target_affected=False,
            details=f"{self.name}: {rounds} rounds, {total_sent} packets sent",
        )
