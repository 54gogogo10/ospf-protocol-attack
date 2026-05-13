"""攻击执行器 — 在后台线程中运行攻击，通过队列回传日志。"""

import queue
import threading
import traceback

from ..cli.commands import ATTACK_REGISTRY
from ..config.config import build_config


def _execute_attack(attack_name: str, config_dict: dict, stop_event: threading.Event,
                    log_queue: queue.Queue):
    """在后台线程中执行攻击。写入日志到 log_queue。"""
    try:
        log_queue.put(("SYSTEM", f"正在初始化攻击模块: {attack_name}"))

        attack_cls, _ = ATTACK_REGISTRY[attack_name]

        # 构建配置
        config = build_config(attack_name, config_dict)

        # 实例化攻击（注入 stop_event）
        attack = attack_cls(config, stop_event=stop_event)

        log_queue.put(("SYSTEM", f"开始执行 {attack_name} ..."))

        log_queue.put(("INFO", f"目标: {config_dict.get('target', 'N/A')}"))
        log_queue.put(("INFO", f"接口: {config_dict.get('iface', 'N/A')}"))

        # 执行攻击
        result = attack.run()

        # 报告结果
        if result.success:
            log_queue.put(("INFO", f"攻击完成 — 发送 {result.packets_sent} 个报文"))
            log_queue.put(("SYSTEM", f"详情: {result.details}"))
        else:
            log_queue.put(("ERROR", f"攻击失败 — {result.details}"))

        log_queue.put(("_RESULT_", str(result)))

    except Exception as e:
        log_queue.put(("ERROR", f"执行异常: {e}"))
        log_queue.put(("ERROR", traceback.format_exc()))
        log_queue.put(("_ERROR_", str(e)))


class AttackRunner:
    """封装攻击线程的启动/停止/状态查询。"""

    def __init__(self, attack_name: str, config_dict: dict,
                 stop_event: threading.Event, log_queue: queue.Queue):
        self._attack_name = attack_name
        self._config_dict = config_dict
        self._stop_event = stop_event
        self._log_queue = log_queue
        self._thread: threading.Thread | None = None

    def start(self):
        """启动攻击线程。"""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=_execute_attack,
            args=(self._attack_name, self._config_dict,
                  self._stop_event, self._log_queue),
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """发出停止信号。"""
        self._stop_event.set()

    def join(self, timeout: float | None = None):
        """等待攻击线程结束。"""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
