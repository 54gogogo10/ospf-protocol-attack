from typing import Callable, Dict, List


class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {}

    def on(self, event_type: str, handler: Callable) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def emit(self, event_type: str, **kwargs) -> None:
        for handler in self._handlers.get(event_type, []):
            handler(**kwargs)

    def clear(self) -> None:
        self._handlers.clear()
