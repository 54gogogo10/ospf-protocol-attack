from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RouterIdentity:
    router_id: str
    area_id: str = "0.0.0.0"
    router_priority: int = 1
    auth_type: int = 0                   # 0=none, 1=plain, 2=md5
    auth_key: bytes = b""
    hello_interval: int = 10
    router_dead_interval: int = 40
    interfaces: dict = field(default_factory=dict)

    def get_hello_config(self) -> dict:
        return {
            "router_id": self.router_id,
            "area_id": self.area_id,
            "router_priority": self.router_priority,
            "hello_interval": self.hello_interval,
            "router_dead_interval": self.router_dead_interval,
            "auth_type": self.auth_type,
            "auth_key": self.auth_key,
        }
