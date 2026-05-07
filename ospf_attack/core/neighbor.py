from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class NeighborState(IntEnum):
    DOWN = 0
    ATTEMPT = 1
    INIT = 2
    TWO_WAY = 3
    EXSTART = 4
    EXCHANGE = 5
    LOADING = 6
    FULL = 7


@dataclass
class NeighborEntry:
    router_id: str
    ip: str
    state: NeighborState = NeighborState.DOWN
    dr: str = "0.0.0.0"
    bdr: str = "0.0.0.0"
    area_id: str = "0.0.0.0"


class NeighborTable:
    def __init__(self):
        self._entries: Dict[str, NeighborEntry] = {}

    def add(self, router_id: str, ip: str) -> NeighborEntry:
        entry = NeighborEntry(router_id=router_id, ip=ip)
        self._entries[router_id] = entry
        return entry

    def get(self, router_id: str) -> Optional[NeighborEntry]:
        return self._entries.get(router_id)

    def remove(self, router_id: str) -> None:
        self._entries.pop(router_id, None)

    def list_all(self) -> List[NeighborEntry]:
        return list(self._entries.values())

    def count_by_state(self, state: NeighborState) -> int:
        return sum(1 for e in self._entries.values() if e.state == state)
