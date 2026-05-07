from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class LSAEntry:
    lsa_type: int
    link_state_id: str
    advertising_router: str
    sequence: int
    age: int
    checksum: int = 0
    length: int = 0
    body: bytes = b""


class LSADatabase:
    def __init__(self):
        self._entries: Dict[Tuple[int, str, str], LSAEntry] = {}

    def _key(self, lsa_type: int, link_state_id: str, adv_router: str) -> tuple:
        return (lsa_type, link_state_id, adv_router)

    def add(self, entry: LSAEntry) -> None:
        key = self._key(entry.lsa_type, entry.link_state_id, entry.advertising_router)
        existing = self._entries.get(key)
        if existing is None or entry.sequence > existing.sequence:
            self._entries[key] = entry

    def get(self, lsa_type: int, link_state_id: str, adv_router: str) -> Optional[LSAEntry]:
        return self._entries.get(self._key(lsa_type, link_state_id, adv_router))

    def remove(self, lsa_type: int, link_state_id: str, adv_router: str) -> None:
        self._entries.pop(self._key(lsa_type, link_state_id, adv_router), None)

    def list_all(self) -> List[LSAEntry]:
        return list(self._entries.values())

    def count(self) -> int:
        return len(self._entries)
