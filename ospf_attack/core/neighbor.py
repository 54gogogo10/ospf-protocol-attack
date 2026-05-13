from enum import IntEnum


class NeighborState(IntEnum):
    DOWN = 0
    ATTEMPT = 1
    INIT = 2
    TWO_WAY = 3
    EXSTART = 4
    EXCHANGE = 5
    LOADING = 6
    FULL = 7
