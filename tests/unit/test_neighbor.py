from ospf_attack.core.neighbor import NeighborState


class TestNeighborState:
    def test_progression(self):
        assert NeighborState.DOWN.value == 0
        assert NeighborState.FULL.value == 7

    def test_state_values(self):
        assert NeighborState.INIT > NeighborState.DOWN
        assert NeighborState.FULL > NeighborState.EXCHANGE
