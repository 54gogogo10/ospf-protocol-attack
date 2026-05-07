from ospf_attack.core.neighbor import NeighborState, NeighborEntry, NeighborTable


class TestNeighborState:
    def test_progression(self):
        states = [NeighborState.DOWN, NeighborState.INIT, NeighborState.TWO_WAY,
                  NeighborState.EXSTART, NeighborState.EXCHANGE, NeighborState.LOADING,
                  NeighborState.FULL]
        assert NeighborState.DOWN.value == 0
        assert NeighborState.FULL.value == 7


class TestNeighborEntry:
    def test_create(self):
        e = NeighborEntry(router_id="2.2.2.2", ip="10.0.0.2")
        assert e.state == NeighborState.DOWN
        assert e.dr == "0.0.0.0"

    def test_transition(self):
        e = NeighborEntry(router_id="2.2.2.2", ip="10.0.0.2")
        e.state = NeighborState.INIT
        assert e.state == NeighborState.INIT
        e.state = NeighborState.FULL
        assert e.state == NeighborState.FULL


class TestNeighborTable:
    def test_add_and_get(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        n = t.get("2.2.2.2")
        assert n is not None
        assert n.router_id == "2.2.2.2"

    def test_remove(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.remove("2.2.2.2")
        assert t.get("2.2.2.2") is None

    def test_list_all(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.add("3.3.3.3", "10.0.0.3")
        assert len(t.list_all()) == 2

    def test_count_by_state(self):
        t = NeighborTable()
        t.add("2.2.2.2", "10.0.0.2")
        t.add("3.3.3.3", "10.0.0.3")
        assert t.count_by_state(NeighborState.DOWN) == 2
        assert t.count_by_state(NeighborState.FULL) == 0
