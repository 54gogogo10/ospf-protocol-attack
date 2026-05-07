from unittest.mock import patch, MagicMock
from ospf_attack.core.sniffer import Sniffer, TopologyModel


class TestTopologyModel:
    def test_empty(self):
        t = TopologyModel()
        assert t.router_ids == []
        assert t.area_ids == []
        assert t.dr_bdr_map == {}
        assert t.lsa_summary == []

    def test_add_router(self):
        t = TopologyModel()
        t.add_router("1.1.1.1", "0.0.0.0")
        assert "1.1.1.1" in t.router_ids
        assert "0.0.0.0" in t.area_ids

    def test_add_hello(self):
        t = TopologyModel()
        t.add_hello(router_id="2.2.2.2", area_id="0.0.0.0",
                    dr="2.2.2.2", bdr="3.3.3.3", priority=100)
        assert t.dr_bdr_map["0.0.0.0"] == ("2.2.2.2", "3.3.3.3")

    def test_add_lsa(self):
        t = TopologyModel()
        t.add_lsa(lsa_type=1, link_state_id="1.1.1.1",
                  advertising_router="1.1.1.1", sequence=0x80000001, age=0)
        assert len(t.lsa_summary) == 1


class TestSniffer:
    def test_no_npcap(self):
        with patch("ospf_attack.core.sniffer.HAS_PCAP", False):
            s = Sniffer(iface="eth0")
            assert not s.available

    def test_init(self):
        with patch("ospf_attack.core.sniffer.HAS_PCAP", True):
            s = Sniffer(iface="eth0")
            assert s.iface == "eth0"
            assert s.available is True
