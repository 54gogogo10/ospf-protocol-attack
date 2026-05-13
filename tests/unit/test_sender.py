from unittest.mock import patch, MagicMock
from ospf_attack.network.sender import PacketSender


class TestPacketSender:
    @patch("ospf_attack.network.sender.send")
    def test_send_scapy(self, mock_send):
        sender = PacketSender(iface="eth0", packet_rate=10)
        result = sender.send_raw(b"\x45\x00")
        assert result is True

    @patch("ospf_attack.network.sender.sendp")
    def test_send_l2(self, mock_sendp):
        sender = PacketSender(iface="eth0")
        from scapy.all import Ether
        pkt = Ether()
        result = sender.send_l2(pkt)
        assert result is True

    def test_packet_rate_throttle(self):
        sender = PacketSender(iface="eth0", packet_rate=100)
        assert sender._packet_interval == 0.01

    def test_max_packets_unlimited(self):
        sender = PacketSender(iface="eth0", max_packets=0)
        assert sender._rate_limit() is True
