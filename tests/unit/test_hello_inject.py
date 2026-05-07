from unittest.mock import patch, MagicMock
from ospf_attack.attacks.adjacency.hello_inject import HelloInjectAttack
from ospf_attack.config.types import HelloInjectionConfig


class TestHelloInjectAttack:
    def test_init(self):
        config = HelloInjectionConfig(iface="eth0", target="10.0.0.1")
        attack = HelloInjectAttack(config)
        assert attack.name == "hello-inject"
        assert attack.category.value == "adjacency"

    @patch("ospf_attack.attacks.adjacency.hello_inject.build_hello_packet")
    @patch("ospf_attack.attacks.adjacency.hello_inject.PacketSender")
    def test_launch_sends_packets(self, MockSender, mock_build):
        mock_build.return_value = MagicMock()
        mock_sender = MagicMock()
        mock_sender.send_raw.return_value = True
        mock_sender.sent_count = 5
        MockSender.return_value = mock_sender

        config = HelloInjectionConfig(iface="eth0", target="224.0.0.5",
                                       router_priority=255)
        attack = HelloInjectAttack(config)
        attack._sender = mock_sender
        attack._sniffed_params = {"netmask": "255.255.255.0", "hello_interval": 10,
                                   "dead_interval": 40, "area_id": "0.0.0.0",
                                   "auth_type": 0, "auth_key": b""}

        result = attack.launch()
        assert result.success is True
        assert result.packets_sent == 5
