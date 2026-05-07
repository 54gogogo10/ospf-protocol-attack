import pytest
from ospf_attack.utils.validators import is_valid_ip, is_valid_router_id


class TestIsValidIP:
    def test_valid_ip(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_zero(self):
        assert is_valid_ip("0.0.0.0") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is False

    def test_empty_string(self):
        assert is_valid_ip("") is False

    def test_not_ip(self):
        assert is_valid_ip("hello") is False


class TestIsValidRouterID:
    def test_valid(self):
        assert is_valid_router_id("1.1.1.1") is True

    def test_zero(self):
        assert is_valid_router_id("0.0.0.0") is True

    def test_multicast(self):
        assert is_valid_router_id("224.0.0.5") is False

    def test_invalid(self):
        assert is_valid_router_id("abc") is False
