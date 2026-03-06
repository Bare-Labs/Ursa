"""Tests for Ursa Minor network tools (mocked I/O)."""

import socket

import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.network
class TestTcpConnectScan:

    def test_open_port(self):
        from ursa_minor.server import _tcp_connect_scan

        with patch("ursa_minor.server.socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.connect_ex.return_value = 0
            assert _tcp_connect_scan("10.0.0.1", 22) is True

    def test_closed_port(self):
        from ursa_minor.server import _tcp_connect_scan

        with patch("ursa_minor.server.socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.connect_ex.return_value = 111
            assert _tcp_connect_scan("10.0.0.1", 22) is False

    def test_exception_returns_false(self):
        from ursa_minor.server import _tcp_connect_scan

        with patch("ursa_minor.server.socket.socket") as mock_sock:
            mock_sock.side_effect = OSError("network down")
            assert _tcp_connect_scan("10.0.0.1", 22) is False


@pytest.mark.network
class TestGrabBanner:

    def test_banner_returned(self):
        from ursa_minor.server import _grab_banner

        with patch("ursa_minor.server.socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
            result = _grab_banner("10.0.0.1", 22)
            assert "OpenSSH" in result


@pytest.mark.network
class TestGetLocalIp:

    def test_returns_ip_string(self):
        from ursa_minor.server import _get_local_ip

        with patch("ursa_minor.server.socket.socket") as mock_sock:
            instance = mock_sock.return_value
            instance.getsockname.return_value = ("192.168.1.50", 0)
            ip = _get_local_ip()
            assert ip == "192.168.1.50"
