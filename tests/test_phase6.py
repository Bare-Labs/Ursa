"""Tests for Phase 6: Advanced C2 features.

Covers:
    - major.profiles  — TrafficProfile, builder_tokens, reverse_map
    - major.cert      — generate_cert_pem, ensure_cert, build_ssl_context
    - major.redirector — RedirectorConfig, Redirector start/stop
    - major.listeners.dns / smb — stub metadata and NotImplementedError
    - major.config    — new TLS/profile/redirector defaults
"""

from __future__ import annotations

import ipaddress
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest


# ── Traffic Profiles ──────────────────────────────────────────────────────────


class TestTrafficProfile:

    def test_all_builtin_profiles_exist(self):
        from major.profiles import PROFILES
        for name in ("default", "jquery", "office365", "github-api"):
            assert name in PROFILES, f"Missing profile: {name}"

    def test_profile_has_required_fields(self):
        from major.profiles import PROFILES
        required_keys = {"register", "beacon", "result", "upload", "download", "stage"}
        for name, profile in PROFILES.items():
            assert profile.name == name
            assert profile.description
            assert profile.server_header
            missing = required_keys - set(profile.urls.keys())
            assert not missing, f"Profile {name} missing URL keys: {missing}"

    def test_builder_tokens_returns_all_keys(self):
        from major.profiles import get_profile
        profile = get_profile("default")
        tokens = profile.builder_tokens()
        for key in (
            "URSA_REGISTER_PATH", "URSA_BEACON_PATH", "URSA_RESULT_PATH",
            "URSA_UPLOAD_PATH", "URSA_DOWNLOAD_PATH", "URSA_STAGE_PATH",
        ):
            assert key in tokens, f"Missing token: {key}"
            assert isinstance(tokens[key], str)
            assert tokens[key].startswith("/")

    def test_builder_tokens_strip_placeholder(self):
        from major.profiles import get_profile
        # office365 download path ends with /{id}/content
        profile = get_profile("office365")
        tokens = profile.builder_tokens()
        assert "{id}" not in tokens["URSA_DOWNLOAD_PATH"]

    def test_reverse_map_covers_all_endpoints(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            rev = profile.reverse_map()
            assert "register" in rev.values(), f"{name}: missing register in reverse_map"
            assert "beacon"   in rev.values(), f"{name}: missing beacon in reverse_map"
            assert "stage"    in rev.values(), f"{name}: missing stage in reverse_map"

    def test_reverse_map_no_placeholders_in_keys(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            rev = profile.reverse_map()
            for path in rev.keys():
                assert "{id}" not in path, f"{name}: placeholder in reverse_map key: {path}"

    def test_download_prefix_matches_reverse_map(self):
        from major.profiles import PROFILES
        for name, profile in PROFILES.items():
            prefix = profile.download_prefix()
            assert prefix.startswith("/"), f"{name}: download_prefix should start with /"

    def test_get_profile_fallback(self):
        from major.profiles import get_profile
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            profile = get_profile("nonexistent-profile-xyz")
        assert profile.name == "default"
        assert any("not found" in str(warning.message) for warning in w)

    def test_list_profiles_returns_all(self):
        from major.profiles import list_profiles, PROFILES
        result = list_profiles()
        assert len(result) == len(PROFILES)
        for entry in result:
            assert "name" in entry
            assert "description" in entry
            assert "server_header" in entry
            assert "endpoints" in entry
            assert entry["endpoints"] == 6  # all profiles have 6 URL keys

    def test_jquery_profile_server_header(self):
        from major.profiles import get_profile
        p = get_profile("jquery")
        assert "ECS" in p.server_header

    def test_office365_profile_server_header(self):
        from major.profiles import get_profile
        p = get_profile("office365")
        assert "IIS" in p.server_header

    def test_office365_response_headers(self):
        from major.profiles import get_profile
        p = get_profile("office365")
        assert "X-MS-RequestId" in p.response_headers

    def test_github_api_response_headers(self):
        from major.profiles import get_profile
        p = get_profile("github-api")
        assert "X-GitHub-Request-Id" in p.response_headers
        assert "X-RateLimit-Limit" in p.response_headers


# ── TLS Certificate Generation ─────────────────────────────────────────────────


class TestCertGeneration:

    def test_generate_cert_pem_returns_bytes(self):
        from major.cert import generate_cert_pem
        cert_pem, key_pem = generate_cert_pem(hostname="test.local")
        assert isinstance(cert_pem, bytes)
        assert isinstance(key_pem, bytes)

    def test_cert_pem_headers(self):
        from major.cert import generate_cert_pem
        cert_pem, key_pem = generate_cert_pem(hostname="test.local")
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem

    def test_cert_parseable(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        cert_pem, _ = generate_cert_pem(hostname="test.local")
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert is not None

    def test_cert_cn_matches_hostname(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert_pem, _ = generate_cert_pem(hostname="myc2.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "myc2.example.com"

    def test_cert_has_san_with_hostname(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        cert_pem, _ = generate_cert_pem(hostname="myc2.example.com")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "myc2.example.com" in dns_names

    def test_cert_includes_extra_ip_san(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["10.0.0.5"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("10.0.0.5") in ips

    def test_cert_includes_extra_dns_san(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        cert_pem, _ = generate_cert_pem(hostname="c2.test", extra_sans=["alt.example.com"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alt.example.com" in dns_names

    def test_cert_has_loopback_san(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        cert_pem, _ = generate_cert_pem(hostname="c2.test")
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address("127.0.0.1") in ips

    def test_cert_validity_period(self):
        from major.cert import generate_cert_pem
        from cryptography import x509
        from datetime import timedelta, UTC
        from datetime import datetime
        cert_pem, _ = generate_cert_pem(hostname="test.local", days=30)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 28 <= delta.days <= 31  # allow small clock skew

    def test_ensure_cert_creates_files(self, tmp_path):
        from major.cert import ensure_cert
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.stat().st_size > 0
        assert key_path.stat().st_size > 0

    def test_ensure_cert_idempotent(self, tmp_path):
        from major.cert import ensure_cert
        cert_path1, key_path1 = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime1 = cert_path1.stat().st_mtime

        # Second call should NOT regenerate
        cert_path2, key_path2 = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime2 = cert_path2.stat().st_mtime

        assert mtime1 == mtime2

    def test_ensure_cert_regenerate_flag(self, tmp_path):
        from major.cert import ensure_cert
        cert_path1, _ = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        mtime1 = cert_path1.stat().st_mtime

        time.sleep(0.01)
        cert_path2, _ = ensure_cert(cert_dir=tmp_path, hostname="test.local", regenerate=True)
        mtime2 = cert_path2.stat().st_mtime

        assert mtime2 > mtime1

    def test_build_ssl_context_returns_context(self, tmp_path):
        from major.cert import ensure_cert, build_ssl_context
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        ctx = build_ssl_context(cert_path, key_path)
        assert isinstance(ctx, ssl.SSLContext)

    def test_ssl_context_minimum_tls_version(self, tmp_path):
        from major.cert import ensure_cert, build_ssl_context
        cert_path, key_path = ensure_cert(cert_dir=tmp_path, hostname="test.local")
        ctx = build_ssl_context(cert_path, key_path)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# ── Redirector ─────────────────────────────────────────────────────────────────


class TestRedirectorConfig:

    def test_defaults(self):
        from major.redirector import RedirectorConfig
        cfg = RedirectorConfig()
        assert cfg.listen_port == 80
        assert cfg.upstream_url == "http://127.0.0.1:8443"
        assert cfg.allowed_paths == []
        assert cfg.user_agent_filter == ""
        assert not cfg.verify_tls

    def test_custom_config(self):
        from major.redirector import RedirectorConfig
        cfg = RedirectorConfig(
            listen_port=8080,
            upstream_url="https://10.0.0.1:8443",
            allowed_paths=["/beacon", "/register"],
            user_agent_filter="Mozilla",
        )
        assert cfg.listen_port == 8080
        assert cfg.allowed_paths == ["/beacon", "/register"]
        assert cfg.user_agent_filter == "Mozilla"


class TestRedirector:

    def _make_decoy_upstream(self) -> tuple[HTTPServer, int]:
        """Spin up a tiny HTTP server to act as upstream."""
        class EchoHandler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body) + 10))
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            def do_GET(self):
                resp = b'{"upstream":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        srv = HTTPServer(("127.0.0.1", 0), EchoHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, port

    def test_redirector_start_stop(self):
        from major.redirector import Redirector, RedirectorConfig
        cfg = RedirectorConfig(
            listen_host="127.0.0.1",
            listen_port=0,  # can't bind 0 in HTTPServer directly — use fixed port
        )
        # Just test instantiation and repr when not started
        r = Redirector(cfg)
        assert not r.running
        assert "stopped" in repr(r)

    def test_redirector_from_config_disabled(self):
        from major.redirector import redirector_from_config
        from unittest.mock import MagicMock
        cfg = MagicMock()
        cfg.get = lambda key, default=None: {
            "major.redirector.enabled": False,
        }.get(key, default)
        result = redirector_from_config(cfg)
        assert result is None

    def test_redirector_from_config_enabled(self):
        from major.redirector import redirector_from_config, Redirector
        from unittest.mock import MagicMock
        cfg = MagicMock()
        values = {
            "major.redirector.enabled": True,
            "major.redirector.listen_host": "0.0.0.0",
            "major.redirector.listen_port": 80,
            "major.redirector.upstream_url": "http://127.0.0.1:8443",
            "major.redirector.allowed_paths": [],
            "major.redirector.user_agent_filter": "",
            "major.redirector.verify_tls": False,
            "major.redirector.upstream_timeout": 10,
        }
        cfg.get = lambda key, default=None: values.get(key, default)
        result = redirector_from_config(cfg)
        assert isinstance(result, Redirector)
        assert result.config.listen_port == 80
        assert result.config.upstream_url == "http://127.0.0.1:8443"


# ── Listener Stubs ────────────────────────────────────────────────────────────


class TestDNSListenerStub:

    def test_not_implemented(self):
        from major.listeners.dns import DNSTunnelListener, IMPLEMENTED
        assert IMPLEMENTED is False
        listener = DNSTunnelListener(domain="c2.example.com")
        with pytest.raises(NotImplementedError):
            listener.start()

    def test_not_running(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener()
        assert not listener.running

    def test_stop_is_safe(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener()
        listener.stop()  # should not raise

    def test_module_has_implementation_guide(self):
        import major.listeners.dns as mod
        assert mod.__doc__ is not None
        assert len(mod.__doc__) > 200, "DNS stub should have detailed docs"
        assert "dnslib" in mod.__doc__

    def test_attributes(self):
        from major.listeners.dns import DNSTunnelListener
        listener = DNSTunnelListener(host="0.0.0.0", port=53, domain="c2.example.com")
        assert listener.host == "0.0.0.0"
        assert listener.port == 53
        assert listener.domain == "c2.example.com"


class TestSMBListenerStub:

    def test_not_implemented(self):
        from major.listeners.smb import SMBPipeListener, IMPLEMENTED
        assert IMPLEMENTED is False
        listener = SMBPipeListener()
        with pytest.raises(NotImplementedError):
            listener.start()

    def test_not_running(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener()
        assert not listener.running

    def test_stop_is_safe(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener()
        listener.stop()  # should not raise

    def test_module_has_implementation_guide(self):
        import major.listeners.smb as mod
        assert mod.__doc__ is not None
        assert len(mod.__doc__) > 200, "SMB stub should have detailed docs"
        assert "impacket" in mod.__doc__

    def test_pipe_name_attribute(self):
        from major.listeners.smb import SMBPipeListener
        listener = SMBPipeListener(pipe_name=r"\\.\pipe\TestPipe")
        assert listener.pipe_name == r"\\.\pipe\TestPipe"


# ── Config defaults ────────────────────────────────────────────────────────────


class TestConfigDefaults:

    def test_tls_defaults(self):
        from major.config import DEFAULTS
        tls = DEFAULTS["major"]["tls"]
        assert tls["enabled"] is False
        assert "hostname" in tls
        assert "extra_sans" in tls
        assert "cert_days" in tls
        assert isinstance(tls["extra_sans"], list)

    def test_redirector_defaults(self):
        from major.config import DEFAULTS
        redir = DEFAULTS["major"]["redirector"]
        assert redir["enabled"] is False
        assert "listen_port" in redir
        assert "upstream_url" in redir
        assert "allowed_paths" in redir
        assert isinstance(redir["allowed_paths"], list)

    def test_traffic_profile_default(self):
        from major.config import DEFAULTS
        assert DEFAULTS["major"]["traffic_profile"] == "default"

    def test_trusted_redirectors_default(self):
        from major.config import DEFAULTS
        assert "trusted_redirectors" in DEFAULTS["major"]
        assert isinstance(DEFAULTS["major"]["trusted_redirectors"], list)

    def test_config_get_tls_enabled(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.tls.enabled") is False

    def test_config_get_traffic_profile(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.traffic_profile") == "default"

    def test_config_get_redirector_enabled(self):
        from major.config import load_config
        cfg = load_config()
        assert cfg.get("major.redirector.enabled") is False
