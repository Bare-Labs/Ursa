"""Tests for the Ursa payload builder (implants/builder.py)."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from implants.builder import Builder, PayloadConfig, auto_c2_url, detect_local_ip

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_templates(tmp_path: Path) -> Path:
    """A temporary templates directory with one test template."""
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "basic.py").write_text(
        'C2 = "URSA_C2_URL"\n'
        'INTERVAL = int("URSA_INTERVAL")\n'
        'JITTER = float("URSA_JITTER")\n'
    )
    return tdir


@pytest.fixture()
def tmp_templates_multi(tmp_path: Path) -> Path:
    """Templates directory with multiple extensions."""
    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "http_py.py").write_text('C2 = "URSA_C2_URL"\n')
    (tdir / "http_zig.zig").write_text(
        'const C2_URL: []const u8 = "URSA_C2_URL";\n'
        "const INTERVAL: u64 = URSA_INTERVAL;\n"
        "const JITTER: f64 = URSA_JITTER;\n"
    )
    (tdir / "http_go.go").write_text('var c2 = "URSA_C2_URL"\n')
    return tdir


@pytest.fixture()
def builder(tmp_templates: Path) -> Builder:
    return Builder(templates_dir=tmp_templates)


@pytest.fixture()
def config() -> PayloadConfig:
    return PayloadConfig(
        c2_url="http://10.0.0.1:8443",
        interval=10,
        jitter=0.2,
        template="basic",
    )


# ── PayloadConfig ─────────────────────────────────────────────────────────────


class TestPayloadConfig:
    def test_tokens_defaults(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443")
        tokens = cfg.tokens()
        assert tokens["URSA_C2_URL"] == "http://1.2.3.4:8443"
        assert tokens["URSA_INTERVAL"] == "5"
        assert tokens["URSA_JITTER"] == "0.1"

    def test_tokens_custom_values(self, config: PayloadConfig):
        tokens = config.tokens()
        assert tokens["URSA_C2_URL"] == "http://10.0.0.1:8443"
        assert tokens["URSA_INTERVAL"] == "10"
        assert tokens["URSA_JITTER"] == "0.2"

    def test_extra_tokens_included(self):
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            extra_tokens={"URSA_CUSTOM": "hello"},
        )
        assert cfg.tokens()["URSA_CUSTOM"] == "hello"


# ── Builder.list_templates ────────────────────────────────────────────────────


class TestListTemplates:
    def test_lists_available_templates(self, builder: Builder, tmp_templates: Path):
        (tmp_templates / "second.py").write_text("")
        names = builder.list_templates()
        assert "basic" in names
        assert "second" in names

    def test_returns_stems_not_filenames(self, builder: Builder):
        names = builder.list_templates()
        assert all(not n.endswith(".py") for n in names)

    def test_sorted_alphabetically(self, builder: Builder, tmp_templates: Path):
        (tmp_templates / "aaa.py").write_text("")
        (tmp_templates / "zzz.py").write_text("")
        names = builder.list_templates()
        assert names == sorted(names)

    def test_empty_directory(self, tmp_path: Path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        assert Builder(templates_dir=empty_dir).list_templates() == []

    def test_missing_directory(self, tmp_path: Path):
        missing = tmp_path / "nonexistent"
        assert Builder(templates_dir=missing).list_templates() == []


# ── Builder.build ─────────────────────────────────────────────────────────────


class TestBuild:
    def test_substitutes_c2_url(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert "http://10.0.0.1:8443" in source
        assert "URSA_C2_URL" not in source

    def test_substitutes_interval(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert '"10"' in source or "int(\"10\")" in source or "10" in source
        assert "URSA_INTERVAL" not in source

    def test_substitutes_jitter(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        assert "URSA_JITTER" not in source

    def test_all_tokens_replaced(self, builder: Builder, config: PayloadConfig):
        source = builder.build(config)
        for token in ("URSA_C2_URL", "URSA_INTERVAL", "URSA_JITTER"):
            assert token not in source

    def test_missing_template_raises(self, builder: Builder):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443", template="doesnotexist")
        with pytest.raises(FileNotFoundError, match="doesnotexist"):
            builder.build(cfg)

    def test_extra_tokens_substituted(self, tmp_templates: Path):
        (tmp_templates / "custom.py").write_text("KEY = 'URSA_MYKEY'\n")
        b = Builder(templates_dir=tmp_templates)
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            template="custom",
            extra_tokens={"URSA_MYKEY": "secret123"},
        )
        assert "secret123" in b.build(cfg)
        assert "URSA_MYKEY" not in b.build(cfg)

    def test_returns_string(self, builder: Builder, config: PayloadConfig):
        assert isinstance(builder.build(config), str)


# ── Builder.build_stager ──────────────────────────────────────────────────────


class TestBuildStager:
    def test_substitutes_c2_url(self, tmp_path: Path):
        stager = tmp_path / "stager.py"
        stager.write_text('C2 = "URSA_C2_URL"\n')

        import implants.builder as bmod
        orig = bmod.STAGER_PATH
        bmod.STAGER_PATH = stager
        try:
            source = Builder().build_stager("http://10.0.0.1:8443")
        finally:
            bmod.STAGER_PATH = orig

        assert "http://10.0.0.1:8443" in source
        assert "URSA_C2_URL" not in source

    def test_missing_stager_raises(self, tmp_path: Path):
        import implants.builder as bmod
        orig = bmod.STAGER_PATH
        bmod.STAGER_PATH = tmp_path / "nonexistent.py"
        try:
            with pytest.raises(FileNotFoundError):
                Builder().build_stager("http://1.2.3.4:8443")
        finally:
            bmod.STAGER_PATH = orig


# ── Builder.write / build_to_file ─────────────────────────────────────────────


class TestWrite:
    def test_writes_file(self, tmp_path: Path):
        out = tmp_path / "payload.py"
        Builder().write("# hello\n", out)
        assert out.read_text() == "# hello\n"

    def test_creates_parent_dirs(self, tmp_path: Path):
        out = tmp_path / "deep" / "nested" / "payload.py"
        Builder().write("x", out)
        assert out.exists()

    def test_build_to_file(self, builder: Builder, config: PayloadConfig, tmp_path: Path):
        out = tmp_path / "out.py"
        result = builder.build_to_file(config, out)
        assert result == out
        assert "http://10.0.0.1:8443" in out.read_text()


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestHelpers:
    def test_auto_c2_url_format(self):
        url = auto_c2_url(port=9000)
        assert url.startswith("http://")
        assert ":9000" in url

    def test_detect_local_ip_returns_string(self):
        ip = detect_local_ip()
        assert isinstance(ip, str)
        assert "." in ip  # IPv4 dotted notation

    def test_auto_c2_url_default_port(self):
        url = auto_c2_url()
        assert ":8443" in url


# ── real http_python template ─────────────────────────────────────────────────


class TestRealTemplate:
    """Smoke-test the actual http_python template that ships with the project."""

    def test_http_python_builds(self):
        b = Builder()  # uses default templates dir
        if "http_python" not in b.list_templates():
            pytest.skip("http_python template not present")
        cfg = PayloadConfig(c2_url="http://192.168.1.1:8443", template="http_python")
        source = b.build(cfg)
        assert "192.168.1.1" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source


# ── Multi-extension template discovery ───────────────────────────────────────


class TestMultiExtension:
    def test_lists_zig_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert "http_zig" in names

    def test_lists_go_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        assert "http_go" in b.list_templates()

    def test_all_three_present(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert set(names) == {"http_go", "http_py", "http_zig"}

    def test_sorted_alphabetically(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        names = b.list_templates()
        assert names == sorted(names)

    def test_no_duplicates_on_stem_conflict(self, tmp_templates_multi: Path):
        # If two files share a stem, only one entry should appear.
        (tmp_templates_multi / "http_zig.py").write_text("# duplicate stem\n")
        b = Builder(templates_dir=tmp_templates_multi)
        assert b.list_templates().count("http_zig") == 1

    def test_builds_zig_template(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        cfg = PayloadConfig(c2_url="http://10.0.0.1:8443", template="http_zig")
        source = b.build(cfg)
        assert "http://10.0.0.1:8443" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source

    def test_finds_zig_by_stem(self, tmp_templates_multi: Path):
        b = Builder(templates_dir=tmp_templates_multi)
        p = b.template_path("http_zig")
        assert p.suffix == ".zig"


# ── PayloadConfig.post_build ──────────────────────────────────────────────────


class TestPostBuild:
    def test_default_is_empty(self):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443")
        assert cfg.post_build == ""

    def test_custom_post_build_stored(self):
        cmd = "zig build-exe {output} -femit-bin={binary}"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443", post_build=cmd)
        assert cfg.post_build == cmd

    def test_post_build_not_in_tokens(self):
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            post_build="zig build-exe {output}",
        )
        assert "post_build" not in cfg.tokens()


# ── Builder.compile ───────────────────────────────────────────────────────────


class TestCompile:
    def test_returns_none_when_no_post_build(self, tmp_path: Path):
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443")
        result = Builder().compile(cfg, tmp_path / "agent.zig")
        assert result is None

    def test_returns_binary_path_on_success(self, tmp_path: Path):
        src = tmp_path / "agent.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            post_build="echo {output}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            result = Builder().compile(cfg, src)
        assert result == tmp_path / "agent"  # extension stripped

    def test_raises_on_nonzero_exit(self, tmp_path: Path):
        src = tmp_path / "agent.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            post_build="false",  # always exits 1
        )
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, ["false"])
            with pytest.raises(subprocess.CalledProcessError):
                Builder().compile(cfg, src)

    def test_substitutes_output_placeholder(self, tmp_path: Path):
        src = tmp_path / "payload.zig"
        src.write_text("// stub\n")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            post_build="mycc {output} -o {binary}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            Builder().compile(cfg, src)
        call_args = mock_run.call_args[0][0]  # first positional arg = cmd list
        assert str(src) in call_args
        assert str(tmp_path / "payload") in call_args


# ── Builder.build_and_compile ─────────────────────────────────────────────────


class TestBuildAndCompile:
    def test_returns_source_path(self, tmp_templates: Path, tmp_path: Path):
        out = tmp_path / "payload.py"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443", template="basic")
        src, _bin = Builder(templates_dir=tmp_templates).build_and_compile(cfg, out)
        assert src == out
        assert out.exists()

    def test_binary_none_when_no_post_build(self, tmp_templates: Path, tmp_path: Path):
        out = tmp_path / "payload.py"
        cfg = PayloadConfig(c2_url="http://1.2.3.4:8443", template="basic")
        _src, binary = Builder(templates_dir=tmp_templates).build_and_compile(cfg, out)
        assert binary is None

    def test_binary_returned_when_post_build_set(
        self, tmp_templates: Path, tmp_path: Path
    ):
        out = tmp_path / "agent.zig"
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443",
            template="basic",
            post_build="echo {output}",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = None
            _src, binary = Builder(templates_dir=tmp_templates).build_and_compile(
                cfg, out
            )
        assert binary == tmp_path / "agent"


# ── Real http_zig template ────────────────────────────────────────────────────


class TestRealZigTemplate:
    """Smoke-test the http_zig.zig template that ships with the project."""

    def test_http_zig_builds(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        cfg = PayloadConfig(c2_url="http://192.168.1.1:8443", template="http_zig")
        source = b.build(cfg)
        assert "192.168.1.1" in source
        assert "URSA_C2_URL" not in source
        assert "URSA_INTERVAL" not in source
        assert "URSA_JITTER" not in source

    def test_http_zig_numeric_interval(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        cfg = PayloadConfig(
            c2_url="http://1.2.3.4:8443", template="http_zig", interval=15
        )
        source = b.build(cfg)
        assert "15" in source
        assert "URSA_INTERVAL" not in source

    def test_http_zig_template_has_zig_extension(self):
        b = Builder()
        if "http_zig" not in b.list_templates():
            pytest.skip("http_zig template not present")
        assert b.template_path("http_zig").suffix == ".zig"
