"""Shared fixtures for the Ursa test suite."""

import sys
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "minor" / "src"))


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Provide a fresh, isolated SQLite database for each test.

    Patches major.db.DB_PATH so all db functions use a temp file.
    """
    import major.db as db_mod

    db_file = tmp_path / "test_ursa.db"
    monkeypatch.setattr(db_mod, "DB_PATH", db_file)
    db_mod.init_db()
    return db_file


@pytest.fixture
def crypto_instance():
    """Return a UrsaCrypto instance with a known test key."""
    from major.crypto import UrsaCrypto

    return UrsaCrypto(b"test-key-for-ursa-crypto-suite!!")


@pytest.fixture
def c2_test_server(tmp_db):
    """Start a real C2 HTTP server on an ephemeral port.

    Yields (host, port). Server runs in a daemon thread and is
    torn down after the test.
    """
    from major.server import UrsaC2Handler

    server = HTTPServer(("127.0.0.1", 0), UrsaC2Handler)
    host, port = server.server_address

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield host, port

    server.shutdown()


@pytest.fixture
def sample_session(tmp_db):
    """Create and return a sample session ID for tests that need one."""
    from major.db import create_session

    return create_session(
        remote_ip="10.0.0.42",
        hostname="TESTBOX",
        username="testuser",
        os_info="Linux 5.15",
        arch="x86_64",
        pid=1234,
        process_name="python3",
        encryption_key="deadbeef" * 8,
        beacon_interval=10,
        jitter=0.2,
    )
