import pytest

from mcpscanner_gui.store import KeyStore


class FakeKeyring:
    """In-memory stand-in for the keyring module."""

    def __init__(self):
        self._store = {}

    def get_password(self, service, user):
        return self._store.get((service, user))

    def set_password(self, service, user, value):
        self._store[(service, user)] = value


@pytest.fixture
def store(tmp_path):
    return KeyStore(db_path=tmp_path / "settings.db", keyring_backend=FakeKeyring())


def test_set_and_get_roundtrip(store):
    store.set_key("llm", "sk-secret-123")
    assert store.get_key("llm") == "sk-secret-123"


def test_get_missing_returns_none(store):
    assert store.get_key("virustotal") is None


def test_ciphertext_is_not_plaintext_on_disk(tmp_path):
    db = tmp_path / "settings.db"
    store = KeyStore(db_path=db, keyring_backend=FakeKeyring())
    store.set_key("cisco_api", "PLAINTEXTKEY")
    raw = db.read_bytes()
    assert b"PLAINTEXTKEY" not in raw


def test_clear_key(store):
    store.set_key("llm", "x")
    store.clear_key("llm")
    assert store.get_key("llm") is None


def test_list_providers(store):
    store.set_key("llm", "a")
    store.set_key("virustotal", "b")
    assert sorted(store.list_providers()) == ["llm", "virustotal"]


def test_master_key_persisted_in_keyring(tmp_path):
    kr = FakeKeyring()
    KeyStore(db_path=tmp_path / "s.db", keyring_backend=kr)
    assert kr.get_password("mcp-scanner-gui", "master-key") is not None
