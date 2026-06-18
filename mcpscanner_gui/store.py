"""Encrypted local storage for API keys."""

from __future__ import annotations

import pathlib
import sqlite3

import keyring as _keyring
from cryptography.fernet import Fernet


def _default_db_path() -> pathlib.Path:
    return pathlib.Path.home() / ".mcp-scanner-gui" / "settings.db"


class KeyStore:
    KEYRING_SERVICE = "mcp-scanner-gui"
    KEYRING_USER = "master-key"

    def __init__(self, db_path: pathlib.Path | None = None, keyring_backend=_keyring):
        self._db_path = pathlib.Path(db_path) if db_path else _default_db_path()
        self._keyring = keyring_backend
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_or_create_master_key())
        self._init_db()
        self._migrate_legacy_llm_key()

    def _load_or_create_master_key(self) -> bytes:
        existing = self._keyring.get_password(self.KEYRING_SERVICE, self.KEYRING_USER)
        if existing:
            return existing.encode("ascii")
        key = Fernet.generate_key()
        self._keyring.set_password(
            self.KEYRING_SERVICE, self.KEYRING_USER, key.decode("ascii")
        )
        return key

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS keys ("
                "provider TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS prefs ("
                "name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )

    def set_key(self, provider: str, value: str) -> None:
        token = self._fernet.encrypt(value.encode("utf-8"))
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO keys(provider, ciphertext) VALUES(?, ?) "
                "ON CONFLICT(provider) DO UPDATE SET ciphertext=excluded.ciphertext",
                (provider, token),
            )

    def get_key(self, provider: str) -> str | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT ciphertext FROM keys WHERE provider=?", (provider,)
            ).fetchone()
        if row is None:
            return None
        return self._fernet.decrypt(row[0]).decode("utf-8")

    def clear_key(self, provider: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM keys WHERE provider=?", (provider,))

    def list_providers(self) -> list[str]:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute("SELECT provider FROM keys").fetchall()
        return [r[0] for r in rows]

    def get_pref(self, name: str) -> str | None:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT value FROM prefs WHERE name=?", (name,)
            ).fetchone()
        return row[0] if row else None

    def set_pref(self, name: str, value: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO prefs(name, value) VALUES(?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                (name, value),
            )

    def _migrate_legacy_llm_key(self) -> None:
        """Copy a legacy single 'llm' key into the 'llm:openai' slot once."""
        legacy = self.get_key("llm")
        if legacy and self.get_key("llm:openai") is None:
            self.set_key("llm:openai", legacy)
