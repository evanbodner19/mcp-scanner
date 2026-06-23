"""Assemble the scan `keys` dict from the encrypted KeyStore."""

from __future__ import annotations

from mcpscanner_gui.controllers import llm_store_key_id, required_providers


def assemble_keys(store, analyzers, llm_provider):
    """Return {provider: key_value} for analyzers that need a key.

    Pulls values from `store`. The `llm` provider's key is looked up under the
    `llm:<provider>` id; other providers (`cisco_api`, `virustotal`) use their
    own id. Providers without a stored key are omitted (validation happens later
    in `build_scan_request`).
    """
    keys: dict[str, str] = {}
    for provider in required_providers(analyzers):
        if provider == "llm":
            store_id = llm_store_key_id(llm_provider or "openai")
        else:
            store_id = provider
        value = store.get_key(store_id)
        if value:
            keys[provider] = value
    return keys
