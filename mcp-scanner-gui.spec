# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for MCP Scanner GUI.

Build with:
    pyinstaller mcp-scanner-gui.spec

Output: dist/MCP Scanner/  (onedir, no console window)
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

block_cipher = None

# ── data files ───────────────────────────────────────────────────────────────

datas = []

# mcpscanner and mcpscanner_gui — collect everything explicitly
mcpscanner_datas, mcpscanner_binaries, mcpscanner_hiddenimports = collect_all("mcpscanner")
mcpscanner_gui_datas, mcpscanner_gui_binaries, mcpscanner_gui_hiddenimports = collect_all("mcpscanner_gui")
datas += mcpscanner_datas
datas += mcpscanner_gui_datas
binaries = mcpscanner_binaries + mcpscanner_gui_binaries
hiddenimports = mcpscanner_hiddenimports + mcpscanner_gui_hiddenimports

# litellm ships a large model-pricing JSON and other assets
litellm_datas, litellm_binaries, litellm_hiddenimports = collect_all("litellm")
datas += litellm_datas

# mcp protocol library
mcp_datas, mcp_binaries, mcp_hiddenimports = collect_all("mcp")
datas += mcp_datas

# tree-sitter grammar packages — each contains a queries/ directory
ts_packages = [
    "tree_sitter",
    "tree_sitter_python",
    "tree_sitter_javascript",
    "tree_sitter_typescript",
    "tree_sitter_java",
    "tree_sitter_go",
    "tree_sitter_rust",
    "tree_sitter_c_sharp",
    "tree_sitter_kotlin",
    "tree_sitter_ruby",
    "tree_sitter_php",
]
for pkg in ts_packages:
    datas += collect_data_files(pkg)

# ── binaries ─────────────────────────────────────────────────────────────────

binaries += litellm_binaries
binaries += mcp_binaries

# ── hidden imports ────────────────────────────────────────────────────────────

hiddenimports += litellm_hiddenimports
hiddenimports += mcp_hiddenimports

# keyring — Windows Credential Manager backend
hiddenimports += [
    "keyring.backends.Windows",
    "keyring.backends.fail",
    "keyring.core",
]

# cryptography (Fernet key storage)
hiddenimports += [
    "cryptography",
    "cryptography.fernet",
    "cryptography.hazmat.backends",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.primitives.ciphers",
]

# yara-python native extension
hiddenimports += ["yara"]

# tree-sitter submodules
for pkg in ts_packages:
    hiddenimports += collect_submodules(pkg)

# mcpscanner subpackages (analyzers live in nested dirs)
hiddenimports += collect_submodules("mcpscanner")
hiddenimports += collect_submodules("mcpscanner_gui")

# tiktoken encodings (used by litellm for token counting)
hiddenimports += ["tiktoken", "tiktoken_ext", "tiktoken_ext.openai_public"]

# httpx transports used at runtime by various async clients
hiddenimports += ["httpx._transports.default", "httpx._transports.asgi"]

# ── analysis ──────────────────────────────────────────────────────────────────

a = Analysis(
    ["build_scripts/gui_launcher.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest", "doctest", "_pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MCP Scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # no terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MCP Scanner",
)
