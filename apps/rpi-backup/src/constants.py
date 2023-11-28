from __future__ import annotations

from pathlib import Path

DATA_DIR: Path = Path(".data")
CACHE_DIR: Path = Path(".cache")
SERIALIZE_DIR: Path = Path(".serialize")

SSH_KEY_OUTPUT_DIR: Path = Path(f"{DATA_DIR}/ssh_keypairs")
TARGETS_DIR: Path = Path("targets")