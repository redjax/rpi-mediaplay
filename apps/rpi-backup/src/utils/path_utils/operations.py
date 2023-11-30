from typing import Union
from pathlib import Path
import json

from domain.ssh import RemoteHostSSH
from constants import TARGETS_DIR

from loguru import logger as log


def load_host_configs(search_dir: Union[str, Path] = None) -> list[RemoteHostSSH]:
    """Load remote host config .json files from a given directory."""
    if search_dir is None:
        raise ValueError(f"Missing search_dir")
    if isinstance(search_dir, str):
        search_dir = Path(search_dir)
        
    if not search_dir.exists():
        raise FileNotFoundError(f"Could not find any targets in {TARGETS_DIR}. Path '{TARGETS_DIR}' exists: {TARGETS_DIR.exists()}")
    
    host_dicts: list[dict] = []
    hosts: list[RemoteHostSSH] = []
    
    for f in search_dir.glob("**/*.json"):
        if f.name == "example.json":
            log.debug(f"Ignoring {f}")
        else:
            try:
                with open(f, "r") as f:
                    data = f.read()
                    
                    host_dict: dict = json.loads(data)
                    host_dicts.append(host_dict)
                    
            except Exception as exc:
                raise Exception(f"Unhandled exception reading JSON file: {f}. Details: {exc}")
            
    for _host in host_dicts:
        host: RemoteHostSSH = RemoteHostSSH.model_validate(_host)
        hosts.append(host)
        
    return hosts