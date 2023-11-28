"""Generate an SSH keypair.

Outputs to the project's DATA_DIR, path concatenated from DATA_DIR + keypair_name.
"""
from __future__ import annotations

import sys

sys.path.append(".")

import json

from constants import SSH_KEY_OUTPUT_DIR, TARGETS_DIR
from gen_ssh import POST_GEN_MSG, generate_keys, prompt_generate_keys
from domain.ssh import SSHHostConfig

from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

if __name__ == "__main__":
    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])

    if not TARGETS_DIR.exists():
        raise FileNotFoundError(f"Could not find any targets in {TARGETS_DIR}. Path '{TARGETS_DIR}' exists: {TARGETS_DIR.exists()}")
    
    host_dicts: list[dict] = []
    hosts: list[SSHHostConfig] = []
    
    for f in TARGETS_DIR.glob("**/*.json"):
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
        
    log.debug(f"Loaded [{len(host_dicts)}] host config(s)")
    
    for _host in host_dicts:
        host: SSHHostConfig = SSHHostConfig.model_validate(_host)
        hosts.append(host)
    
    log.debug(f"Converted [{len(hosts)}] host dict(s) to SSHHostConfig object(s)")
    
    if len(hosts) == 1:
        host: SSHHostConfig = hosts[0]
    
        log.debug(f"Detected a single host: {host}")
        log.debug(f"Keys in: {host.keyfiles_dir} -- {'exists' if host.keyfiles_dir.exists() else 'does not exist'}")
        log.debug(f"Private key: {host.private_key} -- {'exists' if host.private_key.exists() else 'does not eixst'}")
        log.debug(f"Public key: {host.public_key} -- {'exists' if host.public_key.exists() else 'does not eixst'}")

    else:
        log.debug(f"Hosts: {hosts}")
        for host in hosts:
            log.debug(f"[HOST: {host.name}] Keys in: {host.keyfiles_dir} -- {'exists' if host.keyfiles_dir.exists() else 'does not exist'}")
            log.debug(f"[HOST: {host.name}] Private key: {host.private_key} -- {'exists' if host.private_key.exists() else 'does not eixst'}")
            log.debug(f"[HOST: {host.name}] Public key: {host.public_key} -- {'exists' if host.public_key.exists() else 'does not eixst'}")
