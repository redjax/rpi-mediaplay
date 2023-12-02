"""Generate an SSH keypair.

Outputs to the project's DATA_DIR, path concatenated from DATA_DIR + keypair_name.
"""
from __future__ import annotations

import sys

sys.path.append(".")

from pathlib import Path

from constants import TARGETS_DIR
from domain.ssh import RemoteHostSSH
from gen_ssh import POST_GEN_MSG, generate_keys, copy_ssh_keys
from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

from provides.utils.path_utils import load_host_configs
from provides.utils.debug_utils import dbg_hosts
from provides.utils import sshlib


def gen_copy_ssh_keys(host: RemoteHostSSH | None = None) -> bool:
    """Copy SSH keys to a provided RemoteHostSSH object."""
    if not host.keyfiles_dir.exists():
        log.info(f"Host keyfiles do not exist at {host.keyfiles_dir}. Generating keys.")
        gen_keys_res = generate_keys(host.private_key)

        if not gen_keys_res:
            log.error(f"Unable to generate SSH keys")
            exit(1)

    else:
        log.info(f"Host [{host.name}] keyfile directory exists at {host.keyfiles_dir}")
        if host.private_key.exists() and host.public_key.exists():
            log.info(f"Host [{host.name}] keys already exist at {host.keyfiles_dir}")
        else:
            log.warning(
                f"Keyfiles directory '{host.keyfiles_dir}' exists, but one or more keys do not."
            )
            log.warning(
                f"Private key ({host.private_key}) exists: {host.private_key.exists()}, Public key ({host.public_key}) exists: {host.public_key.exists()}"
            )

    log.info(f"Attempting to copy SSH key to {host.hostname}")
    copy_res = copy_ssh_keys(host=host)

    return copy_res


def ssh_keygen_main(DEBUG: bool = False) -> None:
    hosts: list[RemoteHostSSH] = load_host_configs(search_dir=TARGETS_DIR)

    if DEBUG:
        dbg_hosts(hosts)

    for host in hosts:
        gen_copy_res = gen_copy_ssh_keys(host=host)

        if gen_copy_res:
            test_conn_res = sshlib.test_connection(host=host)
        else:
            log.error(f"Error generating & copying SSH keys. Skipping connection test.")


if __name__ == "__main__":
    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])

    ssh_keygen_main(DEBUG=True)
