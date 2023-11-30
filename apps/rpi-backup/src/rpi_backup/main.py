from __future__ import annotations

import sys

sys.path.append(".")

from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

from utils.path_utils import load_host_configs
from utils import sshlib
from constants import TARGETS_DIR

from generate_ssh_keys import ssh_keygen_main

if __name__ == "__main__":
    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])
    log.info(
        f"[env:{app_settings.env}|container_env:{app_settings.container_env}] main.py start"
    )

    remote_hosts = load_host_configs(search_dir=TARGETS_DIR)
    log.debug(f"Remote hosts [{len(remote_hosts)}]: {remote_hosts}")

    for host in remote_hosts:
        if not host.private_key.exists():
            ssh_keygen_main()
        else:
            log.info(f"Found SSH key for host {host.hostname} at {host.private_key}")

        hostname_test = sshlib.test_connection(host=host)
        log.debug(f"Hostname test success: {hostname_test}")

    # test_ls = sshlib.ssh_exec(remote_host=remote_hosts[0], cmd="ls -la")
    # log.debug(f"'ls' test output:\n{test_ls.stdout}")
