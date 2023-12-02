from __future__ import annotations

import sys

sys.path.append(".")

from typing import Union
from pathlib import Path

from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

from provides.utils.path_utils import load_host_configs
from provides.utils import sshlib, time_utils
from constants import TARGETS_DIR, BACKUP_DIR
from domain.ssh import RemoteHostSSH

from rpi_backup.utils.backup_utils import backup_homedir

from generate_ssh_keys import ssh_keygen_main

import pendulum

REMOTE_BACKUP_DIR: str = "/tmp/backup"


def copy_backup_from_remote(
    host: RemoteHostSSH = None,
    backup_type: str | None = "home",
    remote_path_base: str = REMOTE_BACKUP_DIR,
    local_backup_output: Union[str, Path] = BACKUP_DIR,
):
    if host is None:
        raise ValueError("Missing RemoteHostSSH object")
    if remote_path_base is None:
        raise ValueError("Missing remote_path_base")
    if local_backup_output is None:
        raise ValueError("Missing local backup output path")
    if backup_type is None:
        raise ValueError("Missing backup type")
    if backup_type not in ["home"]:
        raise ValueError(f"Invalid backup type: {backup_type}. Must be one of ['home']")

    if isinstance(local_backup_output, str):
        local_backup_output: Path = Path(local_backup_output)

    _tmp: Path = Path(f"{local_backup_output}/{host.name}/{backup_type}")
    local_backup_output = _tmp

    local_backup_output: Path = Path(f"{str(local_backup_output).replace('//', '/')}")

    if local_backup_output.exists():
        log.warning(f"Backup already exists at {local_backup_output}")

        return False

    if not local_backup_output.exists():
        local_backup_output.mkdir(parents=True, exist_ok=True)

    remote_backup_path: str = f"{remote_path_base}/{backup_type}"

    log.info(
        f"[Host: {host.name}] Copy remote backup(s) at {remote_backup_path}' -> local path: {local_backup_output}"
    )


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

        if hostname_test:
            # test_ls = sshlib.ssh_exec(remote_host=host, cmd="ls -la")
            # log.debug(f"'ls' test output:\n{test_ls.stdout}")

            homedir_backup = backup_homedir(
                host=host, remote_backup_output=REMOTE_BACKUP_DIR
            )
            log.debug(
                f"[{host.user}@{host.name}] Backup homedir test success: {homedir_backup}"
            )

            # log.info(f"TEST: copy backup from remote")
            # copy_backup_from_remote(host=host)

    # log.debug(f"TMP: TEST SFTP")

    # test = sshlib.check_remote_path_exists(
    #     host=remote_hosts[0], remote_path="/home/test"
    # )
    # log.debug(
    #     f"Remote path '/home/test' exists on remote {remote_hosts[0].name}: {test}"
    # )
