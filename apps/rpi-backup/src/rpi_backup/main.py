from __future__ import annotations

import sys

sys.path.append(".")

from typing import Union
from pathlib import Path

from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

from utils.path_utils import load_host_configs
from utils import sshlib
from constants import TARGETS_DIR, BACKUP_DIR
from domain.ssh import RemoteHostSSH

from generate_ssh_keys import ssh_keygen_main

import pendulum

REMOTE_BACKUP_DIR: str = "/tmp/backup"


def get_backup_ts(as_str: bool = True):
    ts = pendulum.now()

    if as_str:
        formatted_ts = ts.strftime("%Y-%m-%d")

        return formatted_ts
    else:
        return ts


def backup_homedir(
    host: RemoteHostSSH | None = None,
    local_backup_output: Union[str, Path] = BACKUP_DIR,
    remote_backup_output: str = REMOTE_BACKUP_DIR,
) -> bool:
    """Create a backup of the /home/host.user directory.

    Backup will be in .tar.gz format, and will be copied to the local host at the path defined
    in local_backup_dir.

    Params:
    -------
    - host (RemoteHostSSH): An initialized RemoteHostSSH object.
    - backup_output (str/Path): A local path to output backup archive to. This should be a directory path,
        not a path to a file.
        - GOOD: .data/backup
        - BAD: .data/backup/hostname.tar.gz
    """
    if host is None:
        raise ValueError("Missing a RemoteHostSSH object")
    if remote_backup_output is None:
        remote_backup_output: str = REMOTE_BACKUP_DIR

    if isinstance(local_backup_output, str):
        local_backup_output: Path = Path(local_backup_output)

    _tmp: Path = Path(f"{local_backup_output}/{host.name}")
    local_backup_output = _tmp

    backup_ts = get_backup_ts()

    remote_backup_output: Path = Path(
        f"{str(f'{remote_backup_output}/home').replace('//', '/')}"
    )
    local_backup_output: Path = Path(f"{str(local_backup_output).replace('//', '/')}")

    if local_backup_output.exists():
        log.warning(f"Backup already exists at {local_backup_output}")

        return False
    else:
        log.info(f"Creating backup of /home/{host.user} on {host.name}")

        archive_name: str = f"{host.name}_{backup_ts}"
        archive_path: str = f"{remote_backup_output}/{archive_name}"
        cmd = f"tar czvf {archive_path}.tar.gz /home/{host.user}"

        ensure_remote_path = sshlib.ensure_remote_path_exists(
            host=host, remote_path=remote_backup_output
        )

        if not ensure_remote_path:
            log.error(
                f"Unable to create backup, could not ensure directory '{remote_backup_output}' exists on host {host.name}"
            )

            return False

        try:
            mkdir_cmd = f"mkdir {remote_backup_output} -pv"

            mkdir_success: bool = sshlib.ssh_exec(remote_host=host, cmd=mkdir_cmd)

            if not mkdir_success:
                log.error(
                    f"Error creating directory {remote_backup_output} on host {host.name}."
                )
                return False

        except Exception as exc:
            msg = Exception(
                f"Unhandled exception creating path {remote_backup_output} on host {host.name}. Details: {exc}"
            )
            log.error(msg)

            return False

        log.info(f"Creating backup of $HOME directory on {host.user}@{host.name}")
        log.debug(f"Backup command: {cmd}")

        try:
            backup_res = sshlib.ssh_exec(remote_host=host, cmd=cmd)

            return True

        except Exception as exc:
            msg = Exception(f"Unhandled exception creating backup file '{archive_name}")
            log.error(msg)

            return False


if __name__ == "__main__":
    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])
    log.info(
        f"[env:{app_settings.env}|container_env:{app_settings.container_env}] main.py start"
    )

    remote_hosts = load_host_configs(search_dir=TARGETS_DIR)
    log.debug(f"Remote hosts [{len(remote_hosts)}]: {remote_hosts}")

    # for host in remote_hosts:
    #     if not host.private_key.exists():
    #         ssh_keygen_main()
    #     else:
    #         log.info(f"Found SSH key for host {host.hostname} at {host.private_key}")

    #     hostname_test = sshlib.test_connection(host=host)
    #     log.debug(f"Hostname test success: {hostname_test}")

    #     if hostname_test:
    #         # test_ls = sshlib.ssh_exec(remote_host=host, cmd="ls -la")
    #         # log.debug(f"'ls' test output:\n{test_ls.stdout}")

    #         test_backup = backup_homedir(host=host)
    #         log.debug(
    #             f"[{host.user}@{host.name}] Backup homedir test success: {test_backup}"
    #         )

    log.debug(f"TMP: TEST SFTP")

    test = sshlib.check_remote_path_exists(
        host=remote_hosts[0], remote_path="/home/osmc"
    )
    log.debug(
        f"Remote path '/home/osmc' exists on remote {remote_hosts[0].name}: {test}"
    )
