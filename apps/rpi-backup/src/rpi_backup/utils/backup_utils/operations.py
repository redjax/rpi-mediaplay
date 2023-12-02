from typing import Union
from pathlib import Path

from domain.ssh import RemoteHostSSH
from constants import BACKUP_DIR
from provides.utils import time_utils, sshlib

from loguru import logger as log


def backup_homedir(
    host: RemoteHostSSH | None = None,
    remote_backup_output: str = None,
    include_timestamp: bool = True,
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
        raise ValueError("Missing remote output directory for backup")

    backup_ts = time_utils.get_ts_today()

    remote_backup_output: Path = Path(
        f"{str(f'{remote_backup_output}/home').replace('//', '/')}"
    )

    log.info(f"[{host.name}] Creating backup of dir: /home/{host.user}")

    archive_name: str = f"{host.name}"
    if include_timestamp:
        archive_name: str = f"{archive_name}_{backup_ts}"

    archive_path: str = f"{remote_backup_output}/{archive_name}.tar.gz"
    backup_cmd = f"tar czvf {archive_path} /home/{host.user}"

    log.info(f"[Host: {host.name}] Checking if backup exists at: {archive_path}")
    remote_archive_exists: bool = sshlib.check_remote_path_exists(
        host=host, remote_path=archive_path
    )

    if remote_archive_exists:
        log.warning(
            f"[Host: {host.name}] Archive path exists: {archive_path}. Skipping archive"
        )
        return False
    else:
        ensure_remote_path = sshlib.ensure_remote_path_exists(
            host=host, remote_path=remote_backup_output
        )

        if not ensure_remote_path:
            log.error(
                f"[{host.name}] Unable to create backup, could not ensure directory exists: '{remote_backup_output}'"
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
                f"[{host.name}] Unhandled exception creating path: {remote_backup_output}. Details: {exc}"
            )
            log.error(msg)

            return False

        log.info(f"Creating backup of $HOME directory on {host.user}@{host.name}")
        log.debug(f"[{host.name}] Backup command: {backup_cmd}")

        try:
            backup_res = sshlib.ssh_exec(remote_host=host, cmd=backup_cmd)

            if backup_res.stderr:
                log.debug(f"STDERR: {backup_res.stderr}")

            return True

        except Exception as exc:
            msg = Exception(f"Unhandled exception creating backup file '{archive_name}")
            log.error(msg)

            return False
