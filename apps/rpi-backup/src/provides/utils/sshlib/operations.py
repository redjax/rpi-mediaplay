from loguru import logger as log

from typing import Union
from pathlib import Path

import stat
import paramiko

from domain.ssh import RemoteHostSSH, SSHCmdOutput, SSHSFTPOutput, SFTPEntry
from red_utils.ext.context_managers.cli_spinners import SimpleSpinner

from provides.exc import (
    MissingRemoteHostSSHError,
    MissingRemotePathError,
    MissingCmdError,
    MissingLocalPathError,
)


def get_ssh_client(
    remote_host: RemoteHostSSH = None, missing_host_policy=paramiko.AutoAddPolicy()
) -> paramiko.SSHClient:
    if remote_host is None:
        raise MissingRemoteHostSSHError

    try:
        ssh = paramiko.SSHClient()

        ## Set missing host key policy, auto-approve connections to hosts not in authorized_hosts
        ssh.set_missing_host_key_policy(missing_host_policy)

        return ssh
    except Exception as exc:
        raise Exception(
            f"Unhandled exception building paramiko.SSHClient object. Details: {exc}"
        )


def get_sftp(host: RemoteHostSSH = None) -> paramiko.SFTPClient:
    """Connect to an initialized RemoteHostSSH object and get an SFTP client."""
    if host is None:
        raise MissingRemoteHostSSHError

    ssh_client = get_ssh_client(remote_host=host)

    log.info(f"Loading SSH private key from {host.private_key}")
    try:
        pkey = paramiko.RSAKey.from_private_key_file(
            filename=str(host.private_key.absolute())
        )
    except Exception as exc:
        raise Exception(
            f"Unhandled exception opening private key file: {host.private_key.absolute()}. Details: {exc}"
        )

    log.info(f"Connecting to host: {host.user}@{host.name}")
    try:
        ssh_client.connect(
            hostname=host.hostname,
            port=host.port,
            username=host.user,
            # password=password,
            pkey=pkey,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as exc:
        raise Exception(
            f"Unhandled exception connecting to {host.user}@{host.name}. Details: {exc}"
        )

    # log.info(f"Getting SFTPClient")
    try:
        sftp = ssh_client.open_sftp()

        return sftp
    except Exception as exc:
        raise Exception(f"Unhandled exception opening SFTP client. Details: {exc}")


def ssh_exec(remote_host: RemoteHostSSH = None, cmd: str = None) -> SSHCmdOutput:
    """Execute a command on remote host.

    Builds an SSH client object, executes command, and returns an SSHCmdOutput object, which
    has .stdout and .stderr properties.
    """
    if remote_host is None:
        raise MissingRemoteHostSSHError
    if cmd is None:
        raise MissingCmdError

    ssh = get_ssh_client(remote_host=remote_host)
    target_host = remote_host.hostname
    target_port = remote_host.port
    target_key = paramiko.RSAKey.from_private_key_file(
        filename=str(remote_host.private_key.absolute())
    )
    target_user = remote_host.user

    try:
        with SimpleSpinner(f"Executing command on remote: {cmd}"):
            # log.info("Opening SSH connection")
            with ssh as ssh_client:
                ssh_client.connect(
                    hostname=target_host,
                    port=target_port,
                    username=target_user,
                    # password=target_password,
                    pkey=target_key,
                    look_for_keys=False,
                    allow_agent=False,
                )

                stdin, stdout, stderr = ssh_client.exec_command(cmd)

                stdout = stdout.read().decode().strip()
                stderr = stderr.read().decode().strip()

                return_obj = SSHCmdOutput(stdout=stdout, stderr=stderr)

                return return_obj

    except paramiko.PasswordRequiredException as pass_req_exc:
        exc_msg = paramiko.PasswordRequiredException(
            f"Password required. Details: {pass_req_exc}"
        )
        log.error(exc_msg)
    except paramiko.BadHostKeyException as bad_hostkey_exc:
        exc_msg = paramiko.BadHostKeyException(
            f"Bad host key. Details: {bad_hostkey_exc}"
        )
        log.error(exc_msg)
    except paramiko.BadAuthenticationType as bad_auth_exc:
        exc_msg = paramiko.BadAuthenticationType(
            f"Bad authentication type. Details: {bad_auth_exc}"
        )
        log.error(exc_msg)
    except paramiko.AuthenticationException as auth_exc:
        exc_msg = paramiko.AuthenticationException(
            f"Unable to authenticate. Details: {auth_exc}"
        )
        log.error(exc_msg)
    except Exception as exc:
        exc_msg = Exception(
            f"Unhandled exception executing SSH connection. Details: {exc}"
        )
        log.error(exc_msg)


def sftp_crawl(
    remote_host: RemoteHostSSH = None, remote_dir: str = None, recursive: bool = False
) -> SSHSFTPOutput:
    """Open SFTP connection, list all files/dirs in remote_dir."""
    if remote_host is None:
        raise MissingRemoteHostSSHError
    if remote_dir is None:
        raise MissingRemotePathError

    ssh = get_ssh_client(remote_host=remote_host)
    target_host = remote_host.hostname
    target_port = remote_host.port
    target_key = paramiko.RSAKey.from_private_key_file(
        filename=str(remote_host.private_key.absolute())
    )
    target_user = remote_host.user

    sftp_res: SSHSFTPOutput = SSHSFTPOutput(remote_dir=remote_dir, files=[], dirs=[])

    def crawl_remote(
        remote_dir=remote_dir,
        ssh_client: paramiko.SSHClient = ssh,
        host=target_host,
        port=target_port,
        user=target_user,
        # password=target_password,
        pkey=target_key,
        results_obj: SSHSFTPOutput = sftp_res,
    ):
        try:
            ssh_client.connect(
                hostname=host,
                port=port,
                username=user,
                # password=password,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
            )

            ## Start SFTP
            sftp: paramiko.SFTPClient = ssh_client.open_sftp()

            for entry in sftp.listdir_attr(remote_dir):
                mode = entry.st_mode
                if stat.S_ISDIR(mode):
                    remote_entry_path: str = f"{remote_dir}/{entry.filename}".replace(
                        "//", "/"
                    )
                    FILE: SFTPEntry = SFTPEntry(
                        host=remote_host.hostname,
                        type="dir",
                        name=entry.filename,
                        remote_path=remote_entry_path,
                        chmod=entry.st_mode,
                        size=entry.st_size,
                        last_accessed=entry.st_atime,
                        last_modified=entry.st_mtime,
                        uid=entry.st_uid,
                        gid=entry.st_gid,
                    )

                    results_obj.dirs.append(FILE)

                elif stat.S_ISREG(mode):
                    remote_entry_path: str = f"{remote_dir}/{entry.filename}".replace(
                        "//", "/"
                    )
                    DIR: SFTPEntry = SFTPEntry(
                        host=remote_host.hostname,
                        type="file",
                        name=entry.filename,
                        remote_path=remote_entry_path,
                        chmod=entry.st_mode,
                        size=entry.st_size,
                        last_accessed=entry.st_atime,
                        last_modified=entry.st_mtime,
                        uid=entry.st_uid,
                        gid=entry.st_gid,
                    )

                    results_obj.files.append(DIR)

        except paramiko.PasswordRequiredException as pass_req_exc:
            exc_msg = paramiko.PasswordRequiredException(
                f"Password required. Details: {pass_req_exc}"
            )
            log.error(exc_msg)
        except paramiko.BadHostKeyException as bad_hostkey_exc:
            exc_msg = paramiko.BadHostKeyException(
                f"Bad host key. Details: {bad_hostkey_exc}"
            )
            log.error(exc_msg)
        except paramiko.BadAuthenticationType as bad_auth_exc:
            exc_msg = paramiko.BadAuthenticationType(
                f"Bad authentication type. Details: {bad_auth_exc}"
            )
            log.error(exc_msg)
        except paramiko.AuthenticationException as auth_exc:
            exc_msg = paramiko.AuthenticationException(
                f"Unable to authenticate. Details: {auth_exc}"
            )
            log.error(exc_msg)
        except Exception as exc:
            exc_msg = Exception(
                f"Unhandled exception executing SSH connection. Details: {exc}"
            )
            log.error(exc_msg)

        return results_obj

    with SimpleSpinner(f"Crawling remote path: {remote_dir}, recurse: {recursive}"):
        sftp_res = crawl_remote(remote_dir=remote_dir, results_obj=sftp_res)

    if recursive:
        for d in sftp_res.dirs:
            with SimpleSpinner(f"Crawling subdirectory: {d.remote_path}"):
                sftp_res = crawl_remote(remote_dir=d.remote_path, results_obj=sftp_res)
    else:
        pass

    return sftp_res


def test_connection(
    host: RemoteHostSSH = None,
    cmd: str | None = "echo '[REMOTE CONNECTION TEST] Hostname:' $HOSTNAME",
) -> bool:
    if host is None:
        raise MissingRemoteHostSSHError
    if cmd is None:
        raise MissingCmdError

    log.info(f"Testing connectivity with hostname command")
    try:
        test_ssh = ssh_exec(
            remote_host=host,
            cmd="echo '[REMOTE CONNECTION TEST] Hostname:' $HOSTNAME",
        )
        log.debug(test_ssh.stdout)

        return True

    except Exception as exc:
        msg = Exception(f"Unhandled exception performing hostname test. Details: {exc}")
        log.error(msg)

        return False


def ensure_remote_path_exists(
    host: RemoteHostSSH = None, remote_path: str = None
) -> bool:
    """Run an mkdir command on a remote host to ensure a path exists."""
    if host is None:
        raise MissingRemoteHostSSHError
    if remote_path is None:
        raise MissingRemotePathError

    cmd = f"mkdir -pv {remote_path}"

    log.info(f"[{host.name}] Running command: {cmd}")

    try:
        mkdir_res = ssh_exec(remote_host=host, cmd=cmd)

        return True
    except Exception as exc:
        msg = msg = Exception(
            f"Unhandled exception running command {cmd} on host {host.name}. Details: {exc}"
        )
        log.error(msg)


def check_remote_path_exists(
    host: RemoteHostSSH = None, remote_path: str = None
) -> bool:
    """Check if a path to a file/dir exists on a RemoteHostSSH object."""
    if host is None:
        raise MissingRemoteHostSSHError
    if remote_path is None:
        raise MissingRemotePathError

    log.info(f"[{host.name}] Checking if path exists: {remote_path}")
    with get_sftp(host=host) as sftp_client:
        try:
            remote_exists = sftp_client.stat(remote_path)
            return True

        except IOError:
            log.warning(f"[{host.name}] Did not find path: '{remote_path}'")

            return False

        except Exception as exc:
            msg = Exception(
                f"Unhandled exception checking for existence of path {remote_path} on host {host.name}. Details: {exc}"
            )
            log.error(msg)

            return False


def list_remote_files(host: RemoteHostSSH = None, remote_path: str = None) -> list[str]:
    """Connect to a RemoteHostSSH object and list files in a remote_path."""
    if host is None:
        raise MissingRemoteHostSSHError
    if remote_path is None:
        raise MissingRemotePathError

    log.info(f"[{host.name}] Listing files in dir: {remote_path}")
    try:
        with get_sftp(host=host) as sftp:
            files: list[files] = sftp.listdir()

    except Exception as exc:
        msg = Exception(
            f"[{host.name}] Unhandled exception listing files in remote dir: {remote_path}. Details: {exc}"
        )
        log.error(msg)

        raise msg

    if files is not None and len(files) > 0:
        log.debug(
            f"[{host.name}] Found [{len(files)}] files in remote dir: {remote_path}"
        )

    else:
        log.debug(f"[{host.name}] No files found in remote dir: {remote_path}")

    return files


def copy_from_remote(
    host: RemoteHostSSH = None,
    remote_path: str = None,
    local_path: Union[str, Path] = None,
) -> bool:
    if host is None:
        raise MissingRemoteHostSSHError
    if remote_path is None:
        raise MissingRemotePathError
    if local_path is None:
        raise MissingLocalPathError

    log.info(f"[{host.name}] Listing files in dir: {remote_path}")
    files = list_remote_files(host=host, remote_path=remote_path)

    if files is not None:
        if len(files) > 0:
            if Path(remote_path).name in files:
                log.info(
                    f"[{host.name}] Success: Found remote file '{Path(remote_path).name}' in directory {Path(remote_path).parent}"
                )
            else:
                log.warning(
                    f"[{host.name}] Did not find file '{Path(remote_path).name}' in directory {Path(remote_path).parent}"
                )

                return None

    else:
        return None
