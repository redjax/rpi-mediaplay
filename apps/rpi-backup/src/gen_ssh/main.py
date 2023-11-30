"""Generate an RSA SSH keypair.

Copy the public (.pub) key to the remote.
"""
from __future__ import annotations

import sys

sys.path.append(".")

from loguru import logger as log

from pathlib import Path
from typing import Union

from provides.conf import app_settings
from gen_ssh.constants import POST_GEN_MSG

from domain.ssh import RemoteHostSSH

import subprocess
import getpass


def generate_keys(key_output: Union[str, Path] | None = Path("id_rsa")) -> bool:
    """Generate a public/private RSA SSH keyfile for use with Paramiko.

    By default, outputs keys to the project's root, at ./id_rsa and ./id_rsa_pub.

    Requires host OS to have OpenSSH installed so the ssh-keygen command can be used.

    Params:
    -------
    - key_output (str/Path): Path to output RSA keys. By default, outputs to ./id_rsa.
        Note: If providing a custom path, you must also include the private key's name (default: id_rsa).
                A .pub public key will be created as well.
    """
    if isinstance(key_output, str):
        key_output: Path = Path(key_output)

    if key_output.exists():
        print(f"Key already exists at {key_output}")
        return False

    if not key_output.parent.exists():
        key_output.parent.mkdir(parents=True, exist_ok=True)

    ## Build ssh-keygen command
    cmd = f"ssh-keygen -t rsa -b 4096 -f {key_output} -N ''"

    try:
        ## Execute ssh-keygen command
        process = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Access the captured output
        stdout_result = process.stdout
        stderr_result = process.stderr

        log.info("SSH key generation successful!")
        log.debug(f"STDOUT: {stdout_result}")
        if stderr_result:
            log.error(f"STDERR: {stderr_result}")

        return True

    except subprocess.CalledProcessError as e:
        log.error(f"Error during SSH key generation: {e}")
        log.error("STDOUT:", e.stdout)
        log.error("STDERR:", e.stderr)

        return False


def copy_ssh_keys(host: RemoteHostSSH = None) -> bool:
    """Copy SSH public key to a remote host.

    Params:
    -------
    - host (RemoteHostSSH): An initialized RemoteHostSSH object defining the remote host to copy keys to.
    """
    if host is None:
        raise ValueError("Missing a RemoteHostSSH object")

    if host.port != 22:
        cmd = f"ssh-copy-id -i {host.public_key} -p {host.port} {host.user}@{host.hostname}"
    else:
        cmd = f"ssh-copy-id -i {host.public_key} {host.user}@{host.hostname}"

    if not host.private_key.exists():
        raise FileNotFoundError(f"Could not find SSH key at {host.keyfiles_dir}")

    try:
        ## Copy SSH key with ssh-copy-id. A prompt will appear for the remote user's password
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        process.stdin.flush()

        stdout, stderr = process.communicate()

        log.info(
            f"Successfully copied SSH key {host.public_key} to host {host.hostname}"
        )

        if stdout:
            log.debug(f"STDOUT: {stdout}")
        if stderr:
            log.debug(f"STDERR: {stderr}")

        return True

    except subprocess.CalledProcessError as e:
        log.error(f"Error during SSH key copy: {e}")
        log.error("STDOUT:", e.stdout)
        log.error("STDERR:", e.stderr)

        return False


if __name__ == "__main__":
    from red_utils.ext.loguru_utils import init_logger, LoguruSinkStdOut

    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])
    generate_keys(key_output=Path("id_rsa"))
