from __future__ import annotations

from pathlib import Path

POST_GEN_MSG: str = """
!! ----------- !!
!   IMPORTANT   !
!! ----------- !!

Don't forget to copy the public key to the target machine before running any scripts
that will interact with the remote. Scroll up to see the path your keys were outputted to.

Example:
    $ ssh-copy-id -i .data/ssh/keypairs/example-host/id_rsa.pub user@example-host    
"""

SSH_KEY_OUTPUT_DIR: Path = Path("./ssh_keypairs")
