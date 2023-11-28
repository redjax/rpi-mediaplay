"""Generate an RSA SSH keypair.

Copy the public (.pub) key to the remote.
"""
from __future__ import annotations

import sys

sys.path.append(".")

from pathlib import Path
from typing import Union

from gen_ssh.domain import KeyPair

def generate_keys(name: str = None, keypair: KeyPair = KeyPair(), output_dir: Union[str, Path] = None) -> None:
    keypair.output_dir = output_dir
    keypair.name = name
    
    print(f"Saving keypair to: {keypair.output_path.absolute()}")
    keypair.save_keys()
    

def prompt_generate_keys() -> None:
    """Guide user through naming keys & specifying output."""
    keypair_name: str = input("Enter a name for new keypair (leave blank for random):\nKeypair name> ")
    if keypair_name == "":
        print(f"[WARNING] Keypair name empty, a random name will be generated.")
        keypair_name = None
        
    print("")
    output_dir: str = input(f"""Enter a directory where generated keys will be saved:
    NOTE: If empty, will use path: {Path('.').absolute()}
          To use a path relative to the project root, write a path without a leading slash
          i.e. 'output/keys'
output path> """)
    if output_dir == "":
        print(f"[WARNING] Output path empty, defaulting to {Path('.').absolute()}")
        output_dir = Path(".")

    print("")

    print("Generating SSH keys")
    generate_keys(name=keypair_name, output_dir=output_dir)

if __name__ == "__main__":
    prompt_generate_keys()
