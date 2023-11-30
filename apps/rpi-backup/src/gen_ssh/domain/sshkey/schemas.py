from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union
from uuid import uuid4

from gen_ssh.utils.rand_utils import random_keyname

from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import subprocess


@dataclass
class KeyPair:
    name: str | None = field(default_factory=random_keyname)
    output_dir: Union[str, Path] = field(default=None)
    backend: Backend = field(default_factory=crypto_default_backend)
    exponent: int = 65537
    size: int = 4096

    def __post_init__(self):
        if isinstance(self.output_dir, str):
            p: Path = Path(self.output_dir)
            self.output_dir = p

    def ensure_output_path(self) -> None:
        """Ensure existence of output_path Path parameter."""
        if self.output_path is None:
            pass
        else:
            if not self.output_path_exists:
                try:
                    self.output_path.mkdir(parents=True, exist_ok=True)
                except PermissionError as perm:
                    msg = PermissionError(
                        f"Permission error while creating path: {self.output_path}. Details: {perm}"
                    )
                    raise msg
                except Exception as exc:
                    msg = Exception(
                        f"Unhandled exception creating output path: {self.output_path}. Details: {exc}"
                    )
                    raise msg

    # def save_keys(self, output_path: Union[str, Path] = None) -> None:
    #     """Save public/private keypair to output_path."""
    #     if output_path is None:
    #         if self.output_path is None:
    #             print(
    #                 "[WARNING] No 'output_path' parameter provided. Output will be at the root of this app."
    #             )
    #             _path: Path = Path("./ssh/keypairs")
    #             self.output_path = _path
    #     else:
    #         if isinstance(output_path, str):
    #             output_path: Path = Path(output_path)
    #         elif isinstance(output_path, Path):
    #             pass
    #         else:
    #             raise TypeError(
    #                 f"Invalid type for output_path: ({type(output_path)}). Must be one of [str, pathlib.Path]"
    #             )

    #     if self.output_path_exists:
    #         print(f"[WARNING] A keypair already exists at path: {self.output_path}")
    #         return

    #     print(f"[DEBUG] In-class output_path: {self.output_path}")
    #     self.ensure_output_path()

    #     privkey: dict[str, bytes] = {"name": "id_rsa", "bytes": self.priv_key}
    #     pubkey: dict[str, bytes] = {"name": "id_rsa.pub", "bytes": self.pub_key}

    #     try:
    #         with open(f"{self.output_path}/{privkey['name']}", "wb") as f:
    #             f.write(privkey["bytes"])
    #     except Exception as exc:
    #         raise Exception(
    #             f"Unhandled exception saving private key bytes. Details: {exc}"
    #         )

    #     try:
    #         with open(f"{self.output_path}/{pubkey['name']}", "wb") as f:
    #             f.write(pubkey["bytes"])
    #     except Exception as exc:
    #         raise Exception(
    #             f"Unhandled exception saving public key bytes. Details: {exc}"
    #         )

    #     print(f"Success: saved keypair to {self.output_path}")

    # def save_keys(self, key_output: Union[str, Path] | None = "id_rsa") -> bool:
    #     if isinstance(key_output, str):
    #         key_output: Path = Path(key_output)

    #     if key_output.exists():
    #         print(f"Key already exists at {key_output}")
    #         return False

    #     if not key_output.parent.exists():
    #         key_output.parent.mkdir(parents=True, exist_ok=True)

    #     cmd = f"ssh-keygen -t rsa -b 4096 -f {key_output} -N ''"

    #     try:
    #         process = subprocess.run(
    #             cmd,
    #             shell=True,
    #             check=True,
    #             stdout=subprocess.PIPE,
    #             stderr=subprocess.PIPE,
    #             text=True,
    #         )

    #         # Access the captured output
    #         stdout_result = process.stdout
    #         stderr_result = process.stderr

    #         print("SSH key generation successful!")
    #         # print("STDOUT:", stdout_result)
    #         # print("STDERR:", stderr_result)

    #         return True

    #     except subprocess.CalledProcessError as e:
    #         print(f"Error during SSH key generation: {e}")
    #         print("STDOUT:", e.stdout)
    #         print("STDERR:", e.stderr)

    #         return False

    @property
    def output_path(self) -> Path:
        if self.name is None:
            name = random_keyname()
            self.name = name

        _path: Path = Path(f"{self.output_dir}/{self.name}")

        ## For some reason this function returns output_dir/name/name,
        #  instead of output_dir/name. This if statement fixes occurrences
        #  of that issue
        if f"{self.name}/{self.name}" in str(_path):
            _path: Path = Path(f"{self.output_dir}")

        return _path

    @property
    def output_path_exists(self) -> bool:
        if self.output_path is None:
            return None
        else:
            return self.output_path.exists()
