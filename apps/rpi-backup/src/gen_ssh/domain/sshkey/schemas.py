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

@dataclass
class KeyPair:
    name: str | None = field(default_factory=random_keyname)
    output_dir: Union[str, Path] = field(default=None)
    backend: Backend = field(default_factory=crypto_default_backend)
    exponent: int = 65537
    size: int = 4096
    
    def __post_init__(self):
        if isinstance(self.output_path, str):
            p: Path = Path(self.output_path)
            self.output_path = p
            
    def ensure_output_path(self) -> None:
        """Ensure existence of output_path Path parameter."""
        if self.output_path is None:
            pass
        else:
            if not self.output_path_exists:
                try:
                    self.output_path.mkdir(parents=True, exist_ok=True)
                except PermissionError as perm:
                    msg = PermissionError(f"Permission error while creating path: {self.output_path.parent}. Details: {perm}")
                    raise msg
                except Exception as exc:
                    msg = Exception(f"Unhandled exception creating output path: {self.output_path.parent}. Details: {exc}")
                    raise msg
                
    def save_keys(self, output_path: Union[str, Path] = None) -> None:
        """Save public/private keypair to output_path."""
        if output_path is None:
            if self.output_path is None:
                print("[WARNING] No 'output_path' parameter provided. Output will be at the root of this app.")
                _path: Path = Path("./ssh/keypairs")
                self.output_path = _path
        else:
            if isinstance(output_path, str):
                output_path: Path = Path(output_path)
            elif isinstance(output_path, Path):
                pass
            else:
                raise TypeError(f"Invalid type for output_path: ({type(output_path)}). Must be one of [str, pathlib.Path]")        
        
        if self.output_path_exists:
            print(f"[WARNING] A keypair already exists at path: {self.output_path}")
            return

        self.ensure_output_path()
        
        privkey: dict[str, bytes] = {"name": "id_rsa", "bytes": self.priv_key}
        pubkey: dict[str, bytes] = {"name": "id_rsa.pub", "bytes": self.pub_key}
        
        try:
            with open(f"{self.output_path}/{privkey['name']}", "wb") as f:
                f.write(privkey['bytes'])
        except Exception as exc:
            raise Exception(f"Unhandled exception saving private key bytes. Details: {exc}")
        
        try:
            with open(f"{self.output_path}/{pubkey['name']}", "wb") as f:
                f.write(pubkey['bytes'])
        except Exception as exc:
            raise Exception(f"Unhandled exception saving public key bytes. Details: {exc}")
        
        print(f"Success: saved keypair to {self.output_path}")
            
    @property
    def output_path(self) -> Path:
        if self.name is None:
            name = random_keyname()
            self.name = name

        _path: Path = Path(f"{self.output_dir}/{self.name}")
        
        return _path

    @property
    def output_path_exists(self) -> bool:
        if self.output_path is None:
            return None
        else:
            return self.output_path.exists()

    @property
    def key_starter(self) -> rsa.RSAPrivateKey:
        """Generate a keypair.

        The public/private key can be accessed with the class properties '.pub_key' and '.priv_key'
        """
        try:
            key: rsa.RSAPrivateKey = rsa.generate_private_key(
                backend=self.backend,
                public_exponent=self.exponent,
                key_size=self.size,
            )

            return key
        except Exception as exc:
            msg = Exception(
                f"Unhandled exception generating RSAPrivateKey. Details: {exc}"
            )
            raise msg

    @property
    def priv_key(self) -> bytes:
        """Extract private key bytestring from key."""
        try:
            private_key: bytes = self.key_starter.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption(),
            )

            return private_key
        except Exception as exc:
            msg = Exception(
                f"Unhandled exception extracting private key bytes from RSAPrivateKey object. Details: {exc}"
            )
            raise msg

    @property
    def pub_key(self) -> bytes:
        """Extract public key bytestring from key."""
        try:
            public_key: bytes = self.key_starter.public_key().public_bytes(
                crypto_serialization.Encoding.OpenSSH,
                crypto_serialization.PublicFormat.OpenSSH,
            )

            return public_key
        except Exception as exc:
            msg = Exception(
                f"Unhandled exception extracting private key bytes from RSAPrivateKey object. Details: {exc}"
            )
            raise msg
