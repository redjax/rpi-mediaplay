from __future__ import annotations

from pathlib import Path
from typing import Union

from constants import SSH_KEY_OUTPUT_DIR
from loguru import logger as log
import pendulum

from pydantic import BaseModel, Field, ValidationError, field_validator

tz: str = "America/New_York"


class SFTPEntry(BaseModel):
    """A file or directory found on remote host via SFTP."""

    host: str | None = Field(default=None)
    type: str | None = Field(default=None)
    name: str | None = Field(default=None)
    remote_path: str | None = Field(default=None)
    chmod: int | None = Field(default=None)
    ## In bytes
    size: int | None = Field(default=None)
    last_accessed: pendulum.Time | None = Field(default=None)
    last_modified: pendulum.Time | None = Field(default=None)
    uid: int | None = Field(default=None)
    gid: int | None = Field(default=None)

    class Config:
        arbitrary_types_allowed = True

    @property
    def friendly_last_accessed(self) -> str:
        """Convert timestamp to "friendly"/human-readable output."""
        _converted = pendulum.from_timestamp(self.last_accessed, tz=tz)

        return _converted

    @property
    def friendly_last_modified(self) -> str:
        """Convert timestamp to "friendly"/human-readable output."""
        _converted = pendulum.from_timestamp(self.last_modified, tz=tz)

        return _converted

    def as_dict(self) -> dict:
        """Return a dict representation of the SFTP object with limited properties."""
        _dict: dict = {
            "type": self.type,
            "name": self.name,
            "dir": str(Path(f"{self.remote_path}").parent),
            "size": self.size,
            "last_accessed": str(self.friendly_last_accessed),
            "last_modified": str(self.friendly_last_modified),
        }

        return _dict

    @field_validator("type")
    def validate_type(cls, v) -> str:
        if v not in ["file", "dir"]:
            raise ValueError(f"Invalid SFTP entry type: ({v}). Must be 'file' or 'dir")
        elif not isinstance(v, str):
            raise ValidationError
        return v


class SSHCmdOutput(BaseModel):
    """Stores STDIN, STDOUT, and STDERR messages from an SSH command."""

    stdin: str | None = Field(default=None)
    stdout: str | None = Field(default=None)
    stderr: str | None = Field(default=None)


class SSHSFTPOutput(BaseModel):
    """Stores files & directories found on remote host via SFTP."""

    remote_dir: str | None = Field(default=None)
    files: list[SFTPEntry] | None = Field(default=None)
    dirs: list[SFTPEntry] | None = Field(default=None)

    class Config:
        arbitrary_types_allowed = True


class RemoteHostSSH(BaseModel):
    """Define an SSH connection to a remote host."""

    name: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    port: int | None = Field(default=22)
    user: str | None = Field(default="root")
    # password: str | None = Field(default=None, repr=False)
    # ssh_keyfile: str | None = Field(default=None)
    # default_dir: str | None = Field(default=None)

    @property
    def keyfiles_dir(self) -> Path:
        return Path(f"{SSH_KEY_OUTPUT_DIR}/{self.name}")

    @property
    def private_key(self) -> Path:
        return Path(f"{self.keyfiles_dir}/id_rsa")

    @property
    def public_key(self) -> Path:
        return Path(f"{self.keyfiles_dir}/id_rsa.pub")
