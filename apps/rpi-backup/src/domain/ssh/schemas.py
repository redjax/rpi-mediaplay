from typing import Union
from pathlib import Path

from loguru import logger as log
from pydantic import BaseModel, Field, field_validator, ValidationError

from constants import SSH_KEY_OUTPUT_DIR

class SSHHostConfig(BaseModel):
    name: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    user: str | None = Field(default=None)
    
    @property
    def keyfiles_dir(self) -> Path:
        return Path(f"{SSH_KEY_OUTPUT_DIR}/{self.name}")

    @property
    def private_key(self) -> Path:
        return Path(f"{self.keyfiles_dir}/id_rsa")
    
    @property
    def public_key(self) -> Path:
        return Path(f"{self.keyfiles_dir}/id_rsa.pub")