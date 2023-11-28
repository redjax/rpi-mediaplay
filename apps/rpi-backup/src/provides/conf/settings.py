from __future__ import annotations

from typing import Union

from dynaconf import settings
from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings

class AppSettings(BaseSettings):
    """Application settings, with values populated by Dynaconf.

    App will check the environment for whatever value is in 'env' before loading
    from Dynaconf settings.toml file.
    """

    env: str | None = Field(default=settings.ENV, env="ENV")
    container_env: bool = Field(default=settings.CONTAINER_ENV, env="CONTAINER_ENV")
    log_level: str | None = Field(default=settings.LOG_LEVEL, env="LOG_LEVEL")
