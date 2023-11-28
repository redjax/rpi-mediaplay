from __future__ import annotations

from dynaconf import Dynaconf

settings = Dynaconf(
    # envvar_prefix="DYNACONF",
    root_path="conf",
    settings_files=["settings.toml", ".secrets.toml"],
)

# `envvar_prefix` = export envvars with `export DYNACONF_FOO=bar`.
# `settings_files` = Load these files in the order.