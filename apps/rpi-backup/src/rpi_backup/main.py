from __future__ import annotations

import sys

sys.path.append(".")

from loguru import logger as log
from provides.conf import app_settings
from red_utils.ext.loguru_utils import LoguruSinkStdOut, init_logger

if __name__ == "__main__":
    init_logger(sinks=[LoguruSinkStdOut(level=app_settings.log_level).as_dict()])
    log.info(
        f"[env:{app_settings.env}|container_env:{app_settings.container_env}] main.py start"
    )
