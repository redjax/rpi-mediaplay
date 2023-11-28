from __future__ import annotations

import sys

sys.path.append(".")

from gen_ssh import generate_keys, prompt_generate_keys
from gen_ssh.constants import SSH_KEY_OUTPUT_DIR

if __name__ == "__main__":
    prompt_generate_keys(output_dir=SSH_KEY_OUTPUT_DIR)
