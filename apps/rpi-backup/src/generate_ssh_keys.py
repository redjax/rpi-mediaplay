"""Generate an SSH keypair.

Outputs to the project's DATA_DIR, path concatenated from DATA_DIR + keypair_name.
"""
from __future__ import annotations

import sys

sys.path.append(".")

from constants import SSH_KEY_OUTPUT_DIR
from gen_ssh import POST_GEN_MSG, generate_keys, prompt_generate_keys

if __name__ == "__main__":
    # prompt_generate_keys(output_dir=SSH_KEY_OUTPUT_DIR)
    generate_keys(name="rpi-mediaplay", output_dir=SSH_KEY_OUTPUT_DIR)
    print(POST_GEN_MSG)
