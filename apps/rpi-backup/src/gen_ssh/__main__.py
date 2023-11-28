from __future__ import annotations

import sys

sys.path.append(".")

from gen_ssh import generate_keys, prompt_generate_keys

if __name__ == "__main__":
    prompt_generate_keys()
