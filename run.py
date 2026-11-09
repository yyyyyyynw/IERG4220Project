"""Start AuthLab in normal (non-lab) mode.

    python run.py
    open http://localhost:5010

For the experiment harness, see experiments/run_experiments.py instead.
"""
from __future__ import annotations

import os

from authlab import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("AUTHLAB_HOST", "127.0.0.1"),
        port=int(os.environ.get("AUTHLAB_PORT", "5010")),
        debug=os.environ.get("AUTHLAB_DEBUG", "0") == "1",
        use_reloader=False,
    )
