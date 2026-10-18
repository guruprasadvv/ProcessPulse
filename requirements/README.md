# Dependency boundary

| Layer | Interpreter | Dependencies | Why |
|---|---|---|---|
| Telemetry (`processpulse` agent, C collector, BCC collector) | system `/usr/bin/python3` (3.14 on Ubuntu 26.04), run as root for BCC | apt: `python3-bpfcc` (0.35), `bpfcc-tools`; Python stdlib only | BCC is distributed only as an apt package for the system interpreter. Code stays Python 3.12-compatible. |
| ML / offline (M2+) | Python **3.12** venv (D-14), created by `tools/setup_py312_env.sh` | `py312-dev.txt` now; ML packages (scikit-learn, shap, lime, numpy) are pinned when M4/M5 start, after their versions are verified | Reproducible ML stack; never imports BCC. Consumes recorded JSONL. |

`jsonschema` is used only by tests as a cross-check of the stdlib validator
(`processpulse/validate.py`); the agent itself has no third-party runtime
dependency.
