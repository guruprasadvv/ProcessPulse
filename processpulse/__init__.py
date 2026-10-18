"""ProcessPulse-C telemetry package (M1 foundations).

Runs on the system Python with BCC for the privileged collectors and stays
Python 3.12-compatible so the offline/ML layer can import the stdlib-only
modules (schemas, validation, framing, identity).
"""

SCHEMA_VERSION = 1
