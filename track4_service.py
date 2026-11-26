"""JSON stdin/stdout service adapter.

Reads exactly one JSON object from stdin, calls src.dispatch.dispatch(),
writes exactly one JSON object to stdout and exits 0.  Diagnostics go to
stderr only.  Responses never contain key material, shared secrets, private
keys or protected plaintext.
"""

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_service():
    try:
        raw = sys.stdin.read()      # contract: one JSON object through EOF
        if not raw.strip():
            _emit({"status": "error", "message": "no_input"})
            return 0
        request = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write("Invalid JSON input: %s\n" % e)
        _emit({"status": "error", "message": "invalid_json"})
        return 0
    except Exception as e:
        sys.stderr.write("Input read error: %s\n" % e)
        _emit({"status": "error", "message": "input_read_failed"})
        return 0

    from src.dispatch import dispatch
    try:
        resp = dispatch(request)
    except Exception:
        sys.stderr.write(traceback.format_exc())
        resp = {"status": "error", "message": "dispatch_failed"}
    _emit(resp)
    return 0


def _emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(run_service())
