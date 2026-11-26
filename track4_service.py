"""Adapter entry point for Hackathon Track 4.

Reads JSON from stdin, calls team_app.dispatch(request),
writes single JSON to stdout, exits 0.

Never prints key material, shared secrets, private keys, or protected resource
contents to stdout/stderr. All diagnostics/errors go to stderr only.
"""

import sys
import json
import traceback

# Ensure team_app is importable from the same root
import team_app


def run_service():
    """Read one JSON object from stdin, dispatch, write JSON to stdout, exit 0."""
    try:
        raw = sys.stdin.readline()
        if not raw:
            # EOF - write empty/ERROR JSON and exit
            sys.stdout.write(json.dumps({"status": "error", "message": "no_input"}))
            sys.stdout.flush()
            sys.exit(0)
        request = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        sys.stderr.flush()
        sys.stdout.write(json.dumps({"status": "error", "message": "invalid_json"}))
        sys.stdout.flush()
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Input read error: {e}\n")
        sys.stderr.flush()
        sys.stdout.write(json.dumps({"status": "error", "message": str(e)}))
        sys.stdout.flush()
        sys.exit(0)

    try:
        resp = team_app.dispatch(request)
        # Strictly one valid JSON object on stdout
        sys.stdout.write(json.dumps(resp, separators=(",", ":")))
        sys.stdout.flush()
    except Exception as e:
        # Unexpected error - emit to stderr, JSON on stdout
        sys.stderr.write(f"Dispatch error: {e}\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        sys.stdout.write(json.dumps({"status": "error", "message": "dispatch_failed"}))
        sys.stdout.flush()

    sys.exit(0)


if __name__ == "__main__":
    run_service()
