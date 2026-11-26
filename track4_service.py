"""JSON stdin/stdout service adapter.

Reads exactly one JSON object from stdin, calls src.dispatch.dispatch(),
writes exactly one JSON object to stdout and exits 0.  Diagnostics go to
stderr only.  Responses never contain key material, shared secrets, private
keys or protected plaintext.

Hardening:
* NO traceback is ever printed; every failure path emits a valid JSON
  error object (a failure inside json.dumps itself is caught too).
* A process-level advisory file lock (fcntl) serializes concurrent
  adapter processes against one state dir, so read-modify-write cycles
  (load -> mutate -> save) cannot interleave across processes.
"""

import fcntl
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _emit(obj):
    """One JSON object on stdout - guaranteed, even on serialization bugs."""
    try:
        text = json.dumps(obj, separators=(",", ":"))
    except Exception:
        # Never leak internals; a non-serializable value is our bug.
        text = json.dumps({"status": "error", "message": "encoding_failed"},
                          separators=(",", ":"))
    sys.stdout.write(text)
    sys.stdout.write("\n")
    sys.stdout.flush()


def run_service():
    try:
        raw = sys.stdin.read()      # contract: one JSON object through EOF
        if not raw.strip():
            _emit({"status": "error", "message": "no_input"})
            return 0
        request = json.loads(raw)
    except json.JSONDecodeError:
        # keep the invalid payload on stderr for the operator only
        sys.stderr.write("Invalid JSON input (not echoed)\n")
        _emit({"status": "error", "message": "invalid_json"})
        return 0
    except Exception:
        sys.stderr.write("Input read error\n")
        _emit({"status": "error", "message": "input_read_failed"})
        return 0

    from src.dispatch import dispatch
    state_dir = os.environ.get("TRACK4_STATE_DIR") or "track4_state"
    lock_path = os.path.join(state_dir, "adapter.lock")
    try:
        os.makedirs(state_dir, exist_ok=True)
        with open(lock_path, "a") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)   # cross-process serialize
            try:
                resp = dispatch(request)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
    except OSError as exc:
        # state dir not writable etc: fail closed, no traceback, no path leak
        sys.stderr.write("State access error\n")
        _emit({"status": "error", "message": "state_unavailable",
               "error_class": type(exc).__name__})
        return 0
    except Exception as exc:
        sys.stderr.write("Dispatch failure\n")
        _emit({"status": "error", "message": "dispatch_failed",
               "error_class": type(exc).__name__})
        return 0
    _emit(resp)
    return 0


if __name__ == "__main__":
    sys.exit(run_service())
