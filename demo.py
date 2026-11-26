#!/usr/bin/env python3
"""Run the scripted end-to-end demonstration and print a readable report."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.demo import demo_script  # noqa: E402

if __name__ == "__main__":
    d = demo_script()
    print("Track 4 demo - %d steps, all_ok=%s\n" % (d["steps"], d["all_ok"]))
    for k, v in d["highlights"].items():
        print("  %-44s %s" % (k, v))
    print("\nfull JSON:")
    print(json.dumps(d, indent=2)[:2000])
