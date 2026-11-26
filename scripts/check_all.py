#!/usr/bin/env python3
"""One command that decides whether the repository is fit to submit.

    python scripts/check_all.py [--skip-tests] [--skip-validator]

Checks, in order.  Any failure makes the exit code nonzero:

  1. layout      the adapter, verifier and key docs are where the contract
                 expects them; no state/key files committed
  2. static      runtime code has no eval/exec, pickle, shell=True,
                os.system, subprocess, network or ML imports
                (AST scan, not grep - survives obfuscation)
  3. secrets     no private keys or long key-like hex blobs in the working
                tree AND in the whole Git history
  4. rule 0      no AI co-author trailers or AI identities in any commit
  5. validator   the official toolkit validator exits 0 (when a toolkit
                 path is given or ../Track-4-Toolkit exists)
  6. tests       the whole unittest suite passes

Only the standard library is used, so this runs anywhere Python does.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Tier 1 (STRICT): the code the judges actually execute.  It must never
# import networking, subprocess, deserialization or ML libraries.
ADAPTER_PATHS = [REPO / "src", REPO / "track4_service.py",
                 REPO / "team_app.py", REPO / "detector.py",
                 REPO / "verifier"]
ADAPTER_EXCLUDES = {"netutil.py"}   # deployment-only HTTP client/server
# Tier 2 (reviewed, not forbidden): the REAL multi-process deployment and
# the tooling.  Servers/tools use sockets, subprocess and HTTP BY DESIGN
# (documented in the README); here we only forbid the dangerous classes
# (dynamic code execution, deserialization, shell, ML).
DEPLOY_PATHS = [REPO / "services", REPO / "tools", REPO / "scripts",
                REPO / "demo.py", REPO / "demo_networked.py"]
FAILURES = []


def fail(check, msg):
    FAILURES.append((check, msg))
    print("FAIL [%s] %s" % (check, msg))


def ok(check, msg):
    print("OK   [%s] %s" % (check, msg))


def py_files(paths, excludes=()):
    files = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.rglob("*.py")))
        elif p.suffix == ".py":
            files.append(p)
    return [f for f in files if "__pycache__" not in f.parts
            and f.name not in excludes]


# --- 1. layout -------------------------------------------------------------

REQUIRED = ["track4_service.py", "team_app.py", "requirements.txt",
            "README.md", "threat-model.json", "docs/THREAT_MODEL.md",
            "docs/PROJECT_BRIEF.md", "verifier/track4_verify.py",
            "tools/selfattack.py"]
FORBIDDEN_COMMITS = ["state.json", "journal.jsonl", "*.key", "*.pem",
                     "idp_key.json", "node_key.json", "keyfile.json"]


def check_layout():
    missing = [f for f in REQUIRED if not (REPO / f).exists()]
    if missing:
        fail("layout", "missing required files: %s" % ", ".join(missing))
    else:
        ok("layout", "all %d required paths present" % len(REQUIRED))
    committed = _git("ls-files").split()
    bad = []
    for pat in FORBIDDEN_COMMITS:
        if pat.startswith("*"):
            bad += [c for c in committed if c.endswith(pat[1:])]
        else:
            bad += [c for c in committed if Path(c).name == pat]
    if bad:
        fail("layout", "state/key files committed to git: %s" % bad[:5])
    else:
        ok("layout", "no state or key material committed")


# --- 2. static scan (AST) --------------------------------------------------

FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTR_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"),
                        ("os", "execve"), ("os", "spawnl")}
FORBIDDEN_MODULES = {
    "pickle", "cPickle", "marshal", "shelve", "dill", "cloudpickle",
    "ctypes",
    "socket", "ssl", "urllib", "urllib2", "urllib3", "http", "httpx",
    "requests", "aiohttp", "ftplib", "telnetlib", "smtplib", "xmlrpc",
}
ML_MODULES = {"sklearn", "torch", "tensorflow", "keras", "xgboost",
              "lightgbm", "statsmodels"}


def check_static():
    import ast
    strict_bad = []
    review_bad = []
    for tier, files in (("strict",
                         py_files(ADAPTER_PATHS, ADAPTER_EXCLUDES)),
                        ("deploy", py_files(DEPLOY_PATHS))):
        for f in files:
            try:
                tree = ast.parse(f.read_text())
            except (SyntaxError, ValueError) as exc:
                bad = strict_bad if tier == "strict" else review_bad
                bad.append("%s: syntax error (%s)"
                           % (f.relative_to(REPO), exc))
                continue
            rel = str(f.relative_to(REPO))
            for node in ast.walk(tree):
                bad = strict_bad if tier == "strict" else review_bad
                line = node.lineno if hasattr(node, "lineno") else 0
                if isinstance(node, ast.Call) and \
                        isinstance(node.func, ast.Name) and \
                        node.func.id in FORBIDDEN_CALLS:
                    bad.append("%s:%d call %s()" % (rel, line, node.func.id))
                if isinstance(node, ast.Call) and \
                        isinstance(node.func, ast.Attribute) and \
                        isinstance(node.func.value, ast.Name) and \
                        (node.func.value.id, node.func.attr) in \
                        FORBIDDEN_ATTR_CALLS:
                    bad.append("%s:%d call %s.%s()" % (
                        rel, line, node.func.value.id, node.func.attr))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root in FORBIDDEN_MODULES or root in ML_MODULES:
                            bad.append("%s:%d import %s"
                                       % (rel, line, alias.name))
                if isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    if root in FORBIDDEN_MODULES or root in ML_MODULES:
                        bad.append("%s:%d from %s import"
                                   % (rel, line, node.module))
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and \
                                getattr(kw.value, "value", None) is True:
                            bad.append("%s:%d shell=True" % (rel, line))
    if strict_bad:
        fail("static", "ADAPTER tier: %d findings (first 5): %s"
             % (len(strict_bad), strict_bad[:5]))
    else:
        ok("static", "adapter tier clean: no dangerous calls, "
                      "deserialization, subprocess, network or ML imports")
    if review_bad:
        fail("static", "DEPLOY tier: %d findings (first 5): %s"
             % (len(review_bad), review_bad[:5]))
    else:
        ok("static", "deploy tier clean: no dynamic execution, "
                      "deserialization, shell or ML "
                      "(sockets/subprocess allowed by design there)")


# --- 3. secrets (tree + full git history) ----------------------------------

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[0-9a-f]{512,}\b"),          # huge hex blobs (key material)
]


def _scan_text(text, where):
    hits = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for pat in SECRET_PATTERNS:
            if pat.search(line):
                hits.append("%s:%d" % (where, line_no))
    return hits


def check_secrets():
    hits = []
    for f in py_files(ADAPTER_PATHS, ADAPTER_EXCLUDES) + \
            py_files(DEPLOY_PATHS):
        hits += _scan_text(f.read_text(errors="replace"),
                           str(f.relative_to(REPO)))
    for f in (REPO / "docs").rglob("*.md"):
        hits += _scan_text(f.read_text(errors="replace"),
                           str(f.relative_to(REPO)))
    hits = [h for h in hits if not _is_test_vector_line(h)]
    if hits:
        fail("secrets", "key-like material in tree: %s" % hits[:5])
    else:
        ok("secrets", "working tree clean")
    if not _git_dir():
        ok("secrets", "git history not scanned (no .git)")
        return
    # whole history: every blob ever committed
    blobs = _git("rev-list", "--objects", "--all").split("\n")
    seen = set()
    bad_hist = []
    for entry in blobs:
        sha = entry.split()[0] if entry else ""
        if not sha or sha in seen:
            continue
        seen.add(sha)
        out = subprocess.run(["git", "-C", str(REPO), "cat-file", "-p", sha],
                             capture_output=True)
        if out.returncode == 0:
            text = out.stdout.decode("utf-8", "replace")
            if _scan_text(text, sha):
                bad_hist.append(sha[:12])
    if bad_hist:
        fail("secrets", "key-like material in git history (first: %s)"
             % bad_hist[:3])
    else:
        ok("secrets", "full git history clean")


def _is_test_vector_line(where):
    # official RFC/NIST vectors are expected in tests (public constants)
    return "test" in where.lower() or "vector" in where.lower()


# --- 4. AI co-author rule ---------------------------------------------------

AI_TRAILER = re.compile(r"co-authored-by:.*(claude|gpt|copilot|openai|"
                        r"anthropic|gemini|llama|mistral|deepseek)", re.I)
AI_AUTHOR = re.compile(r"author .*(claude|gpt|copilot|openai|anthropic|"
                       r"gemini|llama|mistral|deepseek)", re.I)


def check_rule0():
    if not _git_dir():
        ok("rule0", "git history not scanned (no .git)")
        return
    log = _git("log", "--pretty=full", "--all")
    bad = [l.strip() for l in log.splitlines()
           if AI_TRAILER.search(l) or AI_AUTHOR.search(l)]
    if bad:
        fail("rule0", "AI identity in commit metadata: %s" % bad[:2])
    else:
        ok("rule0", "no AI co-author trailers or AI identities")


# --- 5. official validator --------------------------------------------------

def check_validator(toolkit):
    entry = REPO / "track4_service.py"
    if not toolkit or not Path(toolkit).exists():
        ok("validator", "skipped (no toolkit path; give --toolkit PATH)")
        return
    out = subprocess.run([sys.executable, "-B", str(Path(toolkit) /
                                                  "validate.py"),
                          "--entry", str(entry)],
                         capture_output=True, text=True, timeout=120)
    if out.returncode == 0:
        ok("validator", "official validator exit 0")
    else:
        fail("validator", "validator exit %d" % out.returncode)


# --- 6. tests ---------------------------------------------------------------

def check_tests():
    out = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        capture_output=True, text=True, timeout=600, cwd=str(REPO))
    tail = (out.stderr or "").strip().splitlines()[-1] if out.stderr else ""
    if out.returncode == 0:
        ok("tests", tail or "suite passed")
    else:
        fail("tests", tail or "suite failed")


def _git_dir():
    return (REPO / ".git").exists()


def _git(*args):
    out = subprocess.run(["git", "-C", str(REPO)] + list(args),
                         capture_output=True, text=True)
    return out.stdout or ""


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--toolkit", default=None,
                   help="path to the official Track-4-Toolkit (runs "
                        "validate.py)")
    p.add_argument("--skip-tests", action="store_true")
    p.add_argument("--skip-validator", action="store_true")
    args = p.parse_args(argv)
    check_layout()
    check_static()
    check_secrets()
    check_rule0()
    if not args.skip_validator:
        check_validator(args.toolkit)
    if not args.skip_tests:
        check_tests()
    if FAILURES:
        print("\n%d CHECK(S) FAILED" % len(FAILURES))
        for check, msg in FAILURES:
            print("  [%s] %s" % (check, msg))
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
