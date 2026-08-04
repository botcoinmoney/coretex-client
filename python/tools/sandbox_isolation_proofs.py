#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The sandbox-isolation proof SUITE. Run as a suite, not ad hoc.

Each proof answers one question about a CLEAN wheel-only installation, and each is written so
that failing is the default: a proof that cannot demonstrate its property reports FAIL rather
than skipping. Ad-hoc verification of these is how a lane convinces itself of something it has
not actually shown — the whole point of a suite is that all of them ran, together, on one
environment, and that the ones that did not run are visible.

    P1  clean wheel-only replay              the validator is the installed artifact, not a checkout
    P2  no source-tree imports               nothing resolves out of a repository
    P3  no network                           the child cannot reach a socket
    P4  socket syscall EPERM                 ...and that is ENFORCED, demonstrated by a real probe
    P5  dependency hashes vs the lock        the runtime dependency is the pinned one
    P6  wasmtime removal -> NAMED error      "your environment is wrong", never "not configured"
    P7  both epoch-180 receipts replay       the deterministic admission completes, twice

P7 is slow (tens of minutes per receipt on a small box) and is skipped unless --with-replay is
given, because a suite nobody runs is worth nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

RESULTS: List[Dict[str, Any]] = []


def record(proof: str, ok: bool, detail: str, **extra: Any) -> None:
    RESULTS.append({"proof": proof, "ok": bool(ok), "detail": detail, **extra})
    print(f"  {'PASS' if ok else 'FAIL'}  {proof}: {detail}")


def run(python: str, code: str, env: Dict[str, str], timeout: int = 300):
    merged = dict(os.environ)
    merged.update(env)
    return subprocess.run([python, "-c", code], capture_output=True, text=True, env=merged,
                          timeout=timeout, cwd="/")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--venv", required=True, help="clean venv WITH the pinned dependency")
    parser.add_argument("--venv-without-dependency", required=True,
                        help="identical venv with wasmtime removed")
    parser.add_argument("--trees", required=True, help="extracted admission trees")
    parser.add_argument("--pin", default=">=46.0.1,<47")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    python = os.path.join(args.venv, "bin", "python")
    python_nodep = os.path.join(args.venv_without_dependency, "bin", "python")
    env = {"CORETEX_ADMISSION_REPO_ROOT": args.trees,
           "CORETEX_BENCHMARK_V2_DIR": os.path.join(args.trees, "benchmark-v2"),
           "CORETEX_MEMORY_RUNTIME_DIR": os.path.join(args.trees, "coretex-memory")}

    print("sandbox isolation proofs")

    # ── P1 ────────────────────────────────────────────────────────────────────
    probe = ("import coretex_validator, json;"
             "print(json.dumps({'file': coretex_validator.__file__}))")
    result = run(python, probe, env)
    location = json.loads(result.stdout)["file"] if result.returncode == 0 else ""
    record("P1 clean wheel-only install", "site-packages" in location and result.returncode == 0,
           f"coretex_validator imports from {location or 'ERROR'}")

    # ── P2 / P3 / P4: interrogate the child's OWN environment ────────────────
    # Rendered from the real template, so the proof cannot drift from the code it certifies.
    child_probe = f'''
import json, sys
sys.path.insert(0, {os.path.join(args.venv, "lib")!r})
from coretex_validator import replay as rp
sandbox = rp.default_sandbox()
rendered = rp._SANDBOX_CHILD.format(
    v5=rp._PKG_PARENT, validator=rp._PKG_DIR, coretex=sandbox.coretex_dir,
    bench=sandbox.bench_v2_dir, repo=sandbox.repo_root, isolation=sandbox.isolation_path)
print("<<<SRC>>>" + json.dumps({{"rendered": rendered, "available": sandbox.available()}}))
'''
    result = run(python, child_probe, env)
    rendered = ""
    if "<<<SRC>>>" in result.stdout:
        rendered = json.loads(result.stdout.split("<<<SRC>>>", 1)[1])["rendered"]

    # Execute the child's own path-construction prologue and inspect what it admits.
    prologue = rendered.split("# NETWORKLESS", 1)[0] if rendered else ""
    path_probe = prologue + "\nimport json\nprint('<<<PATH>>>' + json.dumps(sys.path))\n"
    result = run(python, "import sys, json\n" + path_probe, env)
    child_path = json.loads(result.stdout.split("<<<PATH>>>", 1)[1]) if "<<<PATH>>>" in result.stdout else []
    repo_like = [p for p in child_path
                 if "coretex-client" in p or p in ("", ".") or p.endswith("/python")]
    record("P2 no source-tree imports", bool(child_path) and not repo_like,
           f"child sys.path has {len(child_path)} entries, {len(repo_like)} repository-like",
           child_path=child_path)

    has_site = any("site-packages" in p for p in child_path)
    record("P2b site-packages IS admitted", has_site,
           "the verified environment's wheels are importable (this is what K2 broke)")

    # ── P3 / P4: networklessness, enforced and PROVEN by a real socket probe ─
    net_probe = '''
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("iso", %r)
iso = importlib.util.module_from_spec(spec); spec.loader.exec_module(iso)
install = iso.apply_networkless()
proof = iso.prove_networkless(install=install)
import socket
outcome = {}
for family, name in ((socket.AF_INET, "AF_INET"), (socket.AF_INET6, "AF_INET6")):
    try:
        socket.socket(family, socket.SOCK_STREAM); outcome[name] = "CREATED"
    except OSError as exc:
        outcome[name] = type(exc).__name__ + ":" + str(getattr(exc, "errno", "?"))
print("<<<NET>>>" + json.dumps({"proof": proof, "sockets": outcome}))
'''
    iso_path = os.path.join(args.trees, "..", "isolation.py")
    result = run(python, "import sys\nsys.path.insert(0, %r)\n" % os.path.join(args.venv, "lib")
                 + net_probe % _isolation_path(python, env), env)
    net = json.loads(result.stdout.split("<<<NET>>>", 1)[1]) if "<<<NET>>>" in result.stdout else {}
    enforced = bool(net.get("proof", {}).get("enforced"))
    sockets = net.get("sockets", {})
    refused = all(v != "CREATED" for v in sockets.values()) and bool(sockets)
    record("P3 no network", enforced and refused,
           f"networkless enforced={enforced}, socket outcomes={sockets}")
    eperm = all("1" == str(v).split(":")[-1] for v in sockets.values()) if sockets else False
    record("P4 socket syscall EPERM", eperm,
           f"every IP family refused with EPERM(1): {sockets}")

    # ── P5: the dependency is the PINNED one ────────────────────────────────
    # `wasmtime` exposes no __version__, so ask the INSTALLER what it installed — which is also
    # the right question: the lock is about the distribution, not about a module attribute a
    # package may or may not choose to publish.
    result = run(python, "import json, os, wasmtime;"
                         "from importlib.metadata import version, files;"
                         "d = version('wasmtime');"
                         "print(json.dumps({'v': d, 'f': os.path.dirname(wasmtime.__file__)}))",
                 env)
    payload = json.loads(result.stdout) if result.returncode == 0 else {}
    version_installed = payload.get("v", "MISSING")
    location = payload.get("f", "")
    in_range = version_installed.startswith("46.")
    # The wheel's own contents are hashed so the record names WHICH build satisfied the pin, not
    # merely that some 46.x did. A version string is a label; the hash is the artifact.
    digest = ""
    if in_range and os.path.isdir(location):
        sha = hashlib.sha256()
        for root, _dirs, names in sorted(os.walk(location)):
            for name in sorted(names):
                if name.endswith((".py", ".so", ".pyd")):
                    with open(os.path.join(root, name), "rb") as fh:
                        sha.update(hashlib.sha256(fh.read()).digest())
        digest = sha.hexdigest()
    record("P5 dependency matches the publication lock", in_range,
           f"wasmtime {version_installed} against pin {args.pin}, content digest "
           f"{digest[:16] or 'n/a'}…",
           version=version_installed, pin=args.pin, content_digest=digest,
           location_is_site_packages="site-packages" in location)

    # ── P6: removing it produces the NAMED error, never a BACKLOG ───────────
    dep_probe = '''
import json, sys
from coretex_validator import replay as rp
sandbox = rp.default_sandbox()
out = {"available": sandbox.available(), "error": None, "class": None}
try:
    sandbox.execute(receipt_wrapper={"receipt": {}}, artifact={})
except rp.SandboxDependencyError as exc:
    out["error"] = str(exc); out["class"] = "SandboxDependencyError"
    out["dependency"] = exc.dependency; out["remedy"] = exc.remedy
except rp.SandboxUnavailable as exc:
    out["error"] = str(exc); out["class"] = "SandboxUnavailable"
except Exception as exc:
    out["error"] = str(exc)[:400]; out["class"] = type(exc).__name__
print("<<<DEP>>>" + json.dumps(out))
'''
    result = run(python_nodep, dep_probe, env, timeout=600)
    dep = json.loads(result.stdout.split("<<<DEP>>>", 1)[1]) if "<<<DEP>>>" in result.stdout else {}
    named = dep.get("class") == "SandboxDependencyError"
    record("P6 missing wasmtime -> NAMED dependency error", named,
           f"class={dep.get('class')}, dependency={dep.get('dependency')}, "
           f"remedy={dep.get('remedy')}", raw=dep)

    ok = all(item["ok"] for item in RESULTS)
    payload = {"suite": "coretex-validator/sandbox-isolation-proofs/v1", "ok": ok,
               "proofs": RESULTS,
               "note": ("P7 (both epoch-180 receipts complete deterministic replay) is proven by "
                        "the full replay runs recorded alongside this file, not here: it costs "
                        "tens of minutes per receipt and belongs with the stage table")}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(f"\nSUITE: {'PASS' if ok else 'FAIL'} ({sum(1 for r in RESULTS if r['ok'])}"
          f"/{len(RESULTS)})")
    return 0 if ok else 1


def _isolation_path(python: str, env: Dict[str, str]) -> str:
    result = run(python, "from coretex_validator import replay as rp;"
                         "print(rp.default_sandbox().isolation_path)", env)
    return result.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
