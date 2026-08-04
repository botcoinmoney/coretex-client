#!/usr/bin/env python3
# SPDX-License-Identifier: UNLICENSED
"""Candidate-execution isolation for the V5 evaluator worker (directive §7B).

WHAT §7B DEMANDS, VERBATIM
--------------------------
    Candidate execution must be networkless. Only the outer worker supervisor may communicate
    with the spool/content store; the sandboxed candidate process receives no network,
    credentials or signing material.

THE HONEST TRUTH ABOUT WHAT THE EXISTING SANDBOX ENFORCES
---------------------------------------------------------
The frozen candidate sandbox is ``v5/validator/replay.py::BenchmarkV2Sandbox``, which shells
``benchmark-v2/validator/replay.py::replay_receipt`` in a child interpreter. Read literally
(``replay.py:522-552``), what that child gets is:

  * a ``sys.path`` scrubbed of the v5 lane (import isolation, NOT process isolation);
  * an environment with ``http_proxy``/``https_proxy``/``HTTP_PROXY``/``HTTPS_PROXY``/``ALL_PROXY``
    removed and ``NO_PROXY=*`` set;
  * a ``subprocess.run(...)`` with a timeout;
  * a returned dict carrying ``"networkless": True`` — a HARD-CODED literal, until the W2 fix below.

**That flag WAS an ASSERTION, not an enforcement** — a hard-coded literal at ``replay.py:549``
checked against itself at ``:1044`` (ruling §9 W2). Scrubbing proxy variables stops an *accidental*
egress through a configured proxy; it does not stop a direct ``socket.connect()`` or
``os.system("curl …")``. There is no network namespace, no capability drop and no rlimit anywhere on
that path. A plain ``subprocess`` inherits the parent's network namespace in full, loopback included.

W2 FIX (2026-07-30): the sandbox child now installs THIS module's filter itself (loaded by absolute
path so the v5 lane stays off its ``sys.path``) and then calls :func:`prove_networkless` — a real
``socket(2)`` per IP family — BEFORE ``replay_receipt`` runs. ``"networkless"`` is DERIVED from that
observation, the proof travels with the execution result, and ``validator/replay.py`` fails the
replay when the probe shows an IP socket was creatable. So the same mechanism the worker installs
per job is now also in force (and, more importantly, PROVEN) when a bare validator drives the
sandbox with no worker around it.

WHERE THE CANDIDATE ACTUALLY RUNS — audited, not assumed
--------------------------------------------------------
It is easy to assume Wasmtime is the candidate boundary. It is not. Tracing the real path:

    v5/validator/replay.py:538          subprocess -> child #1 (v5 sandbox wrapper)
    benchmark-v2/validator/replay.py:133  -> evaluate.evaluate_candidate
    benchmark-v2/validator/evaluate.py:72 subprocess -> child #2 (validator.eval_worker)
    benchmark-v2/miner_abi/seam.py:108    subprocess -> child #3 (miner_abi.pack_worker)
    benchmark-v2/miner_abi/loader.py:164  exec(compile(module_source, …))   <-- MINER CODE RUNS HERE

So the candidate is **CPython source ``exec``'d three subprocess levels down**, same UID, same
filesystem, same network namespace, same cgroup. Wasmtime *is* used, and its confinement is
genuinely tight (no WASI at all, a 6-symbol host ABI, an import/export allowlist, 200M fuel, a fixed
non-growable 16-page memory) — but it runs the **frozen signed policy module**, not the candidate.
It therefore contributes nothing to the candidate boundary.

The candidate's ``__import__`` allowlist (``miner_abi/loader.py:96-109``) is bypassable through the
object graph of an allowlisted package, which ``benchmark-v2/miner_abi/SECURITY.md:46-65`` already
documents honestly ("In-process Python confinement is **not airtight** … a runtime module's own
``os`` attribute"). Consequently ``socket``, ``open`` and ``eval`` are all reachable from candidate
code. **This module is therefore not a nice-to-have: it is the only network enforcement anywhere on
the candidate path.**

Because a seccomp filter is inherited across ``fork`` and ``execve``, installing it once in the
worker's per-job child covers children #1, #2 and #3 and anything they exec — without editing a
single line of frozen consensus law.

WHAT THIS MODULE ADDS, AND WHY THIS MECHANISM
---------------------------------------------
This module installs a **seccomp-BPF filter** that makes ``socket(2)`` return ``EPERM`` for every
IP-capable address family (``AF_INET``, ``AF_INET6``, ``AF_PACKET``) while leaving ``AF_UNIX``
usable. Properties that made it the chosen mechanism:

  1. **It needs no privilege.** ``PR_SET_NO_NEW_PRIVS`` followed by
     ``PR_SET_SECCOMP(SECCOMP_MODE_FILTER)`` is permitted to an unprivileged process. Verified in a
     default (no ``--cap-add``, default seccomp profile) container on this host.
  2. **It is irrevocable and inherited.** A seccomp filter survives ``fork`` and ``execve`` and
     cannot be removed by the process that installed it or by any descendant. Installing it in the
     worker's per-job child therefore covers the benchmark-v2 sandbox child, its own children, and
     anything they exec — without editing one line of the frozen law.
  3. **It costs nothing at runtime** and breaks nothing the evaluation needs: ``AF_UNIX`` sockets,
     pipes, ``fork``/``exec``, temp files and Wasmtime all keep working.

WHAT THIS MODULE DOES **NOT** DO — stated so nobody over-reads it
-----------------------------------------------------------------
  * It does **not** create a network namespace. ``unshare -n`` requires ``CAP_SYS_ADMIN``, which a
    default container does not have (measured on this host: ``CapPrm=0x00000000a80425fb``, no
    ``CAP_SYS_ADMIN``), and ``unshare -Urn`` is refused by Docker's default seccomp profile. Granting
    ``CAP_SYS_ADMIN`` to gain a netns would hand the container a *far* larger privilege than the one
    it removes, so it is deliberately not done. :func:`describe` reports ``netns: False``.
  * It does **not** block an already-open inherited socket FD. The worker opens no IP socket ever
    (it has no RPC, no S3 and no HTTP client), so there is none to inherit — but that is a property
    of the worker, not of this filter.
  * It does **not** block filesystem access, ``AF_NETLINK``, or local IPC. Filesystem confinement is
    the container's job.
  * It does **not** replace the container-level control. **The authoritative enforcement point for
    "the evaluator has no network" is ``network_mode: "none"`` on the evaluator service**
    (``docker-compose.v5.yml``). This filter is defence in depth *inside* that boundary — it is what
    still holds if someone runs the image without ``--network none``, and it additionally blocks
    loopback, which ``network_mode: none`` does not.
  * On a non-x86-64 host the filter's architecture guard denies **every** syscall rather than
    silently allowing IP sockets, so a wrong-arch build fails loudly instead of quietly unprotected.

:func:`require_networkless` is the fail-closed variant the evaluator uses: if the filter cannot be
installed it raises, and the job is refused rather than executed unprotected.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
import socket
import struct
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "IsolationUnavailable",
    "AUDIT_ARCH_X86_64",
    "DENIED_ADDRESS_FAMILIES",
    "PROVEN_ADDRESS_FAMILIES",
    "PROOF_VERSION",
    "apply_networkless",
    "require_networkless",
    "describe",
    "probe_ip_socket_denied",
    "probe_address_families",
    "prove_networkless",
]


class IsolationUnavailable(RuntimeError):
    """The requested isolation could not be established. Always a refusal, never a warning."""


# ── seccomp / prctl constants (linux/seccomp.h, linux/prctl.h, linux/audit.h) ──
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_ERRNO = 0x0005_0000
SECCOMP_RET_ALLOW = 0x7FFF_0000

AUDIT_ARCH_X86_64 = 0xC000_003E

# classic BPF opcodes (linux/filter.h) — seccomp filters are cBPF, not eBPF.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

# offsets into struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARG0_LO = 16          # little-endian low word of args[0]

#: ``__NR_socket`` on x86-64. The only syscall this filter inspects: without an IP socket FD every
#: other network syscall (``connect``, ``sendto``, ``bind``, …) has nothing to act on.
_NR_SOCKET_X86_64 = 41

#: The IP-capable families denied. ``AF_UNIX`` (1) is deliberately ALLOWED — the worker's own job
#: protocol is a unix socket, and ``multiprocessing``/``socketpair`` need it.
DENIED_ADDRESS_FAMILIES: Tuple[int, ...] = (
    getattr(socket, "AF_INET", 2),
    getattr(socket, "AF_INET6", 10),
    getattr(socket, "AF_PACKET", 17),
)

_EPERM = 1


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("HBBI", code, jt, jf, k)


def _build_program(families: Tuple[int, ...] = DENIED_ADDRESS_FAMILIES) -> bytes:
    """The cBPF program, assembled explicitly so the control flow is auditable.

    ::

        A = arch;                if A != AUDIT_ARCH_X86_64 -> return ERRNO(EPERM)   # wrong arch:
                                                                                   # deny EVERYTHING
        A = nr;                  if A != __NR_socket        -> return ALLOW
        A = args[0] (low word);  if A in {AF_INET, AF_INET6, AF_PACKET} -> return ERRNO(EPERM)
                                 else                                   -> return ALLOW

    Denying every syscall on a foreign architecture is the fail-closed choice: an unexpected arch
    must not silently mean "IP sockets are fine here".
    """
    prog = b""
    prog += _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_ARCH)
    prog += _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, AUDIT_ARCH_X86_64, 1, 0)
    prog += _stmt(_BPF_RET | _BPF_K, SECCOMP_RET_ERRNO | _EPERM)

    prog += _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_NR)
    prog += _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, _NR_SOCKET_X86_64, 1, 0)
    prog += _stmt(_BPF_RET | _BPF_K, SECCOMP_RET_ALLOW)

    prog += _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_ARG0_LO)
    count = len(families)
    for index, family in enumerate(families):
        # jump-true distance: skip the remaining comparisons AND the ALLOW that follows them.
        prog += _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, int(family), count - index, 0)
    prog += _stmt(_BPF_RET | _BPF_K, SECCOMP_RET_ALLOW)
    prog += _stmt(_BPF_RET | _BPF_K, SECCOMP_RET_ERRNO | _EPERM)
    return prog


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def apply_networkless(*, families: Tuple[int, ...] = DENIED_ADDRESS_FAMILIES) -> Dict[str, Any]:
    """Install the filter on the CURRENT process. Idempotent-safe, irreversible, inherited.

    Returns a report dict. Raises :class:`IsolationUnavailable` if the kernel refused, so the
    caller can decide to refuse the job — this function never returns "it did not work".
    """
    if os.name != "posix" or platform.system() != "Linux":
        raise IsolationUnavailable(
            f"seccomp network denial needs Linux; this is {platform.system()!r}")
    machine = platform.machine()
    if machine not in ("x86_64", "AMD64"):
        raise IsolationUnavailable(
            f"the assembled seccomp program is x86-64 cBPF; refusing to install it on {machine!r} "
            "where its architecture guard would deny every syscall")

    libc = _libc()
    program = _build_program(families)
    buffer = ctypes.create_string_buffer(program, len(program))
    fprog = _SockFprog(len(program) // ctypes.sizeof(_SockFilter),
                       ctypes.cast(buffer, ctypes.c_void_p))

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise IsolationUnavailable(
            f"PR_SET_NO_NEW_PRIVS failed: errno {ctypes.get_errno()} — a seccomp filter cannot be "
            "installed without it by an unprivileged process")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        errno = ctypes.get_errno()
        raise IsolationUnavailable(
            f"PR_SET_SECCOMP(SECCOMP_MODE_FILTER) failed: errno {errno}. The kernel has no "
            "CONFIG_SECCOMP_FILTER, or an outer seccomp profile forbids the prctl. The candidate "
            "would run without in-process network denial, so the job is refused.")
    return {
        "mechanism": "seccomp-bpf(socket(2) EPERM for AF_INET/AF_INET6/AF_PACKET)",
        "installed": True,
        "denied_address_families": [int(f) for f in families],
        "allowed_address_families_note": "AF_UNIX and AF_NETLINK remain usable by design",
        "inherited_across_exec": True,
        "revocable": False,
        "instruction_count": len(program) // ctypes.sizeof(_SockFilter),
    }


def probe_ip_socket_denied() -> bool:
    """Prove the filter by USING it: try to create an ``AF_INET`` socket and require refusal.

    A boolean from a real syscall, not a re-read of the flag we just set.
    """
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, PermissionError):
        return True
    probe.close()
    return False


#: Schema version of the :func:`prove_networkless` evidence block. Bump it if the field set
#: changes, so a consumer can never silently mis-read an older/newer proof.
PROOF_VERSION = 1

#: The families :func:`probe_address_families` attempts by default. AF_PACKET is deliberately NOT
#: probed: it needs CAP_NET_RAW, so its refusal would be indistinguishable from the filter's and
#: would make the proof weaker, not stronger.
PROVEN_ADDRESS_FAMILIES: Tuple[str, ...] = ("AF_INET", "AF_INET6")


def probe_address_families(families: Tuple[str, ...] = PROVEN_ADDRESS_FAMILIES) -> Dict[str, Any]:
    """Attempt a real ``socket(2)`` for each named family and report the CONCRETE outcome.

    Per family: ``{"created": bool, "errno": int|None, "errno_name": str|None, "error": str|None}``.
    ``created: True`` means the syscall SUCCEEDED — i.e. nothing is denying IP sockets here. This
    function never raises for a refused socket; a refusal is the evidence it exists to collect.
    """
    out: Dict[str, Any] = {}
    for name in families:
        family = getattr(socket, name, None)
        if family is None:                                   # pragma: no cover - all Linux have both
            out[name] = {"created": False, "errno": None, "errno_name": None,
                         "error": f"{name} is not defined on this platform"}
            continue
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            out[name] = {"created": False, "errno": exc.errno,
                         "errno_name": errno.errorcode.get(exc.errno), "error": str(exc)}
        else:
            probe.close()
            out[name] = {"created": True, "errno": None, "errno_name": None, "error": None}
    return out


def prove_networkless(*, install: Optional[Dict[str, Any]] = None,
                      families: Tuple[str, ...] = PROVEN_ADDRESS_FAMILIES) -> Dict[str, Any]:
    """The EVIDENCE block: what a real ``socket(2)`` did, in THIS process, right now.

    This is the thing a "networkless" claim is allowed to rest on. It is not a re-read of a flag
    and not a restatement of the install report — it is the observed outcome of the syscall the
    filter exists to deny, taken in the same process (and therefore the same seccomp domain) the
    candidate will run in, before the candidate runs.

    ``enforced`` is True **only** if EVERY probed IP family was refused. If any of them was
    created, ``enforced`` is False and ``unenforced_families`` names them — the caller must then
    treat the execution as NOT networkless. ``install`` (optional) is carried verbatim for
    provenance; it is never what ``enforced`` is derived from.
    """
    probes = probe_address_families(families)
    unenforced = sorted(name for name, p in probes.items() if p.get("created"))
    return {
        "proof_version": PROOF_VERSION,
        "method": "socket(2) attempted per address family in the process that runs the candidate",
        "probed_families": list(families),
        "probes": probes,
        "enforced": not unenforced,
        "unenforced_families": unenforced,
        "expected_mechanism": ("seccomp-BPF SECCOMP_RET_ERRNO(EPERM) on socket(2) for "
                               "AF_INET/AF_INET6/AF_PACKET — see worker/isolation.py"),
        "scope_note": ("proves in-process/in-container denial for the probing process and every "
                       "descendant (a seccomp filter is inherited across fork and execve); it does "
                       "NOT prove the container-level boundary, which is network_mode: \"none\""),
        "install": install,
    }


def require_networkless(*, verify: bool = True) -> Dict[str, Any]:
    """Install the filter and, by default, PROVE it with a real syscall. Fail-closed.

    This is what the evaluator's per-job child calls before touching candidate evidence. If the
    verification probe still gets an ``AF_INET`` socket, the process refuses rather than proceeding
    with a filter that demonstrably is not doing anything.
    """
    report = apply_networkless()
    if verify:
        if not probe_ip_socket_denied():
            raise IsolationUnavailable(
                "the seccomp filter installed but an AF_INET socket was still created; refusing "
                "to execute a candidate whose network denial is unproven")
        report["verified_by_syscall_probe"] = True
    return report


def describe(*, spool_only: Optional[bool] = None) -> Dict[str, Any]:
    """The isolation posture, stated for a report/artifact. Claims only what is mechanised."""
    return {
        "statement_version": 1,
        "candidate_execution_path": (
            "v5/validator/replay.py::BenchmarkV2Sandbox -> child interpreter -> "
            "benchmark-v2/validator/replay.py::replay_receipt"
        ),
        "enforced": {
            "in_process_ip_socket_denial": {
                "mechanism": "seccomp-BPF, PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP(MODE_FILTER)",
                "scope": "the worker's per-job child and every descendant, across execve",
                "note": "socket(2) returns EPERM for AF_INET/AF_INET6/AF_PACKET, loopback included",
            },
            "frozen_policy_wasm_confinement": {
                "mechanism": "pinned Wasmtime engine: no WASI, 6-symbol host ABI, import/export "
                             "allowlist, 200M fuel, fixed non-growable 16-page memory",
                "note": "IMPORTANT — this confines the FROZEN SIGNED POLICY module, NOT the "
                        "candidate. The candidate is CPython exec'd three subprocess levels down "
                        "(miner_abi/loader.py:164), so Wasmtime contributes nothing to the "
                        "candidate boundary. Do not cite it as candidate isolation.",
            },
            "secrets_absent_from_the_candidate_process": {
                "mechanism": "benchmark-v2/miner_abi/seam.py runs the candidate in a separate "
                             "process that never loads the scorer or the gold view; the evaluator "
                             "image additionally DELETES benchmark-v2/validator/keys/"
                             "validator_seed.test.hex, which only the wrapper-MINTING path needs "
                             "(validator/receipt.py:184) and which the replay path does not "
                             "(replay_receipt takes only the public pin)",
                "note": "this is the load-bearing architectural guarantee; the candidate cannot "
                        "steal what is not in its process image or its filesystem",
            },
            "container_network": {
                "mechanism": 'docker-compose.v5.yml evaluator service: network_mode: "none"',
                "note": "THE authoritative enforcement point; this is a deployment control, so it "
                        "is only in force when the service is started from that compose file",
            },
            "sandbox_child_networkless_proof": {
                "mechanism": "v5/validator/replay.py::BenchmarkV2Sandbox's child installs THIS "
                             "filter itself (apply_networkless) and then calls prove_networkless() "
                             "— a real socket(2) per IP family — before replay_receipt runs",
                "note": "ruling §9 W2: the sandbox's \"networkless\" field is now DERIVED from that "
                        "syscall observation instead of being a hard-coded literal, and "
                        "validator/replay.py FAILS the replay when the probe shows an IP socket was "
                        "creatable. The proof covers the in-container boundary only (see "
                        "container_network for the authoritative one)",
            },
            "no_credential_material_present": {
                "mechanism": "the worker image and service mount no signing key, no RPC URL and no "
                             "S3/AWS credential; there is nothing to leak even on egress",
            },
        },
        "not_enforced": {
            "network_namespace": (
                "unshare(CLONE_NEWNET) needs CAP_SYS_ADMIN, absent from a default container; "
                "unshare -Urn is blocked by Docker's default seccomp profile. Granting "
                "CAP_SYS_ADMIN to gain a netns would be a net privilege INCREASE, so it is not done"
            ),
            "frozen_sandbox_proxy_scrubbing": (
                "BenchmarkV2Sandbox also scrubs http_proxy/https_proxy/ALL_PROXY and sets "
                "NO_PROXY=*; that is accidental-egress hygiene, NOT an enforcement. The "
                "enforcement on that path is the seccomp filter the child now installs itself "
                "(see enforced.sandbox_child_networkless_proof) plus network_mode: \"none\""
            ),
            "candidate_import_allowlist": (
                "miner_abi/loader.py guards __import__ only; the object graph of an allowlisted "
                "package reaches os/socket/open/eval. Documented by the tree itself at "
                "benchmark-v2/miner_abi/SECURITY.md:46-65. NOT fixed here — it is frozen law — but "
                "the seccomp filter above makes the recovered `socket` useless"
            ),
            "candidate_compute_metering": (
                "miner_abi/context.py's ComputeMeter relies on sys.settrace, which candidate code "
                "can reach. Ruling §9 W1 added fail-closed TAMPER DETECTION (ComputeMeterTampered: "
                "the tracer must still be the meter's own object when the hook returns, and the "
                "meter's counter/ceiling/registered-sources must be unmutated), so clearing the "
                "tracer now REFUSES the candidate instead of crediting it ~0 compute. What is still "
                "NOT prevented in-process: clearing the tracer and restoring the IDENTICAL object "
                "before the hook returns, and suppressing per-frame tracing (frame.f_trace = None / "
                "f_trace_lines = False). Complete in-process prevention is impossible in CPython; "
                "the untamperable bound is the OUTER wall/CPU limit, and making that bound the "
                "AUTHORITY for the compute axis is a future-season operator decision, never a "
                "post-freeze change"
            ),
            "filesystem_confinement": "the container's job, not this module's. No Landlock ruleset "
                                      "is installed (it would have to enumerate every path the "
                                      "three nested children legitimately touch, incl. per-run "
                                      "mkdtemp; that is a bigger change than this cut's scope)",
            "cpu_memory_limits": "compose mem_limit/cpus and the sandbox's own subprocess timeout "
                                 "(5400s, measurement_policy.py:100). No setrlimit, no cgroup",
        },
        "spool_only_mode": spool_only,
    }
