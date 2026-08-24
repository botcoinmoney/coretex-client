# SPDX-License-Identifier: Apache-2.0
"""``setup`` ends with the LIVE admission law installed, or says exactly why it did not.

WHAT THIS REPLACES. Until now the last line of a fresh install was an apology: `law.synced: false`
and a paragraph telling the operator to find a publication root "by some unspecified means" and
run a second command with it. That is the same unauditable step finding F4 removed for the trees
themselves, moved up one level to their address — and the address is the part that decides WHICH
law you install, so leaving it to a paste is where a rehearsal root ends up on a live host.

The root is a property of the deployment, so it is DISCOVERED: the coordinator kit carries a
``law_publication`` component whose note names it, and whose files are the publication manifest
plus one tar per code root. Setup downloads them under their kit-declared hashes, lays them out as
a local ``flat-cas`` mirror (the manifest under the PUBLICATION ROOT's name, each object under its
own), and hands that directory to the ordinary :func:`law.sync_law` — which re-derives every
address from the bytes that arrived, exactly as it does for any other mirror. Nothing here is a
second verification path, and nothing here is weaker than `sync-law --mirror URL --root ROOT`.

THE THREE OUTCOMES, KEPT APART:

* discovered and verified -> ``law.synced: true`` and the pins are on disk;
* NOT OFFERED (an older coordinator, no such component; a note naming no root or two) ->
  ``law.synced: false`` with a remedy, and setup still succeeds. A coordinator that does not
  publish its law is a fact about the coordinator, not a broken install;
* offered and WRONG (a tar that does not hash to its kit entry, or a tree that does not reproduce
  the root it is addressed by) -> setup FAILS, loudly. Never a soft "law unavailable": bytes that
  disagree with their address are the one thing that must not be shrugged off.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from coretex_validator import cli, law
from coretex_validator import setup as su

from test_law_sync import build_publication                                    # noqa: F401

COORDINATOR = "https://coordinator.example"


# --------------------------------------------------------------------------- #
# a kit that serves a law publication
# --------------------------------------------------------------------------- #
class FakeKit:
    """The coordinator's kit endpoints, in memory. No socket is opened anywhere in this file."""

    def __init__(self, *, component: bool = True, note=None, extra_components=(),
                 corrupt: str = "") -> None:
        self.root, self.manifest_bytes, self.objects = build_publication()
        self.files = {}
        entries = []

        def publish(path: str, data: bytes) -> None:
            sha = hashlib.sha256(data).hexdigest()
            self.files[sha] = data
            entries.append({"path": path, "sha256": sha,
                            "download": f"/coretex/v5/kit/file/{sha}",
                            "downloadEncoding": "raw-bytes"})

        publish("v5/law-publication/LAW-PUBLICATION.json", self.manifest_bytes)
        for object_root, blob in sorted(self.objects.items()):
            publish(f"v5/law-publication/{object_root}", blob)
        publish("v5/law-publication/README.md", b"the six admission trees\n")

        if corrupt == "bytes":
            # served bytes differ from the sha the KIT declares -> caught on download
            victim = entries[1]["sha256"]
            self.files[victim] = self.files[victim] + b"\x00"
        elif corrupt == "container":
            # the kit's own hash agrees, so only the PUBLICATION manifest's tar digest can refuse
            victim = entries[1]["sha256"]
            forged = self.files[victim].replace(b"VALUE", b"EVIL!")
            assert len(forged) == len(self.files[victim])
            self.files[victim] = forged
            entries[1]["sha256"] = hashlib.sha256(forged).hexdigest()
            self.files[entries[1]["sha256"]] = forged

        components = [{"id": "frozen_runtime_packet", "files": []}, *extra_components]
        if component:
            components.append({
                "id": "law_publication",
                "note": (f"admission law publication root {self.root} — the six trees "
                         "deterministic admission needs") if note is None else note,
                "files": entries})
        self.manifest = {"kit": {"format": "coretex.v5.kit/v1", "components": components}}

    # -- transport ---------------------------------------------------------- #
    def fetch(self, url: str, *, timeout: float, limit: int) -> bytes:
        assert url.startswith(COORDINATOR), url
        path = url[len(COORDINATOR):]
        if path == "/coretex/v5/kit/manifest":
            return json.dumps(self.manifest).encode("utf-8")
        prefix = "/coretex/v5/kit/file/"
        if path.startswith(prefix):
            sha = path[len(prefix):]
            if sha not in self.files:
                raise RuntimeError(f"the kit serves nothing at {sha}")
            data = self.files[sha]
            if len(data) > limit:
                raise RuntimeError(f"{url} exceeded {limit} bytes")
            return data
        raise RuntimeError(f"no such kit route: {path}")

    def install(self, monkeypatch) -> "FakeKit":
        monkeypatch.setattr(su, "_fetch", self.fetch)
        return self


@pytest.fixture()
def kit(monkeypatch):
    return FakeKit().install(monkeypatch)


def sync(kit_obj, tmp_path, **kwargs):
    return su.sync_law_from_kit(
        COORDINATOR, kit_obj.manifest, packages_dir=str(tmp_path / "packages"),
        cache_dir=str(tmp_path / "law-cache"), **kwargs)


# --------------------------------------------------------------------------- #
# the honest path
# --------------------------------------------------------------------------- #
def test_setup_discovers_the_publication_root_and_installs_the_law(kit, tmp_path):
    report = sync(kit, tmp_path)
    assert report["synced"] is True
    assert report["publicationRoot"] == kit.root
    assert sorted(report["trees"]) == sorted(law.REQUIRED_TREES)
    # the SEVENTH sealed root is a file, and `setup` alone has to be enough to obtain it (D-3)
    assert sorted(report["files"]) == sorted(law.REQUIRED_FILES)
    # the cache is real: it loads, and it re-verifies from what is on disk RIGHT NOW
    cache = law.load_cache(kit.root, cache_dir=str(tmp_path / "law-cache"))
    assert cache.verify() == {**report["trees"], **report["files"]}
    assert set(cache.env()) == set(law.ENV_PINS)
    assert os.path.isfile(cache.posture_path)


def test_the_local_mirror_is_laid_out_the_way_law_addresses_it(kit, tmp_path):
    """flat-cas: the MANIFEST is named by the PUBLICATION root, each object by its own."""
    report = sync(kit, tmp_path)
    mirror = report["mirror_dir"]
    assert os.path.isfile(os.path.join(mirror, kit.root))
    with open(os.path.join(mirror, kit.root), "rb") as fh:
        assert fh.read() == kit.manifest_bytes
    for object_root in kit.objects:
        assert os.path.isfile(os.path.join(mirror, object_root))
    # the kit's non-addressed documentation is NOT mirrored: it has no address to be checked by
    assert sorted(os.listdir(mirror)) == sorted([kit.root, *kit.objects])
    assert "README.md" not in os.listdir(mirror)


def test_a_second_setup_reuses_what_it_already_verified(kit, tmp_path):
    first = sync(kit, tmp_path)
    second = sync(kit, tmp_path)
    assert second["synced"] is True and second["publicationRoot"] == first["publicationRoot"]
    assert second["trees"] == first["trees"]


def test_the_note_is_parsed_defensively_not_greedily(kit, tmp_path):
    """Any wording is fine as long as it names exactly ONE address."""
    kit.manifest["kit"]["components"][-1]["note"] = f"root={kit.root}"
    assert sync(kit, tmp_path)["synced"] is True


def test_an_explicit_publication_root_field_is_preferred_when_a_coordinator_sends_one(
        kit, tmp_path):
    component = kit.manifest["kit"]["components"][-1]
    component["publicationRoot"] = kit.root
    component["note"] = "see publicationRoot"
    assert sync(kit, tmp_path)["synced"] is True


# --------------------------------------------------------------------------- #
# NOT OFFERED — a fact about the coordinator, not a broken install
# --------------------------------------------------------------------------- #
def test_a_coordinator_that_publishes_no_law_leaves_a_remedy_and_setup_still_succeeds(
        monkeypatch, tmp_path):
    kit_obj = FakeKit(component=False).install(monkeypatch)
    report = sync(kit_obj, tmp_path)
    assert report["synced"] is False
    assert "law_publication" in report["reason"]
    assert "sync-law" in report["reason"]
    assert "publicationRoot" not in report


@pytest.mark.parametrize("note,why", [
    ("the admission law trees", "names no publication root"),
    ("roots " + "a" * 64 + " and " + "b" * 64, "names 2"),
])
def test_a_note_that_does_not_name_exactly_one_root_is_reported_not_guessed(
        monkeypatch, tmp_path, note, why):
    kit_obj = FakeKit(note=note).install(monkeypatch)
    report = sync(kit_obj, tmp_path)
    assert report["synced"] is False
    assert why in report["reason"]


def test_skip_law_keeps_the_old_behaviour(kit, tmp_path):
    report = sync(kit, tmp_path, skip_law=True)
    assert report["synced"] is False and "--skip-law" in report["reason"]


# --------------------------------------------------------------------------- #
# OFFERED AND WRONG — loud, every time
# --------------------------------------------------------------------------- #
def test_a_file_that_does_not_match_its_kit_hash_fails_setup(monkeypatch, tmp_path):
    kit_obj = FakeKit(corrupt="bytes").install(monkeypatch)
    with pytest.raises(RuntimeError) as exc:
        sync(kit_obj, tmp_path)
    assert "hashed to" in str(exc.value)


def test_a_container_the_publication_manifest_does_not_bind_fails_setup(monkeypatch, tmp_path):
    """The kit's own hash agrees — this is caught by re-deriving the address from the bytes."""
    kit_obj = FakeKit(corrupt="container").install(monkeypatch)
    with pytest.raises(law.LawVerifyError) as exc:
        sync(kit_obj, tmp_path)
    assert "sha256" in str(exc.value) or "tree hash" in str(exc.value)
    assert not os.path.isdir(os.path.join(str(tmp_path / "law-cache"), kit_obj.root))


# --------------------------------------------------------------------------- #
# the command line
# --------------------------------------------------------------------------- #
def test_setup_exposes_skip_law_and_a_law_cache_directory():
    parser = cli.build_parser()
    args = parser.parse_args(["setup"])
    assert args.skip_law is False and args.law_cache is None
    args = parser.parse_args(["setup", "--skip-law", "--law-cache", "/tmp/x"])
    assert args.skip_law is True and args.law_cache == "/tmp/x"


def test_the_setup_command_passes_the_law_options_through(monkeypatch, capsys):
    seen = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {"ok": True, "law": {"synced": True}}

    monkeypatch.setattr(su, "run", fake_run)
    code = cli.main(["--compact", "setup", "--skip-law", "--law-cache", "/tmp/lc"])
    capsys.readouterr()
    assert code == 0
    assert seen["skip_law"] is True and seen["law_cache"] == "/tmp/lc"
