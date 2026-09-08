# SPDX-License-Identifier: Apache-2.0
"""Consumer configuration; every open refreshes current chain state before module adoption."""
import json
import os
from pathlib import Path
from coretex_memory_agent.config import ConfigError, DEFAULT_PROFILE, default_store_path
from .current_state import CurrentState, authority_from_current

SYNC_CONFIG_FORMAT = "coretex-consumer/config/v1"


def load_config(path, *, required=True):
    target = Path(path).expanduser()
    if not target.exists() and not required:
        return None
    value = json.loads(target.read_bytes())
    fields = {"format", "store", "profile", "release_dir", "sync"}
    if not isinstance(value, dict) or set(value) != fields or value["format"] != SYNC_CONFIG_FORMAT:
        raise ConfigError("unsupported consumer configuration")
    for key in ("store", "profile", "release_dir"):
        if not isinstance(value[key], str) or not value[key]:
            raise ConfigError(f"consumer {key} must be non-empty")
    from coretex_memory_agent.authority import PROFILE_IDS
    if value["profile"] not in PROFILE_IDS:
        raise ConfigError("unknown profile")
    validate_sync_settings(value["sync"])
    return value


def load_authority(config, *, progress=None):
    snapshot = CurrentState.load(sync_config(config, progress=progress))
    return authority_from_current(config["release_dir"], snapshot)


def validate_sync_settings(value):
    fields = {"expected_release_root", "rpc", "rpc_env", "rpc_file", "objects",
              "confirmations", "output_dir"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConfigError(f"sync fields must be exactly {sorted(fields)}")
    from coretex_memory_agent.authority import _root
    from .chain_reader import validate_url
    _root(value["expected_release_root"], "sync release root")
    chosen = [value[key] for key in ("rpc", "rpc_env", "rpc_file") if value[key] is not None]
    if len(chosen) != 1 or not isinstance(chosen[0], str) or not chosen[0]:
        raise ConfigError("sync requires exactly one non-empty rpc, rpc_env or rpc_file")
    if value["rpc"] is not None:
        validate_url(value["rpc"])
    validate_url(value["objects"])
    if type(value["confirmations"]) is not int or not 1 <= value["confirmations"] <= 256:
        raise ConfigError("sync confirmations must be in 1..256")
    if not isinstance(value["output_dir"], str) or not value["output_dir"]:
        raise ConfigError("sync output_dir must be a non-empty path")


def sync_config(config, *, progress=None):
    from .current_sync import sync_current
    settings = config["sync"]
    validate_sync_settings(settings)
    rpc = settings["rpc"]
    if settings["rpc_env"] is not None:
        rpc = os.environ.get(settings["rpc_env"])
    elif settings["rpc_file"] is not None:
        rpc = Path(settings["rpc_file"]).expanduser().read_text().strip()
    if not rpc:
        raise ConfigError("configured RPC source is empty or unavailable")
    return sync_current(release_dir=config["release_dir"],
        expected_release_root=settings["expected_release_root"], rpc_url=rpc,
        object_url=settings["objects"], output_dir=settings["output_dir"],
        confirmations=settings["confirmations"], progress=progress)


def init_sync_config(path, *, release_dir, settings, store=None, profile=DEFAULT_PROFILE,
                     progress=None):
    """Publish a following configuration only after the first successful sync."""
    from coretex_memory_agent.authority import PROFILE_IDS
    from .current_sync import _atomic_write
    from .chain_reader import PUBLIC_RPC
    if profile not in PROFILE_IDS:
        raise ConfigError("unknown profile")
    target = Path(path).expanduser().absolute()
    if target.exists():
        raise ConfigError("configuration already exists; use coretex-consumer sync --config to refresh")
    if all(settings.get(key) is None for key in ("rpc", "rpc_env", "rpc_file")):
        settings = dict(settings, rpc=PUBLIC_RPC, rpc_env=None, rpc_file=None)
    validate_sync_settings(settings)
    settings = dict(settings, output_dir=str(Path(settings["output_dir"]).expanduser().absolute()))
    if settings["rpc_file"]:
        settings["rpc_file"] = str(Path(settings["rpc_file"]).expanduser().absolute())
    document = {"format": SYNC_CONFIG_FORMAT,
        "store": str(Path(store or default_store_path()).expanduser().absolute()),
        "profile": profile, "release_dir": str(Path(release_dir).expanduser().absolute()),
        "sync": settings}
    snapshot = sync_config(document, progress=progress)
    target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, (json.dumps(document, sort_keys=True, indent=2) + "\n").encode(),
                  replace=False)
    return snapshot
