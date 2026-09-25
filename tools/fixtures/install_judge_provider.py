"""A deterministic, OFFLINE judgment provider for the consumer installation check.

It exists to prove the launcher's enable control really reaches the serving store's provider
binding without a paid call or a socket: it resolves through the REAL
``coretex_memory.judge_providers`` entry point, exactly as the shipped addon does.

``CORETEX_FAKE_JUDGE_MODE`` selects the arm:
  ``ok``       (default) an enabled provider that answers from a fixed table
  ``decline``  the factory returns None -- an installed-but-not-configured provider
  ``fail``     every judgment raises -- the provider-failure arm
  ``timeout``  the actual addon wheel with a stalled offline HTTP transport
"""
import os
import json
import time

__version__ = "0.1.0"
NETWORK_CALLS = 0


class FakeJudgeProvider(object):
    provider_id = "judge.provider.fake"

    def __init__(self, config=None, mode="ok"):
        self._config = config
        self._mode = mode
        from coretex_memory.judge.contract import JudgeDescriptor
        self._descriptor = JudgeDescriptor(
            model_id="fake-judge-1", template_set_hash="00" * 32,
            state_builder_id="judge.state.need.m1.v1",
            domain_policy_id="domain.lexical_entity_events.v1@cap96",
            limits={"max_refs_per_wave": 4, "max_waves_per_query": 1,
                    "query_scoped": 1, "samples_per_row": 1})

    @property
    def descriptor(self):
        return self._descriptor

    @property
    def descriptor_root(self):
        return self._descriptor.root()

    def enabled(self):
        return True

    def judge(self, states):
        log = os.environ.get("CORETEX_FAKE_JUDGE_LOG")
        if log:
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"mode": self._mode, "states": len(states)}) + "\n")
        if self._mode == "fail":
            raise RuntimeError("fake judge provider failure")
        from coretex_memory.judge.contract import (FEATURE_NAMES, JudgeResult, STATUS_OK)
        features = {name: (0 if self._mode == "trim" else 1) for name in FEATURE_NAMES}
        return [JudgeResult(STATUS_OK, features=dict(features),
                            descriptor_root=self.descriptor_root) for _ in states]

    def purge_event(self, event_id):
        return 0

    def purge_scope(self, store_id, scope_id):
        return 0


def factory(config=None, **kwargs):
    mode = os.environ.get("CORETEX_FAKE_JUDGE_MODE", "ok")
    if mode == "decline":
        return None
    if mode == "timeout":
        # Import unmodified release addon bytes; only HTTP is replaced. The same
        # entry point exercises the installed host and the real addon deadline.
        import sys
        sys.path.insert(0, os.environ["CORETEX_TEST_ADDON_IMPORT"])
        from coretex_jev_addon.config import JevAddonConfig
        from coretex_jev_addon.provider import LiveJudgeProvider
        from coretex_jev_addon.client import HttpResult

        class StalledTransport:
            def request(self, method, url, headers, body, timeout):
                if method == "GET":
                    return HttpResult(200, b'{"models":[]}', {})
                time.sleep(2.0)
                return HttpResult(200, b'{"model":"jev-1.13.0","answers":{}}', {})

        class RecordedLiveProvider(LiveJudgeProvider):
            def judge(self, states):
                started = time.monotonic()
                result = super().judge(states)
                with open(os.environ["CORETEX_FAKE_JUDGE_LOG"], "a") as handle:
                    handle.write(json.dumps({"mode": mode, "states": len(states),
                        "elapsed": time.monotonic() - started,
                        "reasons": [r.reason for r in result]}) + "\n")
                return result

        return RecordedLiveProvider(JevAddonConfig(enabled=True, latency_budget_ms=400,
            max_calls_per_serve=16, max_concurrency=16, timeout_ms=5000,
            key_status={"available": True, "key_length": 8, "source": "test"}),
            transport=StalledTransport())
    return FakeJudgeProvider(config, mode)
