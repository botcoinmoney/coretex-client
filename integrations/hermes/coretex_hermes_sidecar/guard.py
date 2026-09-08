# SPDX-License-Identifier: Apache-2.0
"""Checked turn boundary for Hermes' best-effort memory manager.

Callers must buffer model output and tool effects. The supplied chat command does
not stream and disables tools. An ordinary Hermes gateway is not made fail-closed
merely by installing the provider.
"""
import threading
from .client import MemoryUnavailable


class GuardedConversation:
    def __init__(self, agent):
        self.agent = agent
        self.manager = getattr(agent, '_memory_manager', None)
        self.provider = None if self.manager is None else self.manager.get_provider('coretex_sidecar')
        if self.provider is None:
            raise MemoryUnavailable('Hermes did not activate coretex_sidecar; no model call permitted')
        self.provider.require_ready()
        self.lock = threading.Lock()

    def run(self, prompt, **kwargs):
        with self.lock:
            provider = self.provider
            provider.prepare_turn(prompt)
            before = provider.write_count
            recalled = provider.recall_count
            result = self.agent.run_conversation(prompt, **kwargs)
            if not self.manager.flush_pending(timeout=2 * provider.client.timeout + 5):
                provider.failure = 'Hermes pending memory writes did not drain; status unknown'
            provider.require_ready()
            if provider.write_count != before + 1:
                provider.failure = 'Hermes did not acknowledge exactly one completed turn write'
                raise MemoryUnavailable(provider.failure)
            from agent.memory_provider import is_trivial_prompt
            if not is_trivial_prompt(prompt) and provider.recall_count <= recalled:
                provider.failure = 'Hermes did not consume the prepared memory context'
                raise MemoryUnavailable(provider.failure)
            provider.flush_checked()
            return result
