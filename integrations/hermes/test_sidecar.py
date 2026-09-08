"""Real Hermes MemoryManager + fault-injected loopback HTTP sidecar, no model API."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from agent.memory_manager import MemoryManager
from coretex_hermes_sidecar.client import MemoryUnavailable, SidecarClient
from coretex_hermes_sidecar.provider import CoreTexSidecarProvider, DATA_HEADER
from coretex_hermes_sidecar.guard import GuardedConversation


@pytest.fixture
def sidecar():
    state = {'healthy': True, 'profile': 'event.schema.v1', 'fail_write': False,
             'writes': [], 'module': 'a' * 64, 'render': 'Spare key: glass-maple. Acknowledge without repeating it.'}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            if self.path == '/health':
                self.send(200, {'ok': state['healthy'], 'in_sync': True, 'integrity': 'ok',
                    'profile_id': state['profile'], 'serving_module': {
                        'profile': state['profile'], 'module_root': state['module']}})
            else:
                self.send(200, {'profile_id': state['profile'], 'module_root': state['module']})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path == '/sync_turn':
                state['writes'].append(body)
                if state['fail_write']:
                    self.send(500, {'error': 'private text must not leak'})
                else:
                    self.send(200, {'receipts': [{'event_id': str(i)} for i in range(len(body['messages']))]})
            elif self.path == '/prefetch':
                self.send(200, {'render': state['render'], 'receipt': {'render_hash': 'b' * 64}})
            else:
                self.send(200, {'flushed': True, 'in_sync': True})
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    settings = {'url': 'http://127.0.0.1:' + str(server.server_port),
                'profile': state['profile'], 'ready_timeout_seconds': .02, 'timeout_seconds': .1}
    yield state, settings
    server.shutdown()
    server.server_close()
    thread.join()


def setup_agent(settings):
    provider = CoreTexSidecarProvider(settings)
    manager = MemoryManager()
    manager.add_provider(provider)
    manager.initialize_all('test')
    calls = []
    def run(prompt):
        calls.append(prompt)
        context = manager.prefetch_all(prompt)
        manager.sync_all(prompt, 'saved')
        return {'final_response': 'saved', 'context': context}
    return SimpleNamespace(_memory_manager=manager, run_conversation=run), provider, calls


def test_real_hermes_swallows_initialize_but_guard_stops_before_model(sidecar):
    state, settings = sidecar
    state['healthy'] = False
    agent, provider, calls = setup_agent(settings)
    assert not provider.initialized
    assert not provider.is_available()
    with pytest.raises(MemoryUnavailable):
        GuardedConversation(agent)
    assert not calls
    agent._memory_manager.shutdown_all()


def test_real_hermes_swallows_sync_error_but_guard_never_returns_saved(sidecar):
    state, settings = sidecar
    agent, provider, calls = setup_agent(settings)
    guard = GuardedConversation(agent)
    state['fail_write'] = True
    with pytest.raises(MemoryUnavailable) as caught:
        guard.run('Remember my spare key label.')
    assert 'private text' not in str(caught.value)
    assert len(state['writes']) == 1  # no blind write retry
    with pytest.raises(MemoryUnavailable):
        guard.run('Try again')
    assert len(calls) == 1
    agent._memory_manager.shutdown_all()


def test_success_waits_for_receipts_and_quotes_unchanged_render(sidecar):
    state, settings = sidecar
    agent, provider, calls = setup_agent(settings)
    result = GuardedConversation(agent).run('What is my spare key label?')
    assert result['final_response'] == 'saved'
    assert provider.write_count == 1 and len(provider.last_receipts) == 2
    quoted = json.loads(result['context'][len(DATA_HEADER):])
    assert quoted['recorded_text'] == state['render']
    assert state['writes'][0]['messages'][0]['content'] == 'What is my spare key label?'
    agent._memory_manager.shutdown_all()


@pytest.mark.parametrize('change', [{'profile': 'conv.pref.v1'}, {'module': ''}, {'healthy': False}])
def test_wrong_sidecar_or_unbound_store_is_unavailable(sidecar, change):
    state, settings = sidecar
    state.update(change)
    assert not CoreTexSidecarProvider(settings).is_available()


def test_health_loss_between_turns_stops_model(sidecar):
    state, settings = sidecar
    agent, provider, calls = setup_agent(settings)
    guard = GuardedConversation(agent)
    state['healthy'] = False
    with pytest.raises(MemoryUnavailable):
        guard.run('Remember this new fact.')
    assert not calls and not state['writes']
    agent._memory_manager.shutdown_all()


@pytest.mark.parametrize('url', ['http://localhost:1234', 'http://example.com:80',
                               'http://127.0.0.1:1234/path', 'http://u:p@127.0.0.1:1234'])
def test_connector_refuses_nonliteral_or_ambiguous_loopback(url):
    with pytest.raises(MemoryUnavailable):
        SidecarClient({'url': url, 'profile': 'event.schema.v1'})
