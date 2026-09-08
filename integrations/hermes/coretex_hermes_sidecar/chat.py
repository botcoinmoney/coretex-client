# SPDX-License-Identifier: Apache-2.0
"""One guarded, nonstreaming Hermes turn. No answer is emitted before write confirmation."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', required=True)
    parser.add_argument('--prompt-file', required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--provider', default='custom')
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--api-key-env', required=True)
    args = parser.parse_args()
    os.environ['HERMES_HOME'] = str(Path(args.home).expanduser().resolve())
    key = os.environ.get(args.api_key_env)
    if not key:
        parser.error('API-key environment variable is empty')
    agent = None
    try:
        from run_agent import AIAgent
        from .guard import GuardedConversation
        from .client import SidecarClient
        from hermes_cli.config import load_config
        SidecarClient(load_config().get('memory', {}).get('coretex_sidecar', {})).wait_ready()
        # Hermes diagnostics may include draft responses. Keep them private until the gate passes.
        with contextlib.redirect_stdout(io.StringIO()):
            agent = AIAgent(model=args.model, provider=args.provider, api_mode='chat_completions',
                base_url=args.base_url, api_key=key, enabled_toolsets=[], quiet_mode=True,
                max_iterations=2, max_tokens=400, skip_context_files=True,
                skip_background_review=True, load_soul_identity=False,
                session_id='coretex-' + uuid.uuid4().hex)
            guard = GuardedConversation(agent)
            result = guard.run(Path(args.prompt_file).read_text())
        print(json.dumps({'ok': True, 'memory_write_confirmed': True,
                          'result': result}, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__,
                          'message': 'Turn not confirmed; no answer released. '
                                     'Check sidecar health and reconcile writes before retrying.'}),
              file=sys.stderr)
        return 1
    finally:
        if agent is not None:
            with contextlib.redirect_stdout(io.StringIO()):
                agent.shutdown_memory_provider()
