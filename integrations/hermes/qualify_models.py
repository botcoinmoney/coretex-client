#!/usr/bin/env python3
"""Bounded real-Hermes recall qualification against an explicitly configured test sidecar.

Writes synthetic records. One ingest, one fresh-session recall, and one unknown
question per model. Never use this with a personal or production store. Output
records model answers; no API credentials or private operator files are read.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chat', default='coretex-hermes-chat')
    parser.add_argument('--home', required=True)
    parser.add_argument('--model', action='append', required=True)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--api-key-env', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if not 1 <= len(args.model) <= 3:
        parser.error('qualify one to three models per run')
    output = Path(args.out)
    if output.exists():
        parser.error('--out already exists; preserve earlier evidence')
    results = []
    with tempfile.TemporaryDirectory(prefix='coretex-recall-fixtures-') as work:
        for model in args.model:
            subject = 'project-' + uuid.uuid4().hex[:8]
            label = 'glass-maple-' + uuid.uuid4().hex[:8]
            prompts = [
                ('ingest', f'For {subject}, my spare-key label is {label}. '
                 'Remember this. Acknowledge without repeating it.'),
                ('recall', f'What is my spare-key label for {subject}? Give the label itself.'),
                ('unknown', f'What is my vault access code for {subject}? '
                 'If it was never recorded, say you do not know.'),
            ]
            row = {'model': model, 'fixture': subject, 'expected_label': label, 'turns': []}
            for phase, prompt in prompts:
                path = Path(work) / 'prompt.txt'
                path.write_text(prompt)
                started = time.monotonic()
                process = subprocess.run([args.chat, '--home', args.home,
                    '--prompt-file', str(path), '--model', model, '--base-url', args.base_url,
                    '--api-key-env', args.api_key_env], capture_output=True, text=True, timeout=180)
                try:
                    result = json.loads(process.stdout)
                except ValueError:
                    result = {'ok': False, 'error': 'no confirmed JSON result'}
                answer = (result.get('result') or {}).get('final_response', '')
                turn = {'phase': phase, 'prompt': prompt, 'exit_code': process.returncode,
                        'seconds': round(time.monotonic() - started, 2), 'response': result}
                if phase == 'recall':
                    turn['label_in_answer'] = label in answer
                row['turns'].append(turn)
                print(json.dumps({'model': model, 'phase': phase, 'exit_code': process.returncode}), flush=True)
                if process.returncode:
                    break  # A write may be ambiguous; do not retry or continue that model.
            results.append(row)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps({'models': results, 'scope':
                'bounded harness qualification; retrieval is distinct from answer accuracy'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
