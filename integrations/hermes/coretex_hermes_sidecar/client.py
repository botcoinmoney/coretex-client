# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-retrying loopback transport. Never logs private memory contents."""
import ipaddress
import json
import re
import time
import urllib.parse
import urllib.request


class MemoryUnavailable(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise MemoryUnavailable('sidecar redirects are refused')


class SidecarClient:
    def __init__(self, settings):
        self.url = settings.get('url', '').rstrip('/')
        parsed = urllib.parse.urlsplit(self.url)
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except (ValueError, TypeError):
            local = False
        if not local or parsed.scheme != 'http' or not parsed.port or parsed.username \
                or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise MemoryUnavailable('configure an explicit loopback IP URL, e.g. http://127.0.0.1:18761')
        self.profile = settings.get('profile')
        if self.profile not in ('conv.pref.v1', 'doc.tool.v1', 'event.schema.v1'):
            raise MemoryUnavailable('configure one explicit CoreTex profile')
        self.budget = settings.get('budget', 800)
        if type(self.budget) is not int or not 1 <= self.budget <= 100000:
            raise MemoryUnavailable('budget must be an integer in 1..100000')
        self.timeout = float(settings.get('timeout_seconds', 30))
        self.ready_timeout = float(settings.get('ready_timeout_seconds', 15))
        if not 0 < self.timeout <= 120 or not 0 <= self.ready_timeout <= 120:
            raise MemoryUnavailable('sidecar timeout is outside 0..120 seconds')
        self.expected_module = settings.get('expected_module_root')
        if self.expected_module is not None and not re.fullmatch('[0-9a-f]{64}', self.expected_module):
            raise MemoryUnavailable('expected_module_root must be a lowercase 64-hex root')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, body=None, *, timeout=None):
        data = None if body is None else json.dumps(body, allow_nan=False).encode()
        if data is not None and len(data) > 1024 * 1024:
            raise MemoryUnavailable('turn exceeds the sidecar 1 MiB request limit')
        request = urllib.request.Request(self.url + path, data=data,
                                         headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=timeout or self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('response too large')
            result = json.loads(raw)
            if not isinstance(result, dict) or 'error' in result:
                raise ValueError('sidecar error response')
            return result
        except Exception as exc:
            # A failed POST may already have committed. Never automatically retry a turn.
            raise MemoryUnavailable(f'CoreTex {path} failed ({type(exc).__name__}); '
                                    'write status may be unknown; reconcile before retrying') from None

    def health(self, *, timeout=None):
        health = self.request('/health', timeout=timeout)
        module = health.get('serving_module') or {}
        if health.get('ok') is not True or health.get('in_sync') is not True \
                or health.get('integrity') != 'ok' or health.get('profile_id') != self.profile \
                or module.get('profile') != self.profile \
                or not re.fullmatch('[0-9a-f]{64}', str(module.get('module_root', ''))):
            raise MemoryUnavailable('sidecar store is not healthy and bound to the configured profile/module')
        if self.expected_module and module['module_root'] != self.expected_module:
            raise MemoryUnavailable('sidecar module differs from expected_module_root')
        return health

    def wait_ready(self):
        deadline = time.monotonic() + self.ready_timeout
        while True:
            try:
                return self.health(timeout=min(self.timeout, max(.01, deadline - time.monotonic())))
            except MemoryUnavailable:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(.25, remaining))
