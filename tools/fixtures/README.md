`install_judge_provider.py` is an offline test provider for the public installer check.
Build it with `tools/build-install-test-provider.py`. Its entry point is named `live`,
matching the host's actual discovery contract. It logs nonempty judgment calls,
provides deterministic answers, and can exercise trim, failure, timeout and decline.
It is never published as the Jev addon or used for scoring.
