# Seal Python SDK 1.0.5

Release candidate: build and test before publishing to PyPI. `from seal import seal` is the public API. Earlier Python 1.0.4 sandbox and deployment APIs are retained.

```python
import os
from seal import seal

seal.init(api_key=os.environ["SEAL_API_KEY"], app_name="My API",
          environment="production", signing_secret=os.environ.get("SEAL_SIGNING_SECRET"))
# FastAPI/Starlette: app.add_middleware(seal.asgi_middleware())
```

`init` also accepts `ingest_url`, `sandbox`, and `waf`. Each outgoing request is signed over its exact bytes. Heartbeats run every 60 seconds independently of startup delivery and expose `seal.delivery_health`. Reinitializing does not add heartbeat threads or recursive exception hooks. `seal.register_deployment(version)` returns whether delivery succeeded. Startup/deployment markers do not prove that incidents recovered.

Application WAF rules use explicit `action: report` or `action: drop`. Scanner signals report by default; curl, wget and Python requests are ordinary clients. Path traversal drops by default, preserving the existing Python setting. Configure `waf={"pathTraversal":{"action":"report"}}` for an observation-only pilot. SQL/XSS URL heuristics report only. Forwarded IP/country headers are ignored unless `trustProxyHeaders` is explicitly enabled behind a proxy that strips untrusted incoming headers.

Threat telemetry contains approved request metadata and a path hash. It omits credentials, cookies, arbitrary headers, raw URLs, query strings and request bodies. Error reports still include exception messages, stack traces and surrounding source context; avoid placing secrets in those values. This SDK reports crashes and WAF signals; it does not execute AI-generated Python or JavaScript patches.

Run `python -m unittest discover -s tests -v`. Build from a clean checkout with `python -m build`; verify that the wheel contains `seal/__init__.py` and `seal/client.py` before release.

## Optional enforcement rules

The `honeypot`, `sqli`, and `xss` rules accept an `action` of `drop` or `report`. They default to `report`: upgrading does not silently block new classes of traffic. Enable each rule after testing legitimate application workflows. `drop` rejects matching requests and records `action: blocked`; observation mode records `observed`. Honeypot paths include WordPress login/admin paths and must not be blocked on sites that legitimately use those paths. Historical records are not reclassified.
