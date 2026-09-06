# Publishing desicon-seal

Configure the existing PyPI project trusted publisher with owner `Desicon-AI`, repository `grumpy-python`, workflow `publish-pypi.yml`, environment `pypi`.

Run the Publish Python package workflow on `main` with publish=false to test, build, validate metadata and retain the distributions as an artifact. After verifying a new version in setup.py is unused on PyPI, run with publish=true. The publish job uploads only those tested artifacts through OIDC; no stored PyPI token is required. A push to main alone does not publish a package. Published version numbers cannot be reused.
