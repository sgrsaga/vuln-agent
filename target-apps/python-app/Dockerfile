# Reference app for vuln-agent's base-image hardening feature (see
# target-apps/README.md). Base is deliberately an older pinned tag so there's a
# real vulnerability surface for the hardening loop to work against.
#
# `test` and `runtime` both descend from `base` (never from an unrelated
# stage), so `_patch_dockerfile_base()` (agent/hardener.py) correctly resolves
# and swaps this single real base line for every candidate it tries, and a
# passing `docker build --target test` is real evidence about the exact image
# that would ship.
FROM python:3.9-slim AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

FROM base AS test
RUN pip install --no-cache-dir pytest
RUN pytest -q

FROM base AS runtime
EXPOSE 8080
CMD ["python", "app.py"]
