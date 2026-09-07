# Adjudication demo app (use case: zero CVEs is UNREACHABLE, so Claude's
# balanced judgment + code-fix suggestions always run):
#   1. requirements.txt pins ecdsa==0.18.0 — CVE-2024-23342 (HIGH) has NO
#      fixed release, so the dependency loop cannot clear it and no candidate
#      ever reaches strict golden.
#   2. tests/test_platform.py asserts /etc/debian_version exists — a
#      deliberate portability bug: zero-CVE minimal bases (alpine/distroless/
#      chainguard) FAIL the test suite, debian bases PASS but keep the CVE.
# Phase C must therefore weigh security-best-but-broken against
# passing-but-vulnerable — and suggest the code-level fixes for both levers.
FROM python:3.11.4-slim AS base
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
