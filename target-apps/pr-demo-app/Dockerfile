# PR-promotion demo app (use case: successful remediation → GitOps PR).
# Deps are clean and tests are portable, so the ONLY vulnerability surface is
# the deliberately old pinned base — the ladder fixes it, the result is
# deployable, and _finish() opens the promotion PR against the GitOps repo
# (gitops/environments/ppe/pr-demo-app/values.yaml holds the ref it patches).
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
