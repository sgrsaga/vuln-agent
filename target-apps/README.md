# target-apps

Small, real, working sample applications used as reference fixtures for
`agent/hardener.py`'s base-image hardening feature — one each for Python, Go,
Java, Node.js, and TypeScript. Each is independently buildable and runnable:

```bash
cd target-apps/python-app
docker build --target test .   # runs the real test suite — build fails if tests fail
docker build -t python-app .   # builds the actual runtime image
docker run -p 8080:8080 python-app
```

Every base image tag is deliberately older/pinned (not `latest`) so there's a
real vulnerability surface for `suggest_base_images()`/`harden_image()` to
work against. None of this is required reading to *use* vuln-agent — it's here
so the hardening feature (ownership marking → config resolution → clone →
patch → test → rescan → adopt) has concrete fixtures to evaluate against
instead of only hypothetical config, and so the pattern below has a working
reference the first time you onboard a real app.

## The lineage-safe Dockerfile pattern every app here follows

`agent/hardener.py: _patch_dockerfile_base()` only ever rewrites the `FROM`
line for the stage that actually becomes the *shipped* image — the last stage
in the file (what a plain `docker build` with no `--target` produces, matching
what Trivy scans), walking backwards through `AS`-alias references until it
lands on a real image. Your `test`/`testStage` **must build on top of that
same stage** — not an unrelated earlier stage — or a passing test run isn't
actually evidence about the image that gets hardened and pushed:

```dockerfile
FROM python:3.9-slim AS base      # ← the real base; this line gets swapped
RUN ...
COPY . .

FROM base AS test                 # descends from `base` — shares its lineage
RUN pytest

FROM base AS runtime               # also descends from `base`
CMD ["python", "app.py"]
```

**Compiled languages (`go-app`, `java-app`) have a real tension here**: the
whole point of a multi-stage build is usually to compile in a heavy toolchain
image and ship a minimal runtime (`FROM golang:1.21 AS builder` ... `FROM
alpine:3.18 AS runtime`) — but that minimal runtime can't run `go test`/`mvn
test` itself, and a `test` stage built from the *builder* image would have a
different lineage than `runtime`, exactly the pitfall above. This repo's
samples resolve it by shipping the toolchain image itself as the runtime base
(see the comment in each Dockerfile) — simpler, and correct-by-construction,
at the cost of a larger runtime image. A production Dockerfile that wants a
truly minimal final stage instead can have `test` temporarily install the
toolchain *onto that same minimal base* (e.g. `RUN apk add --no-cache go`) so
`test` and `runtime` still share lineage — more setup, but ships less in
`runtime`.

## Onboarding one of these (or a real app) for hardening

Two equivalent ways — see `README.md`'s "Base image hardening" section for
the full picture. `dockerfile-path` is relative to the clone root, and the
agent uses the Dockerfile's directory as the build context — so an app can be
a subdirectory of a monorepo (as all of these apps are, in `myorg/target-apps`)
or a repo of its own (`dockerfile-path: Dockerfile`). Using `python-app` as
the example, assuming its image lived at `ghcr.io/myorg/python-app:v1.0.0`:

**Self-service, on the app's own Deployment** (no separate file to touch):
```yaml
metadata:
  labels:
    vuln-agent.io/harden: "true"
  annotations:
    vuln-agent.io/source-repo: myorg/target-apps
    vuln-agent.io/dockerfile-path: python-app/Dockerfile
    vuln-agent.io/test-stage: test
```

**Central, in `chart/values.yaml`**:
```yaml
discovery:
  ownedImageLabelSelector: "vuln-agent.io/harden=true"
hardening:
  images:
    - repo: python-app
      sourceRepo: myorg/target-apps
      dockerfilePath: python-app/Dockerfile
      testStage: test
```

## The apps

| Directory | Runtime | Base image | Test command |
|---|---|---|---|
| `python-app/` | Flask API (`/health`, `/fib/<n>`) — deliberately pins old `flask==2.2.2`/`werkzeug==2.2.2` (known CVEs) so the dependency-upgrade loop has something real to fix | `python:3.9-slim` | `pytest` |
| `go-app/` | `net/http` server (`/health`) | `golang:1.21-alpine` | `go vet ./... && go test ./...` |
| `java-app/` | `com.sun.net.httpserver` server (`/health`), Maven | `eclipse-temurin:17-jdk-alpine` | `mvn test` |
| `nodejs-app/` | `node:http` server (`/health`) | `node:18-slim` | `node --test` (built-in test runner) |
| `typescript-app/` | Same shape as `nodejs-app`, compiled via `tsc` | `node:18-slim` | `npm run build && node --test` on the compiled output |
