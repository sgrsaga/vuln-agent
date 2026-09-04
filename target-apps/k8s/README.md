# Deploying the sample apps for real vuln-agent testing

Manifests for running all five target apps in the `apps` namespace as
**owned workloads** — labeled and annotated so a discovery run of the agent
picks them up and takes them through the full internal pipeline (base ladder →
standalone base artifact → dependency loop → golden/optimized outcome).

## One shared repo: apps + reports side by side

All five apps live in the **same repo the agent writes its reports into**
(`sgrsaga/reports` by default — matching `reports.repo` in `chart/values.yaml`),
each under its own folder, so application code and the remediation reports
about it sit in one place:

```
sgrsaga/reports
├── python-app/        ← app source (this script publishes these)
├── go-app/ …          ← one folder per app
└── reports/           ← written by the agent (per-image + run summaries)
```

The hardening pipeline clones `vuln-agent.io/source-repo` and **builds the
directory that holds `vuln-agent.io/dockerfile-path`**: with
`dockerfile-path: python-app/Dockerfile` the agent uses `python-app/` inside
the clone as the build context, and the dependency manifests the dep loop
edits (`requirements.txt`, `package.json`, `go.mod`, `pom.xml`) are looked up
there too. `publish-apps.sh` syncs only the app folders (never touching
`reports/`, never force-pushing), logs docker into ghcr.io itself, and
builds/pushes each app's image from its subdirectory in one step.

## Setup

```bash
# 1. Publish the app folders + per-app images (idempotent; re-run after editing an app)
#    Token needs classic scopes: repo + write:packages
GITHUB_TOKEN=ghp_... ./publish-apps.sh sgrsaga v1 reports

# 2. Namespace + pull secret
kubectl apply -f namespace.yaml
kubectl -n apps create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=ghp_...

# 3. Deploy the apps
kubectl apply -f .
kubectl -n apps get pods
```

## Agent configuration that must line up

In `chart/values.yaml`:

- `discovery.targetNamespaces` must include `apps` — it does.
- `discovery.ownedImageLabelSelector: "vuln-agent.io/harden=true"` — matches
  the label these Deployments put on their pods. **Empty selector = the apps
  are scanned as external images only** (tag bump + OS patch, no rebuild).

Everything else is self-service via the pod annotations already in these
manifests (`source-repo` / `dockerfile-path` / `test-stage`) — no central
`hardening.images` entry needed.

## What a discovery run should show per app

Each image is deliberately built on an older base (e.g. `python:3.9-slim`,
`node:18-slim`, `golang:1.21-alpine`, `eclipse-temurin:17-jdk-alpine`) and
`python-app` additionally pins vulnerable `flask==2.2.2`/`werkzeug==2.2.2` as a
dependency-loop fixture. Expect: Phase A improving or swapping the base
(test-gated), a standalone `-golden-base`/`-optimized-base` artifact, Phase B
bumping the python-app pins, and a `-golden-base-app`/`-optimized-app` final
image plus the summary report per image and one run-level `run-summary.md`.

## Trigger a run immediately

```bash
kubectl -n security create job vuln-agent-manual --from=cronjob/vuln-agent
kubectl -n security logs -f job/vuln-agent-manual
```
