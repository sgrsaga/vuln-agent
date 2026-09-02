# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An agentic pipeline: scan a Docker image with Trivy → check for a newer upstream tag
that already fixes CVEs → deterministically generate an OS-package-upgrade patch
Dockerfile (no LLM — see `agent/patcher.py`) → build/rescan locally → adopt only if
the rescan shows a net CVE reduction. Repeats until clean, a safety cap is hit, or no
further automated fix is possible. Exactly one image ever reaches the registry per
run (`<original-tag>-optimized`), and exactly one Claude Opus-authored before/after
summary report is produced — the only LLM call anywhere in the pipeline — both at
the very end, not per iteration. See `README.md` for the full user-facing
walkthrough (local setup, k8s deployment, output format).

## Commands

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
trivy image --download-db-only   # pre-warm the ~600MB Trivy DB once

# Run — single image
python main.py ghcr.io/dexidp/dex:v2.45.1
python main.py <image> --max-iterations 3 --output-dir /tmp/scan-results

# Run — cluster-wide discovery (reads pods via kubeconfig / in-cluster SA / kubectl fallback)
python main.py --discover --namespaces argocd,monitoring
python main.py --discover --exclude-namespaces kube-system,kube-public

# Build the agent's own container image
docker build -t vuln-agent .

# Helm chart (the actively-developed k8s deployment path — see below)
helm lint chart/
helm template vuln-agent chart/
helm upgrade --install vuln-agent chart/ -n security -f chart/values.yaml
```

There is no test suite, linter, or formatter configured in this repo (no `pytest`,
`ruff`/`flake8`, or CI beyond the manual-trigger workflow in
`.github/workflows/vuln-remediate.yml`). Requires `trivy`, `crane`, and (for local
builds only) `docker` on PATH; `ANTHROPIC_API_KEY` must be set.

## Architecture

### The remediation loop (`agent/orchestrator.py: run()`)

Per iteration, in order — nothing here writes an artifact or touches the registry;
that all happens once, after the loop, in the epilogue below:
1. **Scan** (`agent/scanner.py`) — Trivy JSON, flattened to `{id, severity, package,
   type, fixed, ...}` dicts. `type` distinguishes OS-package vulns (`alpine`,
   `debian`, `ubuntu`, ...) from `gobinary` (compiled-in Go dependency CVEs). Only
   iteration 1's scan is captured as `baseline_vulns`; every iteration's scan
   updates `final_vulns` so it always reflects the current true state.
2. **Go binary analysis** (`agent/go_analyzer.py`, iteration 1 only, cached) — for
   each `gobinary` CVE, extracts the binary via `crane export` (no Docker daemon
   needed) and runs `govulncheck -mode binary` to reclassify Trivy's version-range
   matches as `false_positive` / `confirmed` / `skipped`. This cache is invalidated
   (`go_analysis = None`) whenever the image changes underneath it via a tag bump,
   since a different upstream tag likely has different compiled binaries.
3. **Base image tag bump** (`agent/tag_finder.py`) — checks whether a newer upstream
   tag of the *same* repo already has fewer vulnerabilities, via `crane ls` +
   Trivy-scanning nearest candidates ascending. If one improves, it's adopted
   directly (`crane copy` into `GHCR_NAMESPACE` if set, otherwise referenced
   in-place), `current_image_source` is set to `"tag_bump"`, and the loop restarts —
   no Claude calls, no Dockerfile, no build. Crucially, this always checks the
   **original upstream repo**, tracked separately as `origin_repo`/`baseline_tag`
   computed once from the initial `image_ref` — never `current_image`, which after
   an OS-layer patch points into `GHCR_NAMESPACE` (your own patched-artifact repo,
   not upstream releases). `original_tag` (also captured once, but never mutated)
   is kept distinct from `baseline_tag` (which ratchets forward on every adopted
   bump) specifically so the *final* promoted tag reflects what the user actually
   asked to scan, not wherever the search ended up.
4. **Patch** (`agent/patcher.py`) — **deterministic, no LLM call.** Trivy already
   reports the exact package manager (`type`) and fixed version for every
   OS-fixable CVE, so this is a lookup-table dispatch (`_UPGRADE_COMMANDS`) to a
   blanket `apk upgrade`/`apt-get upgrade`/`yum update`, layered on the *current*
   tag (never switches tags itself — that's step 3's job) — never touches Go
   binaries (structurally impossible at the image layer). `_image_user()` reads
   the image's real `USER` via `crane config` so the `USER root ... USER
   <original>` bracketing (when needed) reflects actual image config instead of
   being guessed. Returns `None` when no OS-fixable vulnerabilities remain —
   nothing more can be done this way, no API call spent finding that out.
5. **Build → rescan → adopt** (`agent/builder.py`) — builds locally (`docker build`,
   requires a Docker daemon — see `docker_available()`), rescans the result, and
   *adopts* it (`current_image_source = "local_build"`) only if the rescan shows a
   strict improvement — but does **not** push yet. A no-improvement build is
   discarded and the loop stops.

### The epilogue (`agent/orchestrator.py: _finish()`) — runs exactly once, however the loop ended

Every loop exit (`break` with a `status` set, the `while...else` on `max_iterations`,
or an immediate `return` on an iteration-1 scan failure before there's anything to
report) funnels through one epilogue that:
- **Promotes the final image** to `<original_tag>-optimized`, but only when there's
  a real reason to: skipped entirely if nothing ever changed, or if a tag bump alone
  reached fully clean (that upstream tag is already public — duplicating it adds
  nothing). Otherwise: a `"local_build"` image only exists in the local Docker
  daemon, so promotion is `tag_local_image()` + `push_image()`; a `"tag_bump"`
  image is registry-only, so promotion is `copy_image()` (`crane copy`) — these two
  mechanisms are not interchangeable, which is why `current_image_source` is tracked
  at all.
- **Generates the one summary report** (`reporter.generate_summary_report()`) from
  `baseline_vulns` vs `final_vulns` — a real CVE-ID diff (resolved / still-present /
  newly-introduced), not just a count comparison, since a net improvement can still
  introduce something new. When the run ended in `no_docker` (a patch was generated
  but never built), the unbuilt Dockerfile text is folded into the prompt so the
  summary's remediation guidance matches what was actually computed.

Termination statuses: `clean`, `no_further_patches`, `no_improvement`,
`max_iterations`, `no_docker` (Dockerfile generated but no daemon to build it),
plus `*_error` variants. `main.py`'s exit code is 0 only for `clean`.

### Promotion to higher environments (`agent/promoter.py`)

Pushing `<original-tag>-optimized` is where the pipeline itself stops — nothing
here rewrites a deployment manifest automatically. Two independent, non-chained
paths close that gap, chosen per environment tier (see README's "Promoting
optimized images to higher environments" for the full picture):
- **Lower environments**: ArgoCD Image Updater, a separately-installed controller
  that polls the registry directly. Zero code/hooks in this repo — pure config on
  the *target* app's `Application` resource, documented in the README only.
  `update-strategy: digest` is the correct choice (not `semver`) specifically
  because `-optimized` is a fixed tag overwritten in place, not a growing series.
- **Higher environments (PPE/Prod)**: `_finish()` calls
  `promoter.open_promotion_pr()` when `GITOPS_REPO` is set and a promotion
  actually happened this run (`final_image != image_ref`). It patches
  `GITOPS_IMAGE_PATH_TEMPLATE.format(repo_name=...)` in `GITOPS_REPO` via the
  GitHub Contents API (regex on the bare repo name, not an exact prior value —
  works on the very first promotion too) and opens a PR — never merges. Re-runs
  reuse a **stable** branch name (`vuln-agent/optimize-<repo_name>`, no
  timestamp): if a PR is already open on that branch, the branch content is just
  updated in place rather than opening a duplicate. Follows the exact same
  `httpx` + GitHub REST pattern as `publisher.create_github_release()` — no `gh`
  CLI, no new dependency. `GITOPS_TOKEN` falls back to `GITHUB_TOKEN` when unset.

### Base image hardening (`agent/hardener.py`)

The one place this pipeline rebuilds an image from source rather than patching
an existing one — and deliberately the narrowest-scoped feature in the repo:
only ever runs for images matching `OWNED_IMAGE_LABEL_SELECTOR`
(`discoverer.discover_owned_images()`, intersected with the already
namespace-filtered discovery list in `main.py`) **and** with enough config to
locate the source/tests — never for third-party images (see README's "Base
image hardening" section for the full reasoning: no test authority means no
confidence a rebuild didn't break anything).

Config comes from two places that merge, annotations winning field-by-field:
`vuln-agent.io/source-repo`/`dockerfile-path`/`test-stage`/`test-command`
annotations read directly off the pod by `discoverer.discover_owned_images()`
(self-service — a Deployment's `spec.template.metadata.annotations` already
propagates to its pods, so no extra k8s calls), and `HARDENING_CONFIG`
(central, keyed by bare repo name) for apps that haven't self-annotated yet or
platform-managed defaults. `main.py: _maybe_harden()` does the merge
(`{**central.get(repo_name, {}), **annotation_overrides}`) and gates on the
merged entry having a `sourceRepo` — not on `HARDENING_CONFIG` membership,
since a repo can now be fully configured via annotations alone.

Candidate generation is two-tiered, deterministic first — `harden_image()`
clones `sourceRepo`, reads the cloned Dockerfile's actual current base via
`_resolve_final_base_stage()` (see below), then:
- **Tier 1** — reuses `tag_finder.find_better_tag()` (the same Trivy-verified
  tag-bump logic the main remediation loop already uses) to check for a newer
  tag of that *same* base repo. Zero ambiguity, zero LLM calls — a
  newer-point-release question has an objectively correct answer a
  registry+scanner lookup can already give.
- **Tier 2** — `suggest_base_images()`, the one Claude call in this module,
  reached *only* if tier 1 found nothing or its candidate didn't survive the
  app's real test suite. Given the actual current base image reference (not
  just `scanner.extract_os_info()`'s OS family/version — real signal on what
  runtime this is) and vuln profile, it's explicitly told a same-repo tag has
  already been ruled out, and asked for candidates from a genuinely different
  family/vendor. This is the actually LLM-shaped part (world knowledge about
  which minimal/distroless bases exist per runtime, not derivable from scan
  data) — unlike tier 1, and unlike `patcher.py`'s deterministic OS-upgrade
  logic.

Both tiers' candidates flow through the same `_try_candidate()` validation —
`_patch_dockerfile_base()` rewrites the `FROM` line for whichever stage
actually becomes the final built image (`_resolve_final_base_stage()`: start
at the *last* stage — what a plain `docker build` with no `--target` produces,
matching what Trivy scans — and walk backwards through `AS`-alias references
until landing on a real image, not another stage's name). This matters
concretely for the common builder+runtime pattern (`FROM golang:1.21 AS
builder` ... `FROM alpine:3.18 AS runtime`): only the alpine line is real for
the shipped image, since the builder stage is discarded after its artifacts
are `COPY --from=`'d out — patching the builder's base would be a silent
no-op on the actual deployed image. Residual gap, documented in the README
rather than solved: if a repo's `testStage` doesn't share lineage with the
runtime stage, a passing test run doesn't actually validate the swapped base —
onboarding a repo for hardening requires structuring `test` to build on top of
the runtime stage. Validates via `testStage` (`docker build --target test` —
build failure *is* test failure, no separate check needed) or `testCommand`
(`builder.run_isolated()`, `docker run --network none` — network denied
specifically so a compromised/malicious cloned test suite can't exfiltrate the
agent's mounted credentials; **not** full sandboxing, still shares the docker
daemon/host kernel, called out as a known limitation in the README rather than
quietly assumed away). First candidate to both pass and reduce vulnerabilities
wins, pushed as `<original-tag>-golden` — a tag family kept distinct from
`-optimized` since swapping the base entirely is a categorically bigger change
than layering package upgrades.

### Discovery mode (`agent/discoverer.py`)

Lists unique container images across cluster pods (in-cluster SA → kubeconfig →
`kubectl` subprocess fallback, in that priority order). Namespace selection is a
whitelist (`target_namespaces`) that takes priority over a blacklist
(`excluded_namespaces`) when both are given. `main.py: run_discovery()` runs each
discovered image through `orchestrator.run()` sequentially, each into its own
`output/<slugified-image>/` subdirectory, then creates one combined GitHub Release
at the end (`create_release=False` per-image, one final call).

Since discovery mode is what the CronJob runs on a schedule (`chart/templates/cronjob.yaml`),
`agent/image_tracker.py` skips images that haven't changed since last time, keyed
by digest (`crane digest <ref>`, resolved fresh each run — not the pod-reported tag)
against a state file at `<output-dir>/.vuln-agent-state/tracked-images.json` on the
`output` PVC. Skip requires all of: digest unchanged, prior status not one of
`ERROR_STATUSES` (always retry a failed attempt), and `last_scanned` within
`RESCAN_INTERVAL_DAYS` (default 7 — even an unchanged image gets periodically
rechecked, since the point of a recurring scan is catching newly-disclosed CVEs
too, not just new deployments). `publisher.create_github_release()`'s file walk
explicitly excludes `image_tracker.STATE_DIR_NAME` so the state file never ends up
attached as a release asset. Scoped to discovery mode only — single-image mode
(`main.py <image>`) always runs regardless of this state.

### Output / publishing (`agent/publisher.py`)

Exactly two files land in `OUTPUT_DIR` per image: `scan-baseline.json` (written once,
from iteration 1) and `summary-report.md` (written once, from the epilogue) —
`create_github_release()` uploads whatever it finds there wholesale, so keeping the
artifact set minimal is enforced by simply not writing anything else, not by
filtering at upload time. `publish_go_analysis()` still logs to
`$GITHUB_STEP_SUMMARY` for live GitHub Actions visibility, but no longer persists a
JSON file — that content now lives inside the one summary report instead. Outside
Actions (local or in k8s), `create_github_release()` uploads the two files as
release assets via the GitHub REST API directly — no `gh` CLI dependency, which
matters since the k8s deployment path has no CLI tooling installed. Inside Actions,
`create_github_release()` no-ops and `.github/workflows/vuln-remediate.yml`'s own
`gh release create` step does it instead — both have their own hardcoded
release-notes text describing the artifact set, so keep them in sync if it changes
again.

### crane vs docker

`crane` (bundled in the agent's own Dockerfile, downloaded as a pre-built binary
from GitHub releases rather than via `go install`, to avoid Go proxy flakiness) is
used for every daemon-less registry operation: binary extraction for govulncheck,
tag listing, and tag-bump promotion. `docker` is used only for building and pushing
OS-layer patches, and requires a real daemon — in k8s that means mounting the host's
`/var/run/docker.sock`, which is why `chart/values.yaml`'s `docker.hostSocketPath`
defaults empty (analysis-only mode: scan, classify, generate reports/Dockerfiles,
skip build+push) rather than assuming socket access is available.

Note: `main.py: _check_deps()` currently requires `docker` on PATH unconditionally,
even though the orchestrator has a documented no-Docker analysis-only path
(`docker_available()` returning `False` → `no_docker` status). Keep this in mind if
you're debugging why analysis-only mode isn't reachable from the CLI.

### Two parallel k8s deployment paths

- `k8s/*.yaml` — raw Job/CronJob manifests, documented step-by-step in `README.md`.
  Assumes host Docker socket access and manually-created `kubectl create secret`s.
- `chart/` — a Helm chart (see `chart/values.yaml`) that is the more actively
  developed path per git history: SealedSecrets for credentials
  (`chart/sealed-secrets.yaml`, applied separately before `helm upgrade --install`),
  a `discovery.targetNamespaces`/`excludedNamespaces` whitelist-first model, and
  `docker.hostSocketPath` opt-in (empty by default → analysis-only mode).

  Check git history / ask before assuming which path a given k8s change should
  target — they are not kept in sync automatically.
