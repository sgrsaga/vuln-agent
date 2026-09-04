# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An agentic pipeline: scan a Docker image with Trivy → check for a newer upstream tag
that already fixes CVEs → deterministically generate an OS-package-upgrade patch
Dockerfile (no LLM — see `agent/patcher.py`) → build/rescan locally → adopt only if
the rescan shows a net CVE reduction. Repeats until clean, a safety cap is hit, or no
further automated fix is possible. Two scopes: EXTERNAL (third-party) images get
tag bump + OS patch only, kept as `<tag>-optimized-ext` behind KEEP_EXTERNAL_IMAGES
(including when a tag bump alone reaches zero — spec decision); INTERNAL (owned,
label-selected) images are rebuilt from source through bounded phased loops
(`agent/hardener.py`), every candidate build+test+rescan-validated, ending as
`<tag>-golden-base-app` (strict golden: zero TOTAL CVEs and tests passing) or
`<tag>-optimized-app` (best balanced pick — possibly flagged non-deployable when
its tests fail), plus the winning base published standalone as
`<base>:<base-tag>-golden-base`/`-optimized-base`. Exactly four LLM call sites,
all in service of genuinely ambiguous decisions: base suggestion from app code
context, balanced-pick adjudication, the per-image summary report, and the
discovery-run-level report — everything else is deterministic and Trivy-verified.
See `README.md` for the full user-facing walkthrough (local setup, k8s
deployment, output format).

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
2. **Base image tag bump** (`agent/tag_finder.py`) — checks whether a newer upstream
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
3. **Patch** (`agent/patcher.py`) — **deterministic, no LLM call.** Trivy already
   reports the exact package manager (`type`) and fixed version for every
   OS-fixable CVE, so this is a lookup-table dispatch (`_UPGRADE_COMMANDS`) to a
   blanket `apk upgrade`/`apt-get upgrade`/`yum update`, layered on the *current*
   tag (never switches tags itself — that's step 2's job) — never touches Go
   binaries (structurally impossible at the image layer). `_image_user()` reads
   the image's real `USER` via `crane config` so the `USER root ... USER
   <original>` bracketing (when needed) reflects actual image config instead of
   being guessed. Returns `None` when no OS-fixable vulnerabilities remain —
   nothing more can be done this way, no API call spent finding that out.
4. **Build → rescan → adopt** (`agent/builder.py`) — builds locally (`docker build`,
   requires a Docker daemon — see `docker_available()`), rescans the result, and
   *adopts* it (`current_image_source = "local_build"`) only if the rescan shows a
   strict improvement — but does **not** push yet. A no-improvement build is
   discarded and the loop stops.

### The epilogue (`agent/orchestrator.py: _finish()`) — runs exactly once, however the loop ended

Every loop exit (`break` with a `status` set, the `while...else` on `max_iterations`,
or an immediate `return` on an iteration-1 scan failure before there's anything to
report) funnels through one epilogue that:
- **Names and pushes the final image** per the two-scope model, only when there's
  a real reason to: `internal_build` → `-golden-base-app` when strict-golden
  (status `golden_base_app`), else `-optimized-app` (always kept; a
  non-deployable balanced pick is pushed as evidence but flagged, and the
  GitOps PR-bot is gated on `deployable`); external `local_build`/`tag_bump`
  improvements → `-optimized-ext`, gated by `KEEP_EXTERNAL_IMAGES` (default
  true — keeping third-party copies is a team decision). A tag bump alone
  reaching fully clean IS still promoted to `-optimized-ext` (spec 1.1 —
  deliberate reversal of the earlier don't-duplicate-public-tags rule).
  Skipped entirely only if nothing ever changed. Mechanism follows
  `current_image_source`:
  `local_build`/`internal_build` images only exist in the local Docker daemon
  (`tag_local_image()` + `push_image()`); a `tag_bump` image is registry-only
  (`copy_image()`/`crane copy`) — not interchangeable, which is why the source
  is tracked at all.
- **Generates the one summary report** (`reporter.generate_summary_report()`) from
  `baseline_vulns` vs `final_vulns` — a real CVE-ID diff (resolved / still-present /
  newly-introduced), not just a count comparison, since a net improvement can still
  introduce something new. When the run ended in `no_docker` (a patch was generated
  but never built), the unbuilt Dockerfile text is folded into the prompt so the
  summary's remediation guidance matches what was actually computed. Internal runs
  also fold the full ladder/dep-loop `trail` (every step, outcome, rollback) in.

Termination statuses: external — `clean`, `no_further_patches`, `no_improvement`,
`max_iterations`, `no_docker` (Dockerfile generated but no daemon to build it),
plus `*_error` variants; internal — `golden_base_app`, `optimized_app`,
`no_improvement`. `main.py`'s exit code is 0 only for `clean` or
`golden_base_app`. All "improved?" comparisons are severity-ordered:
`scanner.severity_key(vulns)` → `(CRITICAL count, HIGH count)` tuple, lower is
better — a 0C/8H result beats 1C/2H despite the higher raw count.

### Promotion to higher environments (`agent/promoter.py`)

Pushing the final image (`-optimized-ext`/`-golden-base-app`/`-optimized-app`) is where the pipeline itself stops — nothing
here rewrites a deployment manifest automatically. Two independent, non-chained
paths close that gap, chosen per environment tier (see README's "Promoting
optimized images to higher environments" for the full picture):
- **Lower environments**: ArgoCD Image Updater, a separately-installed controller
  that polls the registry directly. Zero code/hooks in this repo — pure config on
  the *target* app's `Application` resource, documented in the README only.
  `update-strategy: digest` is the correct choice (not `semver`) specifically
  because these are fixed tags overwritten in place, not a growing series.
- **Higher environments (PPE/Prod)**: `_finish()` calls
  `promoter.open_promotion_pr()` when `GITOPS_REPO` is set, a promotion
  actually happened this run (`final_image != image_ref`), **and** the result
  is `deployable` (a balanced pick with failing tests never gets a PR). It patches
  `GITOPS_IMAGE_PATH_TEMPLATE.format(repo_name=...)` in `GITOPS_REPO` via the
  GitHub Contents API (regex on the bare repo name, not an exact prior value —
  works on the very first promotion too) and opens a PR — never merges. Re-runs
  reuse a **stable** branch name (`vuln-agent/optimize-<repo_name>`, no
  timestamp): if a PR is already open on that branch, the branch content is just
  updated in place rather than opening a duplicate. Follows the exact same
  `httpx` + GitHub REST pattern as `publisher.create_github_release()` — no `gh`
  CLI, no new dependency. `GITOPS_TOKEN` falls back to `GITHUB_TOKEN` when unset.

### Internal remediation (`agent/hardener.py: remediate_internal()`)

The internal (owned-image) pipeline — rebuilds from source, never patches the
published image: only ever runs for images matching `OWNED_IMAGE_LABEL_SELECTOR`
(`discoverer.discover_owned_images()`, intersected with the already
namespace-filtered discovery list in `main.py`) **and** with enough config to
locate the source/tests — never for third-party images (see README's "Base
image hardening" section for the full reasoning: no test authority means no
confidence a rebuild didn't break anything). Called from inside
`orchestrator.run()` when `internal_config` is set — internal images entirely
skip the external loop (its image-layer OS patch is rescan-verified but never
test-verified, which is unacceptable when we *have* the test suite).

Config comes from two places that merge, annotations winning field-by-field:
`vuln-agent.io/source-repo`/`dockerfile-path`/`test-stage`/`test-command`
annotations read directly off the pod by `discoverer.discover_owned_images()`
(self-service — a Deployment's `spec.template.metadata.annotations` already
propagates to its pods, so no extra k8s calls), and `HARDENING_CONFIG`
(central, keyed by bare repo name) for apps that haven't self-annotated yet or
platform-managed defaults. `main.py: _internal_config_for()` does the merge
(`{**central.get(repo_name, {}), **annotation_overrides}`) and gates on the
merged entry having a `sourceRepo` — a labeled repo without one falls back to
external treatment with a warning.

Every candidate is validated the same way (`_build_test_scan()`: rebuild → the
app's real test suite → rescan; adoption requires tests passing AND a
severity-ordered improvement) and the repo state is **rolled back
byte-for-byte on failure** (`_snapshot`/`_restore` over the Dockerfile and
manifest files) — but the failing attempt itself is **retained** in `states`
(image tag, test result, vuln snapshot) as an adjudication candidate. Three
phases, cumulative — each adopted step builds on the last:
- **Phase A — base ladder** (`LLM_BASE_MAX_ROUNDS` outer rounds, default 5,
  under a global `INTERNAL_MAX_ATTEMPTS` build/test/rescan budget, default 20):
  - **Rung 1** (loop ≤ 5) — newer tag of the *same* base repo
    (`tag_finder.find_better_tag()`, Trivy-verified, zero LLM).
  - **Rung 2** (loop ≤ 5) — the OS-package upgrade injected into the
    Dockerfile's base stage (`patcher.upgrade_lines()` — same lookup table as
    the external patch; `_inject_os_upgrade()` anchors it after the resolved
    base FROM). Deterministic.
  - **Rung 3** — `suggest_base_images()` (Claude), reached *only* if rungs 1–2
    left vulns behind. Prompted with the actual current base reference, vuln
    profile, **application code context** (`_code_context()`: Dockerfile +
    dependency manifests, size-capped), and the `tried_bases` exclusion list
    (cycle prevention). An adopted swap re-enters rungs 1–2 on the new base.
    Candidates are applied with rung 2's injected upgrade lines stripped
    (`_strip_injected_upgrade`) — another family's package-manager command
    would just break the new base's build.
  Then `_publish_base_artifact()`: the winning base (plus any injected upgrade
  layer) is built **standalone**, scanned, and pushed under the base repo's
  name as `-golden-base` (zero CVEs) or `-optimized-base`; its vuln IDs feed
  Phase B's delta.
- **Phase B — dependency loop** (≤ `DEP_UPGRADE_MAX_ITERATIONS`, default 5) —
  targets only the **app-introduced delta** (app scan minus the standalone base
  scan's IDs): `dep_upgrader.apply()` bumps to Trivy's own reported fixed
  versions (requirements.txt pin/append, package.json direct/`overrides`,
  go.mod edit + `go mod tidy` run *inside the app's own base image* since the
  agent has no Go toolchain, pom.xml direct deps only), stopping on the first
  non-improvement (rolled back). Go `stdlib` findings are skipped — that's a
  toolchain-level fix belonging to Phase A.
- **Phase C — outcome**: strict golden (zero TOTAL CVEs + tests passing) passes
  through untouched; otherwise `judge_best_candidate()` (Claude) adjudicates
  across every retained state — weighing vulnerability impact vs test breakage
  and implied code impact, returning `{chosen, justification, code_fixes}`. The
  pick is adopted only if it severity-improves on the baseline; deployability
  comes from its actual test result, never the model. Malformed/failed
  responses fall back deterministically to the severity-best *passing* state.
  Non-winner local images are cleaned up.

`_patch_dockerfile_base()` rewrites the `FROM` line for whichever stage
actually becomes the final built image (`_resolve_final_base_stage()`: start
at the *last* stage — what a plain `docker build` with no `--target` produces,
matching what Trivy scans — and walk backwards through `AS`-alias references
until landing on a real image, not another stage's name). This matters
concretely for the common builder+runtime pattern (`FROM golang:1.21 AS
builder` ... `FROM alpine:3.18 AS runtime`): only the alpine line is real for
the shipped image. Residual gap, documented in the README rather than solved:
if a repo's `testStage` doesn't share lineage with the runtime stage, a passing
test run doesn't actually validate the swapped base — onboarding a repo
requires structuring `test` to build on top of the runtime stage. Validates via
`testStage` (`docker build --target test` — build failure *is* test failure) or
`testCommand` (`builder.run_isolated()`, `docker run --network none` — network
denied so a compromised cloned test suite can't exfiltrate the agent's mounted
credentials; **not** full sandboxing, still shares the docker daemon/host
kernel — a known limitation. The dep loop's `go mod tidy` container run is the
one deliberate exception: network ON, because module fetch needs it and the
command is ours, not repo-controlled).

`remediate_internal()` returns `{final_tag, final_vulns, deployable, trail,
base_artifact, judgment}` and pushes only the standalone base artifact itself —
`orchestrator._finish()` owns the app image's naming (`-golden-base-app` /
`-optimized-app`) and push.

### Discovery mode (`agent/discoverer.py`)

Lists unique container images across cluster pods (in-cluster SA → kubeconfig →
`kubectl` subprocess fallback, in that priority order). Namespace selection is a
whitelist (`target_namespaces`) that takes priority over a blacklist
(`excluded_namespaces`) when both are given. `main.py: run_discovery()` runs each
discovered image through `orchestrator.run()` sequentially, each into its own
`output/<slugified-image>/` subdirectory, then writes the run-level report
(`reporter.generate_run_report()` → `<output-dir>/run-summary.md` — the fourth
LLM call site: one External + one Internal section across every image this run,
best-effort/try-except so a report failure never fails the run) and creates one
combined GitHub Release at the end (`create_release=False` per-image, one final
call).

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
plus, in discovery mode only, one `run-summary.md` at the output root.
Reports fan out to three human-facing destinations beyond the Release archive,
all best-effort (a failure never fails the run): `push_report_to_repo()` /
`push_summary_reports()` commit each report to `REPORTS_REPO` (dated file +
stable `latest.md` under `reports/<repo>/<tag>/`, `reports/run-summary/` for
the run report — Contents API, `REPORTS_TOKEN`→`GITHUB_TOKEN` fallback, unset
repo = silent no-op); `_finish()` generates the summary *before* the PR-bot so
`open_promotion_pr(summary=...)` can fold it into the PR body (truncated to a
50k budget, re-PATCHed onto an existing open PR so re-runs stay fresh); and a
non-deployable balanced pick files `promoter.open_code_fix_issue()` on the
app's own `sourceRepo` (stable title keyed by image ref — re-runs comment on
the existing open issue; gated by `CODE_FIX_ISSUES`, default true).
`publish_summary()` returns the fully composed markdown for exactly this reuse.
`create_github_release()` uploads whatever it finds there wholesale, so keeping the
artifact set minimal is enforced by simply not writing anything else, not by
filtering at upload time. Outside
Actions (local or in k8s), `create_github_release()` uploads the files as
release assets via the GitHub REST API directly — no `gh` CLI dependency, which
matters since the k8s deployment path has no CLI tooling installed. Inside Actions,
`create_github_release()` no-ops and `.github/workflows/vuln-remediate.yml`'s own
`gh release create` step does it instead — both have their own hardcoded
release-notes text describing the artifact set, so keep them in sync if it changes
again.

### crane vs docker

`crane` (bundled in the agent's own Dockerfile, downloaded as a pre-built binary
from GitHub releases rather than via `go install`, to avoid Go proxy flakiness) is
used for every daemon-less registry operation: tag listing, digest resolution,
and tag-bump promotion. `docker` is used only for building and pushing
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
  Carries the full env parameter set (aligned with `.env.example` and the chart
  ConfigMap): the CronJob runs discovery mode (`--discover`, ServiceAccount +
  ClusterRole in `k8s/rbac.yaml`); the one-shot Job is single-image mode with
  `HARDEN_BASE_IMAGE` as the internal-scope opt-in.
- `chart/` — a Helm chart (see `chart/values.yaml`) that is the more actively
  developed path per git history: SealedSecrets for credentials
  (`chart/sealed-secrets.yaml`, applied separately before `helm upgrade --install`),
  a `discovery.targetNamespaces`/`excludedNamespaces` whitelist-first model, and
  `docker.hostSocketPath` opt-in (empty by default → analysis-only mode).

  Check git history / ask before assuming which path a given k8s change should
  target — they are not kept in sync automatically.
