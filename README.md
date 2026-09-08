# vuln-agent

An agentic pipeline that automatically scans every Docker image running in a cluster and remediates by ownership: **owned applications** are rebuilt from source through bounded agentic loops — Claude-suggested base images and dependency upgrades, every candidate gated by the app's own test suite — producing golden (zero-CVE) base and app images, with Claude adjudicating the best balanced pick when zero isn't reachable and writing the before/after reports. Third-party images (not recommended and not the intended scope, but worth considering for short-term requirements) get deterministic tag bumps and OS-package patches, kept only when a rescan proves improvement.

Free and open source under the [MIT](https://choosealicense.com/licenses/mit/) — use it, fork it,
adapt it to your organization. Read
[Adopting this project — pros, cons & risks](#adopting-this-project--pros-cons--risks)
before running it against a real cluster.

## Who is this for?

**Best fit — fast-paced development.** This project earns its keep where
container images change *constantly*: rapid application development with
frequently shifting scope, teams spinning up many prototypes and short-lived
services, platform teams onboarding new apps every sprint. In that environment
nobody has time to chase CVEs per image — the agent absorbs the external
security overhead automatically (scan, rebase, patch, test-verify, report),
developers keep shipping, and every newly built image gets pulled toward a
golden base without a security review blocking the loop.

**Weak fit — stable/legacy estates.** Organizations maintaining the same
application code for years with minor changes gain much less: their images
rarely change (so the digest-gated runs are mostly silent), their base images
are already institutionalized, and established patch-management processes
usually cover the same ground with more ceremony. The one thing such estates
still get from a scheduled run is early warning — periodic rescans catch
*newly disclosed* CVEs against images nobody has touched in months, plus the
report/issue trail to act on them — but the agentic rebuild machinery that is
the heart of this project will sit mostly idle.

## Overview — what this does once it's running in your cluster

Deployed as a scheduled Kubernetes CronJob (see `chart/`), with zero manual
triggering: it discovers every image running across your cluster, scans each
one, and only ever reaches for Claude at the five specific points where a
lookup table genuinely can't do the job — everything else (tag bumps, package
upgrades, build/test/rescan verification) is deterministic and Trivy-verified.

<img src="gif-vuln-agent.gif" alt="vuln-agent — cluster-wide scan, remediate, verify, and report pipeline" width="100%">


## Agentic flow

```mermaid
flowchart TD
    classDef llm fill:#fff3cd,stroke:#c9971e,stroke-width:2px,color:#3a2f00
    classDef det fill:#dbe9ff,stroke:#4a76c9,stroke-width:1px,color:#0b2447
    classDef out fill:#d9f2e3,stroke:#2f9e5f,stroke-width:1px,color:#0b3d24
    classDef ppl fill:#fde2e2,stroke:#c0564a,stroke-width:2px,color:#4a1410

    CRON["📅 Scheduled CronJob<br/>no human trigger needed"]:::det
    DISC["🔎 Discover every image running in the cluster<br/>skip ones unchanged since last run"]:::det
    SCAN["🩺 Trivy scan for CVEs"]:::det
    OWNEDQ{{"Is this an app you own,<br/>labeled & configured<br/>for rebuild-from-source?"}}:::det

    subgraph PHASEA["🔁 BASE-IMAGE agentic loop — ≤5 rounds, global budget of 20 attempts"]
        direction TB
        LADDER["🛠️ Deterministic rungs:<br/>1. newer tag of the SAME base (≤5)<br/>2. OS-package patch in the base stage (≤5)"]:::det
        TESTA["✅ Validate EVERY candidate:<br/>rebuild → app's OWN test suite → rescan;<br/>failures rolled back but RETAINED as evidence"]:::det
        T2["🤖 Claude — base determination<br/>from the APPLICATION CODE<br/>(already-tried bases excluded)"]:::llm
        RESTR["🤖 Claude — Dockerfile restructure:<br/>build WITH tooling, COPY artifacts into<br/>the minimal runtime + smoke-verify"]:::llm
        LADDER --> TESTA
        TESTA -. "CVEs remain" .-> T2
        T2 -. "swap adopted —<br/>re-enter the rungs" .-> LADDER
        T2 -. "zero-CVE base<br/>lacks shell/pip" .-> RESTR
        RESTR -. "re-validated +<br/>smoke-gated" .-> TESTA
    end

    BASEART["🧱 Winning base pushed standalone:<br/>vendor-qualified -golden-base / -optimized-base<br/>— a curated base OTHER apps can adopt"]:::out

    subgraph PHASEB["🔁 APPLICATION-IMAGE agentic loop — ≤5 passes"]
        direction TB
        DEP["🛠️ Bump only APP-introduced CVEs<br/>to Trivy's exact fixed versions"]:::det
        TESTB["✅ rebuild → test → rescan"]:::det
        DEP --> TESTB
        TESTB -. "improved & app<br/>CVEs remain" .-> DEP
    end

    OUTQ{{"zero TOTAL CVEs<br/>+ tests passing?"}}:::det
    JUDGE["🤖 Claude — balanced adjudication across<br/>every retained candidate: vuln impact vs<br/>test breakage; suggests code fixes and files<br/>them as an issue on the app's own repo"]:::llm
    GOLDEN["🏆 tag-golden-base-app (strict golden) or<br/>📦 tag-optimized-app (balanced pick,<br/>flagged NON-DEPLOYABLE if tests fail)"]:::out
    SUMMARY["🤖 Claude — per-image before/after report<br/>+ run-level summary, committed to the<br/>reports repo next to the app's code"]:::llm
    REMED["🛠️ External remediation loop<br/>(3rd-party — not the intended scope):<br/>newer upstream tag or OS-package patch<br/>→ build → rescan → keep only if improved<br/>+ its own before/after report"]:::det
    OPT["📦 tag-optimized-ext pushed<br/>to your registry<br/>(team opt-in)"]:::out
    PROMO["🚀 GitOps PR (reviewed) or ArgoCD Image<br/>Updater carries it to staging/PPE/prod<br/>(never for non-deployable picks)"]:::out
    DEV["👩‍💻 Developers read the reports & code-fix issues:<br/>fix breaking tests, adopt golden bases,<br/>restructure Dockerfiles"]:::ppl

    CRON --> DISC --> SCAN --> OWNEDQ
    OWNEDQ -->|"yes — internal"| LADDER
    TESTA -->|"best base wins"| BASEART
    BASEART --> DEP
    TESTB --> OUTQ
    OUTQ -->|"yes"| GOLDEN
    OUTQ -->|"no — weigh ALL attempts"| JUDGE --> GOLDEN
    GOLDEN --> SUMMARY
    GOLDEN --> PROMO
    OWNEDQ -->|"no — 3rd-party"| REMED --> OPT --> PROMO
    SUMMARY ==> DEV
    DEV ==>|"fixes committed → next scheduled run re-validates"| DISC
```

**Where Claude actually creates value (and only there)** — the five yellow
nodes above. Everything else is deterministic because Trivy already knows the
exact package, fixed version, and package manager; the LLM is reserved for the
five decisions a lookup table can't make:
1. **Base image suggestion** — knowing which minimal/distroless bases plausibly exist for *this* app's runtime is world-knowledge a static table would constantly fall behind on. Reached only after the deterministic rungs left CVEs; prompted with the app's real code and every base already tried.
2. **Dockerfile restructure** — when a zero-CVE base fails *only* for missing build tooling, Claude rewrites it into the builder/runtime pattern. The proposal is never trusted: rebuild + tests + a runtime smoke run must all pass, and only a severity improvement adopts it.
3. **Balanced-pick adjudication** — when zero isn't reachable, someone must weigh "is this CVE worth a broken test?" across every retained attempt. Claude picks, justifies, and suggests concrete code fixes — but deployability always comes from the actual test result, never the model.
4. **The per-image before/after report** — turning a raw CVE diff into a prioritized, readable narrative is a writing/judgment task, not a lookup.
5. **The run-level summary** — one evidence-grounded External + Internal report per discovery run.

### Every activity at a glance — Deterministic vs LLM, and the value delivered

The complete activity list in one panel: each numbered step tagged with who
performs it (blue = deterministic code, yellow = one of the five LLM call
sites), alongside everything the pipeline delivers. Note the ratio — 13 of 18
activities are deterministic, and even the LLM steps only *propose*: adoption
is always decided by builds, tests, and rescans.

```mermaid
flowchart LR
    classDef det fill:#dbe9ff,stroke:#4a76c9,color:#0b2447,text-align:left
    classDef llm fill:#fff3cd,stroke:#c9971e,stroke-width:2px,color:#3a2f00,text-align:left
    classDef out fill:#d9f2e3,stroke:#2f9e5f,color:#0b3d24,text-align:left

    subgraph ACT1["ACTIVITIES 1–9 — who does what"]
        direction TB
        A1["1. Discover every image running in the cluster — Deterministic"]:::det
        A2["2. Track digests: skip unchanged images, gate publishing on real change — Deterministic"]:::det
        A3["3. Trivy CVE scan (baseline + every rescan) — Deterministic"]:::det
        A4["4. Classify ownership via labels & self-service annotations — Deterministic"]:::det
        A5["5. Newer-tag bump of the same base (crane + Trivy-verified) — Deterministic"]:::det
        A6["6. OS package patch injection (apk / apt / yum) — Deterministic"]:::det
        A7["7. Gate EVERY change: rebuild → app's own tests → rescan → rollback — Deterministic"]:::det
        A8["8. Base image determination from the application code — LLM 🤖"]:::llm
        A9["9. Dockerfile restructure to builder/runtime + smoke check — LLM 🤖 (gates stay deterministic)"]:::llm
        A1 ~~~ A2 ~~~ A3 ~~~ A4 ~~~ A5 ~~~ A6 ~~~ A7 ~~~ A8 ~~~ A9
    end

    subgraph ACT2["ACTIVITIES 10–18"]
        direction TB
        A10["10. Build, scan & publish the standalone base artifact — Deterministic"]:::det
        A11["11. Bump app dependencies to Trivy's exact fixed versions — Deterministic"]:::det
        A12["12. Balanced-pick adjudication + code-fix suggestions — LLM 🤖 (deployability from test results)"]:::llm
        A13["13. Name & push final images; block non-deployable promotion — Deterministic"]:::det
        A14["14. Open/update the GitOps promotion PR — Deterministic"]:::det
        A15["15. File code-fix GitHub issues on the app's repo — Deterministic (content from 12)"]:::det
        A16["16. Per-image before/after report — LLM 🤖"]:::llm
        A17["17. Run-level summary, grounded in the run's evidence — LLM 🤖"]:::llm
        A18["18. Commit reports to the reference repo + GitHub Release — Deterministic"]:::det
        A10 ~~~ A11 ~~~ A12 ~~~ A13 ~~~ A14 ~~~ A15 ~~~ A16 ~~~ A17 ~~~ A18
    end

    subgraph VAL["VALUE DELIVERED"]
        direction TB
        V1["🏆 Golden (zero-CVE) application images,<br/>every change test-verified"]:::out
        V2["🧱 Curated golden/optimized base catalog<br/>(vendor-qualified) other apps adopt directly"]:::out
        V3["📦 Optimized third-party copies<br/>(opt-in, short-term stopgap)"]:::out
        V4["🚀 Reviewable promotion PRs to<br/>higher environments — never auto-merged"]:::out
        V5["🐛 Developer work lists: code-fix issues +<br/>adjudication reasoning for what machines can't fix"]:::out
        V6["📚 Stakeholder reports repo — rendered, diffable,<br/>stable links; feeds Notion/Confluence/Jira"]:::out
        V7["🗄️ Immutable audit trail — change-gated<br/>GitHub Releases, no duplicate noise"]:::out
        V8["🔁 Continuous re-validation — every fix and<br/>every new CVE rechecked on schedule"]:::out
        V1 ~~~ V2 ~~~ V3 ~~~ V4 ~~~ V5 ~~~ V6 ~~~ V7 ~~~ V8
    end

    ACT1 ~~~ ACT2 ~~~ VAL
```

## How it works

Two very different paths, chosen by ownership — an owned app is rebuilt from
source through bounded agentic loops, every candidate gated by its own test
suite, while a third-party image is only ever patched at the image layer (no
test authority means no rebuild).

### Internal scope — the two agentic loop boxes above (owned apps)

**At a glance — what happens to an owned app's image, in order.** Blue steps
are deterministic code (lookup tables, builds, scans — same input, same
output); yellow steps are the only places Claude is consulted; green boxes are
what gets delivered; red is you.

```mermaid
flowchart TD
    classDef det fill:#dbe9ff,stroke:#4a76c9,color:#0b2447
    classDef llm fill:#fff3cd,stroke:#c9971e,stroke-width:2px,color:#3a2f00
    classDef out fill:#d9f2e3,stroke:#2f9e5f,color:#0b3d24
    classDef ppl fill:#fde2e2,stroke:#c0564a,stroke-width:2px,color:#4a1410

    S1["1. Scan the running image with Trivy"]:::det
    S2["2. Clone the app's source repo"]:::det
    S3["3. Try a newer tag of the same base (≤5)"]:::det
    S4["4. Inject an OS package patch (≤5)"]:::det
    G["Every change: rebuild → app's own tests → rescan.<br/>Keep only if severity improves; else roll back"]:::det
    S5["5. 🤖 LLM: pick a better base image<br/>by reading the app's code"]:::llm
    S6["6. 🤖 LLM: restructure the Dockerfile<br/>(build with tooling, ship the minimal base)<br/>+ runtime smoke check"]:::llm
    S7["7. Publish the winning base standalone:<br/>golden-base / optimized-base"]:::out
    S8["8. Bump app dependencies to<br/>Trivy's fixed versions (≤5)"]:::det
    Q{"Zero CVEs and<br/>tests passing?"}:::det
    S9["9. 🤖 LLM: adjudicate the balanced pick —<br/>vuln impact vs test breakage,<br/>with concrete code-fix suggestions"]:::llm
    S10["10. Push final image:<br/>🏆 golden-base-app or 📦 optimized-app<br/>→ GitOps PR opened for review (if deployable)"]:::out
    S11["11. 🤖 LLM: write the per-image report<br/>+ the run-level summary"]:::llm
    DEV["12. 👩‍💻 Developers act on the report:<br/>apply code fixes, adopt golden bases,<br/>fix broken tests"]:::ppl

    S1 --> S2 --> S3 --> S4 --> G
    G -->|CVEs remain| S5
    S5 -->|"new base adopted — repeat 3–4"| S3
    S5 -.->|"zero-CVE base lacks build tooling"| S6 --> G
    G -->|best base found| S7 --> S8 --> Q
    Q -->|yes| S10
    Q -->|no| S9 --> S10
    S10 --> S11 ==> DEV
    DEV ==>|"next scheduled scan re-validates the fixes"| S1
```

**Why the per-image report (step 11) matters as much as the images:** the
pipeline fixes everything a rebuild *can* fix — but what's left after step 9 is
by definition work only a developer can do (an unfixable dependency to migrate
away from, a test that breaks on a better base, a Dockerfile that couples the
app to one distro). The report turns that into a concrete work list: every base
candidate tried and why it was rejected, the adjudication's reasoning, and its
specific code-fix suggestions — committed to the reports repo next to the app's
own code, folded into the promotion PR body, and (for non-deployable picks)
filed as a GitHub issue on the app's repo. When developers act on it, the next
scheduled scan re-validates automatically (step 12 → step 1) — the pipeline and
the team ratchet the image toward golden together, run after run.

Every loop above is bounded (each ≤5, plus a global budget of 20
build/test/rescan attempts per image), and every change is validated the same
way: rebuild → the app's own test suite → Trivy rescan, rolled back on failure
but retained as adjudication evidence. Internal runs end in `golden_base_app`
(zero total CVEs, tests passing), `optimized_app` (best balanced pick), or
`no_improvement` (nothing pushed). Phase-by-phase mechanics, configuration,
onboarding, and the test-stage-lineage rule are covered in
[Base image hardening](#base-image-hardening--golden-images-for-owned-applications).

### External scope — zooming into the external remediation loop above (3rd-party images)

```
Input image
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│                 Remediation Loop (per iteration)                   │
│                                                                    │
│   Trivy scan                                                       │
│       │                                                            │
│       ▼                                                            │
│   Newer upstream tag already fixes it?                             │
│       │                                                            │
│       ├── yes ──► adopt it (no build needed)                       │
│       │                                                            │
│       └── no ───► OS-package patch (apk/apt/yum — no LLM)          │
│                       │                                            │
│                       ▼                                            │
│                   docker build ──► rescan                          │
│                       │                                            │
│                       ▼                                            │
│                   improved?                                        │
│                    │      │                                        │
│                   yes     no ──► discard build, stop               │
│                    │                                               │
│                    └──────► loop back to Trivy scan                │
└────────────────────────────────────────────────────────────────────┘
                                 │ clean, or no further patches possible
                                 ▼
        push <tag>-optimized-ext ─► ONE Claude Opus before/after
        to private registry       summary report ──► GitHub Release
```

**Loop termination — first condition wins:**

| Condition | Status |
|-----------|--------|
| Zero HIGH/CRITICAL CVEs remain | `clean` |
| All remaining CVEs require source rebuild (Go binaries, no upstream fix) | `no_further_patches` |
| Patch applied but CVE count did not decrease | `no_improvement` |
| `MAX_ITERATIONS` reached (default: 5) | `max_iterations` |

**Output artifacts per run:**

Only the baseline scan and one final summary are kept per image — no
per-iteration files. At most one final app image reaches the registry per run
(plus, for internal runs, the winning base published standalone):

| Artifact | Description |
|----------|-------------|
| `output/scan-baseline.json` | Full Trivy JSON output from the first scan, before any changes |
| `output/summary-report.md` | Claude Opus 4.8 before/after remediation summary covering the whole image's run |
| `output/run-summary.md` | Discovery mode only: one Claude-composed run-level report — External + Internal sections across every image scanned this run |
| GitHub Release | The files above attached as downloadable release assets — the immutable audit archive. Discovery mode creates one **only when a filtered image's digest changed** since the last run (scoped to that run's files), so a scheduled tick over an unchanged environment publishes nothing |
| Reports repo (optional) | With `REPORTS_REPO` set, every report is *also* committed as rendered, diffable markdown at stable paths (`reports/<repo>/<tag>/latest.md` + dated history, `reports/run-summary/`). The **stakeholder-facing reference location**: share links with any team or auditor, or point Notion/Confluence/Jira/Slack importers at it — no agent changes needed |
| Promotion PR body | The per-image summary is folded into the GitOps promotion PR (collapsed section), so reviewers see the security story where they approve the change |
| Code-fix issue | A non-deployable balanced pick files the adjudication's `code_fixes` as a GitHub Issue on the app's own source repo (stable title — re-runs comment instead of duplicating) |
| Final image | External: `<name>:<original-tag>-optimized-ext` — any real improvement, incl. a tag bump alone reaching zero (gated by `KEEP_EXTERNAL_IMAGES`; nothing is pushed for an already-clean image). Internal: `-golden-base-app` (zero CVEs, tests passing) or `-optimized-app` (best balanced pick — if its tests failed it is still pushed as flagged **non-deployable** evidence and never promoted), plus the winning base standalone as `-golden-base`/`-optimized-base` |

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3.12+ | Runtime | [python.org](https://www.python.org/downloads/) |
| Trivy | Vulnerability scanning | [trivy.dev](https://trivy.dev/latest/getting-started/installation/) |
| Docker CLI | Build and push patched images | [docs.docker.com](https://docs.docker.com/engine/install/) |
| crane | Daemon-less registry ops: tag listing, digest resolution, tag-bump promotion | [go-containerregistry releases](https://github.com/google/go-containerregistry/releases) |
| Anthropic API key | Claude Opus 4.8 — the five LLM call sites (base pick, Dockerfile restructure, adjudication, per-image + run reports) | [console.anthropic.com](https://console.anthropic.com/) |
| GitHub PAT | Create releases, push artifacts | Scopes: `repo` + `write:packages` |

---

## Running locally

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/sgrsaga/vuln-agent.git
cd vuln-agent

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Install Trivy

```bash
# Linux / macOS
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin latest

# macOS (Homebrew)
brew install trivy
```

### 3. Configure environment variables

```bash
cp .env.example .env
# Edit .env with your values
```

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key (`sk-ant-...`) |
| `GHCR_NAMESPACE` | No | Registry prefix for pushed images, e.g. `ghcr.io/myorg`. Leave empty to build locally only |
| `GITHUB_TOKEN` | No | GitHub PAT (`ghp_...`) with `repo` + `write:packages` scopes. Enables GitHub Release creation |
| `GITHUB_REPO` | No | `owner/repo` or full GitHub URL. Required for release creation |
| `TARGET_NAMESPACES` | No | Discovery mode: comma-separated namespace whitelist. Takes priority over `EXCLUDED_NAMESPACES`. Also settable via `--namespaces` |
| `EXCLUDED_NAMESPACES` | No | Discovery mode: comma-separated namespace blacklist, used only when `TARGET_NAMESPACES` is empty. Also settable via `--exclude-namespaces` |
| `INCLUDE_INIT_CONTAINERS` | No | Discovery mode: also scan images running in init containers (default: `false`) |
| `MAX_ITERATIONS` | No | Safety cap on remediation loops (default: `5`) |
| `OUTPUT_DIR` | No | Directory for artifacts (default: `output`) |
| `ALLOW_MAJOR_TAG_BUMP` | No | Allow the base-image tag-bump check to cross a major version when hunting for a tag that already fixes CVEs (default: `false` — patch/minor bumps only) |
| `RESCAN_INTERVAL_DAYS` | No | Discovery mode only: rescan an image again after this many days even if it hasn't changed (default: `7`) |
| `FORCE_RESCAN` | No | Discovery mode only: ignore tracked scan state and rescan every discovered image this run (default: `false`) |
| `KEEP_EXTERNAL_IMAGES` | No | Push patched EXTERNAL images as `<tag>-optimized-ext` — keeping third-party copies is a team decision (default: `true`) |
| `LLM_BASE_MAX_ROUNDS` | No | Internal: max LLM base-determination rounds — the outer ladder loop (default: `5`) |
| `DEP_UPGRADE_MAX_ITERATIONS` | No | Internal: max dependency-upgrade rebuild/test/rescan passes (default: `5`) |
| `INTERNAL_MAX_ATTEMPTS` | No | Internal: global cap on build/test/rescan cycles per image — bounds the product of the nested loops (default: `20`) |
| `GITOPS_REPO` | No | `owner/repo` of a GitOps manifests repo to open promotion PRs against. Leave empty to disable (see [Promoting optimized images](#promoting-optimized-images-to-higher-environments)) |
| `GITOPS_TOKEN` | No | PAT with access to `GITOPS_REPO`. Falls back to `GITHUB_TOKEN` if unset |
| `GITOPS_BASE_BRANCH` | No | Branch to open promotion PRs against (default: `main`) |
| `GITOPS_IMAGE_PATH_TEMPLATE` | No | Path within `GITOPS_REPO` to patch, e.g. `environments/ppe/{repo_name}/values.yaml` — `{repo_name}` is filled in per image |
| `REPORTS_REPO` | No | `owner/repo` to commit summary reports into — the shared reference repo external stakeholders read (and the source for forwarding into Notion/Confluence/Jira etc.). Dated file + stable `latest.md` per image. Empty disables — reports then live only on releases/PVC |
| `REPORTS_BRANCH` | No | Branch in `REPORTS_REPO` to commit to (default `main`) |
| `REPORTS_TOKEN` | No | PAT with access to `REPORTS_REPO`. Falls back to `GITHUB_TOKEN` if unset |
| `CODE_FIX_ISSUES` | No | File the adjudication's code-fix suggestions as a GitHub Issue on the app's source repo when a balanced pick is non-deployable (default `true`) |
| `OWNED_IMAGE_LABEL_SELECTOR` | No | k8s label selector identifying owned images eligible for base-image hardening (discovery mode only). Empty disables hardening entirely |
| `HARDENING_CONFIG` | No | JSON list mapping owned repos to source/test config — see [Base image hardening](#base-image-hardening-golden-images-for-owned-applications) |
| `HARDENING_MAX_CANDIDATES` | No | Max alternative base images to try per image (default: `3`) |
| `HARDEN_BASE_IMAGE` | No | Single-image mode only: opt-in to hardening (`--harden`). Discovery mode uses `OWNED_IMAGE_LABEL_SELECTOR` instead (default: `false`) |

### 4. Log in to your private registry

```bash
# GitHub Container Registry
echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Any other registry (AWS ECR, GCP Artifact Registry, Docker Hub, etc.)
docker login your.registry.io
```

### 5. Pre-warm Trivy (first run only)

On the first run Trivy downloads its vulnerability database (~600 MB). Pre-download it once to avoid a timeout during the scan:

```bash
trivy image --download-db-only
```

### 6. Run the agent

```bash
source .venv/bin/activate

python main.py ghcr.io/dexidp/dex:v2.45.1
```

Or with explicit flags:

```bash
python main.py ghcr.io/your-org/your-image:tag \
  --max-iterations 3 \
  --output-dir /tmp/scan-results
```

### 7. View results

Artifacts are written to `output/` in real time — only the baseline scan and the
final summary, regardless of how many iterations the run takes internally. If
`GITHUB_TOKEN` and `GITHUB_REPO` are configured, a GitHub Release is created at
the end of every run with both files attached.

```
output/
├── scan-baseline.json     ← full Trivy scan from before any changes (63 KB)
└── summary-report.md      ← Claude before/after remediation summary (12–15 KB)
```

Example output for `ghcr.io/dexidp/dex:v2.45.1`:

```
🚀  [pipeline_start] Starting remediation for ghcr.io/dexidp/dex:v2.45.1
🔍  [scan_complete] Found 104 vulnerabilities (CRITICAL: 11, HIGH: 93)
🏷️  [tag_bump_unavailable] No newer upstream tag improves on current CVEs
🔧  [patch_generated] Patch Dockerfile generated (4 lines)
✅  [improvement] Severity reduced: (C,H) (11, 93) → (9, 80)
🔍  [scan_complete] Found 89 vulnerabilities (CRITICAL: 9, HIGH: 80)
🏁  [pipeline_complete] No further patches possible — remaining CVEs require source rebuild
✅  [final_image] Final optimized image: ghcr.io/sgrsaga/dex:v2.45.1-optimized-ext
ℹ️  [summary_start] Generating before/after summary report with Claude Opus 4.8 ...
```

---

## Running in a Kubernetes cluster

The agent runs as a Kubernetes **Job** (one-shot on demand) or **CronJob** (automated schedule). Builds need a Docker daemon, provided one of two ways: the Helm chart runs a **Docker-in-Docker native sidecar** inside the pod (portable — works on containerd nodes with no Docker installed), while the legacy raw manifests mount the node's Docker socket.

Two deployment paths, pick one:

- **Option A — Helm chart (`chart/`, recommended)**: the actively-developed
  path — discovery mode, SealedSecrets, whitelist namespace model, all
  parameters in one `values.yaml`.
- **Option B — raw manifests (`k8s/`)**: step-by-step `kubectl apply`, useful
  when Helm isn't available or you want to see every moving part.

### Cluster architecture

```
┌───────────────────────────────────────────────────────────┐
│  Kubernetes namespace: vuln-agent (chart) / security (raw)│
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │  CronJob / Job pod                                 │   │
│  │                                                    │   │
│  │  [init]    trivy --download-db-only                │   │
│  │  [sidecar] docker:dind (chart path — privileged,   │   │
│  │            native sidecar; shares /var/run socket) │   │
│  │            └ raw-manifest path mounts the node's   │   │
│  │              /var/run/docker.sock instead          │   │
│  │                                                    │   │
│  │  [main] vuln-agent                                 │   │
│  │    ├── discover pods       (k8s API, RBAC-scoped)  │   │
│  │    ├── Trivy scan          (local process)         │   │
│  │    ├── Claude API calls    (HTTPS outbound)        │   │
│  │    ├── docker build/test   (in-pod dind daemon)    │   │
│  │    └── docker push / PRs / reports (HTTPS) ────────┼───┼──► Registry, GitHub
│  │                                                    │   │
│  │  Volumes:                                          │   │
│  │    /var/run                ← emptyDir shared w/dind│   │
│  │    /home/agent/.docker     ← registry secret       │   │
│  │    /app/output             ← PVC (artifacts+state) │   │
│  │    /trivy-cache            ← PVC (Trivy DB)        │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
          │
          └──► GitHub Releases + reports repo + GitOps promotion PRs
```

### Option A — Helm chart (recommended)

#### A1 — Build and push the agent image

```bash
docker build -t ghcr.io/your-org/vuln-agent:<yyyymmdd> .
docker push ghcr.io/your-org/vuln-agent:<yyyymmdd>
```

Set the reference in `chart/values.yaml` under `image:` — pin by `digest` (as
the checked-in values do) or by `tag`.

#### A2 — Credentials

The chart expects two secrets in the release namespace:

- `vuln-agent-secrets` — keys `anthropic-api-key` and `github-token`
- `vuln-agent-registry` — a `kubernetes.io/dockerconfigjson` secret for
  pulling the agent image and pushing remediated images

**With SealedSecrets** (how this repo manages them —
`chart/sealed-secrets.yaml` holds both, encrypted for the cluster's
controller):

```bash
kubectl create namespace vuln-agent   # SealedSecrets are namespace-bound — this must match
kubectl apply -f chart/sealed-secrets.yaml
```

To re-seal for your own cluster/namespace, follow the `kubeseal` commands in
the header of `chart/sealed-secrets.yaml`.

**Without SealedSecrets** (quick start), create them directly:

```bash
kubectl create namespace vuln-agent
kubectl -n vuln-agent create secret generic vuln-agent-secrets \
  --from-literal=anthropic-api-key=sk-ant-... \
  --from-literal=github-token=ghp_...
kubectl -n vuln-agent create secret docker-registry vuln-agent-registry \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=ghp_...
```

(Alternatively pass `anthropic.apiKey`/`github.token`/`registry.username`+
`registry.password` as values and the chart renders the secrets itself —
convenient, but the credentials then live in your values file.)

#### A3 — Configure `chart/values.yaml`

The key decisions (everything else has sane defaults):

```yaml
image:
  repository: ghcr.io/your-org/vuln-agent   # from A1

registry:
  namespace: "ghcr.io/your-org"    # where remediated images get pushed

github:
  repo: "your-org/your-repo"       # GitHub Releases land here

discovery:
  targetNamespaces: [apps, monitoring]   # whitelist of namespaces to scan
  ownedImageLabelSelector: "vuln-agent.io/harden=true"  # enables internal hardening

docker:
  dind:
    enabled: true    # REQUIRED for builds — runs dockerd as a privileged native
                     # sidecar in the pod (portable: works on containerd nodes
                     # with no Docker daemon). false = analysis-only mode
                     # (scan + classify + reports, no build/push)

persistence:
  output:      { storageClass: "your-storageclass" }
  trivyCache:  { storageClass: "your-storageclass" }

reports:
  repo: "your-org/security-reports"  # optional: commit reports for browsing/diffing

schedule: "0 2 * * *"                # discovery CronJob cadence
```

#### A4 — Install

```bash
helm lint chart/
helm upgrade --install vuln-agent chart/ -n vuln-agent --create-namespace -f chart/values.yaml
```

The release's NOTES print the trigger/log/artifact commands. RBAC
(ServiceAccount + cluster pod-read for discovery), PVCs, ConfigMap, and the
discovery-mode CronJob are all created by the chart.

#### A5 — Trigger a run now (instead of waiting for the schedule)

```bash
kubectl -n vuln-agent create job vuln-scan-manual --from=cronjob/vuln-agent
kubectl -n vuln-agent logs -f job/vuln-scan-manual
```

#### A6 — Results, upgrades, removal

```bash
# Artifacts: output PVC (scan-baseline.json + summary-report.md per image,
# run-summary.md per run), the GitHub Release, and — when reports.repo is
# set — rendered markdown committed to that repo.

# Apply a values change / new chart version
helm upgrade vuln-agent chart/ -n vuln-agent -f chart/values.yaml

# Remove (PVCs are kept by Helm — delete them explicitly if you want the
# scan state and artifacts gone too)
helm uninstall vuln-agent -n vuln-agent
```

### Option B — raw manifests (`k8s/`)

> **Switching between options?** Both paths create cluster-scoped RBAC named
> `vuln-agent`, so they can't coexist. Moving from B to A: first
> `kubectl delete clusterrole vuln-agent clusterrolebinding vuln-agent`
> (and the old CronJob in `security`), or `helm install` fails with an
> "invalid ownership metadata" error on the ClusterRole.

#### Step 1 — Build and push the agent image

```bash
# Build
docker build -t ghcr.io/your-org/vuln-agent:latest .

# Push to your registry
docker push ghcr.io/your-org/vuln-agent:latest
```

#### Step 2 — Create namespace, persistent storage, and RBAC

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/rbac.yaml    # ServiceAccount + cluster pod-read — needed by the discovery CronJob
```

Two PVCs are created:
- `vuln-agent-output` (1 Gi) — scan JSON, reports, Dockerfiles
- `vuln-agent-trivy-cache` (2 Gi) — Trivy vulnerability DB (avoids re-downloading on every run)

#### Step 3 — Create secrets

```bash
# Anthropic API key + GitHub token
kubectl -n security create secret generic vuln-agent-secrets \
  --from-literal=anthropic-api-key=sk-ant-... \
  --from-literal=github-token=ghp_...

# Registry credentials so the agent can push patched images
kubectl -n security create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username=YOUR_GITHUB_USERNAME \
  --docker-password=ghp_...
```

For other registries replace `--docker-server` with your registry hostname (e.g. `123456789.dkr.ecr.us-east-1.amazonaws.com`).

#### Step 4 — Configure the manifests

Edit `k8s/job.yaml` (and `k8s/cronjob.yaml` if using scheduled scans). The key fields to change:

```yaml
# --- k8s/job.yaml ---

containers:
  - name: vuln-agent
    # ① Your agent image (built in Step 1)
    image: ghcr.io/your-org/vuln-agent:latest

    # ② The target image to scan
    args: ["ghcr.io/your-org/your-image:your-tag"]

    env:
      # ③ Where to push patched images
      - name: GHCR_NAMESPACE
        value: "ghcr.io/your-org"             # or your.registry.io/your-org

      # ④ Where to publish GitHub Release artifacts
      - name: GITHUB_REPO
        value: "your-org/your-repo"

      # ⑤ Max iterations (optional)
      - name: MAX_ITERATIONS
        value: "5"
```

Both manifests now carry the full parameter set with commented defaults —
discovery scope (`TARGET_NAMESPACES`/`EXCLUDED_NAMESPACES`), external tuning
(`ALLOW_MAJOR_TAG_BUMP`, `KEEP_EXTERNAL_IMAGES`, `RESCAN_INTERVAL_DAYS`),
internal loop budgets (`LLM_BASE_MAX_ROUNDS`, `DEP_UPGRADE_MAX_ITERATIONS`,
`INTERNAL_MAX_ATTEMPTS`), hardening selection (`OWNED_IMAGE_LABEL_SELECTOR` +
`HARDENING_CONFIG` in the CronJob; `HARDEN_BASE_IMAGE` opt-in in the one-shot
Job), and the GitOps PR-bot (`GITOPS_*`) — the same knobs as `.env.example`
and the Helm chart's ConfigMap.

#### Step 5 — Run a one-shot Job

```bash
kubectl apply -f k8s/job.yaml

# Stream live logs
kubectl -n security logs -f job/vuln-remediate-dex

# Check completion status
kubectl -n security get job vuln-remediate-dex
```

#### Step 6 — Schedule automatic scans (CronJob)

```bash
kubectl apply -f k8s/cronjob.yaml
```

The CronJob runs in **discovery mode** (`--discover`): it lists every image
running in the cluster via the `vuln-agent` ServiceAccount from Step 2, scoped
by `TARGET_NAMESPACES` (whitelist — wins when set) or `EXCLUDED_NAMESPACES`
(blacklist). Images whose pods match `OWNED_IMAGE_LABEL_SELECTOR` and have
hardening config (annotations or `HARDENING_CONFIG`) take the internal
rebuild-from-source path; everything else gets external tag-bump + OS-patch
treatment.

The default schedule is **every Monday at 04:00 UTC**. To change it, edit `spec.schedule` in `k8s/cronjob.yaml` using standard cron syntax:

```yaml
schedule: "0 4 * * 1"   # Mon 04:00 UTC
schedule: "0 2 * * *"   # Every day at 02:00 UTC
schedule: "0 0 1 * *"   # First day of every month
```

Each run tracks what it already scanned in `<output-dir>/.vuln-agent-state/tracked-images.json`
on the `output` PVC, keyed by image digest. On the next scheduled run, an image is
skipped — not rescanned — if its digest hasn't changed and it was last checked within
`RESCAN_INTERVAL_DAYS` (default 7); it's rescanned regardless of digest if the prior
attempt errored out, or once the TTL passes, so a workload that never gets redeployed
still gets rechecked periodically against newly-disclosed CVEs. Set `FORCE_RESCAN=true`
(or `--force-rescan`) to ignore this and rescan everything on a given run.

The same digest tracking gates **publishing**: a GitHub Release (and the
run-level report) is created only when at least one filtered image's digest
actually changed since the last run — or on `FORCE_RESCAN`. A scheduled tick
that finds the identical environment publishes nothing, so releases mark real
changes instead of repeating daily; even a TTL-forced recheck of unchanged
digests stays silent. Release assets are scoped to the images scanned in that
run (plus `run-summary.md`) — older runs' files persist on the PVC but are
never re-attached.

Trigger a scan immediately without waiting for the schedule:

```bash
kubectl -n security create job vuln-scan-manual \
  --from=cronjob/vuln-agent-scan
```

List all runs and their status:

```bash
kubectl -n security get jobs -l app=vuln-agent
```

### Retrieve artifacts from the cluster

If `GITHUB_TOKEN` and `GITHUB_REPO` are set, all artifacts are automatically uploaded to a GitHub Release — no manual retrieval needed. The release URL is printed in the pod logs.

To access artifacts stored on the PVC directly:

```bash
kubectl -n security run artifact-reader --rm -it \
  --image=busybox \
  --overrides='{
    "spec": {
      "volumes": [{"name":"out","persistentVolumeClaim":{"claimName":"vuln-agent-output"}}],
      "containers": [{
        "name":"reader","image":"busybox","command":["sh"],
        "volumeMounts":[{"name":"out","mountPath":"/output"}]
      }]
    }
  }'

# Inside the shell:
ls -lh /output
cat /output/summary-report.md
```

---

## What gets fixed automatically — and what does not

### Fixed automatically (OS / distro packages)

When Alpine, Debian, or Ubuntu packages have a newer version available:

```dockerfile
FROM your-image:tag
USER root
RUN apk upgrade --no-cache      # Alpine
# or: RUN apt-get update && apt-get upgrade -y    # Debian/Ubuntu
USER original-user
```

### Cannot be fixed at the image layer (requires source rebuild)

**Go binary CVEs** — the vulnerable code is statically compiled into the binary. No package manager can update it. Fixing requires:

1. Bumping Go module dependencies in the source repository
2. Rebuilding the binary with an updated Go toolchain
3. Releasing a new upstream image version

For **external** images the agent identifies these, documents them clearly in the report (including the exact `go get` commands for a source-level fix), and stops iterating rather than applying ineffective patches. For **owned** images this is exactly what the internal pipeline exists for — the dependency loop bumps Go modules and rebuilds from source (see [Internal scope](#internal-scope--the-two-agentic-loop-boxes-above-owned-apps)).

---

## Promoting optimized images to higher environments

Pushing the final image (`-optimized-ext` / `-golden-base-app` / `-optimized-app`) is where this agent's job
ends — nothing in this repo rewrites a deployment manifest to actually reference
it. That's intentional: how an optimized image flows from where it was scanned
(typically a low-trust dev/sandbox environment) into staging, PPE, and production
is an environment-promotion decision, not a scanning one, and different tiers
usually want different levels of friction. Two complementary paths:

### Lower environments — ArgoCD Image Updater (no code here, just config)

[ArgoCD Image Updater](https://argocd-image-updater.readthedocs.io/) is a separate
controller that polls the registry directly and writes updates back itself — this
agent never talks to it. Install it once, then annotate the *target application's*
`Application` resource (in whatever repo/cluster that lives in — not this chart):

```yaml
metadata:
  annotations:
    argocd-image-updater.argoproj.io/image-list: myapp=ghcr.io/me/argocd
    # These tags are fixed and get overwritten in place by each
    # remediation run — it's not a growing semver series — so "digest" (poll
    # the same tag, redeploy when its digest changes) is the right update
    # strategy here, not "semver".
    argocd-image-updater.argoproj.io/myapp.update-strategy: digest
    # Base artifacts (-golden-base/-optimized-base) are building blocks, not
    # app deployables — deliberately NOT matched here. Nor is -optimized-app:
    # it can carry a non-deployable balanced pick, so route it through the
    # reviewed PR-bot path below instead of auto-deploying it.
    argocd-image-updater.argoproj.io/myapp.allow-tags: regexp:^.*-(optimized-ext|golden-base-app)$
    argocd-image-updater.argoproj.io/write-back-method: git
```

Image Updater needs read access to the same registry `GHCR_NAMESPACE` already
pushes to — reuse the existing pull secret. This writes back automatically, with
no human review by default, which is fine for fast-moving lower environments but
not usually what you want pointed straight at production.

### Higher environments (PPE/Prod) — the built-in PR-bot

Set `GITOPS_REPO` (and `GITOPS_IMAGE_PATH_TEMPLATE`) and the agent will, after
promoting a final optimized image, patch that path in `GITOPS_REPO` and open a
PR — it never merges anything itself, so a human always reviews the change before
it reaches a gated environment. The full before/after summary report is folded
into the PR body so reviewers see the security story where they approve it, the
PR only ever fires for **deployable** results (a balanced pick with failing
tests never gets one), and apps without a file at the templated path are
skipped silently. Re-runs that produce the same result update the
existing open PR (a stable `vuln-agent/optimize-<repo>` branch) instead of piling
up duplicates. See the `GITOPS_*` variables in [step 3](#3-configure-environment-variables)
above for the full configuration.

---

## Base image hardening — "golden images" for owned applications

Everything described above operates on an image that already exists: tag-bumping
adopts a newer *upstream* tag, OS-package patching upgrades packages on the
*current* base. Neither ever changes which base image an app is built FROM,
because doing that safely requires rebuilding from source and proving the app
still works — which this agent will only ever attempt for images your
organization actually owns and can test. It is **never** attempted for
third-party/vendor images (e.g. `ghcr.io/dexidp/dex:v2.45.1`) — rebuilding
someone else's software from source with a swapped dependency, with no access to
their test suite, forfeits their QA and provenance guarantees and leaves you
maintaining an unofficial fork with no real confidence it still behaves
correctly. See `agent/hardener.py` for the full rationale.

### How an image becomes eligible

Two things both have to be true:
1. **It's owned.** Set `discovery.ownedImageLabelSelector` (a standard k8s label
   selector, e.g. `vuln-agent.io/harden=true`) in `chart/values.yaml`. App teams
   self-service by labeling their own Deployments — nothing to edit centrally
   per app. (Single-image mode has no pod/label context, so it's explicit
   opt-in instead: `--harden` / `HARDEN_BASE_IMAGE=true`.)
2. **It has enough config to work with** — where the source repo, Dockerfile
   path, and test stage/command live. Two ways to provide this, and they merge
   (annotation values win field-by-field over a matching central entry, so a
   platform team can still set defaults while apps override what they need):

   **Self-service — annotations on the app's own Deployment** (no separate file
   to touch, ever — the config travels with the workload):
   ```yaml
   metadata:
     labels:
       vuln-agent.io/harden: "true"
     annotations:
       vuln-agent.io/source-repo: myorg/myapp
       vuln-agent.io/dockerfile-path: Dockerfile   # monorepo? point into it: myapp/Dockerfile
       vuln-agent.io/test-stage: test
       # vuln-agent.io/test-command: pytest   # fallback if there's no dedicated test stage
   ```

   `dockerfile-path` is relative to the clone root, and the agent builds the
   Dockerfile's directory as the context — so the app can be the whole repo or
   one subdirectory of a monorepo.

   **Central — `hardening.images` in `chart/values.yaml`**, keyed by bare image
   repo name (useful for apps that haven't added annotations yet, or as a
   platform-managed default):
   ```yaml
   hardening:
     images:
       - repo: myapp
         sourceRepo: myorg/myapp   # cloned to rebuild against a candidate base
         dockerfilePath: Dockerfile
         testStage: test            # `docker build --target test` is the pass/fail signal
         # testCommand: "pytest"    # fallback if there's no dedicated test stage
   ```

   See `target-apps/` in this repo for five complete, working examples (Python,
   Go, Java, Node.js, TypeScript) with Dockerfiles structured to satisfy the
   test-stage-lineage requirement below — good references when onboarding a
   real app.

### What happens for an eligible image

1. `sourceRepo` is cloned, and the Dockerfile's actual current base is read —
   whichever stage the `FROM` line for the *final built image* actually
   resolves to (a plain `docker build` produces the last stage in the file,
   so that's the one Trivy's scan and `current_vulns` describe). If that stage
   is itself just an alias to an earlier one (`FROM base AS runtime`), the
   alias chain is walked backwards until it lands on a real image reference —
   correctly leaving earlier build-only stages alone even when they use a
   completely different base (e.g. a `golang:1.21 AS builder` stage feeding a
   binary into a separate `alpine:3.18 AS runtime` stage never gets touched,
   since it doesn't ship in the built image at all).
2. The **base ladder** runs — cumulative, every candidate validated by
   rebuild → the app's real test suite → rescan, with the Dockerfile rolled
   back byte-for-byte on failure so a losing edit never leaks into the next
   attempt. Failing attempts are *retained as evidence* (image, test result,
   vuln snapshot) for the adjudication step below, not silently discarded:
   - **Rung 1 (deterministic, loop ≤ 5)** — is there just a newer tag of this
     *same* base repo? Reuses the same Trivy-verified tag-bump logic the
     external loop already uses (`agent/tag_finder.py`).
   - **Rung 2 (deterministic, loop ≤ 5)** — the OS-package upgrade
     (`apk`/`apt`/`yum`) injected into the Dockerfile's base stage — the same
     fix external images get, but here it's *test-verified* instead of
     rescan-only.
   - **Rung 3 (Claude)** — only if rungs 1–2 left CVEs behind: up to
     `hardening.maxCandidates` alternative bases for this specific app, chosen
     from its actual code context (Dockerfile + dependency manifests) with
     already-tried bases excluded to prevent cycles. Each adopted swap re-runs
     rungs 1–2 on the new base, up to `LLM_BASE_MAX_ROUNDS` (default 5) rounds,
     all under a global `INTERNAL_MAX_ATTEMPTS` (default 20) build/test/rescan
     budget.
   The winning base is then built **standalone** and scanned: zero CVEs →
   pushed as `<vendor-qualified-name>:<base-tag>-golden-base`, otherwise
   `-optimized-base` — a curated base other owned apps can adopt directly.
   Names are vendor-qualified so catalog entries never collide:
   `cgr.dev/chainguard/python` publishes as `chainguard-python:...`,
   `gcr.io/distroless/python3-debian12` as `distroless-python3-debian12:...`,
   while Docker-library bases keep their bare name (`python:...`).
3. CVEs the standalone base scan *doesn't* show are application-introduced by
   definition — the **dependency loop** targets exactly that delta, bumping to
   the fixed versions Trivy reports (requirements.txt / package.json / go.mod /
   pom.xml), then rebuild → test → rescan, repeating until no further
   improvement (`DEP_UPGRADE_MAX_ITERATIONS`, default 5).
4. Outcome: **zero total CVEs with tests passing → `<original-tag>-golden-base-app`**
   (strict golden — nothing residual hides behind the name). Otherwise Claude
   **adjudicates across every retained attempt** — weighing vulnerability
   impact against test breakage and implied code impact, with concrete
   code-fix suggestions when a security fix breaks the app — and the balanced
   pick is pushed as `<original-tag>-optimized-app`. Deployability comes from
   the actual test result, never the model: a failing pick is flagged
   **non-deployable** in the report and the GitOps PR-bot never fires for it.
   No improvement at all → nothing pushed, and the summary report lists every
   step tried and why each failed.

### A residual limitation: your `test`/`testStage` needs to share lineage with the runtime stage

Hardening only ever rewrites the base of the stage that becomes the *final*
image. If your test stage is built from an unrelated base rather than
descending from that same stage (e.g. `FROM golang:1.21 AS test` running unit
tests, feeding into a completely separate `FROM alpine:3.18 AS runtime`), the
test run never actually exercises the new candidate base — it validates the
*old* environment while the *shipped* image gets the swapped one. Structure
`test` to build on top of the runtime stage (`FROM runtime AS test`, or an
earlier stage in the runtime's own lineage) so a passing test run is real
evidence about the image that's actually about to be pushed.

**The one deliberate exception — restructured minimal runtimes**: when the
agent's restructure step (LLM call 2) converts a Dockerfile to a
builder/runtime split so a shell-less base (distroless/Chainguard) can ship,
tests *cannot* run on the runtime stage at all — they run on the builder
lineage (same interpreter and installed dependencies), and the runtime image
must additionally pass a **smoke run** (`docker run --network none` executing
an import/version check) proving the copied artifacts load on the minimal
base. That's a weaker guarantee than same-lineage testing, it's flagged as the
`restructure` step in the trail, and the report states it explicitly.

### Isolation — a known, documented limitation

Test execution (`testCommand` path) runs as `docker run --rm --network none` —
no network interface at all, so a compromised or malicious test suite in a
cloned repo can't exfiltrate the agent's mounted credentials to an external
host. This is a real but partial mitigation, **not full sandboxing** — it still
shares the docker daemon and host kernel with the agent. A dedicated,
minimally-privileged k8s Job per hardening attempt would be the proper
production-grade isolation; it isn't built yet, so treat `sourceRepo` as a
trusted input, not an arbitrary/untrusted one, until that lands.

---

## Security considerations for production

The Job manifests mount `/var/run/docker.sock` from the host node, which gives root-equivalent access to the Docker daemon. For production deployments:

- **Dedicated nodes** — use a `nodeSelector` or taint/toleration to confine socket-mounting pods to designated build nodes
- **Namespace policy** — use OPA Gatekeeper or Kyverno to restrict `hostPath` mounts to the `security` namespace only
- **Rootless builds** — replace the Docker socket with **[Kaniko](https://github.com/GoogleContainerTools/kaniko)** for fully rootless in-cluster image builds (no socket mount required)
- **Secret rotation** — rotate `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` regularly; use External Secrets Operator, HashiCorp Vault, or your cloud provider's secret manager to inject them rather than storing them in Kubernetes Secrets directly

---

## Adopting this project — pros, cons & risks

An honest assessment for anyone considering running this against a real
cluster. The short version: the *verification* is deterministic (Trivy rescans
and your own test suites gate every change), but the agent builds, pushes, and
files PRs/issues on your behalf — adopt it with eyes open.

### Pros

- **Continuous, not point-in-time** — every running image is rechecked on a
  schedule, so CVEs disclosed *after* an image was built still get caught,
  including on workloads nobody has redeployed in months.
- **Nothing ships on a guess** — every candidate must prove itself: a Trivy
  rescan showing a severity-ordered improvement, and (for owned apps) the
  app's own test suite passing. Failing attempts are rolled back, retained
  only as evidence.
- **Bounded, targeted LLM use** — exactly five call sites, each a genuinely
  ambiguous decision; everything else is lookup-table/deterministic code, so
  API cost is small and behavior is auditable. Deployability is decided by
  test results, never by the model.
- **Golden bases compound** — the standalone `-golden-base`/`-optimized-base`
  artifacts become a curated base catalog other teams adopt directly.
- **Humans stay in the loop where it matters** — higher-environment promotion
  is a reviewable PR (never auto-merged), non-deployable picks are flagged and
  never promoted, and code-fix suggestions land as issues in the team's normal
  triage flow.
- **Change-gated noise control** — an unchanged environment produces no new
  release, no new report, no duplicate PRs (stable branch/issue titles).

### Cons

- **Needs a Docker daemon to actually fix anything** — either the privileged
  dind sidecar (chart) or a host socket (legacy manifests). Without one it's
  analysis-only. Builds are also the slow path: a first full run over many
  owned apps takes real time and disk.
- **HIGH/CRITICAL only, Trivy's view only** — MEDIUM/LOW are out of scope by
  default, and coverage is bounded by Trivy's DB (e.g. distro backports can
  produce false positives, unfixed CVEs linger by design).
- **Tag-bump finder is strict-semver** — suffixed or exotic tag schemes
  (e.g. `3.9-slim`) don't parse, so rung 1 silently no-ops for them.
- **Onboarding discipline required** — hardening only works when the
  `test`/`testStage` shares lineage with the runtime stage and the test suite
  is genuinely meaningful; a weak test suite converts "test-verified" into
  false confidence.
- **Sequential discovery** — images are processed one at a time; very large
  clusters need namespace scoping or a wider schedule window.

### Risks — know these before deploying

- **Privileged container / root-equivalent surface**: the dind sidecar runs
  `privileged: true` (and the legacy path mounts the host Docker socket, which
  is root on the node). Confine the agent to dedicated nodes, restrict via
  Pod Security/OPA, or swap in rootless builds (Kaniko) if your threat model
  demands it. See [Security considerations](#security-considerations-for-production).
- **It executes code from cloned repos**: hardening builds and runs the target
  app's own Dockerfile and tests. `testCommand` runs with `--network none`,
  but this is **not full sandboxing** — the build shares the docker daemon
  and kernel. Treat `source-repo` annotations/config as trusted input only;
  a hostile repo (or hostile annotation on a labeled pod) is code execution
  in the agent's environment.
- **Broad credentials in one pod**: a GitHub PAT with `repo` +
  `write:packages` and an Anthropic key live in the agent's namespace.
  Scope tokens to the minimum repos, rotate them, and prefer fine-grained
  PATs where the flows allow.
- **Rebuilt images are *your* artifacts now**: an `-optimized-ext` copy of a
  third-party image (and `-golden-base` forks of upstream bases) shifts
  patch-tracking, provenance, and license responsibility to you, and drifts
  from vendor-supported binaries — some vendors won't support modified
  images. That's why `KEEP_EXTERNAL_IMAGES` is a deliberate team decision.
- **Blanket OS upgrades change behavior**: `apk upgrade`/`apt-get upgrade`
  layers can alter library versions beyond the CVE fix. External images get
  only a rescan (no tests), so a behavioral regression in a third-party image
  would not be caught by this pipeline — canary such images downstream.
- **Non-deployable artifacts exist in the registry**: a failing balanced pick
  is pushed as evidence, flagged in the report, and never gets a PR — but
  nothing physically stops someone `docker pull`ing it. Keep the ArgoCD
  `allow-tags` regex tight (`optimized-ext|golden-base-app` only).
- **LLM output is bounded but not infallible**: base suggestions and
  adjudication justifications come from a model. The test+rescan gate catches
  bad bases, and deployability never comes from the model — but read the
  adjudication reasoning before acting on its code-fix suggestions, same as
  any code review.
- **Prompt-injection surface**: scan results and repo files are folded into
  LLM prompts. A malicious package name or Dockerfile comment could try to
  steer suggestions; the deterministic gates (build/test/rescan, regex-based
  file patching, test-result-driven deployability) are the mitigation — keep
  them in the loop if you extend the LLM's role.

## Project structure

```
vuln-agent/
├── agent/
│   ├── scanner.py        # Trivy wrapper — runs scan, parses JSON
│   ├── tag_finder.py     # Finds a newer upstream tag that already fixes CVEs
│   ├── patcher.py        # Deterministic OS-package-upgrade Dockerfile (no LLM)
│   ├── builder.py        # docker build/tag/push + crane copy to private registry
│   ├── reporter.py       # Claude Opus 4.8 — the one before/after Markdown summary
│   ├── promoter.py       # Opens a GitOps promotion PR for higher environments
│   ├── hardener.py       # Golden base image hardening for owned applications
│   ├── image_tracker.py  # Discovery-mode state: skip unchanged images
│   ├── discoverer.py     # Lists images running across cluster namespaces
│   ├── publisher.py      # Writes artifacts to disk; creates GitHub Release via REST API
│   └── orchestrator.py   # Main remediation loop and termination logic
├── chart/                # Helm chart — the actively-developed k8s deployment path
├── k8s/                  # Legacy raw Job/CronJob manifests (see README's k8s section)
├── .github/
│   └── workflows/
│       └── vuln-remediate.yml  # GitHub Actions workflow (manual trigger)
├── Dockerfile            # Agent container image
├── .dockerignore
├── LICENSE               # MIT
├── main.py               # CLI entry point
├── requirements.txt
└── .env.example
```

## License

[MIT](LICENSE) — free for commercial and private use, modification, and
redistribution. No warranty: you run the remediation pipeline, the images it
produces, and the PRs it opens at your own risk (see the risks section above).
