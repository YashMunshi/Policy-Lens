# Policy Lens · Access Analysis Lab

Analyze access logs, review permission usage, and measure the consequences of
proposed access policies. This project complements implementation of IAM controls
by focusing on **evidence, SQL analysis, and policy validation**.

**[Open the live demo](https://policy-lens-kappa.vercel.app/)** · [GitHub repository](https://github.com/YashMunshi/Policy-Lens)

The public demo runs in your browser without installation or sign-in. All access
logs, identities, permissions, and desired-policy labels are synthetic. It is a
portfolio lab for exploring IAM evidence and testing proposed access policies.

## Understanding the evidence collection

The sidebar summarizes the dataset used throughout the app:

| Label | Meaning |
|---|---|
| Northstar | A fictional organization used to name the demo dataset; no connection to a real company. |
| 30 days / 30-day synthetic window | The fixed observation period represented by the generated access events. It is not live monitoring or a countdown. |
| 12 human and service identities | Twelve fictional principals, including human users and service accounts. |
| Settings stay in this browser | In the hosted demo, candidate controls, policy version, replay count, and last replay policy are stored in this browser's local storage. |

The fixture contains **2,400 access events**, generated with seed **412469**.
Your settings are sent to the API to validate and reconstruct your analysis on
each request. Each request uses a disposable SQLite database; there is no shared
persistent policy database between visitors. Clearing site data or selecting
**Reset demo** restores the default settings. Settings do not sync across browsers
or devices, and browser-provided state is not trusted as authorization or as
precomputed evaluation evidence.

## Analysis workspace

| Tab | Purpose |
|---|---|
| Permission findings | Review unused grants, cross-department access, sensitive exports, and unusual access volume with supporting evidence. |
| Access logs | Filter access events by identity and observed decision, then export the full dataset as CSV. |
| Policy validation | Save candidate controls and replay the same events to compare false allows, false denies, precision, recall, and changed decisions. |
| Review report | Read and download a Markdown report containing findings, evidence, evaluation results, proposed review actions, and limitations. |

The interface pairs self-hosted **Source Serif 4** headings with **IBM Plex Sans**
for navigation, controls, and data. A deep blue, warm paper, and copper palette,
compact corners, crisp borders, and split-pane layouts support evidence review.
Navigation, data tables, form controls, and report text use larger, readable type.
Font license notices are included in `web/fonts/`.

## Hosted and local modes

| Mode | Access and state |
|---|---|
| Public Vercel demo | No sign-in. Browser-local analysis settings; a stateless Python function rebuilds the synthetic fixture for each request. |
| Local analyst workspace | Demo login, session and CSRF protections, analyst authorization, and a local SQLite database. |

Both modes analyze fictional data. Policy replay computes proposed decisions; it
does not grant employee access or change permissions on a live service.

## Run locally

Requires **Python 3.10+**. No packages, API keys, Docker, or paid services.

```bash
git clone https://github.com/YashMunshi/Policy-Lens.git
cd Policy-Lens
python3 app.py
```

Open http://127.0.0.1:8767 and sign in as **admin / DemoPass!2026**.
Windows: `py app.py`. The server binds only to localhost; stop with Ctrl+C.
This login protects the analyst workspace; the project does not grant employee
access, enforce policies on a real service, or change live permissions.

## What it does

- Queries 2,400 seeded synthetic access events across 12 human/service identities
  and a 30-day observation window using SQLite.
- Joins entitlement snapshots to observed successful access to identify unused
  permission candidates. Non-use is a review signal, not automatic revocation.
- Groups successful cross-department access and sensitive exports, including
  event IDs that support investigation.
- Detects unusual hourly volume with an explicit rate heuristic.
- Replays observed and candidate decisions against synthetic desired-policy labels.
- Computes SQL confusion matrices, deny precision/recall, changed decisions,
  sample accuracy intervals, and in-process decision latency.
- Exports logs as CSV, evaluation results as JSON, and an evidence-backed review
  report as Markdown.

## Walkthrough

1. Open Permission findings. Review the unused build-service payroll-export grant.
2. Review the report-service volume spike on day 17, hour 3. Compare its event count
   to the documented threshold and inspect cross-department evidence.
3. Open Access logs; filter report-service and Allowed. Export the complete CSV
   for further analysis. The browser table shows the latest 100 matching rows.
4. Open Policy validation and run the paired replay with all four controls enabled.
5. Disable Department boundary, save a policy version, and rerun. Compare false
   allows and changed decisions before considering a policy recommendation.
6. Open Review report and download the findings, evidence, replay summary, proposed
   review actions, and limitations.

## Evaluation method

Seed: **412469**. The synthetic historical decisions come from a deliberately broad
legacy entitlement snapshot. Desired labels come from a separate synthetic rubric
using department, resource sensitivity, posture, and risk. Candidate rules are
evaluated independently on the same records.

Positive class = **deny**:

| Measure | Definition |
|---|---|
| True positive | Correct denial |
| False positive | False denial of a desired allow |
| False negative | False allowance of a desired deny |
| Precision | TP / (TP + FP); undefined is N/A |
| Recall | TP / (TP + FN); undefined is N/A |

Measured on the included fixture:

| Variant | False allows | False denies |
|---|---:|---:|
| Observed historical decisions | 529 | 0 |
| Full candidate policy | 0 | 0 |
| Candidate with department boundary disabled | 886 | 0 |

There are two unused permission candidates and one injected volume spike in this
fixture. The volume heuristic flags hourly count above
`max(10, mean_hourly_rate + 4 * sqrt(mean_hourly_rate))`, with the mean computed over
720 hours per principal. It is a review heuristic, not a calibrated incident detector.

This is **offline paired replay**, not a live randomized A/B experiment. Synthetic
agreement does not establish production accuracy. Candidate decisions represent
the chosen rubric; temporary grants, SSO context, real business exceptions, and
independently adjudicated incidents are outside this fixture. Wilson intervals
describe the labeled sample. Latency excludes HTTP and database overhead.

Evidence: [evaluation JSON](docs/evaluation.json), [findings](docs/findings.json),
[sample logs](docs/sample-access-events.csv), and [sample review](docs/sample-review.md).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The Python suite contains **30 tests**: 23 local security and analysis tests,
plus 7 hosted-adapter tests. Coverage includes login, session invalidation, CSRF,
origin checks, analyst authorization, known findings, filtering, reproducibility,
policy impact, exports, state validation, and visitor isolation.
Test servers temporarily use port 18767.

Optional browser checks are in `tests/browser-check.cjs` and
`tests/hosted-browser.cjs`. They require Playwright and Chromium; neither is needed
to run the app. The published interface has been checked for policy replay,
log filtering, report output, and a CSV export containing all 2,400 events.

GitHub Actions runs the Python suite on Python 3.10 and 3.12. Runtime databases,
session secrets, and caches are excluded from Git. Stop the server before deleting
`demo.sqlite` and its WAL/SHM companions to reset the fixture.

## Tools and repository structure

Runtime: **Python, SQLite, HTML, CSS, and vanilla JavaScript**. The application uses
Python's standard library and has no third-party JavaScript runtime dependencies.
Hosting and automation: **GitHub, GitHub Actions, and Vercel**.

- `app.py`: data generation, SQL analysis, replay, report, and routing.
- `core.py`: local HTTP and session utilities.
- `api/index.py`: public, stateless Vercel Python function and demo-state validation.
- `build.py`: builds the hosted frontend into `public/`.
- `vercel.json`: build command, output directory, API rewrites, and security headers.
- `web/`: analyst UI and self-hosted fonts with license notices.
- `tests/`: Python tests and optional browser checks.
- `docs/`: sample data, evaluation evidence, security design, and publishing guide.

## Deployment

The repository is connected to Vercel. Changes pushed to `main` trigger a
production deployment at [policy-lens-kappa.vercel.app](https://policy-lens-kappa.vercel.app/).

The included configuration uses:

| Setting | Value |
|---|---|
| Framework preset | Other (`framework: null`) |
| Build command | `python3 build.py` |
| Output directory | `public` |
| Backend | `api/index.py`, a Vercel Python function |

No API keys or database credentials are required for the synthetic demo.
GitHub hosts the source; Vercel serves the frontend and Python API.
GitHub Pages cannot run this backend.

Read [the security design](docs/THREAT-MODEL.md) before adapting beyond the demo.
Additional repository setup steps are in [publishing instructions](docs/PUBLISHING.md).
