# Compliance Orchestrator

Automates architecture compliance testing across MITRE ATT&CK, NIST 800-53,
CIS Controls v8, ISO 27001 Annex A, and the CISA Zero Trust Maturity Model,
using each tool for its actual area of strength:

| Tool | Role | Runs against |
|---|---|---|
| **Caldera** | ATT&CK adversary emulation (chained operations) | Agent-installed hosts, any OS |
| **Atomic Red Team** | ATT&CK single-technique validation | Windows (WinRM) / Linux/macOS (SSH) |
| **Prowler** | Cloud config checks mapped to CIS + NIST 800-53 | AWS / Azure / GCP accounts |
| **OpenSCAP** | Host-level config checks (CIS via SCAP Security Guide) | Linux hosts (SSH) |
| **PingCastle** | AD health check → Zero Trust *Identity* pillar | Domain-joined Windows host (WinRM) |

**Ansible does execution.** Each tool gets its own role and runs against the
inventory group it actually applies to (see the table above). Raw output
lands under `results/<tool>/...` on the control node.

**Python does aggregation.** `main.py aggregate` reads everything under
`results/`, normalizes it into a common `Finding` record, and rolls it up
against the full ATT&CK → NIST 800-53 → CIS Controls crosswalk plus the
curated Zero Trust / ISO 27001 overlay.

```
you run ansible-playbook  →  results/{caldera,atomic,prowler,openscap,pingcastle}/...
                                        │
                              python main.py aggregate
                                        ▼
                     report/summary.json + report/findings.csv
                     (+ console tables: totals, by tool, by ZT pillar,
                       by NIST 800-53 control, by CIS control)
                                        │
                              python main.py push-vanta
                                        ▼
                              Vanta Custom Resources
                          (evidence for Custom Tests you author there)
```

## The ATT&CK → NIST 800-53 → CIS Controls crosswalk

`data/attack_crosswalk.generated.json` is built by `data/build_crosswalk.py`
from two real, versioned, vendored source datasets in `data/sources/`
(full provenance, licenses, and known limitations in
`data/sources/SOURCES.md` - read it before treating this as audit-grade):

1. **ATT&CK → NIST 800-53 Rev5**: MITRE's Center for Threat-Informed
   Defense `mappings-explorer` project - the established, actively
   maintained mapping in this space. 5,314 "mitigates" relationships across
   470 ATT&CK (sub-)techniques and 109 NIST controls (ATT&CK v16.1).
2. **CIS Controls v8.1 → NIST 800-53 Rev5**: `mitre/cis-cci-mappings`, a
   confidence-scored community dataset (not an official CIS publication -
   see SOURCES.md) covering all 150 CIS v8.1 safeguards.

The build script joins these two on their shared NIST control to derive
ATT&CK → CIS Controls associations (there's no free direct mapping for
that pair). Result: **470 of ATT&CK's ~566 enterprise techniques now have
real NIST 800-53 coverage, and 466 of those also get a derived CIS
Controls mapping** - up from the ~20-technique hand-written starter set
this project shipped with initially.

`data/control_mappings.yaml` is now a much smaller **curated overlay**:
just the Zero Trust pillar tags and ISO 27001 Annex A references, which
have no free structured dataset to build from. It's merged on top of the
generated crosswalk at load time (`orchestrator/aggregator.py
load_mappings()`) - a technique can have full NIST/CIS coverage from the
generated file and no ZT/ISO tag yet if nobody's curated one, or vice versa.

To regenerate after ATT&CK, NIST, or CIS publish a new version:

```bash
# refresh the vendored sources (see data/sources/SOURCES.md for exact repos/paths), then:
python3 data/build_crosswalk.py
```

## Why this split

Ansible is the right tool for *reaching* heterogeneous targets (SSH to
Linux, WinRM to Windows/AD, local HTTP calls to Caldera's and Prowler's
own APIs/CLI) with one inventory and one command. It is not a good fit for
cross-framework rollup logic (a technique mapping to three CIS controls and
one NIST control at once, coverage-gap detection, CSV/JSON export) - that's
what the small Python layer is for. Neither side duplicates the other.

## Setup

### 1. Control node (where you run `ansible-playbook` and `python main.py`)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r ansible/requirements.txt      # ansible-core, prowler if run locally
ansible-galaxy collection install -r ansible/requirements.yml
```

### 2. Per-tool setup (on whichever host each tool actually runs on - see table above)

- **Caldera**: stand up the server (or point at an existing one), enroll
  agents on your target hosts, note the server URL + API key + an
  adversary profile id.
- **Atomic Red Team**: on Windows targets, install the
  `invoke-atomicredteam` PowerShell module + clone the
  `atomic-red-team` repo. On Linux/macOS targets, `pip install atomic-operator`.
- **Prowler**: `pip install prowler` on the control/bastion host, and make
  sure cloud credentials are already configured there (AWS profile, `az
  login`, `gcloud auth login`) - Prowler picks those up itself.
- **OpenSCAP**: the `openscap_scan` role installs `openscap-scanner` +
  `scap-security-guide` on each Linux target automatically (requires
  `become`/sudo).
- **PingCastle**: download PingCastle and place `PingCastle.exe` on a
  domain-joined Windows admin host reachable over WinRM.

### 3. Configure inventory and variables

```bash
cp ansible/inventory/hosts.example.yaml ansible/inventory/hosts.yaml
cp ansible/group_vars/all.example.yaml ansible/group_vars/all.yaml
# edit both with your real hosts, URLs, and IDs
ansible-vault encrypt_string 'your-caldera-api-key' --name caldera_api_key
# paste the vaulted value into group_vars/all.yaml (or a separate vault file)
```

## Running it

```bash
cd ansible

# Everything:
ansible-playbook playbooks/site.yml

# Just the tools that cover one framework/area (Ansible tags):
ansible-playbook playbooks/site.yml --tags attack        # Caldera + Atomic
ansible-playbook playbooks/site.yml --tags cis            # Prowler + OpenSCAP
ansible-playbook playbooks/site.yml --tags zerotrust        # PingCastle
ansible-playbook playbooks/site.yml --tags prowler,pingcastle

# Then, from the project root, aggregate everything Ansible produced:
cd ..
python main.py aggregate --results-dir results --out report
```

`report/summary.json` and `report/findings.csv` are the durable output;
the console tables (totals, by tool, by Zero Trust pillar, by NIST/CIS
control) are just a quick look after a run.

## GRC hand-off (Vanta)

`orchestrator/connectors/vanta.py` pushes `report/summary.json` **and**
`report/ai/ai_summary.json` (the garak/OWASP pipeline below) into Vanta as
Custom Resources, so a Custom Test you author there can evaluate pass/fail
against real evidence from this pipeline instead of Vanta's built-in checks
alone. Vanta's public API has no "push a test result" endpoint directly -
custom compliance data flows through a predefined Custom Resource type
instead, so there's a one-time manual setup step in Vanta's UI:

1. **Settings → Developer Console → Build Integrations → new Private
   Integration.** Note the auto-generated `client_id`; generate and save a
   `client_secret` (shown once).
2. **On that integration, open the Resources tab → Custom Resource →
   New**, name it `compliance_control_coverage`, and paste this schema
   (JSON Type Definition):
   ```json
   {
     "properties": {
       "framework": { "type": "string" },
       "control_id": { "type": "string" },
       "pass_count": { "type": "int32" },
       "fail_count": { "type": "int32" },
       "error_count": { "type": "int32" },
       "total_count": { "type": "int32" },
       "pass_rate": { "type": "float64" },
       "last_aggregated_at": { "type": "timestamp" }
     },
     "optionalProperties": {
       "source_tools": { "type": "string" }
     }
   }
   ```
   Save it and note the generated **Resource ID**. This one schema covers
   both pipelines - the AI red-team resources below use the same
   `framework`/`control_id`/`pass_count`/etc. shape, just with
   `framework: "OWASP LLM Top 10 (2025)"` instead of an infra framework
   name, so you don't need a second Custom Resource type in Vanta.
3. **Author a Custom Test** against that resource type (e.g. `fail_count ==
   0`) and map it to the relevant control in Vanta's framework library
   (NIST 800-53, CIS Controls, ISO 27001, or a custom Zero Trust framework
   if you've set one up) - one test per control you want Vanta actively
   tracking, using `control_id` to pick out the right resource instance.
   For the AI pipeline, filter on `framework == "OWASP LLM Top 10 (2025)"`
   and `control_id == "LLM01"` (etc.) to build LLM-specific tests distinct
   from the infra/config ones.

Then push:

```bash
export VANTA_CLIENT_ID=...
export VANTA_CLIENT_SECRET=...
export VANTA_RESOURCE_ID=...          # from step 2

python main.py push-vanta --dry-run    # preview the payload, no creds/network needed
python main.py push-vanta              # pushes whichever of summary.json / ai_summary.json exist
```

`push-vanta` reads both `report/summary.json` (`--summary`, from
`aggregate`) and `report/ai/ai_summary.json` (`--ai-summary`, from
`aggregate-ai`) and pushes them **together in a single call**. Either one
can be missing - if you haven't run `aggregate-ai` yet, `push-vanta` just
skips the AI resources and pushes the infra ones (and vice versa), printing
a note either way; it only errors if neither file exists. They're combined
into one call deliberately, not as two separate pushes, because of the next
point:

**Important**: Vanta's push endpoint replaces the *entire* resource set on
every call - it's not additive. Pushing `summary.json` and then
`ai_summary.json` as two separate calls under the same `resourceId` would
make the second call erase the first's data, so `push-vanta` always builds
resources from whichever inputs exist, merges them (see below), and sends
one PUT. Always push the full current summary files (which `aggregate` /
`aggregate-ai` always regenerate in full), never a partial/manual edit of
them, or you'll silently make Vanta think controls you omitted no longer
exist.

One merge detail worth knowing: both pipelines can independently produce
Zero Trust pillar evidence (e.g. infra tools and garak can both surface
*Identity*-pillar findings). `merge_resources()` sums those pillars'
pass/fail counts and unions their `source_tools` rather than letting
whichever pipeline is listed second overwrite the other's pillar resource -
so a pillar's coverage in Vanta reflects all evidence feeding it, not just
one pipeline's.

See the docstring in `orchestrator/connectors/vanta.py` for the full API
contract (OAuth client_credentials, token endpoint, scopes, the exact PUT
body shape) - it was built against Vanta's published developer docs and
tested with mocked HTTP responses (`tests/test_vanta_connector.py`); it has
not been run against a live Vanta tenant, so validate the Custom Resource
schema and first push carefully with a small/test integration before wiring
it into anything automated.

## Zero Trust: how it's handled

There's no single scanner for Zero Trust, so it's treated as a **cross-cutting
lens over the other tools' output** rather than a standalone tool: every
row in `data/control_mappings.yaml` tags a `zt_pillar` (per the CISA Zero
Trust Maturity Model - Identity, Devices, Networks, Applications &
Workloads, Data, Visibility & Analytics, Automation & Orchestration,
Governance), and the aggregator rolls findings up by pillar regardless of
which tool produced them. PingCastle is the one addition made specifically
for this - it's the strongest free source of *Identity*-pillar evidence for
on-prem AD, and every PingCastle finding is tagged to that pillar directly.

`pillar_tool_coverage` in `control_mappings.yaml`, and `pillar_gaps` in the
aggregator's output, call out pillars this stack has **no evidence for at
all** - currently `automation_orchestration` and `governance`. Those two are
largely program/process maturity (do you have automated response playbooks?
is there governance oversight of the program?) rather than something a
scanner checks, so closing that gap means adding process evidence, not
another tool.

## AI red-teaming (garak + OWASP LLM Top 10) - experimental

A sixth, deliberately-separate pipeline for testing your own AI/LLM systems,
added alongside the five infrastructure/config tools above rather than
merged into them. Same `Finding` → aggregate → report shape you already
know, but its own commands and its own report, because the framework it
targets doesn't share the other five's shape:

- **[garak](https://github.com/NVIDIA/garak)** (NVIDIA-maintained, Apache
  2.0) - an LLM vulnerability scanner. Runs "probes" (jailbreak attempts,
  prompt injection, training-data leakage, package hallucination, and more)
  against a target model/endpoint and records pass/fail per probe+detector.
- Rolls up against the **OWASP LLM Top 10 (2025)**, using garak's *own*
  `owasp:llmXX` tags on its probe classes - not a mapping this project
  invented. 149 of garak's 194 probe classes carry a real OWASP tag,
  covering 9 of the 10 categories (everything except LLM03 Supply Chain,
  which isn't testable by prompting a running model).

**Why it's separate**, not folded into the NIST/CIS/ATT&CK rollup above:
OWASP's LLM Top 10 has no free, structured crosswalk to NIST 800-53 or CIS
Controls the way ATT&CK does - joining garak findings onto the existing
`by_framework` view would mean fabricating a mapping with nothing real
behind it. Full reasoning in `data/ai_redteam/SOURCES.md`.

### Setup

```bash
pip install garak   # heavier install - pulls in torch/transformers
export OPENAI_API_KEY=...   # or whatever your target generator needs - see `garak --list_generators`
```

Edit `ansible/group_vars/all.yaml`: set `garak_target_type` /
`garak_target_name` to the model/endpoint you're authorized to test, and
`garak_probes` to the probe modules you want to run.

### Running it

```bash
cd ansible && ansible-playbook playbooks/site.yml --tags ai    # or run_garak.yml directly
cd .. && python main.py aggregate-ai --results-dir results --out report/ai
```

`report/ai/ai_summary.json` and `report/ai/ai_findings.csv` are separate
files from the main `report/summary.json` - by design, not an oversight.
`python main.py push-vanta` picks up `report/ai/ai_summary.json`
automatically (see "GRC hand-off (Vanta)" above) alongside the main
summary, so there's no separate AI-specific push command.

### Responsible use

Several garak probes (`dan`, `promptinject`, and others) are designed to
elicit genuinely harmful, toxic, or policy-violating output as *proof* a
guardrail failed - that's the point of the test, but it means raw
`.report.jsonl` files and transcripts can contain that content. Only point
this at a model/endpoint you're authorized to test, and treat `results/`
and `report/ai/` the same way you'd treat any other pentest evidence -
access-restricted, not casually shared.

## Known limitations / things to verify before relying on this

- **The CIS Controls association is derived, not direct** (ATT&CK↔NIST is
  real/direct from CTID; NIST↔CIS is a community, confidence-scored
  dataset; CIS↔ATT&CK is this project joining the two). A broad parent
  technique can legitimately produce a broad control list this way (e.g.
  `T1078` → ~57 CIS safeguards) - see `data/sources/SOURCES.md` for why
  that's expected, not noise, and why sub-technique IDs give tighter
  results than parent technique IDs.
- **The Zero Trust pillar / ISO 27001 overlay (`data/control_mappings.yaml`)
  is still a ~20-technique starter set** - unlike NIST/CIS, there's no free
  structured dataset to build the full thing from automatically, so
  extending pillar/ISO coverage to more of the 470 crosswalked techniques
  is manual curation work.
- **The Vanta connector hasn't been run against a live tenant** - built
  against Vanta's published API docs and tested with mocked HTTP responses
  only (no sandbox credentials were available). Validate the Custom
  Resource schema and do a first push carefully.
- **Tool CLI flags and output schemas change.** Prowler's output format in
  particular has shifted across major versions; the parsers here target a
  recent JSON-OCSF-era version but you should diff a sample output file
  against what's parsed if you're on a different version. Comments in each
  `orchestrator/parsers/*.py` file flag exactly what to check.
- **Atomic Red Team parsing is heuristic** (keyword matching on log text,
  not a structured exit code) because neither Invoke-AtomicRedTeam nor
  atomic-operator has a fully stable machine-readable summary across
  versions. Findings with `status: unknown` should be spot-checked.
- **OpenSCAP → CIS control numbers**: the SCAP Security Guide's rule IDs
  don't carry a stable CIS control number in the XML itself. Right now
  OpenSCAP findings surface with their raw rule id; add a rule-id → CIS
  control lookup to `control_mappings.yaml` for the specific SSG content
  version you run if you need that rollup.
- **ISO 27001** stays mostly outside tool automation on purpose - a
  meaningful share of Annex A is organizational (risk treatment, management
  review, policy) rather than technically checkable. The `iso_27001_annex_a`
  column here covers only the technical controls the other four tools can
  actually speak to.
- **Drata/Secureframe/other GRC platforms** aren't wired up - Vanta was the
  one built in this pass. They're not redundant with Vanta so much as
  alternatives to it: all three follow the same shape (define a custom
  resource/test schema in the platform's UI once, then push instances via
  API), so if you're on Drata or Secureframe instead of Vanta, add a sibling
  connector rather than trying to make Vanta's push reach a different
  platform. `orchestrator/connectors/` is where a second connector would
  live; `build_resources()`/`build_ai_resources()`-style pure functions plus
  a thin HTTP client (see `vanta.py`) is the pattern to repeat.
- **garak itself hasn't been run against a live model** in this pass - the
  parser and aggregator are verified against garak's own real report
  schema and probe tag data (see `data/ai_redteam/SOURCES.md`), but nobody
  has pointed a live `garak_target_name` at an actual endpoint yet.

## Project layout

```
compliance-orchestrator/
├── ansible/
│   ├── ansible.cfg
│   ├── requirements.txt / requirements.yml
│   ├── inventory/hosts.example.yaml
│   ├── group_vars/all.example.yaml
│   ├── playbooks/          # site.yml + one playbook per tool
│   └── roles/              # caldera_operation, atomic_redteam, prowler_scan, openscap_scan, pingcastle_scan, garak_scan
├── data/
│   ├── control_mappings.yaml          # curated overlay: ZT pillars + ISO 27001
│   ├── build_crosswalk.py             # generates the file below from data/sources/
│   ├── attack_crosswalk.generated.json  # full ATT&CK -> NIST 800-53 -> CIS crosswalk
│   ├── sources/                       # vendored real source datasets + SOURCES.md
│   └── ai_redteam/                    # garak probe tags + OWASP LLM Top 10 (separate pipeline, own SOURCES.md)
├── orchestrator/            # Python aggregation + hand-off package
│   ├── schema.py             # Finding record
│   ├── parsers/              # one parser per tool's raw output (incl. garak_parser.py)
│   ├── aggregator.py         # rolls findings up to frameworks + ZT pillars
│   ├── ai_aggregator.py      # parallel rollup: garak -> OWASP LLM Top 10 + ZT pillars
│   ├── connectors/vanta.py   # GRC hand-off: pushes summary.json + ai_summary.json to Vanta
│   ├── report.py             # console tables + summary.json/findings.csv (+ ai_ variants)
│   └── cli.py                # `aggregate`, `aggregate-ai`, `push-vanta` subcommands
├── main.py
├── requirements.txt
├── results/                  # Ansible writes here (gitignored)
├── report/                   # python main.py aggregate writes here (gitignored)
└── tests/
```
