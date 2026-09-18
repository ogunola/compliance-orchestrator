# AI red-teaming module - data provenance

## `garak_probe_tags.generated.json`

- **Source**: [NVIDIA/garak](https://github.com/NVIDIA/garak), an open-source
  LLM vulnerability scanner (originally by Leon Derczynski, ITU Copenhagen;
  NVIDIA-maintained since late 2024). Apache 2.0 license
  (`LICENSE-garak.txt`).
- **What it is**: every garak probe class's own `tags` attribute, extracted
  directly from garak's source (`data/ai_redteam/extract_garak_probe_tags.py`)
  by importing each probe module and reading class metadata - no
  hand-curation, no model instantiation, no network calls. garak's probe
  authors tag their own probes with real `owasp:llmXX` references (among
  other taxonomies - `cwe:`, `avid-effect:`, `payload:`); this script just
  surfaces what's already there.
- **Coverage**: 194 probe classes across 44 probe modules (garak version
  installed at extraction time: see garak's own `--version` / this repo's
  git log for when `extract_garak_probe_tags.py` was last run). 149 of
  those 194 carry at least one `owasp:llmXX` tag, spanning **9 of the 10**
  OWASP LLM Top 10 2025 categories - every category except **LLM03 Supply
  Chain**, which no garak probe tags, because supply-chain/provenance risk
  isn't something you can test by prompting a running model.
- **To refresh**: `git clone https://github.com/NVIDIA/garak`, install the
  lightweight deps listed in the script's docstring, then re-run
  `extract_garak_probe_tags.py` against the checkout.

## `owasp_llm_top10_2025.yaml`

- **Source**: [OWASP GenAI Security Project - LLM Top 10](https://genai.owasp.org/llm-top-10/),
  fetched 2026-09-18. The 10 category names/descriptions are OWASP's own;
  the `zt_pillar` tag on each is this project's own curated addition (same
  status as the overlay in `data/control_mappings.yaml` - a starter mapping,
  not an OWASP or NIST publication).
- **Versioning note**: OWASP's page labeled this list "2025" at fetch time.
  Some 2026-dated commentary discusses an anticipated revision, but no
  superseding official list was found published at genai.owasp.org as of
  this build - re-check before assuming this is still current, the same way
  you'd re-check ATT&CK/NIST/CIS versions in `data/sources/SOURCES.md`.

## Why this stays a separate dimension from `data/control_mappings.yaml`

MITRE ATT&CK, NIST 800-53, and CIS Controls share a similar shape (discrete,
comparatively stable techniques/controls with real published crosswalks
between them). OWASP's LLM Top 10 is a vulnerability checklist revised
annually, and there's no free structured crosswalk from it to NIST 800-53
or CIS Controls - forcing garak findings into the existing `by_framework`
NIST/CIS rollup would mean fabricating a mapping with nothing real behind
it, exactly the problem the ATT&CK crosswalk work was meant to fix. Keeping
`owasp_llm_top10` as its own framework key in the aggregator (see
`orchestrator/ai_aggregator.py`) avoids that, at the cost of not getting a
single unified NIST/CIS number that includes AI findings - which is the
right trade-off until a real crosswalk exists to join on.
