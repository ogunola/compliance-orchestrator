# Vendored source datasets

These two files are the real, versioned mapping datasets that
`../build_crosswalk.py` joins into the full ATT&CK → NIST 800-53 → CIS
Controls crosswalk (`../attack_crosswalk.generated.json`). They are vendored
here (not just linked) so the build is reproducible without depending on
GitHub being reachable at build time, and so you can diff future updates
against exactly what was used.

## 1. `nist_800_53-rev5_attack-16.1-enterprise.json`

- **Source**: [center-for-threat-informed-defense/mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer)
- **What it is**: MITRE's Center for Threat-Informed Defense's official ATT&CK → NIST SP 800-53 Rev 5 mapping project. This is the well-established, widely cited mapping in this space (started 2022, actively maintained), covering "mitigates" relationships between ATT&CK (sub-)techniques and NIST 800-53 controls.
- **Version pulled**: ATT&CK v16.1, NIST 800-53 Rev 5, Enterprise domain. Retrieved 2026-09-17.
- **Coverage**: 5,314 "complete" (mappable) entries across 470 unique ATT&CK (sub-)techniques (142 base techniques + 328 sub-techniques) and 109 distinct NIST 800-53 controls. The remaining 96 techniques in ATT&CK Enterprise are marked `non_mappable` by CTID itself (typically because ATT&CK records no known mitigation for that technique) and are carried through as such rather than silently dropped.
- **License**: see `LICENSE-mappings-explorer.txt` (Apache 2.0-family; check the repo for the exact current terms before redistributing further).
- **To refresh**: `git clone https://github.com/center-for-threat-informed-defense/mappings-explorer` and copy the latest `mappings/nist_800_53/attack-<version>/nist_800_53-rev5/enterprise/*.json`.

## 2. `cis-cci-mapping-v8.1.json`

- **Source**: [mitre/cis-cci-mappings](https://github.com/mitre/cis-cci-mappings) (MITRE Security Automation Framework)
- **What it is**: CIS Controls v8.1 safeguard → DISA CCI → NIST 800-53 Rev 5 control mapping. **Read this carefully**: per the repo's own README, this is a confidence-scored, independently-validated *community* dataset (avg confidence 0.91–0.93, all entries ≥0.80, cross-checked against the DISA CCI API), not an official CIS-published crosswalk. CIS does publish its own official "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev. 5" whitepaper at cisecurity.org if you need a vendor-published source for an audit - this repo is the free, structured, machine-readable stand-in used here because it's directly consumable and 100% coverage (150/150 v8.1 safeguards) rather than a PDF table.
- **Version pulled**: CIS Controls v8.1 (June 2024). Retrieved 2026-09-17.
- **License**: Apache 2.0, see `LICENSE-cis-cci-mappings.md`.
- **To refresh**: `git clone https://github.com/mitre/cis-cci-mappings` and copy the latest `mappings/cis-cci-mapping-v8.1.json`.

## Why the join is derived, not direct

There is no free, structured, direct ATT&CK ↔ CIS Controls mapping available.
`build_crosswalk.py` derives one by joining these two datasets on their
shared NIST 800-53 control: *technique X mitigated-by control Y, control Y
implemented-by safeguard Z, therefore technique X relates to safeguard Z*.
That's a legitimate, commonly-used crosswalk methodology, but it is a
two-hop derivation, not a first-party ATT&CK-to-CIS mapping - treat derived
CIS Controls associations as somewhat less precise than the direct
ATT&CK-to-NIST associations, and spot-check anything you plan to cite in an
audit context.

**A broad parent technique will legitimately produce a broad control list.**
E.g. `T1078` (Valid Accounts, a broad parent technique) maps to 25 NIST
controls and ~57 derived CIS safeguards - that's not noise, CTID genuinely
lists that many controls as mitigating it. Sub-techniques are tighter and
more actionable: `T1078.001` (Default Accounts specifically) maps to 14
NIST controls and a correspondingly smaller CIS set. Prefer sub-technique
IDs over parent technique IDs wherever your tool output provides them
(Atomic Red Team and Caldera abilities usually do) for a more precise
rollup.
