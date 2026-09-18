"""
Compliance orchestrator - aggregation and cross-framework reporting layer.

Tool execution (Caldera, Atomic Red Team, Prowler, OpenSCAP, PingCastle) is
handled by the Ansible playbooks in ../ansible/. This package's job starts
after that: read whatever raw output each tool left in results/, normalize
it into a common Finding record, roll it up against data/control_mappings.yaml
into ATT&CK / NIST 800-53 / CIS Controls / ISO 27001 / Zero Trust pillar
views, and produce a report.
"""

__version__ = "0.1.0"
