#!/usr/bin/env python3
"""
Entry point for the aggregation/reporting side of the project.

Usage:
    python main.py aggregate --results-dir results --mappings data/control_mappings.yaml --out report

Tool execution itself happens via Ansible - see ansible/playbooks/site.yml.
"""

from orchestrator.cli import main

if __name__ == "__main__":
    main()
