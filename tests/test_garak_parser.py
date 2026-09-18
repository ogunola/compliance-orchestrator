"""
Parser smoke test using a synthetic .report.jsonl fixture shaped exactly
like garak's own test fixture (tests/_assets/report/report_test.report.jsonl
in the garak repo) - same "verify against real output" standard as the
other parser tests.
"""

import json
from pathlib import Path

from orchestrator.parsers import parse_garak_dir


def test_parse_garak_dir_reads_eval_rows_and_classifies_status(tmp_path: Path):
    target_dir = tmp_path / "garak" / "my-model"
    target_dir.mkdir(parents=True)

    rows = [
        {"entry_type": "start_run setup", "plugins.target_type": "openai.OpenAICompatible", "plugins.target_name": "my-model"},
        {"entry_type": "eval", "probe": "dan.Dan_11_0", "detector": "dan.DAN", "passed": 3, "fails": 2, "total_evaluated": 5, "nones": 0},
        {"entry_type": "eval", "probe": "encoding.InjectBase64", "detector": "encoding.DecodeMatch", "passed": 5, "fails": 0, "total_evaluated": 5, "nones": 0},
        {"entry_type": "eval", "probe": "topic.WordnetControversial", "detector": "always.Pass", "passed": 0, "fails": 0, "total_evaluated": 0, "nones": 0},
        {"entry_type": "attempt", "uuid": "irrelevant-row"},
    ]
    (target_dir / "garak.report.jsonl").write_text("\n".join(json.dumps(r) for r in rows))

    findings = parse_garak_dir(tmp_path)

    assert len(findings) == 3
    by_probe = {f.secondary_tag: f for f in findings}

    assert by_probe["dan.Dan_11_0"].status == "fail"
    assert by_probe["dan.Dan_11_0"].target == "my-model"
    assert by_probe["dan.Dan_11_0"].raw["fails"] == 2

    assert by_probe["encoding.InjectBase64"].status == "pass"
    assert by_probe["topic.WordnetControversial"].status == "not_applicable"


def test_parse_garak_dir_handles_missing_directory_gracefully(tmp_path: Path):
    assert parse_garak_dir(tmp_path) == []
