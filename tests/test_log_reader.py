import json

import pytest

from pocket_sniffer.services.log_reader import ZeekLogError, read_zeek_log


def test_reads_zeek_tsv_fixture():
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "zeek" / "conn.log"
    rows = read_zeek_log(path)
    assert len(rows) == 3
    assert rows[0]["proto"] == "tcp"
    assert rows[0]["id.orig_h"] == "192.0.2.10"


def test_reads_json_lines(tmp_path):
    path = tmp_path / "notice.log"
    path.write_text(json.dumps({"note": "Example::Notice", "src": "192.0.2.1"}) + "\n")
    assert read_zeek_log(path) == [{"note": "Example::Notice", "src": "192.0.2.1"}]


def test_rejects_data_without_fields_header(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("not a Zeek record\n")
    with pytest.raises(ZeekLogError, match="Missing #fields header"):
        read_zeek_log(path)


def test_rejects_tsv_field_count_mismatch(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("#fields\tts\tproto\n1.0\n")
    with pytest.raises(ZeekLogError, match="Expected 2 fields"):
        read_zeek_log(path)


def test_empty_log_is_valid(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("#separator \\x09\n#fields\tts\tproto\n")
    assert read_zeek_log(path) == []


def test_invalid_json_is_reported(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text('{"note":\n')
    with pytest.raises(ZeekLogError, match="Invalid JSON"):
        read_zeek_log(path)
