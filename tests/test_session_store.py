
import pytest

from pocket_sniffer.services.session_store import (
    SessionStore,
    SessionStoreError,
)


def test_index_list_and_select_session(tmp_path):
    session_dir = tmp_path / "capture-001"
    session_dir.mkdir()
    (session_dir / "conn.log").write_text(
        "#fields\tts\tproto\n1.0\ttcp\n", encoding="utf-8"
    )

    store = SessionStore(tmp_path / "index.sqlite3")
    added = store.index_session(session_dir)

    assert added.name == "capture-001"
    assert added.path == str(session_dir.resolve())

    sessions = store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].id == added.id

    selected = store.get_session(added.id)
    assert selected == added


def test_indexing_same_session_does_not_duplicate_it(tmp_path):
    session_dir = tmp_path / "capture-002"
    session_dir.mkdir()
    (session_dir / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

    store = SessionStore(tmp_path / "index.sqlite3")
    first = store.index_session(session_dir)
    second = store.index_session(session_dir)

    assert first.id == second.id
    assert len(store.list_sessions()) == 1


def test_index_rejects_missing_directory(tmp_path):
    store = SessionStore(tmp_path / "index.sqlite3")

    with pytest.raises(SessionStoreError, match="does not exist"):
        store.index_session(tmp_path / "missing")


def test_index_rejects_directory_without_supported_files(tmp_path):
    session_dir = tmp_path / "empty-session"
    session_dir.mkdir()
    (session_dir / "notes.txt").write_text("not a capture")

    store = SessionStore(tmp_path / "index.sqlite3")

    with pytest.raises(SessionStoreError, match="No supported"):
        store.index_session(session_dir)


def test_select_unknown_session_id(tmp_path):
    store = SessionStore(tmp_path / "index.sqlite3")

    with pytest.raises(SessionStoreError, match="No session found"):
        store.get_session(999)


def test_empty_index_returns_empty_list(tmp_path):
    store = SessionStore(tmp_path / "index.sqlite3")

    assert store.list_sessions() == []
