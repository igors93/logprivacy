from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from logprivacy import CleanerPolicy, LogBlockedError, clean_file


def test_clean_file_safely_cleans_in_place_without_truncation(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text("email=john@example.com\npassword=secret123\n", encoding="utf-8")

    result = clean_file(path, output=path)

    assert result == path
    assert path.read_text(encoding="utf-8") == "email=[EMAIL]\npassword=[SECRET]\n"


def test_clean_file_keeps_existing_output_when_cleaning_fails(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "output.log"
    source.write_text("safe line\npassword=secret123\n", encoding="utf-8")
    output.write_text("existing output\n", encoding="utf-8")

    with pytest.raises(LogBlockedError):
        clean_file(source, output=output, policy=CleanerPolicy.production())

    assert output.read_text(encoding="utf-8") == "existing output\n"
    assert list(tmp_path.glob(".logprivacy-*.tmp")) == []


def test_clean_file_does_not_create_output_when_cleaning_fails(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "new-output.log"
    source.write_text("password=secret123\n", encoding="utf-8")

    with pytest.raises(LogBlockedError):
        clean_file(source, output=output, policy=CleanerPolicy.production())

    assert not output.exists()
    assert list(tmp_path.glob(".logprivacy-*.tmp")) == []


def test_clean_file_keeps_output_when_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "output.log"
    source.write_text("password=secret123\n", encoding="utf-8")
    output.write_text("existing output\n", encoding="utf-8")

    def fail_replace(source_path: object, target_path: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("logprivacy.files.operations.os.replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        clean_file(source, output=output)

    assert output.read_text(encoding="utf-8") == "existing output\n"
    assert list(tmp_path.glob(".logprivacy-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_clean_file_preserves_existing_output_permissions(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "output.log"
    source.write_text("password=secret123\n", encoding="utf-8")
    output.write_text("old\n", encoding="utf-8")
    output.chmod(0o640)

    clean_file(source, output=output)

    assert stat.S_IMODE(output.stat().st_mode) == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are required")
def test_clean_file_new_output_inherits_source_permissions(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "output.log"
    source.write_text("password=secret123\n", encoding="utf-8")
    source.chmod(0o600)

    clean_file(source, output=output)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symbolic links are unavailable")
def test_clean_file_follows_output_symlink_without_replacing_it(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    target = tmp_path / "target.log"
    output_link = tmp_path / "output.log"
    source.write_text("password=secret123\n", encoding="utf-8")
    target.write_text("old\n", encoding="utf-8")

    try:
        output_link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not permitted in this environment")

    clean_file(source, output=output_link)

    assert output_link.is_symlink()
    assert target.read_text(encoding="utf-8") == "password=[SECRET]\n"


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links are unavailable")
def test_clean_file_rejects_ambiguous_hard_link_alias(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    alias = tmp_path / "alias.log"
    source.write_text("password=secret123\n", encoding="utf-8")

    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hard links are not permitted in this environment")

    with pytest.raises(ValueError, match="hard-link"):
        clean_file(source, output=alias)

    assert source.read_text(encoding="utf-8") == "password=secret123\n"
    assert alias.read_text(encoding="utf-8") == "password=secret123\n"


def test_clean_file_preserves_crlf_line_endings(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "output.log"
    source.write_bytes(b"email=john@example.com\r\npassword=secret123\r\n")

    clean_file(source, output=output)

    assert output.read_bytes() == b"email=[EMAIL]\r\npassword=[SECRET]\r\n"


def test_clean_file_rejects_directory_output_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    output = tmp_path / "directory"
    source.write_text("password=secret123\n", encoding="utf-8")
    output.mkdir()

    with pytest.raises(IsADirectoryError):
        clean_file(source, output=output)

    assert list(tmp_path.glob(".logprivacy-*.tmp")) == []
