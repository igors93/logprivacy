from pathlib import Path

from logcleaner.__main__ import main


def test_cli_text_outputs_cleaned_text(capsys):
    exit_code = main(["text", "email=john@example.com"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "email=[EMAIL]" in captured.out


def test_cli_scan_returns_one_for_unsafe_file(tmp_path: Path, capsys):
    path = tmp_path / "app.log"
    path.write_text("password=123", encoding="utf-8")

    exit_code = main(["scan", str(path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Risk level" in captured.out
