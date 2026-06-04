from pathlib import Path

from logcleaner import clean_file, scan_file


def test_scan_file_reports_findings(tmp_path: Path):
    path = tmp_path / "app.log"
    path.write_text("email=john@example.com\n", encoding="utf-8")

    report = scan_file(path)

    assert report.safe is False
    assert report.finding_count == 1


def test_clean_file_writes_cleaned_output(tmp_path: Path):
    source = tmp_path / "app.log"
    output = tmp_path / "app.clean.log"
    source.write_text("password=123\n", encoding="utf-8")

    clean_file(source, output=output)

    assert output.read_text(encoding="utf-8") == "password=[SECRET]\n"
