"""Scan and clean a log file."""

import tempfile
from pathlib import Path

from logprivacy import clean_file, scan_file

# Create a temporary log file for the demo
log_content = (
    "INFO  login attempt john@example.com\nDEBUG password=hunter2 attempt=1\nINFO  status ok\n"
)

with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
    f.write(log_content)
    log_path = f.name

output_path = log_path + ".clean"

# Inspect without modifying
report = scan_file(log_path)
print(report.describe())

# Write a cleaned copy
clean_file(log_path, output=output_path)
print(Path(output_path).read_text())
# INFO  login attempt [EMAIL]
# DEBUG password=[SECRET] attempt=1
# INFO  status ok
