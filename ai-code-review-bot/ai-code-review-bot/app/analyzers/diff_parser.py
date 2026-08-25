"""
Parses a GitHub PR file `patch` (unified diff format) into a list of DiffLine
objects representing only the *added* lines, tagged with their line number in
the new version of the file. This is what both the regex scanners and the
GitHub inline-comment poster operate on (GitHub inline comments must reference
a line that exists in the diff).
"""
import re

from app.analyzers.secrets_scanner import DiffLine

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines_from_patch(file_path: str, patch: str | None) -> list[DiffLine]:
    if not patch:
        return []

    result: list[DiffLine] = []
    new_line_no = None

    for raw in patch.splitlines():
        header_match = HUNK_HEADER.match(raw)
        if header_match:
            new_line_no = int(header_match.group(1))
            continue

        if new_line_no is None:
            continue  # haven't hit a hunk header yet

        if raw.startswith("+") and not raw.startswith("+++"):
            result.append(DiffLine(file_path=file_path, line_number=new_line_no, text=raw[1:]))
            new_line_no += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue  # removed line — doesn't consume a new-file line number
        else:
            new_line_no += 1

    return result
