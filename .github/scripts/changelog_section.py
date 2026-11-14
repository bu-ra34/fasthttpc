"""Print the CHANGELOG.md section for a tag (e.g. v0.5.0 or 0.5.0).

Looks for a heading line that contains the version (`## [0.5.0]`, `## v0.5.0`,
`## 0.5.0 - date`); the section runs until the next `## ` heading. Falls back
to a generic line when the version has no section.
"""
import re
import sys

version = sys.argv[1].lstrip("v")
lines = open("CHANGELOG.md", encoding="utf-8").read().splitlines()
pat = re.compile(r"^##\s+\[?v?" + re.escape(version) + r"(?![\w.])")
out, on = [], False
for line in lines:
    if line.startswith("## "):
        if on:
            break
        on = bool(pat.match(line))
        continue
    if on:
        out.append(line)
text = "\n".join(out).strip()
print(text or f"Release {version}. See CHANGELOG.md for details.")
