import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


deny_text = os.environ.get("PUBLIC_DENY_LIST", "")
if not deny_text.strip():
    fail("public-content-guard failed closed: PUBLIC_DENY_LIST is missing or empty")
deny_entries = [entry for entry in deny_text.splitlines() if entry.strip()]
if not deny_entries:
    fail("public-content-guard failed closed: PUBLIC_DENY_LIST has no entries")

base = os.environ.get("BASE_SHA", "")
head = os.environ.get("HEAD_SHA", "")
if not base or not head:
    fail("public-content-guard requires pull request base and head commits")
result = subprocess.run(
    ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"{base}...{head}"],
    check=True,
    capture_output=True,
    text=True,
)
paths = [Path(value) for value in result.stdout.splitlines() if value]
email_pattern = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
scheme_marker = ":" + "/" + "/"
web_prefix = "w" + "ww\\."
url_patterns = [
    re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*" + re.escape(scheme_marker) + r"[^\s<>\"'`]+", re.IGNORECASE),
    re.compile(r"\b" + web_prefix + r"[^\s<>\"'`]+", re.IGNORECASE),
    re.compile(
        r"\b(?:[A-Za-z0-9-]+\.)+(?:com|org|net|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum|mobi|travel|jobs|cat|asia|tel|xxx|post|uk|us|ca|au|nz|de|fr|jp|cn|in|ie|nl|es|it|se|no|fi|ch|be|dk|sg|hk|za|br|mx|ru|io|ai|app|dev|cloud|tech|online|site|website|shop|store|xyz|top|world|space|click|link|live|work|design|agency|solutions|digital|consulting|email|me|co|tv|gg|fm|ly|sh|to|cc|example|test|invalid)(?::\d+)?(?:/[^\s<>\"'`]*)?",
        re.IGNORECASE,
    ),
]
forbidden_term = re.compile(r"\b" + chr(83) + r"ME\b")
forbidden_chars = (chr(0x2014), chr(0x2013))
allowed_hosts = {"github.com", "docs.github.com"}
violations = []
for path in paths:
    try:
        content = path.read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        continue
    for line_number, line in enumerate(content, start=1):
        matched = bool(email_pattern.search(line) or forbidden_term.search(line))
        matched = matched or any(character in line for character in forbidden_chars)
        for pattern in url_patterns:
            for candidate in pattern.findall(line):
                normalized = candidate.rstrip(".,);:!?}")
                parsed = urlsplit(normalized if scheme_marker in normalized else "/" + "/" + normalized)
                host = (parsed.hostname or "").lower()
                if host not in allowed_hosts:
                    matched = True
        if not matched:
            matched = any(entry in line for entry in deny_entries)
        if matched:
            violations.append((str(path), line_number))
if violations:
    print("public-content-guard found disallowed content:")
    for filename, line_number in sorted(set(violations)):
        print(f"{filename}:{line_number}")
    raise SystemExit(1)
print(f"public-content-guard passed for {len(paths)} changed file(s)")
