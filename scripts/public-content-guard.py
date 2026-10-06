import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def deny_entries_from(value):
    return [entry.strip().casefold() for entry in value.splitlines() if entry.strip()]


def line_is_forbidden(line, deny_entries):
    email_pattern = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
    scheme_marker = ":" + "/" + "/"
    web_prefix = "w" + "ww\\."
    url_patterns = [
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*" + re.escape(scheme_marker) + r"[^\s<>\"'`]+", re.IGNORECASE),
        re.compile(r"\b" + web_prefix + r"[^\s<>\"'`]+", re.IGNORECASE),
        re.compile(
            r"\b(?:[A-Za-z0-9-]+\.)+(?:com|org|net|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum|mobi|travel|jobs|cat|asia|tel|xxx|post|uk|us|ca|au|nz|de|fr|jp|cn|in|ie|nl|es|it|se|no|fi|ch|be|dk|sg|hk|za|br|mx|ru|io|ai|app|dev|cloud|tech|online|site|website|shop|store|xyz|top|world|space|click|link|live|work|design|agency|solutions|digital|consulting|email|me|co|tv|gg|fm|ly|sh|to|cc|example|test|invalid)(?![A-Za-z0-9-])(?::\d+)?(?:/[^\s<>\"'`]*)?",
            re.IGNORECASE,
        ),
    ]
    forbidden_term = re.compile(r"\b" + chr(83) + r"ME\b")
    forbidden_chars = (chr(0x2014), chr(0x2013))
    allowed_hosts = {"github.com", "docs.github.com"}
    matched = bool(email_pattern.search(line) or forbidden_term.search(line))
    matched = matched or any(character in line for character in forbidden_chars)
    for pattern in url_patterns:
        for candidate in pattern.findall(line):
            normalized = candidate.rstrip(".,);:!?}")
            parsed = urlsplit(normalized if scheme_marker in normalized else "/" + "/" + normalized)
            host = (parsed.hostname or "").lower()
            if host not in allowed_hosts:
                matched = True
    folded_line = line.casefold()
    return matched or any(entry in folded_line for entry in deny_entries)


def text_is_forbidden(text, deny_entries):
    return any(line_is_forbidden(line, deny_entries) for line in text.splitlines())


def safe_path(path, deny_entries):
    result = path
    for entry in sorted(deny_entries, key=len, reverse=True):
        result = re.sub(re.escape(entry), "[redacted]", result, flags=re.IGNORECASE)
    return result


def git_output(args, binary=False):
    try:
        return subprocess.run(args, check=True, capture_output=True, cwd=Path.cwd()).stdout
    except (OSError, subprocess.CalledProcessError):
        fail("public-content-guard could not inspect the pull request commits")


def main():
    deny_text = os.environ.get("PUBLIC_DENY_LIST", "")
    if not deny_text.strip():
        fail("public-content-guard failed closed: PUBLIC_DENY_LIST is missing or empty")
    deny_entries = deny_entries_from(deny_text)
    if not deny_entries:
        fail("public-content-guard failed closed: PUBLIC_DENY_LIST has no entries")

    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    if not base or not head:
        fail("public-content-guard requires pull request base and head commits")

    changed = git_output(["git", "diff", "--name-only", "-z", "--diff-filter=ACMRT", f"{base}...{head}"], binary=True)
    raw_paths = [value for value in changed.split(b"\0") if value]
    violations = []
    for index, raw_path in enumerate(raw_paths, start=1):
        try:
            path_text = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            violations.append((f"changed path {index}", "non-text file not permitted"))
            continue
        path_forbidden = text_is_forbidden(path_text, deny_entries)
        display_path = f"changed path {index}" if path_forbidden else path_text
        if path_forbidden:
            violations.append((f"{display_path}:1", "disallowed content"))
        try:
            content = Path(path_text).read_bytes()
        except OSError:
            violations.append((display_path, "non-text file not permitted"))
            continue
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            violations.append((display_path, "non-text file not permitted"))
            continue
        for line_number, line in enumerate(decoded.splitlines(), start=1):
            if line_is_forbidden(line, deny_entries):
                violations.append((f"{display_path}:{line_number}", "disallowed content"))

    pr_title = os.environ.get("PR_TITLE", "")
    pr_body = os.environ.get("PR_BODY", "")
    if text_is_forbidden(pr_title, deny_entries):
        violations.append(("pr-title", "disallowed content"))
    if text_is_forbidden(pr_body, deny_entries):
        violations.append(("pr-body", "disallowed content"))

    try:
        commit_ids = git_output(["git", "rev-list", f"{base}..{head}"]).decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("public-content-guard could not read pull request commit identifiers")
    for commit_id in commit_ids:
        message = git_output(["git", "show", "-s", "--format=%B", commit_id]).decode("utf-8", errors="replace")
        if text_is_forbidden(message, deny_entries):
            violations.append((f"commit {commit_id[:7]}", "disallowed content"))

    if violations:
        print("public-content-guard found disallowed content:")
        for location, reason in sorted(set(violations)):
            print(f"{location}: {reason}")
        raise SystemExit(1)
    print(f"public-content-guard passed for {len(raw_paths)} changed file(s)")


if __name__ == "__main__":
    main()
