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


def line_reasons(line, deny_entries):
    reasons = set()
    email_pattern = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
    scheme_marker = ":" + "/" + "/"
    web_prefix = "w" + "ww\\."
    url_patterns = [
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*" + re.escape(scheme_marker) + r"[^\s<>\"'`]+", re.IGNORECASE),
        re.compile(r"\b" + web_prefix + r"[^\s<>\"'`]+", re.IGNORECASE),
        re.compile(
            r"\b(?:[A-Za-z0-9-]+\.)+(?:com|org|net|edu|gov|mil|int|biz|info|name|pro|aero|coop|museum|mobi|travel|jobs|cat|asia|tel|xxx|post|uk|us|ca|au|nz|de|fr|jp|cn|in|ie|nl|es|it|se|no|fi|ch|be|dk|sg|hk|za|br|mx|ru|io|ai|app|dev|cloud|tech|online|site|website|shop|store|xyz|top|world|space|click|link|live|work|design|agency|solutions|digital|consulting|email|me|co|tv|gg|fm|ly|to|cc|example|test|invalid)(?![A-Za-z0-9-])(?::\d+)?(?:/[^\s<>\"'`]*)?",
            re.IGNORECASE,
        ),
    ]
    forbidden_term = re.compile(r"\b" + chr(83) + r"ME\b")
    forbidden_chars = (chr(0x2014), chr(0x2013))
    allowed_hosts = {"github.com", "docs.github.com"}
    if email_pattern.search(line):
        reasons.add("email")
    if forbidden_term.search(line):
        reasons.add("term")
    if any(character in line for character in forbidden_chars):
        reasons.add("dash")
    for pattern in url_patterns:
        for candidate in pattern.findall(line):
            normalized = candidate.rstrip(".,);:!?}")
            parsed = urlsplit(normalized if scheme_marker in normalized else "/" + "/" + normalized)
            host = (parsed.hostname or "").lower()
            if host not in allowed_hosts:
                reasons.add("URL")
    folded_line = line.casefold()
    if any(entry in folded_line for entry in deny_entries):
        reasons.add("deny entry")
    return reasons


def text_is_forbidden(text, deny_entries):
    return any(line_reasons(line, deny_entries) for line in text.splitlines())


def email_is_noreply(value):
    address = value.strip().casefold()
    github_noreply = "@".join(("noreply", "github.com"))
    users_noreply_suffix = "".join(("@users.noreply", ".", "github", ".", "com"))
    return address == github_noreply or address.endswith(users_noreply_suffix)


def git_output(args):
    try:
        return subprocess.run(args, check=True, capture_output=True, cwd=Path.cwd()).stdout
    except (OSError, subprocess.CalledProcessError):
        fail("public-content-guard could not inspect the pull request commits")


def commit_identity(commit_id):
    raw = git_output(["git", "show", "-s", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce", commit_id])
    fields = raw.rstrip(b"\n").decode("utf-8", errors="replace").split("\0")
    if len(fields) != 5:
        fail("public-content-guard could not inspect a commit identity")
    return fields


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

    changed = git_output(["git", "diff", "--name-only", "-z", "--diff-filter=ACMRT", f"{base}...{head}"])
    raw_paths = [value for value in changed.split(b"\0") if value]
    violations = []
    for index, raw_path in enumerate(raw_paths, start=1):
        try:
            path_text = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            violations.append((f"changed path {index}", "non-text file not permitted"))
            continue
        path_reasons = line_reasons(path_text, deny_entries)
        display_path = f"changed path {index}" if path_reasons else path_text
        if path_reasons:
            reasons = ", ".join(sorted(path_reasons))
            violations.append((f"{display_path}:1", f"path contains {reasons}"))
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
            if line_reasons(line, deny_entries):
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
        fields = commit_identity(commit_id)
        _, author_name, author_email, committer_name, committer_email = fields
        short_id = commit_id[:7]
        if not email_is_noreply(author_email) or not email_is_noreply(committer_email):
            violations.append((f"commit {short_id}", "non-noreply identity"))
        if any(entry in author_name.casefold() or entry in committer_name.casefold() for entry in deny_entries):
            violations.append((f"commit {short_id}", "deny entry in author or committer name"))
        message = git_output(["git", "show", "-s", "--format=%B", commit_id]).decode("utf-8", errors="replace")
        if text_is_forbidden(message, deny_entries):
            violations.append((f"commit {short_id}", "disallowed content"))

    if violations:
        print("public-content-guard found disallowed content:")
        for location, reason in sorted(set(violations)):
            print(f"{location}: {reason}")
        raise SystemExit(1)
    print(f"public-content-guard passed for {len(raw_paths)} changed file(s)")


if __name__ == "__main__":
    main()
