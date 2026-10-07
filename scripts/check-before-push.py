import argparse
import os
import subprocess
import sys
from pathlib import Path


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def git(args, cwd):
    try:
        return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        fail("local public content check could not inspect the current branch")


def repository_root(path):
    return Path(git(["git", "rev-parse", "--show-toplevel"], path)).resolve()


def main():
    parser = argparse.ArgumentParser(description="Scan the current branch before pushing it.")
    parser.add_argument("--title", default="", help="planned pull request title")
    parser.add_argument("--body", default="", help="planned pull request body")
    args = parser.parse_args()

    configured_path = os.environ.get("PUBLIC_DENY_LIST_FILE", "")
    if not configured_path.strip():
        fail("local public content check failed closed: PUBLIC_DENY_LIST_FILE is missing")
    deny_path = Path(configured_path).expanduser()
    try:
        deny_path = deny_path.resolve(strict=True)
        if not deny_path.is_file() or not os.access(deny_path, os.R_OK):
            fail("local public content check failed closed: deny list file is unavailable")
        deny_text = deny_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        fail("local public content check failed closed: deny list file is unavailable")
    if not deny_text.strip():
        fail("local public content check failed closed: deny list file is empty")

    probe = subprocess.run(["git", "rev-parse", "--git-dir"], cwd=deny_path.parent, capture_output=True, text=True)
    if probe.returncode == 0:
        fail("local public content check refused a deny list file inside a repository")

    script_path = Path(__file__).resolve()
    root = repository_root(script_path.parent)
    base = git(["git", "rev-parse", "--verify", "origin/main^{commit}"], root)
    head = git(["git", "rev-parse", "--verify", "HEAD^{commit}"], root)
    env = os.environ.copy()
    env.update({
        "PUBLIC_DENY_LIST": deny_text,
        "BASE_SHA": base,
        "HEAD_SHA": head,
        "PR_TITLE": args.title,
        "PR_BODY": args.body,
    })
    result = subprocess.run([sys.executable, "-I", str(script_path.with_name("public-content-guard.py"))], cwd=root, env=env)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
