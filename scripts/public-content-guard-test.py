import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(args, cwd, env=None):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)


def identity_env(base=None, name=None, email=None):
    env = os.environ.copy() if base is None else base.copy()
    if name is not None:
        env["GIT_AUTHOR_NAME"] = name
        env["GIT_COMMITTER_NAME"] = name
    if email is not None:
        env["GIT_AUTHOR_EMAIL"] = email
        env["GIT_COMMITTER_EMAIL"] = email
    return env


def commit(repo, message, name, author_email, committer_name=None, committer_email=None):
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = author_email
    env["GIT_COMMITTER_NAME"] = committer_name or name
    env["GIT_COMMITTER_EMAIL"] = committer_email or author_email
    result = run(["git", "commit", "-qm", message], repo, env)
    if result.returncode:
        raise SystemExit("Self-test setup could not create a commit.")
    return run(["git", "rev-parse", "HEAD"], repo).stdout.strip()


def initialize_repo(repo, clean_email):
    run(["git", "init", "-q"], repo)
    config_name = "".join(("user", ".", "name"))
    config_email = "".join(("user", ".", "email"))
    run(["git", "config", config_name, "Guard Self Test"], repo)
    run(["git", "config", config_email, clean_email], repo)
    (repo / "base.txt").write_text("baseline\n", encoding="utf-8")
    run(["git", "add", "base.txt"], repo)
    base_result = run(["git", "commit", "-qm", "baseline"], repo, identity_env(name="Guard Self Test", email=clean_email))
    if base_result.returncode:
        raise SystemExit("Self-test setup could not create its baseline commit.")
    return run(["git", "rev-parse", "HEAD"], repo).stdout.strip()


def invoke_guard(guard, repo, base, head, deny, title="safe", body="safe"):
    env = os.environ.copy()
    env.update({
        "PUBLIC_DENY_LIST": "  " + deny + "  \n",
        "BASE_SHA": base,
        "HEAD_SHA": head,
        "PR_TITLE": title,
        "PR_BODY": body,
    })
    return run([sys.executable, "-I", str(guard)], repo, env)


def main():
    guard = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("public-content-guard.py")).resolve()
    acme_part = "".join(chr(value) for value in (97, 99, 109, 101))
    bakery_part = "".join(chr(value) for value in (98, 97, 107, 101, 114, 121))
    deny = "-".join((acme_part, bakery_part))
    spaced_variant = " ".join((acme_part.capitalize(), bakery_part.capitalize()))
    underscore_variant = "_".join((acme_part, bakery_part))
    mixed_case = deny.swapcase()
    email = "".join(("guard", "@", "github", ".", "com"))
    url = "".join(("https", ":", "/", "/", "not-allowlisted", ".", "example", "/guide"))
    clean_email = "".join(("guard-self-test", "@users.noreply", ".", "github", ".", "com"))
    rejected_email = "".join(("author", "@", "example", ".", "invalid"))

    with tempfile.TemporaryDirectory(prefix="public-content-guard-self-test-") as temp:
        repo = Path(temp)
        base = initialize_repo(repo, clean_email)
        (repo / "case.txt").write_text(mixed_case + "\n", encoding="utf-8")
        (repo / (spaced_variant + " handover.md")).write_text("safe content\n", encoding="utf-8")
        (repo / "space-variant.txt").write_text(spaced_variant + "\n", encoding="utf-8")
        (repo / "underscore-variant.txt").write_text(underscore_variant + "\n", encoding="utf-8")
        (repo / "binary.dat").write_bytes(b"\xff" + spaced_variant.encode("utf-8"))
        (repo / "email.txt").write_text(email + "\n", encoding="utf-8")
        (repo / "url.txt").write_text(url + "\n", encoding="utf-8")
        run(["git", "add", "-A"], repo)
        first_commit = commit(repo, "".join(("add note about ", deny)), "Guard Self Test", clean_email)

        (repo / "sync-labels.sh").write_text("printf safe\\n\n", encoding="utf-8")
        run(["git", "add", "sync-labels.sh"], repo)
        deny_name_commit = commit(repo, "add helper script", deny, clean_email, "GitHub", "".join(("noreply", "@", "github.com")))

        (repo / "identity.txt").write_text("safe identity check\n", encoding="utf-8")
        run(["git", "add", "identity.txt"], repo)
        invalid_identity_commit = commit(repo, "add identity fixture", "Guard Self Test", rejected_email, "GitHub", clean_email)
        head = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()

        result = invoke_guard(guard, repo, base, head, deny, spaced_variant, underscore_variant)
        output = result.stdout + result.stderr
        expected = [
            "case.txt:1: disallowed content",
            "space-variant.txt:1: disallowed content",
            "underscore-variant.txt:1: disallowed content",
            "changed path 1:1: path contains deny entry",
            "binary.dat: non-text file not permitted",
            "email.txt:1: disallowed content",
            "url.txt:1: disallowed content",
            "pr-title: disallowed content",
            "pr-body: disallowed content",
            f"commit {first_commit[:7]}: disallowed content",
            f"commit {deny_name_commit[:7]}: deny entry in author or committer name",
            f"commit {invalid_identity_commit[:7]}: non-noreply identity",
        ]
        missing = [item for item in expected if item not in output]
        if result.returncode != 1 or missing:
            print("Self-test failed.")
            print("Missing expected violation categories:")
            for item in missing:
                print(item)
            print("Guard exit code:", result.returncode)
            raise SystemExit(1)
        if deny.casefold() in output.casefold() or email in output or url in output or rejected_email in output:
            print("Self-test failed because the guard output exposed matched values.")
            raise SystemExit(1)
        print("Negative cases passed: separator and case normalization, file path, non-text file, PR title and body, commit message, email, non-allowlisted URL, non-noreply identity, and deny entry in author name.")

    with tempfile.TemporaryDirectory(prefix="public-content-guard-boundary-test-") as temp:
        repo = Path(temp)
        base = initialize_repo(repo, clean_email)
        word = "".join(chr(value) for value in (118, 105, 115, 97))
        (repo / "one.txt").write_text(word.capitalize() + "\n", encoding="utf-8")
        (repo / "two.txt").write_text("ad" + word + "ble\n", encoding="utf-8")
        run(["git", "add", "-A"], repo)
        commit(repo, "check word boundary", "Guard Self Test", clean_email)
        head = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
        result = invoke_guard(guard, repo, base, head, word)
        output = result.stdout + result.stderr
        if result.returncode != 1 or "one.txt:1: disallowed content" not in output or "two.txt" in output:
            print("Self-test failed: whole-word matching did not distinguish the two boundary cases.")
            raise SystemExit(1)
        print("Word-boundary cases passed: a word was caught and its embedded form was allowed.")

    with tempfile.TemporaryDirectory(prefix="public-content-guard-shell-test-") as temp:
        repo = Path(temp)
        base = initialize_repo(repo, clean_email)
        (repo / "sync-labels.sh").write_text("printf safe\\n\n", encoding="utf-8")
        run(["git", "add", "sync-labels.sh"], repo)
        commit(repo, "add shell helper", "Guard Self Test", clean_email)
        head = run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
        result = invoke_guard(guard, repo, base, head, deny)
        if result.returncode != 0:
            print("Self-test failed: clean sync-labels.sh change did not pass.")
            raise SystemExit(1)
        print("Positive case passed: clean sync-labels.sh change was accepted.")


if __name__ == "__main__":
    main()
