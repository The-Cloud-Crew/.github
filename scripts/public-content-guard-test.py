import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(args, cwd, env=None, check=False):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=check)


def main():
    guard = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("public-content-guard.py")).resolve()
    deny = "".join(("Acme", " ", "Bakery"))
    mixed_case = deny.swapcase()
    email = "".join(("guard", "@", "github", ".", "com"))
    url = "".join(("https", ":", "/", "/", "not-allowlisted", ".", "example", "/guide"))

    with tempfile.TemporaryDirectory(prefix="public-content-guard-self-test-") as temp:
        repo = Path(temp)
        run(["git", "init", "-q"], repo, check=True)
        run(["git", "config", "user.name", "Guard Self Test"], repo, check=True)
        run(["git", "config", "user.email", "".join(("guard-self-test", "@", "example", ".", "invalid"))], repo, check=True)
        (repo / "base.txt").write_text("baseline\n", encoding="utf-8")
        run(["git", "add", "base.txt"], repo, check=True)
        run(["git", "commit", "-qm", "baseline"], repo, check=True)
        base = run(["git", "rev-parse", "HEAD"], repo, check=True).stdout.strip()

        (repo / "case.txt").write_text(mixed_case + "\n", encoding="utf-8")
        (repo / (deny + " handover.md")).write_text("safe content\n", encoding="utf-8")
        (repo / "binary.dat").write_bytes(b"\xff" + deny.encode("utf-8"))
        (repo / "email.txt").write_text(email + "\n", encoding="utf-8")
        (repo / "url.txt").write_text(url + "\n", encoding="utf-8")
        run(["git", "add", "-A"], repo, check=True)
        commit_message = "".join(("add note about ", deny))
        run(["git", "commit", "-qm", commit_message], repo, check=True)
        head = run(["git", "rev-parse", "HEAD"], repo, check=True).stdout.strip()
        short_head = head[:7]

        env = os.environ.copy()
        env.update({
            "PUBLIC_DENY_LIST": "  " + deny + "  \n",
            "BASE_SHA": base,
            "HEAD_SHA": head,
            "PR_TITLE": mixed_case,
            "PR_BODY": deny,
        })
        result = run([sys.executable, "-I", str(guard)], repo, env)
        output = result.stdout + result.stderr
        expected = [
            "case.txt:1: disallowed content",
            "changed path 1:1: disallowed content",
            "binary.dat: non-text file not permitted",
            "email.txt:1: disallowed content",
            "url.txt:1: disallowed content",
            "pr-title: disallowed content",
            "pr-body: disallowed content",
            f"commit {short_head}: disallowed content",
        ]
        missing = [item for item in expected if item not in output]
        if result.returncode != 1 or missing:
            print("Self-test failed.")
            print("Missing expected violation categories:")
            for item in missing:
                print(item)
            print("Guard exit code:", result.returncode)
            raise SystemExit(1)
        if deny.casefold() in output.casefold() or email in output or url in output:
            print("Self-test failed because the guard output exposed matched values.")
            raise SystemExit(1)
        print("Self-test passed: case-insensitive deny entry, path, non-text file, PR title, PR body, commit message, email, and non-allowlisted URL were caught.")


if __name__ == "__main__":
    main()
