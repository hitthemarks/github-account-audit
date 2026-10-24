"""Tests for github_account_audit.

A fake `gh` (tests/fake_gh.py) and a fake `notify-send` are installed in a
temporary directory, and PATH is set to that directory alone, so the real gh
can never be reached: no test touches a real GitHub account or the network.
The baseline goes to a temporary XDG_STATE_HOME. All account data is made up.
"""

import base64
import copy
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import github_account_audit as gaa  # noqa: E402

OWNER = "example-user"

# Throwaway public key generated only for this test. The fingerprint is what
# `ssh-keygen -lf` printed for it.
KNOWN_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKo2Cx/AdFoMmUSNn7qWq2O9/xLkGSmg1gfxXYPqS3Hf"
KNOWN_FP = "SHA256:rPnyPtOCxYK1PG/KeXwWW3BlZBslBPvFHhrtYP9VqxU"

NOTIFY_SEND = """
import os, sys
with open(os.environ["FAKE_NOTIFY_LOG"], "a") as f:
    f.write(repr(sys.argv[1:]) + "\\n")
"""


def fake_key(label):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(label.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def key_material(key):
    return key.split()[1]


def ssh_key(id_, title, created="2026-01-15T10:00:00Z"):
    return {"id": id_, "title": title, "key": fake_key(title), "created_at": created}


def make_repo(name, visibility="private", **overrides):
    repo = {
        "full_name": f"{OWNER}/{name}",
        "visibility": visibility,
        "private": visibility != "public",
        "fork": False,
        "archived": False,
        "default_branch": "main",
        "deploy_keys": [],
        "hooks": [],
        "collaborators": [],
        "invitations": [],
        "security": {"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled"},
        "vulnerability_alerts": True,
        "classic_protection": True,
        "ruleset_rules": [],
    }
    repo.update(overrides)
    return repo


def base_world():
    return {
        "ssh_keys": [ssh_key(1, "Work laptop")],
        "ssh_signing_keys": [ssh_key(11, "Signing key")],
        "gpg_keys": "no-scope",
        "installations": "refused",
        "repos": [make_repo("public-tool", "public"), make_repo("private-notes")],
        "overrides": {},
    }


def ok(body, status=200):
    return {"status": status, "body": body}


NOT_FOUND = {"status": 404, "body": {"message": "Not Found"}}
LISTING_FIELDS = ("full_name", "visibility", "private", "fork", "archived", "default_branch")


def listing(path, items):
    sep = "&" if "?" in path else "?"
    pages = [items[i:i + 100] for i in range(0, len(items), 100)]
    if not pages or len(pages[-1]) == 100:
        pages.append([])
    return {f"{path}{sep}per_page=100&page={n}": ok(page) for n, page in enumerate(pages, 1)}


def refused(path, accepted):
    reply = {"status": 404, "headers": {"X-Accepted-OAuth-Scopes": accepted},
             "body": {"message": "Not Found"}}
    return {p: reply for p in listing(path, [])}


def build_responses(world):
    r = {"/user": ok({"login": OWNER, "id": 1})}
    r.update(listing("/user/keys", world["ssh_keys"]))
    r.update(listing("/user/ssh_signing_keys", world["ssh_signing_keys"]))
    if world["gpg_keys"] == "no-scope":
        r.update(refused("/user/gpg_keys", "admin:gpg_key, read:gpg_key, write:gpg_key"))
    else:
        r.update(listing("/user/gpg_keys", world["gpg_keys"]))
    if world["installations"] == "refused":
        r["/user/installations?per_page=100"] = {"status": 403, "body": {
            "message": "You must authenticate with an access token authorized to a GitHub App"}}
    else:
        r["/user/installations?per_page=100"] = ok(
            {"total_count": len(world["installations"]), "installations": world["installations"]})
    repos = world["repos"]
    r.update(listing("/user/repos?affiliation=owner&sort=full_name",
                     [{k: repo[k] for k in LISTING_FIELDS} for repo in repos]))
    for repo in repos:
        base = f"/repos/{repo['full_name']}"
        r.update(listing(base + "/keys", repo["deploy_keys"]))
        r.update(listing(base + "/hooks", repo["hooks"]))
        r.update(listing(base + "/collaborators?affiliation=direct", repo["collaborators"]))
        r.update(listing(base + "/invitations", repo["invitations"]))
        if repo["visibility"] != "public":
            continue
        detail = {k: repo[k] for k in LISTING_FIELDS}
        detail["security_and_analysis"] = {k: {"status": v} for k, v in repo["security"].items()}
        r[base] = ok(detail)
        r[base + "/vulnerability-alerts"] = ok(None, 204) if repo["vulnerability_alerts"] else NOT_FOUND
        r[base + "/branches/main/protection"] = (
            ok({"url": "https://api.example.invalid/protection"}) if repo["classic_protection"]
            else {"status": 404, "body": {"message": "Branch not protected"}})
        r[base + "/rules/branches/main"] = ok(repo["ruleset_rules"])
    r.update(world["overrides"])
    return r


def install_script(directory, name, source):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"#!{sys.executable}\n{source}")
    os.chmod(path, 0o755)


class AuditTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = tmp.name
        self.bin = os.path.join(root, "bin")
        os.mkdir(self.bin)
        with open(os.path.join(HERE, "fake_gh.py"), encoding="utf-8") as f:
            install_script(self.bin, "gh", f.read())
        install_script(self.bin, "notify-send", NOTIFY_SEND)
        self.state = os.path.join(root, "state")
        self.baseline = os.path.join(self.state, "github-account-audit", "baseline.json")
        self.responses = os.path.join(root, "responses.json")
        self.gh_log = os.path.join(root, "gh.log")
        self.notify_log = os.path.join(root, "notify.log")
        self.env = {
            "PATH": self.bin,
            "XDG_STATE_HOME": self.state,
            "FAKE_GH_RESPONSES": self.responses,
            "FAKE_GH_LOG": self.gh_log,
            "FAKE_NOTIFY_LOG": self.notify_log,
        }
        self.world = base_world()

    def run_audit(self, *args):
        with open(self.responses, "w", encoding="utf-8") as f:
            json.dump(build_responses(self.world), f)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, self.env), redirect_stdout(out), redirect_stderr(err):
            code = gaa.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def establish_baseline(self):
        code, out, err = self.run_audit("--no-notify")
        self.assertEqual(code, 0, out + err)
        if os.path.exists(self.notify_log):
            os.unlink(self.notify_log)

    def read_baseline(self):
        with open(self.baseline, encoding="utf-8") as f:
            return f.read()

    def notifications(self):
        if not os.path.exists(self.notify_log):
            return []
        with open(self.notify_log, encoding="utf-8") as f:
            return f.read().splitlines()

    def repo(self, name):
        return next(r for r in self.world["repos"] if r["full_name"] == f"{OWNER}/{name}")


class TestFingerprint(unittest.TestCase):
    def test_matches_ssh_keygen(self):
        self.assertEqual(gaa.fingerprint(KNOWN_KEY), ("ssh-ed25519", KNOWN_FP))

    def test_comment_is_ignored(self):
        self.assertEqual(gaa.fingerprint(KNOWN_KEY + " someone@somewhere")[1], KNOWN_FP)

    def test_garbage_is_unknown(self):
        self.assertEqual(gaa.fingerprint("ssh-ed25519 not*base64"), ("ssh-ed25519", "unknown"))
        self.assertEqual(gaa.fingerprint(None), ("unknown", "unknown"))


class TestHookTarget(unittest.TestCase):
    def test_keeps_only_scheme_and_host(self):
        url = "https://user:pa55@hooks.example.net:8443/path?token=abc123"
        self.assertEqual(gaa.hook_target(url), "https://hooks.example.net:8443")

    def test_missing_url(self):
        self.assertEqual(gaa.hook_target(None), "unknown")


class TestFirstRun(AuditTestCase):
    def test_creates_private_baseline_and_prints_inventory(self):
        code, out, err = self.run_audit()
        self.assertEqual(code, 0, out + err)
        self.assertIn("No baseline found", out)
        self.assertIn('"Work laptop" (ssh-ed25519 SHA256:', out)
        self.assertIn(f"{OWNER}/public-tool (public)", out)
        self.assertEqual(stat.S_IMODE(os.stat(self.baseline).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.baseline)).st_mode), 0o700)
        data = json.loads(self.read_baseline())
        self.assertEqual(data["repos"][f"{OWNER}/public-tool"]["security"]["secret_scanning"], True)
        self.assertEqual(self.notifications(), [])

    def test_no_key_material_in_output_or_baseline(self):
        self.world["repos"][0]["deploy_keys"] = [
            {"id": 5, "title": "CI deploy", "key": fake_key("deploy"), "read_only": True,
             "created_at": "2026-02-01T00:00:00Z"}]
        code, out, _ = self.run_audit("--full")
        baseline = self.read_baseline()
        for key in (fake_key("Work laptop"), fake_key("Signing key"), fake_key("deploy")):
            self.assertNotIn(key_material(key), out)
            self.assertNotIn(key_material(key), baseline)
        self.assertNotIn('"key"', baseline)

    def test_webhook_secrets_not_stored(self):
        self.world["repos"][0]["hooks"] = [{
            "id": 7, "name": "web", "active": True, "events": ["push"],
            "config": {"url": "https://bot:hunter2@hooks.example.net/in?token=abc123",
                       "secret": "********"}}]
        self.run_audit()
        baseline = self.read_baseline()
        self.assertIn("https://hooks.example.net", baseline)
        for secret in ("hunter2", "abc123", "********"):
            self.assertNotIn(secret, baseline)

    def test_tightens_loose_state_directory(self):
        os.makedirs(os.path.dirname(self.baseline), mode=0o755)
        os.chmod(os.path.dirname(self.baseline), 0o755)
        self.run_audit()
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.baseline)).st_mode), 0o700)


class TestChanges(AuditTestCase):
    def test_no_changes(self):
        self.establish_baseline()
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("No changes since baseline", out)
        self.assertNotIn("Inventory for", out)
        self.assertEqual(self.notifications(), [])

    def test_repo_became_public(self):
        self.establish_baseline()
        self.repo("private-notes").update(visibility="public", private=False)
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn(f"[!] Repo became public: {OWNER}/private-notes", out)
        lines = [l for l in out.splitlines() if l.startswith("  [")]
        self.assertIn("Repo became public", lines[0])
        self.assertEqual(len(self.notifications()), 1)
        self.assertIn("GitHub account audit", self.notifications()[0])

    def test_new_public_repo(self):
        self.establish_baseline()
        self.world["repos"].append(make_repo("fresh", "public"))
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn(f"[!] New public repo: {OWNER}/fresh", out)

    def test_keys_added_and_removed(self):
        self.establish_baseline()
        self.world["ssh_keys"].append(ssh_key(2, "New desktop", "2026-10-20T08:00:00Z"))
        self.world["ssh_signing_keys"] = []
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn('[+] New SSH authentication key: "New desktop" (ssh-ed25519 SHA256:', out)
        self.assertIn("added 2026-10-20", out)
        self.assertIn('[-] Removed SSH signing key: "Signing key"', out)
        self.assertNotIn(key_material(fake_key("New desktop")), out)

    def test_new_repo_access(self):
        self.establish_baseline()
        repo = self.repo("private-notes")
        repo["hooks"] = [{"id": 9, "name": "web", "active": True, "events": ["push", "release"],
                          "config": {"url": "https://ci.example.org/hook"}}]
        repo["collaborators"] = [{"login": "a-friend", "role_name": "write"},
                                 {"login": OWNER, "role_name": "admin"}]
        repo["invitations"] = [{"id": 3, "invitee": {"login": "stranger"}, "permissions": "admin",
                                "created_at": "2026-10-22T00:00:00Z"}]
        repo["deploy_keys"] = [{"id": 4, "title": "Server", "key": fake_key("server"),
                                "read_only": False, "created_at": "2026-10-21T00:00:00Z"}]
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        where = f"on {OWNER}/private-notes"
        self.assertIn(f"New webhook {where}: https://ci.example.org (events: push, release, active)", out)
        self.assertIn(f"New collaborator {where}: a-friend (write)", out)
        self.assertNotIn(f"collaborator {where}: {OWNER}", out)
        self.assertIn(f"New pending invitation {where}: stranger (admin, sent 2026-10-22)", out)
        self.assertIn(f'New deploy key {where}: "Server" (SHA256:', out)
        self.assertIn("read-write", out)

    def test_security_switched_off(self):
        self.establish_baseline()
        self.repo("public-tool")["vulnerability_alerts"] = False
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn(f"[!] Dependabot alerts switched off on {OWNER}/public-tool", out)

    def test_full_prints_inventory_with_changes(self):
        self.establish_baseline()
        code, out, _ = self.run_audit("--full")
        self.assertEqual(code, 0)
        self.assertIn("Inventory for example-user", out)
        self.assertIn("Security: Secret scanning on; Push protection on", out)
        self.assertIn("No changes since baseline", out)

    def test_accept_updates_baseline(self):
        self.establish_baseline()
        self.world["ssh_keys"].append(ssh_key(2, "New desktop"))
        code, out, _ = self.run_audit("--accept")
        self.assertEqual(code, 0)
        self.assertIn("New SSH authentication key", out)
        self.assertIn("Baseline updated.", out)
        self.assertEqual(self.notifications(), [])
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("No changes since baseline", out)

    def test_change_without_accept_keeps_reporting(self):
        self.establish_baseline()
        self.world["ssh_keys"].append(ssh_key(2, "New desktop"))
        self.assertEqual(self.run_audit("--no-notify")[0], 1)
        code, out, _ = self.run_audit("--no-notify")
        self.assertEqual(code, 1)
        self.assertIn("run with --accept", out)
        self.assertEqual(self.notifications(), [])


class TestFindings(AuditTestCase):
    def test_public_repo_without_secret_scanning(self):
        self.repo("public-tool")["security"] = {
            "secret_scanning": "disabled", "secret_scanning_push_protection": "disabled"}
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn(f"[!] Public repo {OWNER}/public-tool: secret scanning is off", out)
        self.assertIn(f"[!] Public repo {OWNER}/public-tool: push protection is off", out)
        # Findings are current state, so --accept does not silence them.
        self.run_audit("--accept")
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn("secret scanning is off", out)

    def test_private_repos_are_not_findings(self):
        self.repo("private-notes")["security"] = {"secret_scanning": "disabled"}
        self.assertEqual(self.run_audit()[0], 0)

    def test_ruleset_counts_as_branch_protection(self):
        self.repo("public-tool").update(classic_protection=False,
                                        ruleset_rules=[{"type": "pull_request"}])
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("Default branch protection on", out)

    def test_unprotected_branch_is_shown_not_a_finding(self):
        self.repo("public-tool").update(classic_protection=False, vulnerability_alerts=False)
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("Dependabot alerts off; Default branch protection off", out)


class TestNotChecked(AuditTestCase):
    def test_missing_scope_reported(self):
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("GPG keys: needs scope read:gpg_key", out)
        self.assertIn("GitHub App installations: needs a GitHub App user token", out)
        self.assertIn("Authorised OAuth apps: not checkable via API", out)

    def test_gpg_keys_when_scope_present(self):
        self.world["gpg_keys"] = [{"id": 21, "key_id": "ABCDEF0123456789", "can_sign": True,
                                   "created_at": "2026-03-01T00:00:00Z", "expires_at": None,
                                   "emails": [{"email": "someone@example.com"}]}]
        self.establish_baseline()
        self.assertNotIn("someone@example.com", self.read_baseline())
        self.world["gpg_keys"] = []
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn("Removed GPG key: ABCDEF0123456789", out)

    def test_unchecked_section_is_not_a_removal(self):
        self.repo("private-notes")["hooks"] = [
            {"id": 9, "name": "web", "active": True, "events": ["push"],
             "config": {"url": "https://ci.example.org/hook"}}]
        self.establish_baseline()
        self.world["overrides"] = refused(f"/repos/{OWNER}/private-notes/hooks", "admin:repo_hook")
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0, out)
        self.assertNotIn("Removed webhook", out)
        self.assertIn(f"Webhooks on {OWNER}/private-notes: needs scope admin:repo_hook", out)
        # Accepting keeps the old value for the section that was not checked.
        self.run_audit("--accept")
        data = json.loads(self.read_baseline())
        self.assertIn("9", data["repos"][f"{OWNER}/private-notes"]["hooks"])

    def test_installations_listed_when_allowed(self):
        self.world["installations"] = [{"id": 31, "app_slug": "some-bot",
                                        "account": {"login": OWNER},
                                        "repository_selection": "all",
                                        "created_at": "2026-04-01T00:00:00Z"}]
        self.establish_baseline()
        self.world["installations"].append({"id": 32, "app_slug": "other-bot",
                                            "account": {"login": OWNER},
                                            "repository_selection": "selected"})
        code, out, _ = self.run_audit()
        self.assertEqual(code, 1)
        self.assertIn(f"New GitHub App installation: other-bot on {OWNER} (selected repos)", out)


class TestErrors(AuditTestCase):
    def test_rate_limit_exits_3(self):
        self.world["overrides"] = {p: {"status": 403, "headers": {
            "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793000000"},
            "body": {"message": "API rate limit exceeded"}} for p in listing("/user/keys", [])}
        code, out, err = self.run_audit()
        self.assertEqual(code, 3)
        self.assertIn("rate limit reached", err)
        self.assertFalse(os.path.exists(self.baseline))

    def test_secondary_rate_limit_exits_3(self):
        self.world["overrides"] = {"/user": {"status": 429, "headers": {"Retry-After": "60"},
                                             "body": {"message": "slow down"}}}
        code, _, err = self.run_audit()
        self.assertEqual(code, 3)
        self.assertIn("retry after 60 seconds", err)

    def test_gh_failure_exits_3(self):
        self.world["overrides"] = {"/user": {"fail": True}}
        code, _, err = self.run_audit()
        self.assertEqual(code, 3)
        self.assertIn("error connecting", err)

    def test_server_error_exits_3(self):
        self.world["overrides"] = {"/user/repos?affiliation=owner&sort=full_name&per_page=100&page=1":
                                   {"status": 502, "body": {"message": "Bad Gateway"}}}
        self.assertEqual(self.run_audit()[0], 3)

    def test_gh_missing_exits_3(self):
        os.unlink(os.path.join(self.bin, "gh"))
        code, _, err = self.run_audit()
        self.assertEqual(code, 3)
        self.assertIn("gh not found", err)

    def test_corrupt_baseline_exits_3(self):
        os.makedirs(os.path.dirname(self.baseline))
        with open(self.baseline, "w") as f:
            f.write("{not json")
        code, _, err = self.run_audit()
        self.assertEqual(code, 3)
        self.assertIn("could not read baseline", err)

    def test_failed_write_leaves_old_baseline(self):
        self.establish_baseline()
        before = self.read_baseline()
        self.world["ssh_keys"] = []
        with mock.patch.object(gaa.os, "replace", side_effect=OSError("disk full")):
            code, _, err = self.run_audit("--accept")
        self.assertEqual(code, 3)
        self.assertIn("disk full", err)
        self.assertEqual(self.read_baseline(), before)
        self.assertEqual(os.listdir(os.path.dirname(self.baseline)), ["baseline.json"])

    def test_missing_notify_send_is_fine(self):
        os.unlink(os.path.join(self.bin, "notify-send"))
        self.establish_baseline()
        self.world["ssh_keys"] = []
        self.assertEqual(self.run_audit()[0], 1)


class TestReadOnly(AuditTestCase):
    def test_every_call_is_a_plain_get(self):
        self.establish_baseline()
        self.world["repos"].append(make_repo("another", "public"))
        self.run_audit("--full")
        with open(self.gh_log, encoding="utf-8") as f:
            calls = [json.loads(line) for line in f]
        self.assertGreater(len(calls), 20)
        for argv in calls:
            self.assertEqual(len(argv), 3, argv)
            self.assertEqual(argv[:2], ["api", "--include"])
            self.assertTrue(argv[2].startswith("/"), argv)

    def test_pagination(self):
        self.world["ssh_keys"] = [ssh_key(n, f"key-{n:03d}") for n in range(150)]
        code, out, _ = self.run_audit()
        self.assertEqual(code, 0)
        self.assertIn("SSH authentication keys (150):", out)
        self.world["ssh_keys"] = self.world["ssh_keys"][:100]
        self.run_audit("--accept")
        data = json.loads(self.read_baseline())
        self.assertEqual(len(data["ssh_keys"]), 100)


class TestDiffOrdering(unittest.TestCase):
    def test_alerts_come_first(self):
        old = {"ssh_keys": {}, "repos": {"u/r": {"visibility": "private", "archived": False}}}
        new = {"ssh_keys": {"1": {"title": "k", "type": "ssh-ed25519", "fingerprint": "SHA256:x",
                                  "created_at": None}},
               "repos": {"u/r": {"visibility": "public", "archived": False}}}
        changes = gaa.diff(copy.deepcopy(old), new)
        self.assertEqual(changes[0], (gaa.ALERT, "Repo became public: u/r"))
        self.assertEqual(changes[1][0], gaa.ADDED)


if __name__ == "__main__":
    unittest.main()
