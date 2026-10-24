#!/usr/bin/env python3
"""Audit a GitHub account for changes since a saved baseline.

Uses the GitHub CLI (gh), which must already be signed in. Every request is a
read-only GET through `gh api`; nothing on the account is ever changed.

Checks SSH authentication and signing keys, GPG keys, GitHub App
installations, every repo you own (visibility, fork, archived), and on each
repo its deploy keys, webhooks, collaborators and pending invitations. Public
repos also get their secret scanning, push protection, Dependabot alerts and
default branch protection checked.

Privacy:
  - The gh token is never read, printed or stored. gh handles it.
  - Public key material is reduced to a SHA256 fingerprint straight away and
    then discarded. Only titles, types, fingerprints and dates are kept.
  - Webhook URLs are cut down to scheme and host, since the rest of a URL can
    carry secrets.
  - The baseline is written atomically, mode 0600, in a 0700 directory.

Exit codes: 0 = no changes or findings, 1 = changes or findings, 3 = error
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

EXIT_OK = 0
EXIT_CHANGES = 1
EXIT_ERROR = 3

SCHEMA = 1
PER_PAGE = 100
GH_TIMEOUT = 60
OAUTH_APPS_URL = "https://github.com/settings/applications"
INSTALLATIONS_HINT = "needs a GitHub App user token (gh uses an OAuth token)"

# Ranks for sorting and marking changes, most serious first.
ALERT, ADDED, INFO = 0, 1, 2
MARKERS = {ALERT: "!", ADDED: "+", INFO: "-"}


class AuditError(Exception):
    pass


class RateLimited(AuditError):
    pass


class NotChecked(Exception):
    """GitHub refused a request, usually for a missing scope."""


# --- talking to gh ---------------------------------------------------------


def gh_env():
    env = dict(os.environ)
    env.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1", NO_COLOR="1")
    return env


def parse_response(text):
    """Split `gh api --include` output into status, headers and JSON body."""
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    head = parts[0].splitlines()
    try:
        status = int(head[0].split()[1])
    except (IndexError, ValueError):
        raise AuditError("could not parse gh output")
    headers = {}
    for line in head[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    body = None
    if len(parts) > 1 and parts[1].strip():
        try:
            body = json.loads(parts[1])
        except ValueError:
            raise AuditError("gh returned a body that is not JSON")
    return status, headers, body


def message_of(body):
    return body.get("message", "") if isinstance(body, dict) else ""


def is_rate_limited(status, headers, body):
    if status not in (403, 429):
        return False
    return (
        headers.get("x-ratelimit-remaining") == "0"
        or "retry-after" in headers
        or "rate limit" in message_of(body).lower()
    )


def rate_limit_message(headers):
    reset = headers.get("x-ratelimit-reset")
    if reset and reset.isdigit():
        when = datetime.fromtimestamp(int(reset), timezone.utc)
        return f"GitHub API rate limit reached; it resets at {when:%H:%M} UTC"
    retry = headers.get("retry-after")
    if retry:
        return f"GitHub API rate limit reached; retry after {retry} seconds"
    return "GitHub API rate limit reached; try again later"


def gh_api(path):
    """Run one read-only GET. Returns (status, headers, body)."""
    try:
        proc = subprocess.run(
            ["gh", "api", "--include", path],
            capture_output=True,
            text=True,
            timeout=GH_TIMEOUT,
            env=gh_env(),
        )
    except FileNotFoundError:
        raise AuditError("gh not found on PATH; install the GitHub CLI")
    except subprocess.TimeoutExpired:
        raise AuditError(f"gh timed out on {path}")
    if not proc.stdout.strip():
        lines = proc.stderr.strip().splitlines()
        detail = lines[0] if lines else f"exit {proc.returncode}"
        raise AuditError(f"gh api {path} failed: {detail}")
    status, headers, body = parse_response(proc.stdout)
    if is_rate_limited(status, headers, body):
        raise RateLimited(rate_limit_message(headers))
    return status, headers, body


def scope_set(value):
    return {s.strip() for s in (value or "").split(",") if s.strip()}


def missing_scope(headers):
    """Return the scope to ask for if the token lacks every accepted one."""
    accepted = scope_set(headers.get("x-accepted-oauth-scopes"))
    if not accepted or accepted & scope_set(headers.get("x-oauth-scopes")):
        return None
    reads = sorted(s for s in accepted if s.startswith("read:"))
    return reads[0] if reads else sorted(accepted)[0]


def refuse(status, headers, body, hint=None):
    if status >= 500:
        raise AuditError(f"GitHub error (HTTP {status})")
    scope = missing_scope(headers)
    if scope:
        raise NotChecked(f"needs scope {scope}")
    if hint:
        raise NotChecked(hint)
    msg = message_of(body)
    raise NotChecked(f"GitHub refused (HTTP {status}{': ' + msg if msg else ''})")


def get(path, hint=None):
    status, headers, body = gh_api(path)
    if status != 200:
        refuse(status, headers, body, hint)
    return body


def paginate(path, hint=None):
    items = []
    page = 1
    sep = "&" if "?" in path else "?"
    while True:
        body = get(f"{path}{sep}per_page={PER_PAGE}&page={page}", hint)
        if not isinstance(body, list):
            raise AuditError(f"unexpected response from {path}")
        items.extend(body)
        if len(body) < PER_PAGE:
            return items
        page += 1


def probe(path):
    """True for 200/204, False for a plain 404, NotChecked otherwise."""
    status, headers, body = gh_api(path)
    if status in (200, 204):
        return True
    if status == 404 and not missing_scope(headers):
        return False
    refuse(status, headers, body)


# --- collecting ------------------------------------------------------------


def fingerprint(public_key):
    """Return (type, SHA256 fingerprint) for an OpenSSH public key line."""
    parts = (public_key or "").split()
    if len(parts) < 2:
        return "unknown", "unknown"
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        return parts[0], "unknown"
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return parts[0], f"SHA256:{digest}"


def ssh_key_items(keys):
    items = {}
    for k in keys:
        key_type, fp = fingerprint(k.get("key"))
        items[str(k["id"])] = {
            "title": k.get("title") or "",
            "type": key_type,
            "fingerprint": fp,
            "created_at": k.get("created_at"),
        }
    return items


def gpg_key_items(keys):
    return {
        str(k["id"]): {
            "key_id": k.get("key_id"),
            "can_sign": bool(k.get("can_sign")),
            "created_at": k.get("created_at"),
            "expires_at": k.get("expires_at"),
        }
        for k in keys
    }


def installation_items(body):
    return {
        str(i["id"]): {
            "app": i.get("app_slug"),
            "account": (i.get("account") or {}).get("login"),
            "repository_selection": i.get("repository_selection"),
            "created_at": i.get("created_at"),
        }
        for i in (body or {}).get("installations", [])
    }


def deploy_key_items(keys):
    items = {}
    for k in keys:
        _, fp = fingerprint(k.get("key"))
        items[str(k["id"])] = {
            "title": k.get("title") or "",
            "fingerprint": fp,
            "read_only": bool(k.get("read_only")),
            "created_at": k.get("created_at"),
        }
    return items


def hook_target(url):
    """Keep only scheme and host of a webhook URL."""
    try:
        parts = urlsplit(url or "")
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
    except ValueError:
        return "unknown"
    return f"{parts.scheme}://{host}" if host else "unknown"


def hook_items(hooks):
    return {
        str(h["id"]): {
            "name": h.get("name"),
            "active": bool(h.get("active")),
            "events": sorted(h.get("events") or []),
            "target": hook_target((h.get("config") or {}).get("url")),
        }
        for h in hooks
    }


def collaborator_items(users, owner):
    return {
        u["login"]: {"login": u["login"], "permission": u.get("role_name")}
        for u in users
        if u.get("login") != owner
    }


def invitation_items(invites):
    return {
        str(i["id"]): {
            "invitee": (i.get("invitee") or {}).get("login") or "unknown",
            "permission": i.get("permissions"),
            "created_at": i.get("created_at"),
        }
        for i in invites
    }


def collect_security(name, branch, not_checked):
    base = f"/repos/{name}"
    sec = {}
    try:
        analysis = get(base).get("security_and_analysis")
    except NotChecked as e:
        analysis, reason = None, str(e)
    else:
        reason = "not returned by GitHub (needs admin access)"
    for key, field, label in (
        ("secret_scanning", "secret_scanning", "Secret scanning"),
        ("push_protection", "secret_scanning_push_protection", "Push protection"),
    ):
        status = ((analysis or {}).get(field) or {}).get("status")
        sec[key] = None if status is None else status == "enabled"
        if status is None:
            not_checked[f"{label} on {name}"] = reason

    try:
        sec["dependabot_alerts"] = probe(f"{base}/vulnerability-alerts")
    except NotChecked as e:
        sec["dependabot_alerts"] = None
        not_checked[f"Dependabot alerts on {name}"] = str(e)

    sec["branch_protection"] = None
    if not branch:
        not_checked[f"Branch protection on {name}"] = "repo has no default branch"
        return sec
    branch_path = quote(branch, safe="")
    results, reasons = [], []
    for check in (
        lambda: probe(f"{base}/branches/{branch_path}/protection"),
        lambda: bool(get(f"{base}/rules/branches/{branch_path}")),
    ):
        try:
            results.append(check())
        except NotChecked as e:
            reasons.append(str(e))
    if any(results):
        sec["branch_protection"] = True
    elif reasons:
        not_checked[f"Branch protection on {name}"] = reasons[0]
    else:
        sec["branch_protection"] = False
    return sec


REPO_SUBSECTIONS = (
    ("deploy_keys", "Deploy keys", "/keys", deploy_key_items),
    ("hooks", "Webhooks", "/hooks", hook_items),
    ("collaborators", "Collaborators", "/collaborators?affiliation=direct", None),
    ("invitations", "Pending invitations", "/invitations", invitation_items),
)


def collect_repos(owner, not_checked):
    repos = {}
    for r in paginate("/user/repos?affiliation=owner&sort=full_name"):
        name = r["full_name"]
        visibility = r.get("visibility") or ("private" if r.get("private") else "public")
        entry = {
            "visibility": visibility,
            "fork": bool(r.get("fork")),
            "archived": bool(r.get("archived")),
            "default_branch": r.get("default_branch"),
        }
        for key, label, suffix, convert in REPO_SUBSECTIONS:
            try:
                found = paginate(f"/repos/{name}{suffix}")
            except NotChecked as e:
                not_checked[f"{label} on {name}"] = str(e)
                continue
            if convert is None:
                entry[key] = collaborator_items(found, owner)
            else:
                entry[key] = convert(found)
        if visibility == "public":
            entry["security"] = collect_security(name, entry["default_branch"], not_checked)
        repos[name] = entry
    return repos


def collect():
    not_checked = {}
    try:
        user = get("/user")
    except NotChecked as e:
        raise AuditError(f"could not read the signed-in user: {e}")
    owner = user.get("login")
    inv = {
        "schema": SCHEMA,
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account": owner,
        "not_checked": not_checked,
    }
    sections = (
        ("ssh_keys", "SSH authentication keys",
         lambda: ssh_key_items(paginate("/user/keys"))),
        ("ssh_signing_keys", "SSH signing keys",
         lambda: ssh_key_items(paginate("/user/ssh_signing_keys"))),
        ("gpg_keys", "GPG keys",
         lambda: gpg_key_items(paginate("/user/gpg_keys"))),
        ("app_installations", "GitHub App installations",
         lambda: installation_items(get("/user/installations?per_page=100", INSTALLATIONS_HINT))),
        ("repos", "Repos", lambda: collect_repos(owner, not_checked)),
    )
    for key, label, fetch in sections:
        try:
            inv[key] = fetch()
        except NotChecked as e:
            not_checked[label] = str(e)
    not_checked["Authorised OAuth apps"] = f"not checkable via API, review {OAUTH_APPS_URL}"
    return inv


# --- describing ------------------------------------------------------------


def day(value):
    return (value or "unknown date")[:10]


def describe_ssh_key(k):
    return f'"{k["title"]}" ({k["type"]} {k["fingerprint"]}, added {day(k["created_at"])})'


def describe_gpg_key(k):
    expiry = f", expires {day(k['expires_at'])}" if k.get("expires_at") else ""
    return f"{k['key_id']} (added {day(k['created_at'])}{expiry})"


def describe_installation(i):
    return f"{i['app']} on {i['account']} ({i['repository_selection']} repos)"


def describe_deploy_key(k):
    access = "read-only" if k["read_only"] else "read-write"
    return f'"{k["title"]}" ({k["fingerprint"]}, {access}, added {day(k["created_at"])})'


def describe_hook(h):
    state = "active" if h["active"] else "inactive"
    return f"{h['target']} (events: {', '.join(h['events']) or 'none'}, {state})"


def describe_collaborator(c):
    return f"{c['login']} ({c['permission']})"


def describe_invitation(i):
    return f"{i['invitee']} ({i['permission']}, sent {day(i['created_at'])})"


ACCOUNT_SECTIONS = (
    ("ssh_keys", "SSH authentication key", "SSH authentication keys", describe_ssh_key),
    ("ssh_signing_keys", "SSH signing key", "SSH signing keys", describe_ssh_key),
    ("gpg_keys", "GPG key", "GPG keys", describe_gpg_key),
    ("app_installations", "GitHub App installation", "GitHub App installations",
     describe_installation),
)

REPO_DESCRIBE = (
    ("deploy_keys", "deploy key", "Deploy keys", describe_deploy_key),
    ("hooks", "webhook", "Webhooks", describe_hook),
    ("collaborators", "collaborator", "Collaborators", describe_collaborator),
    ("invitations", "pending invitation", "Pending invitations", describe_invitation),
)

SECURITY_FLAGS = (
    ("secret_scanning", "Secret scanning"),
    ("push_protection", "Push protection"),
    ("dependabot_alerts", "Dependabot alerts"),
    ("branch_protection", "Default branch protection"),
)


# --- comparing -------------------------------------------------------------


def diff_items(old, new, label, describe, where, add):
    if old is None or new is None:
        return
    for k in sorted(new.keys() - old.keys()):
        add(ADDED, f"New {label}{where}: {describe(new[k])}")
    for k in sorted(old.keys() - new.keys()):
        add(INFO, f"Removed {label}{where}: {describe(old[k])}")
    for k in sorted(old.keys() & new.keys()):
        if old[k] != new[k]:
            add(ADDED, f"Changed {label}{where}: {describe(new[k])}")


def diff_repo(name, old, new, add):
    if old.get("visibility") != new["visibility"]:
        if new["visibility"] == "public":
            add(ALERT, f"Repo became public: {name}")
        else:
            add(INFO, f"Repo is now {new['visibility']}: {name}")
    if old.get("archived", new["archived"]) != new["archived"]:
        add(INFO, f"Repo {'archived' if new['archived'] else 'unarchived'}: {name}")
    for key, label, _, describe in REPO_DESCRIBE:
        diff_items(old.get(key), new.get(key), label, describe, f" on {name}", add)
    old_sec, new_sec = old.get("security") or {}, new.get("security") or {}
    for key, label in SECURITY_FLAGS:
        before, after = old_sec.get(key), new_sec.get(key)
        if before is True and after is False:
            add(ALERT, f"{label} switched off on {name}")
        elif before is False and after is True:
            add(INFO, f"{label} switched on for {name}")


def diff(old, new):
    """Return a list of (rank, text) changes, most serious first."""
    changes = []

    def add(rank, text):
        changes.append((rank, text))

    for key, label, _, describe in ACCOUNT_SECTIONS:
        diff_items(old.get(key), new.get(key), label, describe, "", add)

    old_repos, new_repos = old.get("repos"), new.get("repos")
    if old_repos is not None and new_repos is not None:
        for name in sorted(new_repos.keys() - old_repos.keys()):
            repo = new_repos[name]
            if repo["visibility"] == "public":
                add(ALERT, f"New public repo: {name}")
            else:
                add(INFO, f"New {repo['visibility']} repo: {name}")
            blank = {key: {} for key, *_ in REPO_DESCRIBE}
            blank.update(visibility=repo["visibility"], archived=repo["archived"])
            diff_repo(name, blank, repo, add)
        for name in sorted(old_repos.keys() - new_repos.keys()):
            add(INFO, f"Repo deleted or no longer owned: {name}")
        for name in sorted(old_repos.keys() & new_repos.keys()):
            diff_repo(name, old_repos[name], new_repos[name], add)

    changes.sort(key=lambda c: c[0])
    return changes


def findings(inv):
    found = []
    for name, repo in sorted((inv.get("repos") or {}).items()):
        sec = repo.get("security")
        if repo["visibility"] != "public" or not sec:
            continue
        if sec.get("secret_scanning") is False:
            found.append(f"Public repo {name}: secret scanning is off")
        if sec.get("push_protection") is False:
            found.append(f"Public repo {name}: push protection is off")
    return found


def merge_unchecked(current, baseline):
    """Carry baseline values forward for anything not checked this run."""
    merged = json.loads(json.dumps(current))
    for key, *_ in ACCOUNT_SECTIONS + (("repos",),):
        if key not in merged and key in baseline:
            merged[key] = baseline[key]
    old_repos = baseline.get("repos") or {}
    for name, repo in (merged.get("repos") or {}).items():
        old = old_repos.get(name) or {}
        for key, *_ in REPO_DESCRIBE:
            if key not in repo and key in old:
                repo[key] = old[key]
        old_sec = old.get("security") or {}
        for key, value in (repo.get("security") or {}).items():
            if value is None and old_sec.get(key) is not None:
                repo["security"][key] = old_sec[key]
    return merged


# --- baseline --------------------------------------------------------------


def baseline_path():
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(state, "github-account-audit", "baseline.json")


def load_baseline(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise AuditError(f"could not read baseline {path}: {e}")
    if not isinstance(data, dict):
        raise AuditError(f"baseline {path} is not a JSON object")
    return data


def save_baseline(path, inv):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if os.stat(directory).st_mode & 0o077:
        os.chmod(directory, 0o700)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".baseline.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(inv, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


# --- output ----------------------------------------------------------------


def print_items(title, items, describe, indent=""):
    if items is None:
        print(f"{indent}{title}: not checked")
    elif not items:
        print(f"{indent}{title}: none")
    else:
        print(f"{indent}{title} ({len(items)}):")
        for _, item in sorted(items.items()):
            print(f"{indent}  - {describe(item)}")


def describe_security(sec):
    parts = []
    for key, label in SECURITY_FLAGS:
        value = sec.get(key)
        state = "not checked" if value is None else ("on" if value else "off")
        parts.append(f"{label} {state}")
    return "; ".join(parts)


def print_inventory(inv):
    print(f"Inventory for {inv.get('account')}:")
    for key, _, title, describe in ACCOUNT_SECTIONS:
        print_items(title, inv.get(key), describe, "  ")
    repos = inv.get("repos")
    if repos is None:
        print("  Repos: not checked")
        print()
        return
    print(f"  Repos ({len(repos)}):")
    for name, repo in sorted(repos.items()):
        flags = [repo["visibility"]]
        if repo["fork"]:
            flags.append("fork")
        if repo["archived"]:
            flags.append("archived")
        print(f"    {name} ({', '.join(flags)})")
        for key, _, title, describe in REPO_DESCRIBE:
            print_items(title, repo.get(key), describe, "      ")
        if "security" in repo:
            print(f"      Security: {describe_security(repo['security'])}")
    print()


def print_report(changes, found, inv, baseline):
    if baseline is not None:
        since = baseline.get("collected_at", "unknown time")
        if changes:
            print(f"Changes since baseline ({since}):")
            for rank, text in changes:
                print(f"  [{MARKERS[rank]}] {text}")
        else:
            print(f"No changes since baseline ({since}).")
        print()
    if found:
        print("Findings:")
        for text in found:
            print(f"  [!] {text}")
        print()
    print("Not checked:")
    for label, reason in sorted(inv["not_checked"].items()):
        print(f"  - {label}: {reason}")


def notify(changes, found):
    exe = shutil.which("notify-send")
    if not exe:
        return
    parts = []
    if changes:
        parts.append(f"{len(changes)} change{'s' if len(changes) != 1 else ''} since baseline")
    if found:
        parts.append(f"{len(found)} finding{'s' if len(found) != 1 else ''}")
    try:
        subprocess.run(
            [exe, "--app-name=github-account-audit", "GitHub account audit",
             ", ".join(parts) + ". Run github-account-audit to review."],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pass


# --- main ------------------------------------------------------------------


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="github-account-audit",
        description="Report what changed on your GitHub account since the saved baseline.",
        epilog="Exit codes: 0 no changes, 1 changes or findings, 3 error.",
    )
    p.add_argument("--full", action="store_true", help="print the whole inventory")
    p.add_argument("--accept", action="store_true",
                   help="save the current state as the new baseline after review")
    p.add_argument("--no-notify", action="store_true", help="do not send a desktop notification")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    path = baseline_path()
    try:
        baseline = load_baseline(path)
        current = collect()
    except AuditError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    found = findings(current)
    changes = [] if baseline is None else diff(baseline, current)
    print(f"GitHub account audit for {current['account']}")
    print()
    if baseline is None or args.full:
        print_inventory(current)
    print_report(changes, found, current, baseline)
    print()

    try:
        if baseline is None:
            save_baseline(path, current)
            print(f"No baseline found, so saved this state as the baseline: {path}")
        elif args.accept:
            save_baseline(path, merge_unchecked(current, baseline))
            print("Baseline updated.")
            return EXIT_OK
        elif changes:
            print("Review the changes, then run with --accept to make this the new baseline.")
    except OSError as e:
        print(f"error: could not save baseline {path}: {e}", file=sys.stderr)
        return EXIT_ERROR

    if not changes and not found:
        return EXIT_OK
    if not args.no_notify:
        notify(changes, found)
    return EXIT_CHANGES


if __name__ == "__main__":
    sys.exit(main())
