# github-account-audit

A small, read-only audit of your own GitHub account. It saves a baseline of
everything that grants access to your account or your code, then on each run
tells you only what has changed since: a new SSH key, a private repo that has
become public, a webhook or collaborator you did not add, or security
features switched off on a public repo.

It is meant to catch the quiet mistakes: making the wrong repo public, a key
on a laptop you no longer own, or an old integration that still has access.

It uses the [GitHub CLI](https://cli.github.com/) (`gh`) and the Python 3
standard library. Nothing else is needed.

## What it checks

| Item | Details kept |
|---|---|
| SSH authentication keys | title, type, SHA256 fingerprint, date added |
| SSH signing keys | title, type, SHA256 fingerprint, date added |
| GPG keys | key ID, whether it can sign, date added, expiry |
| GitHub App installations | app, account, which repos, date added |
| Every repo you own | visibility, fork, archived, default branch |
| Deploy keys on each repo | title, fingerprint, read-only or read-write, date added |
| Webhooks on each repo | events, active or not, scheme and host of the target |
| Collaborators on each repo | login and permission |
| Pending invitations on each repo | invitee, permission, date sent |
| Public repos only | secret scanning, push protection, Dependabot alerts, default branch protection (classic rules or rulesets) |

Changes reported, most serious first:

- `[!]` a repo became public, a new public repo, or a security feature
  switched off on a public repo
- `[+]` anything new or changed: keys, deploy keys, webhooks, collaborators,
  invitations, app installations
- `[-]` anything removed, archived, or made private

**Findings** are reported on every run, whatever the baseline says, until
they are fixed: any public repo with secret scanning or push protection
turned off. Both are free for public repos. Missing Dependabot alerts or
branch protection are shown in the full inventory and reported if they are
switched off later, but do not count as findings.

**Not checked** lists anything GitHub would not tell it, with the reason. A
section that could not be checked keeps its baseline value, so a missing
scope never shows up as everything being removed. Two items always appear
here:

- **Authorised OAuth apps.** GitHub has no API for listing the OAuth apps you
  have authorised, so review them by hand at
  <https://github.com/settings/applications> now and then.
- **GitHub App installations**, unless you use a GitHub App token. GitHub only
  lists installations to tokens issued by a GitHub App, and `gh` uses an
  OAuth token. The same settings page shows them.

## Privacy and safety

- **Read-only.** Every request is a plain `gh api` GET. Nothing on the account
  is ever changed. The tests check that no other kind of call is made.
- **No tokens.** The script never asks `gh` for its token and never sees it.
  `gh` keeps the token in your system keyring.
- **No key material.** Public keys are turned into a SHA256 fingerprint as soon
  as they arrive and the key itself is discarded. The fingerprint is the same
  one `ssh-keygen -lf` prints, so you can match it against your own keys.
- **No webhook secrets.** Webhook URLs can hold tokens in the path or query
  string, so only the scheme and host are kept.
- **No email addresses.** GPG key emails are not stored.
- The baseline lives in `~/.local/state/github-account-audit/baseline.json`
  (or under `$XDG_STATE_HOME` if set). The file is mode 0600, the directory
  0700, and it is written atomically, so an interrupted run can never leave a
  half-written baseline.

## Setup on Ubuntu

### Install the script

```bash
git clone https://github.com/hitthemarks/github-account-audit.git
cd github-account-audit
mkdir -p ~/.local/bin
install -m 755 github_account_audit.py ~/.local/bin/github-account-audit
```

On Ubuntu, `~/.local/bin` is added to your `PATH` at login if it exists. If
`github-account-audit` is not found straight away, log out and back in.

### Sign in to gh

Install `gh` (it is in the Ubuntu archive as `gh`), then sign in:

```bash
gh auth login
```

The default `gh` scopes (`repo`, `read:org`, `gist`, `workflow`) plus
`admin:public_key` cover everything except GPG keys. To include GPG keys, add
the read-only scope:

```bash
gh auth refresh -s read:gpg_key
```

Check which scopes you have with `gh auth status`.

## Usage

### First run

```bash
github-account-audit
```

With no baseline yet, it prints the full inventory and saves it as the
baseline. Read through it once: this is the point where you should recognise
every key, repo, webhook and collaborator. Remove anything you do not
recognise on GitHub, then run with `--accept` to save the cleaned-up state.

### Later runs

```bash
github-account-audit
```

Prints only the changes since the baseline, plus any findings and the list of
things not checked. Changes keep being reported on every run until you accept
them. Once you have reviewed them and are happy:

```bash
github-account-audit --accept
```

To see the whole inventory as well as the changes:

```bash
github-account-audit --full
```

| Option | Effect |
|---|---|
| `--full` | print the whole inventory as well as the changes |
| `--accept` | save the current state as the new baseline |
| `--no-notify` | do not send a desktop notification |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no changes and no findings |
| 1 | changes since the baseline, or findings |
| 3 | error, for example `gh` missing, not signed in, or rate limited |

`--accept` exits 0 once the baseline is saved.

### Desktop notifications

When a run exits 1, it sends a desktop notification with `notify-send`,
which Ubuntu installs by default. If `notify-send` is missing, it is
skipped silently.

## Weekly timer

The `systemd/` folder has a user service and a weekly timer. Install them
yourself, as your own user (no sudo):

```bash
mkdir -p ~/.config/systemd/user
cp systemd/github-account-audit.service systemd/github-account-audit.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now github-account-audit.timer
```

Check when it will next run, and try it once straight away:

```bash
systemctl --user list-timers github-account-audit.timer
systemctl --user start github-account-audit.service
journalctl --user -u github-account-audit.service -n 50
```

The timer runs once a week, with up to an hour of random delay. If the laptop
was off at the scheduled time, it runs at the next boot. Exit code 1 is
treated as success, so a run that finds changes does not show as a failed
unit. The notification tells you to look, and the journal has the report.

The service runs in your user session, so `gh` can read its token from the
keyring once you have logged in. If the keyring is locked, the run fails with
exit code 3 and the next week's run tries again.

To remove it:

```bash
systemctl --user disable --now github-account-audit.timer
rm ~/.config/systemd/user/github-account-audit.service ~/.config/systemd/user/github-account-audit.timer
systemctl --user daemon-reload
```

## Rate limits and missing scopes

A full run makes about four API calls per repo, plus four more for each
public repo. The signed-in rate limit is 5,000 calls an hour, so this is only
a concern with hundreds of repos. If the limit is hit, the run stops with exit
code 3 and says when the limit resets. The baseline is not touched.

If GitHub refuses a request because the token lacks a scope, the item is
listed under "Not checked" with the scope to add, for example
`GPG keys: needs scope read:gpg_key`. Missing scopes never cause an error.

## Limitations

- Only repos you own are covered, not repos in organisations or repos where
  you are a collaborator.
- Authorised OAuth apps cannot be listed through the API (see above).
- Collaborators are direct collaborators only. On a personal account that is
  everyone with access apart from you.
- Secret scanning and push protection status come from the repo's
  `security_and_analysis` settings, which GitHub only shows to repo admins.
  On your own repos that is always you.

## Running the tests

The tests use `unittest` from the standard library. They make no network
calls and never touch a real GitHub account: a fake `gh` that answers with
made-up JSON is installed in a temporary directory, and `PATH` is set to that
directory alone. A fake `notify-send` records notifications. The baseline is
written to a temporary directory.

```bash
python3 -m unittest discover -s tests -v
```

## Licence

Released under the MIT licence. See [LICENSE](LICENSE).
