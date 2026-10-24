"""Fake `gh` for the tests. Installed on PATH as `gh` by the test suite.

Only `gh api --include <path>` is supported. Replies come from the JSON file
named by FAKE_GH_RESPONSES, keyed by path:

    {"/user": {"status": 200, "headers": {...}, "body": {...}}}

An entry with "fail": true prints only to stderr, like gh does when it cannot
reach GitHub at all. Unknown paths get a 404. Every call's arguments are
appended to FAKE_GH_LOG as one JSON line.
"""

import json
import os
import sys

DEFAULT_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "X-OAuth-Scopes": "admin:public_key, admin:ssh_signing_key, gist, read:org, repo, workflow",
    "X-RateLimit-Remaining": "4999",
}
REASONS = {200: "OK", 204: "No Content", 403: "Forbidden", 404: "Not Found",
           429: "Too Many Requests", 502: "Bad Gateway"}


def main(argv):
    with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(argv) + "\n")
    if len(argv) != 3 or argv[:2] != ["api", "--include"]:
        sys.stderr.write(f"fake gh: unsupported arguments {argv}\n")
        return 2
    with open(os.environ["FAKE_GH_RESPONSES"], encoding="utf-8") as f:
        responses = json.load(f)
    reply = responses.get(argv[2], {"status": 404, "body": {"message": "Not Found"}})
    if reply.get("fail"):
        sys.stderr.write("error connecting to api.github.com\n")
        return 1
    status = reply["status"]
    headers = dict(DEFAULT_HEADERS, **reply.get("headers", {}))
    out = [f"HTTP/2.0 {status} {REASONS.get(status, 'Unknown')}"]
    out += [f"{k}: {v}" for k, v in headers.items()]
    body = "" if reply.get("body") is None else json.dumps(reply["body"])
    sys.stdout.write("\r\n".join(out) + "\r\n\r\n" + body)
    if status >= 400:
        sys.stderr.write(f"gh: {REASONS.get(status, 'Error')} (HTTP {status})\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
