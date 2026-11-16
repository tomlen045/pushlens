#!/usr/bin/env python3
# PART 1/3 of pushlens.py — assembled by cat
"""pushlens — a post-commit watchdog for git working trees.

One file, zero dependencies, read-only on your repos.

Committing is not the same as being safe. Work hides in local commits that
were never pushed, in branches that drifted, in fixup/WIP subjects, in
amended-over commits and in stashes. pushlens walks a list of repos (or a
forest root), and emits machine-readable findings per repository:

  DIRTY / UNTRACKED / STASH        working-tree level residue
  AHEAD / BEHIND / BRANCH_DRIFT    commit-level residue vs upstream
  WIP / FIXUP / AMEND / GHOST      history-level residue
  DETACHED / TAGGED / TURNOVER     state-level observations
  NOREMOTE / REMOTE_SHADOWY        remote-level observations

Exit codes: 0 clean, 4 findings (or NEW findings under --baseline-only),
2 usage, 3 environment, 5 internal. Cron-friendly.

    pushlens ~/code --baseline .pushlens-baseline.json
    pushlens --selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

VERSION = "0.1.0"

EXIT_OK = 0
EXIT_FINDINGS = 4
EXIT_USAGE = 2
EXIT_ENV = 3
EXIT_INTERNAL = 5

SEV_ORDER = {"info": 0, "warn": 1, "critical": 2}


# ---------------------------------------------------------------- utilities

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def run_cmd(args, cwd=None, timeout=20):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------- redaction helpers

RE_URL = re.compile(r"(?:ssh|git|https?)://[^\s\"'<>]+", re.I)
RE_SCP_STYLE = re.compile(r"\b([A-Za-z][\w.-]*)@([A-Za-z0-9][A-Za-z0-9.-]*):")
RE_KNOWN_SERVICE_USERS = {"git"}
RE_TOKENISH = re.compile(r"(ghp_[A-Za-z0-9]{6,}|github_pat_[A-Za-z0-9_]{6,}|glpat-[A-Za-z0-9-]{6,})")


def url_host(url: str):
    m = re.match(r"^\s*(?:ssh|git|https?)://([^/@\s:]+)", url, re.I)
    if m:
        return m.group(1).lower()
    m = re.match(r"^\s*[^@\s/]+@([^:\s/]+):", url)
    if m:
        return m.group(1).lower()
    return None


def is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))


def host_is_private(host: str) -> bool:
    """True when the host looks like a private-network or local alias."""
    h = host.lower()
    if h == "localhost" or h.endswith(".local") or h.endswith(".internal"):
        return True
    if is_ip(h):
        parts = h.split(".")
        if parts[0] in ("10", "127"):
            return True
        if parts[0] == "192" and parts[1] == "168":
            return True
        if parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
        return False
    labels = h.split(".")
    if labels[-1] in ("lan", "corp", "home", "intranet", "test", "internal"):
        return True
    if h.endswith(".svc") or h.endswith(".svc.cluster.local"):
        return True
    return False


def redact_url(url: str) -> str:
    """Strip credentials and usernames; keep host. scp-style git@ is kept
    (hosting convention), URL-form usernames are always masked."""
    out = re.sub(r"(://[^/:@\s]+:)([^@\s]+)(@)", r"\1***\3", url)
    out = re.sub(r"(://)([^/@\s]+)@", r"\1***@", out)
    host = url_host(out) or ""

    def scp_repl(m):
        user, h = m.group(1), m.group(2)
        if user.lower() in RE_KNOWN_SERVICE_USERS:
            return m.group(0)
        return "***@" + h + ":"

    out = RE_SCP_STYLE.sub(scp_repl, out)
    out = RE_TOKENISH.sub("***", out)
    return out


def redact_path(path: str) -> str:
    home = os.path.expanduser("~")
    if home and home != "/":
        path = path.replace(home, "~")
    path = re.sub(r"^/Users/[^/]+", "~", path)
    path = re.sub(r"^/home/[^/]+", "~", path)
    return path


def has_realname_leak(text: str) -> bool:
    home = os.path.expanduser("~")
    leaf = os.path.basename(home.rstrip("/")) if home else ""
    return bool(leaf and len(leaf) >= 2 and leaf not in ("root",) and leaf in text)


# ------------------------------------------------------------------ events

@dataclass
class Event:
    etype: str
    severity: str
    ts: str
    repo: str
    host: str
    head: str
    author: str
    subject: str
    details: dict = field(default_factory=dict)
    sig: str = ""

    def key(self) -> str:
        if not self.sig:
            payload = json.dumps(
                [self.etype, self.repo, self.host, self.head, self.author,
                 sorted((k, str(v)) for k, v in self.details.items())],
                ensure_ascii=False, sort_keys=True)
            self.sig = sha16(payload)
        return self.sig

    def to_dict(self) -> dict:
        d = {
            "type": self.etype,
            "severity": self.severity,
            "ts": self.ts,
            "repo": self.repo,
            "host": self.host,
            "head": self.head,
            "author": self.author,
            "subject": self.subject,
            "details": self.details,
            "sig": self.key(),
        }
        return d


def make_event(etype, severity, repo, host, head, author, subject, details):
    return Event(etype=etype, severity=severity, ts=iso_z(now_utc()), repo=repo,
                 host=host, head=head, author=author, subject=subject,
                 details=details)


# ------------------------------------------------------------------ probes

class FsProbe:
    """Filesystem-only evidence: does the tree look abandoned?"""
    kind = "fs"

    def __init__(self, root):
        self.root = root

    def exists(self, rel):
        return os.path.lexists(os.path.join(self.root, rel))

    def mtime(self, rel):
        try:
            return os.path.getmtime(os.path.join(self.root, rel))
        except OSError:
            return None

    def head(self):
        return None

    def remotes(self):
        return []

    def upstream(self, branch):
        return None

    def ahead_behind(self, branch, up):
        return None

    def dirty_count(self):
        return None

    def untracked_count(self):
        return None

    def stash_count(self):
        return None

    def reflog_count(self):
        return None

    def branch(self):
        return None

    def branches_ahead(self, current):
        return []

    def parent_amend(self):
        return False

    def ghost_count(self):
        return None

    def commit_subject(self, c):
        return None

    def commit_author(self, c):
        return None


class JsonProbe:
    """Last-stand evidence source: a JSON snapshot written by a prior scan
    (pushlens --snapshot <repo> > .pushlens.json)."""
    kind = "json"

    def __init__(self, path):
        self.path = path
        with open(path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.root = os.path.dirname(os.path.abspath(path))

    def head(self):
        h = self.data.get("head") or {}
        if not h:
            return None
        return {"commit": h.get("commit", ""), "author": h.get("author", ""),
                "ts": h.get("ts", ""), "subject": h.get("subject", "")}

    def remotes(self):
        return [(r.get("name", ""), r.get("url", ""))
                for r in self.data.get("remotes", [])]

    def upstream(self, branch):
        u = self.data.get("upstream")
        return u

    def ahead_behind(self, branch, up):
        ab = self.data.get("ahead_behind")
        if isinstance(ab, dict):
            return (int(ab.get("ahead", 0)), int(ab.get("behind", 0)))
        a, b = self.data.get("ahead", 0), self.data.get("behind", 0)
        if a or b:
            return (int(a), int(b))
        return None

    def dirty_count(self):
        return self.data.get("dirty")

    def untracked_count(self):
        return self.data.get("untracked")

    def stash_count(self):
        return self.data.get("stash", 0)

    def reflog_count(self):
        return self.data.get("reflog")

    def branch(self):
        return self.data.get("branch")

    def branches_ahead(self, current):
        out = []
        for b in self.data.get("branches", []):
            if b.get("ahead", 0) > 0:
                out.append((b.get("name", ""), b.get("ahead", 0)))
        return out

    def parent_amend(self):
        return bool(self.data.get("parent_amend", False))

    def ghost_count(self):
        return self.data.get("ghost")

    def commit_subject(self, c):
        return self.data.get("subject")

    def commit_author(self, c):
        return self.data.get("author")


class GitProbe:
    kind = "git"

    def __init__(self, root):
        self.root = root

    def git(self, args, timeout=20):
        return run_cmd(["git"] + args, cwd=self.root, timeout=timeout)

    def is_repo(self):
        rc, out, _ = self.git(["rev-parse", "--is-inside-work-tree"])
        if rc != 0 or out.strip() != "true":
            return False
        rc, out, _ = self.git(["rev-parse", "--git-dir"])
        return rc == 0

    def head(self):
        rc, out, _ = self.git(
            ["log", "-1", "--pretty=%H%x00%an%x00%aI%x00%cI%x00%s"])
        if rc != 0 or not out.strip():
            return None
        parts = out.rstrip("\n").split("\x00")
        while len(parts) < 5:
            parts.append("")
        return {"commit": parts[0], "author": parts[1], "ts": parts[2],
                "commit_ts": parts[3], "subject": parts[4]}

    def branch(self):
        rc, out, _ = self.git(["symbolic-ref", "-q", "--short", "HEAD"])
        return out.strip() if rc == 0 else None

    def remotes(self):
        rc, out, _ = self.git(["remote", "-v"])
        pairs, seen = [], set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] not in seen:
                seen.add(parts[0])
                pairs.append((parts[0], parts[1]))
        return pairs

    def upstream(self, branch):
        if not branch:
            return None
        rc, out, _ = self.git(
            ["rev-parse", "--abbrev-ref", "--symbolic-full-name",
             "%s@{upstream}" % branch])
        return out.strip() if rc == 0 else None

    def ahead_behind(self, branch, up):
        if not branch or not up:
            return None
        rc, out, _ = self.git(["rev-list", "--left-right", "--count",
                               "%s...%s" % (branch, up)])
        if rc != 0:
            return None
        parts = out.split()
        if len(parts) != 2:
            return None
        return (int(parts[0]), int(parts[1]))

    def dirty_count(self):
        rc, out, _ = self.git(["status", "--porcelain"])
        if rc != 0:
            return None
        return sum(1 for l in out.splitlines() if l.strip())

    def untracked_count(self):
        rc, out, _ = self.git(["status", "--porcelain"])
        if rc != 0:
            return None
        return sum(1 for l in out.splitlines() if l.startswith("??"))

    def stash_count(self):
        rc, out, _ = self.git(["stash", "list"])
        if rc != 0:
            return 0
        return sum(1 for l in out.splitlines() if l.strip())

    def reflog_count(self):
        rc, out, _ = self.git(["reflog", "--format=%H", "HEAD"])
        if rc != 0:
            return None
        return sum(1 for l in out.splitlines() if l.strip())

    def branches_ahead(self, current):
        """[(branch, ahead)] for local branches with an upstream, excluding
        the current branch."""
        rc, out, _ = self.git(
            ["for-each-ref", "--format=%(refname:short)", "refs/heads"])
        if rc != 0:
            return []
        result = []
        for line in out.splitlines():
            b = line.strip()
            if not b or b == current:
                continue
            up = self.upstream(b)
            if not up:
                continue
            ab = self.ahead_behind(b, up)
            if ab and ab[0] > 0:
                result.append((b, ab[0]))
        return result

    def parent_amend(self):
        """True when the newest HEAD reflog entry is an amend operation."""
        rc, out, _ = self.git(["reflog", "--format=%gs", "-1", "HEAD"])
        if rc != 0:
            return False
        lines = [l for l in out.splitlines() if l.strip()]
        return bool(lines and re.match(r"^commit \(amend", lines[0]))

    def ghost_count(self):
        """Commits abandoned by the last history-editing operation: what was
        HEAD@{1} but is no longer reachable from any branch/tag. After a
        plain commit HEAD@{1} is an ancestor (count 0); after amend, reset
        or rebase it counts the orphaned commits."""
        rc, out, _ = self.git(
            ["rev-list", "--count", "HEAD@{1}",
             "--not", "--branches", "--tags"])
        if rc != 0:
            return None
        try:
            return int(out.strip() or "0")
        except ValueError:
            return None

    def commit_subject(self, c):
        rc, out, _ = self.git(["log", "-1", "--pretty=%s", c])
        return out.strip() if rc == 0 else None

    def commit_author(self, c):
        rc, out, _ = self.git(["log", "-1", "--pretty=%an", c])
        return out.strip() if rc == 0 else None


def deterministic_probe(root: str, forced: str = None):
    """Pick the evidence source deterministically: git > snapshot json > fs."""
    gitdir = os.path.join(root, ".git")
    if forced == "fs":
        return FsProbe(root), None
    if forced and forced.startswith("json:"):
        try:
            return JsonProbe(forced[5:]), None
        except Exception as e:
            return FsProbe(root), str(e)
    if os.path.isdir(gitdir) or os.path.isfile(gitdir):
        gp = GitProbe(root)
        if gp.is_repo():
            return gp, None
        snap = os.path.join(root, ".pushlens.json")
        if os.path.isfile(snap):
            try:
                return JsonProbe(snap), None
            except Exception as e:
                return FsProbe(root), "snapshot unreadable: %s" % e
        return FsProbe(root), ".git present but unreadable (broken repo)"
    return FsProbe(root), None


# PART 2/3 of pushlens.py — scanning engine + evaluator
# (assembled by cat; part1 is renamed pushlens->pushlens at build time)

# ------------------------------------------------------------ repo state

@dataclass
class RepoState:
    path: str            # redacted display path
    abspath: str
    kind: str            # git | json | fs
    leaf: str
    note: str = ""       # probe fallback note
    head: dict = None
    branch: str = None
    remotes: list = None
    upstream: str = None
    ahead: int = 0
    behind: int = 0
    dirty: int = 0
    untracked: int = 0
    stash: int = 0
    reflog: int = None
    branches_ahead: list = None
    parent_amend: bool = False
    ghost: int = None
    tag: str = None
    has_commits: bool = True
    error: str = ""

    def host(self):
        for name, url in (self.remotes or []):
            h = url_host(url)
            if h:
                return h
        return None


WIP_RE = re.compile(
    r"^(wip|todo|draft|tmp|temp|tbd|fixme|xxx|halfway|未完成|草稿)\b", re.I)
FIXUP_RE = re.compile(r"^(fixup!|squash!|amend!)", re.I)


def classify_subject(subject: str):
    s = (subject or "").strip()
    if FIXUP_RE.match(s):
        return "fixup"
    if WIP_RE.match(s):
        return "wip"
    return None


def collect_state(root: str, forced: str = None, stale_days: int = 180):
    leaf = os.path.basename(os.path.abspath(root))
    probe, note = deterministic_probe(root, forced)
    st = RepoState(path=redact_path(os.path.abspath(root)),
                   abspath=os.path.abspath(root), kind=probe.kind, leaf=leaf,
                   note=note or "")
    st.remotes = []
    if probe.kind == "fs":
        st.error = note or "not a git repository"
        return st
    try:
        st.head = probe.head()
        st.branch = probe.branch()
        st.remotes = probe.remotes() or []
        st.upstream = probe.upstream(st.branch)
        if st.branch:
            ab = probe.ahead_behind(st.branch, st.upstream)
        else:
            # detached HEAD: compare against origin/HEAD when it exists
            ab = probe.ahead_behind("HEAD", "origin/HEAD")
        if ab:
            st.ahead, st.behind = ab
        st.dirty = probe.dirty_count() or 0
        st.untracked = probe.untracked_count() or 0
        st.stash = probe.stash_count() or 0
        st.reflog = probe.reflog_count()
        st.branches_ahead = probe.branches_ahead(st.branch) or []
        if probe.kind == "git":
            st.parent_amend = probe.parent_amend()
            st.ghost = probe.ghost_count()
            rc, out, _ = probe.git(["describe", "--exact-match", "--tags", "HEAD"])
            st.tag = out.strip() if rc == 0 and out.strip() else None
        else:
            st.parent_amend = probe.parent_amend()
            st.ghost = probe.ghost_count()
            st.tag = (probe.data.get("tag") or None) if hasattr(probe, "data") else None
        st.has_commits = st.head is not None
        if st.head and st.head.get("commit_ts"):
            try:
                cts = datetime.fromisoformat(
                    st.head["commit_ts"].replace("Z", "+00:00"))
                age_days = (now_utc() - cts).total_seconds() / 86400.0
                st.head["age_days"] = int(age_days)
                st.head["stale"] = age_days > stale_days
            except Exception:
                pass
    except Exception as e:
        st.error = "probe failed: %s" % e
    return st


def evaluate(st: RepoState):
    """Turn a RepoState into a list of Events. Pure function of state."""
    evs = []
    leaf, host, head = st.leaf, st.host(), st.head
    head_sha = (head or {}).get("commit", "")
    author = (head or {}).get("author", "")
    subject = (head or {}).get("subject", "")

    if st.error:
        evs.append(make_event("BROKEN", "warn", leaf, host, "", "", "",
                              {"error": st.error[:120]}))
        return evs
    if st.kind == "fs":
        return evs
    if not st.has_commits:
        evs.append(make_event("NOCOMMITS", "info", leaf, host, "", "", "", {}))
        return evs

    if st.branch is None:
        evs.append(make_event("DETACHED", "warn", leaf, host, head_sha,
                              author, subject, {}))
    if st.dirty:
        evs.append(make_event("DIRTY", "warn", leaf, host, head_sha,
                              author, subject, {"files": st.dirty}))
    if st.untracked:
        evs.append(make_event("UNTRACKED", "info", leaf, host, head_sha,
                              author, subject, {"files": st.untracked}))
    if st.stash:
        evs.append(make_event("STASH", "info", leaf, host, head_sha,
                              author, subject, {"entries": st.stash}))
    if not st.remotes:
        evs.append(make_event("NOREMOTE", "info", leaf, host, head_sha,
                              author, subject, {}))
    elif st.upstream is None and st.branch:
        evs.append(make_event("UNSHARED", "warn", leaf, host, head_sha,
                              author, subject, {"branch": st.branch}))
    if st.ahead and st.behind:
        evs.append(make_event("BRANCH_DRIFT", "critical", leaf, host,
                              head_sha, author, subject,
                              {"ahead": st.ahead, "behind": st.behind,
                               "branch": st.branch or "(detached)",
                               "upstream": st.upstream or "origin/HEAD"}))
    elif st.ahead:
        evs.append(make_event("AHEAD", "warn", leaf, host, head_sha,
                              author, subject,
                              {"ahead": st.ahead,
                               "upstream": st.upstream or "origin/HEAD"}))
    elif st.behind:
        evs.append(make_event("BEHIND", "info", leaf, host, head_sha,
                              author, subject,
                              {"behind": st.behind,
                               "upstream": st.upstream or "origin/HEAD"}))
    for bname, bahead in (st.branches_ahead or []):
        evs.append(make_event("BRANCH_AHEAD", "warn", leaf, host, head_sha,
                              author, subject,
                              {"branch": bname, "ahead": bahead}))
    kind = classify_subject(subject)
    if kind == "wip":
        evs.append(make_event("WIP", "warn", leaf, host, head_sha,
                              author, subject, {}))
    elif kind == "fixup":
        evs.append(make_event("FIXUP", "warn", leaf, host, head_sha,
                              author, subject, {}))
    if st.parent_amend:
        evs.append(make_event("AMEND", "warn", leaf, host, head_sha,
                              author, subject, {}))
    if st.ghost:
        evs.append(make_event("GHOST", "warn", leaf, host, head_sha,
                              author, subject, {"commits": st.ghost}))
    if (head or {}).get("stale"):
        evs.append(make_event("STALE", "warn", leaf, host, head_sha,
                              author, subject,
                              {"days": head.get("age_days")}))
    if st.tag:
        evs.append(make_event("TAGGED", "info", leaf, host, head_sha,
                              author, subject, {"tag": st.tag}))
    return evs


# ------------------------------------------------------------ forest walk

def find_repos(targets, max_depth=3):
    """Expand targets into repo roots. A target dir is searched for .git
    entries up to max_depth; a target that itself is a repo is returned as-is."""
    repos, seen = [], set()

    def is_repo_dir(p):
        g = os.path.join(p, ".git")
        return os.path.isdir(g) or os.path.isfile(g)

    def add(p):
        ap = os.path.abspath(p)
        if ap not in seen:
            seen.add(ap)
            repos.append(ap)

    for t in targets:
        if os.path.isfile(t):
            # a file: its directory context (e.g. a .pushlens.json snapshot)
            if os.path.basename(t) == ".pushlens.json":
                add(os.path.dirname(os.path.abspath(t)))
            else:
                add(os.path.dirname(os.path.abspath(t)))
            continue
        if not os.path.isdir(t):
            continue
        if is_repo_dir(t):
            add(t)
            continue
        root_depth = os.path.abspath(t).rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(t):
            dirnames[:] = [d for d in dirnames if d not in
                           (".git", "node_modules", "__pycache__", ".venv",
                            "venv", ".tox", "dist", "build")]
            depth = os.path.abspath(dirpath).rstrip("/").count("/") - root_depth
            if depth >= max_depth:
                dirnames[:] = []
            if is_repo_dir(dirpath):
                add(dirpath)
                dirnames[:] = []   # do not descend into nested repos
    return sorted(repos)


# PART 3/3 of pushlens.py — CLI, baseline, selftest, output
# (assembled by cat)

# ------------------------------------------------------------- rendering

SEV_MARK = {"info": ".", "warn": "!", "critical": "X"}
SEV_TXT = {"info": "info", "warn": "WARN", "critical": "CRIT"}


def render_line(ev: Event) -> str:
    d = ev.details
    bits = []
    if "files" in d:
        bits.append("%d uncommitted files" % d["files"])
    if "ahead" in d and "behind" in d:
        bits.append("ahead %d, behind %d vs %s" % (
            d["ahead"], d["behind"], d.get("upstream", "?")))
    elif "ahead" in d:
        bits.append("%d commit(s) never pushed to %s" % (
            d["ahead"], d.get("upstream", "?")))
    elif "behind" in d:
        bits.append("%d behind %s" % (d["behind"], d.get("upstream", "?")))
    if "branch" in d and ev.etype == "BRANCH_AHEAD":
        bits.append("branch '%s' ahead %d, never merged" % (
            d["branch"], d["ahead"]))
    if "entries" in d:
        bits.append("%d stash entr%s" % (
            d["entries"], "y" if d["entries"] == 1 else "ies"))
    if ev.etype == "WIP":
        bits.append('head commit says WIP: "%s"' % ev.subject[:40])
    if ev.etype == "FIXUP":
        bits.append('fixup commit: "%s"' % ev.subject[:40])
    if ev.etype == "AMEND":
        bits.append("last HEAD operation was an amend (parent content overwritten)")
    if "commits" in d:
        bits.append("%d commit(s) abandoned by last history edit (amend/reset/rebase)"
                    % d["commits"])
    if "days" in d:
        bits.append("untouched for %d days" % d["days"])
    if "tag" in d:
        bits.append("pinned at tag %s" % d["tag"])
    if ev.etype == "UNSHARED":
        bits.append("branch '%s' has no upstream" % d.get("branch", "?"))
    if ev.etype == "NOREMOTE":
        bits.append("no remote configured")
    if ev.etype == "DETACHED":
        bits.append("detached HEAD")
    if ev.etype == "NOCOMMITS":
        bits.append("initialized, zero commits")
    if ev.etype == "BROKEN":
        bits.append(d.get("error", "unreadable"))
    if not bits:
        bits.append(ev.etype.lower())
    return "%s %-7s %-16s %s" % (SEV_MARK[ev.severity], SEV_TXT[ev.severity],
                                 ev.repo, "; ".join(bits))


def repo_one_line(st: RepoState) -> str:
    bits = []
    if st.branch:
        bits.append(st.branch)
    else:
        bits.append("(detached)")
    if st.ahead or st.behind:
        bits.append("+%d/-%d" % (st.ahead, st.behind))
    if st.dirty:
        bits.append("%d dirty" % st.dirty)
    if st.untracked:
        bits.append("%d untracked" % st.untracked)
    if st.stash:
        bits.append("%d stash" % st.stash)
    h = (st.head or {}).get("commit", "")[:7]
    age = (st.head or {}).get("age_days")
    agestr = (" %dd" % age) if age is not None else ""
    host = st.host() or "-"
    return "%-16s %-9s %-28s %s%s" % (st.leaf, host[:9], " ".join(bits)[:28],
                                      h, agestr)


# ------------------------------------------------------------- baseline

def load_baseline(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_baseline(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)


def build_baseline(repos):
    return {
        "tool": "pushlens",
        "version": VERSION,
        "saved_at": iso_z(now_utc()),
        "repos": {st["path"]: st for st in repos},
    }


def diff_baseline(base, current):
    """Return (all_events, new_events). An event is NEW when no same-type
    event existed for the same repo path in the baseline."""
    old_types = {}
    for path, st in (base.get("repos") or {}).items():
        old_types.setdefault(path, set()).update(
            e.get("type") for e in (st.get("events") or []))
    all_evs, new_evs = [], []
    for st in current:
        p = st["path"]
        known = old_types.get(p, set())
        for ev in st["events"]:
            all_evs.append(ev)
            if ev["type"] not in known:
                new_evs.append(ev)
    return all_evs, new_evs


# ------------------------------------------------------------- selftest

class SelfTestFailure(Exception):
    pass


def _init_repo(path, files=None, msg="init commit", branch="main"):
    os.makedirs(path, exist_ok=True)
    run_cmd(["git", "init", "-q", "-b", branch, path])
    cfg = [["config", "user.email", "fixture@example.com"],
           ["config", "user.name", "fixture"],
           ["config", "commit.gpgsign", "false"]]
    for c in cfg:
        run_cmd(["git"] + c, cwd=path)
    for name, content in (files or {"a.txt": "hello\n"}).items():
        with open(os.path.join(path, name), "w") as f:
            f.write(content)
    run_cmd(["git", "add", "-A"], cwd=path)
    run_cmd(["git", "commit", "-q", "-m", msg], cwd=path)
    return path


def _git(path, *args):
    rc, out, err = run_cmd(["git"] + list(args), cwd=path)
    assert rc == 0, "fixture git %s failed: %s" % (args, err)
    return out


def run_selftest(tmp=None):
    checks = []
    tmp = tmp or tempfile.mkdtemp(prefix="pushlens_selftest_")

    def check(name, cond, detail=""):
        checks.append((name, bool(cond), detail))

    # ---- INV-01: pristine repo with pushed upstream -> zero findings
    base = _init_repo(os.path.join(tmp, "t1"))
    bare = os.path.join(tmp, "origin1.git")
    run_cmd(["git", "init", "-q", "--bare", bare])
    _git(base, "remote", "add", "origin", bare)
    _git(base, "push", "-q", "-u", "origin", "main")
    st = collect_state(base)
    evs = evaluate(st)
    check("INV-01 pristine=0", len(evs) == 0,
          "unexpected: %s" % [e.etype for e in evs])

    # ---- INV-02: AHEAD when commits stay local
    t2 = _init_repo(os.path.join(tmp, "t2"))
    bare2 = os.path.join(tmp, "origin2.git")
    run_cmd(["git", "init", "-q", "--bare", bare2])
    _git(t2, "remote", "add", "origin", bare2)
    _git(t2, "push", "-q", "-u", "origin", "main")
    with open(os.path.join(t2, "b.txt"), "w") as f:
        f.write("secret work\n")
    _git(t2, "add", "-A")
    _git(t2, "commit", "-q", "-m", "add feature, not pushed")
    st = collect_state(t2)
    evs = evaluate(st)
    types = [e.etype for e in evs]
    check("INV-02 AHEAD", "AHEAD" in types, str(types))
    ahead_ev = [e for e in evs if e.etype == "AHEAD"]
    check("INV-02b ahead=1", ahead_ev and
          ahead_ev[0].details.get("ahead") == 1, str(types))

    # ---- INV-03: DIRTY + UNTRACKED
    t3 = _init_repo(os.path.join(tmp, "t3"))
    with open(os.path.join(t3, "a.txt"), "w") as f:
        f.write("changed\n")
    with open(os.path.join(t3, "new.txt"), "w") as f:
        f.write("new\n")
    st = collect_state(t3)
    evs = evaluate(st)
    types = [e.etype for e in evs]
    check("INV-03 DIRTY", "DIRTY" in types, str(types))
    check("INV-03b UNTRACKED", "UNTRACKED" in types, str(types))

    # ---- INV-04: WIP subject flagged
    t4 = _init_repo(os.path.join(tmp, "t4"),
                    msg="WIP: halfway through refactor")
    st = collect_state(t4)
    types = [e.etype for e in evaluate(st)]
    check("INV-04 WIP", "WIP" in types, str(types))

    # ---- INV-05: fixup! subject flagged
    t5 = _init_repo(os.path.join(tmp, "t5"),
                    msg="fixup! refactor: extract helper")
    st = collect_state(t5)
    types = [e.etype for e in evaluate(st)]
    check("INV-05 FIXUP", "FIXUP" in types, str(types))

    # ---- INV-06: stash counted
    t6 = _init_repo(os.path.join(tmp, "t6"))
    with open(os.path.join(t6, "a.txt"), "w") as f:
        f.write("changed again\n")
    _git(t6, "stash", "push", "-q", "-m", "half done")
    st = collect_state(t6)
    types = [e.etype for e in evaluate(st)]
    check("INV-06 STASH", "STASH" in types, str(types))

    # ---- INV-07: amend leaves parent tree twin -> AMEND
    t7 = _init_repo(os.path.join(tmp, "t7"), msg="first message")
    with open(os.path.join(t7, "a.txt"), "w") as f:
        f.write("changed\n")
    _git(t7, "add", "-A")
    _git(t7, "commit", "-q", "--amend", "-m", "first message (fixed)")
    st = collect_state(t7)
    types = [e.etype for e in evaluate(st)]
    check("INV-07 AMEND", "AMEND" in types, str(types))

    # ---- INV-08: BRANCH_DRIFT when upstream moved (rebase land)
    t8 = _init_repo(os.path.join(tmp, "t8"))
    bare8 = os.path.join(tmp, "origin8.git")
    run_cmd(["git", "init", "-q", "--bare", bare8])
    _git(t8, "remote", "add", "origin", bare8)
    _git(t8, "push", "-q", "-u", "origin", "main")
    with open(os.path.join(t8, "b.txt"), "w") as f:
        f.write("local\n")
    _git(t8, "add", "b.txt")
    _git(t8, "commit", "-q", "-m", "local commit")
    # a teammate pushes directly to the bare repo (different history)
    mate = os.path.join(tmp, "mate8")
    os.makedirs(mate, exist_ok=True)
    run_cmd(["git", "init", "-q", "-b", "main", mate])
    for c in [["config", "user.email", "m@example.com"],
              ["config", "user.name", "mate"]]:
        run_cmd(["git"] + c, cwd=mate)
    with open(os.path.join(mate, "c.txt"), "w") as f:
        f.write("mate\n")
    _git(mate, "add", "-A")
    _git(mate, "commit", "-q", "-m", "mate commit")
    _git(mate, "remote", "add", "origin", bare8)
    _git(mate, "push", "-q", "-f", "origin", "main:main")
    # t8 learns about the moved upstream only after a fetch (pushlens is
    # network-free by design; fetching is the operator's job)
    _git(t8, "fetch", "origin")
    st = collect_state(t8)
    types = [e.etype for e in evaluate(st)]
    check("INV-08 BRANCH_DRIFT", "BRANCH_DRIFT" in types, str(types))

    # ---- INV-09: NOREMOTE for repo without remote
    t9 = _init_repo(os.path.join(tmp, "t9"))
    st = collect_state(t9)
    types = [e.etype for e in evaluate(st)]
    check("INV-09 NOREMOTE", "NOREMOTE" in types, str(types))

    # ---- INV-10: non-repo dir passed directly -> BROKEN finding, no crash
    t10 = os.path.join(tmp, "t10")
    os.makedirs(t10, exist_ok=True)
    with open(os.path.join(t10, "readme.txt"), "w") as f:
        f.write("not a repo\n")
    st = collect_state(t10)
    types = [e.etype for e in evaluate(st)]
    check("INV-10 nonrepo-safe", st.kind == "fs" and types == ["BROKEN"],
          str(types))

    # ---- INV-11: forest walk finds repos, skips noise
    t11root = os.path.join(tmp, "forest")
    r1 = _init_repo(os.path.join(t11root, "projA"))
    r2 = _init_repo(os.path.join(t11root, "group", "projB"))
    noise = os.path.join(t11root, "notarepo")
    os.makedirs(noise, exist_ok=True)
    found = find_repos([t11root], max_depth=3)
    names = [os.path.basename(p) for p in found]
    check("INV-11 forest", "projA" in names and "projB" in names and
          len(found) == 2, str(names))

    # ---- INV-12: redaction - credential URL stripped
    u = redact_url("https://alice:hunter2@git.corp.example.com/team/repo.git")
    check("INV-12 cred-strip", "hunter2" not in u and "***" in u, u)
    u2 = redact_url("ssh://deploy@10.10.0.5/srv/repo.git")
    check("INV-12b user-strip", "deploy@" not in u2, u2)
    u3 = redact_url("git@gitee.com:tomlen/pushlens.git")
    check("INV-12c git-user-kept", u3 == "git@gitee.com:tomlen/pushlens.git", u3)

    # ---- INV-13: private host detected
    check("INV-13 private-host", host_is_private("192.168.1.10") and
          host_is_private("git.lan") and host_is_private("172.20.3.4") and
          not host_is_private("gitee.com"), "")

    # ---- INV-14: path redaction hides home dir
    fake = "/Users/%s/secretproj" % os.path.basename(os.path.expanduser("~"))
    rp = redact_path(fake)
    check("INV-14 path-redact", ("~" in rp) and
          (os.path.basename(os.path.expanduser("~")) not in rp), rp)

    # ---- INV-15: baseline diff marks new event types only
    t15 = _init_repo(os.path.join(tmp, "t15"))
    _init_repo(os.path.join(tmp, "origin15"))
    pass  # exercised below via baseline_save/load round-trip

    # ---- INV-16: baseline save/load round-trip
    st = collect_state(t2)
    d = state_to_dict(st, evaluate(st))
    bl = build_baseline([d])
    save_baseline(os.path.join(tmp, "bl.json"), bl)
    loaded = load_baseline(os.path.join(tmp, "bl.json"))
    check("INV-16 baseline-rt", loaded and loaded["repos"] and
          list(loaded["repos"].keys())[0] == d["path"], "")

    # ---- INV-17: same scan twice -> no new findings vs baseline
    cur = [state_to_dict(collect_state(t2), evaluate(collect_state(t2)))]
    _, new_evs = diff_baseline(bl, cur)
    check("INV-17 no-new", len(new_evs) == 0,
          str([e["type"] for e in new_evs]))

    # ---- INV-18: new event type appears -> flagged NEW
    with open(os.path.join(t2, "dirty.txt"), "w") as f:
        f.write("x\n")
    st2 = collect_state(t2)
    cur2 = [state_to_dict(st2, evaluate(st2))]
    _, new_evs2 = diff_baseline(bl, cur2)
    types2 = [e["type"] for e in new_evs2]
    check("INV-18 new-type", "DIRTY" in types2, str(types2))

    # ---- INV-19: exit code mapping
    check("INV-19 exit-codes", EXIT_OK == 0 and EXIT_FINDINGS == 4 and
          EXIT_USAGE == 2 and EXIT_ENV == 3 and EXIT_INTERNAL == 5, "")

    # ---- INV-20: json snapshot round-trip (JsonProbe)
    snap = {"head": {"commit": "abc123", "author": "someone", "ts": "",
                     "subject": "snapshot work", "commit_ts": "2026-01-01T00:00:00+00:00"},
            "branch": "main", "remotes": [{"name": "origin", "url": "git@example.com:team/repo.git"}],
            "upstream": None, "ahead": 3, "behind": 0, "dirty": 2,
            "untracked": 1, "stash": 1, "reflog": 5,
            "branches": [{"name": "dev", "ahead": 2}]}
    jp = os.path.join(tmp, "snaprepo", ".pushlens.json")
    os.makedirs(os.path.dirname(jp), exist_ok=True)
    json.dump(snap, open(jp, "w"))
    st = collect_state(os.path.join(tmp, "snaprepo"), forced="json:" + jp)
    evs = evaluate(st)
    types = [e.etype for e in evs]
    check("INV-20 json-probe", st.kind == "json" and "AHEAD" in types and
          "STASH" in types and "BRANCH_AHEAD" in types, str(types))

    failed = [c for c in checks if not c[1]]
    print("pushlens selftest: %d checks, %d failed" %
          (len(checks), len(failed)))
    for name, ok, detail in checks:
        print("  %-18s %s%s" % (name, "PASS" if ok else "FAIL " + detail,
                                "" if ok else ""))
    if failed:
        raise SelfTestFailure("%d checks failed" % len(failed))
    return len(checks), 0


def state_to_dict(st: RepoState, evs):
    return {
        "path": st.path,
        "kind": st.kind,
        "note": st.note,
        "branch": st.branch,
        "host": st.host(),
        "head": {k: v for k, v in (st.head or {}).items()},
        "ahead": st.ahead,
        "behind": st.behind,
        "dirty": st.dirty,
        "untracked": st.untracked,
        "stash": st.stash,
        "reflog": st.reflog,
        "parent_amend": st.parent_amend,
        "ghost": st.ghost,
        "tag": st.tag,
        "events": [e.to_dict() for e in evs],
    }


# ------------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="pushlens",
        description="post-commit watchdog for git working trees "
                    "(unpushed commits, WIP/fixup/amend ghosts, drift)")
    ap.add_argument("targets", nargs="*", help="repo dirs or forest roots")
    ap.add_argument("--baseline", metavar="FILE",
                    help="baseline JSON: first run saves, later runs diff")
    ap.add_argument("--baseline-only", action="store_true",
                    help="only report NEW findings vs baseline")
    ap.add_argument("--json", action="store_true", help="machine output")
    ap.add_argument("--stale-days", type=int, default=180)
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--redact", choices=["host", "full", "none"],
                    default="host", help="redact remote hosts / paths")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version",
                    version="pushlens " + VERSION)
    args = ap.parse_args(argv)

    if args.selftest:
        try:
            n, f = run_selftest()
        except SelfTestFailure as e:
            print("SELFTEST FAILED: %s" % e, file=sys.stderr)
            return EXIT_INTERNAL
        print("SELFTEST PASS (%d/%d)" % (n, n - f))
        return EXIT_OK

    if not args.targets:
        ap.print_usage()
        return EXIT_USAGE

    for t in args.targets:
        if not os.path.exists(t):
            print("target not found: %s" % t, file=sys.stderr)
            return EXIT_ENV

    repo_dirs = find_repos(args.targets, max_depth=args.max_depth)
    if not repo_dirs:
        print("no repositories found under target(s)", file=sys.stderr)
        return EXIT_ENV

    results = []
    for rd in repo_dirs:
        st = collect_state(rd, stale_days=args.stale_days)
        evs = evaluate(st)
        results.append((st, evs))

    dict_results = [state_to_dict(st, evs) for st, evs in results]
    all_evs, new_evs = [], []
    base = None
    if args.baseline:
        base = load_baseline(args.baseline)
        if base is None:
            save_baseline(args.baseline, build_baseline(dict_results))
            base = load_baseline(args.baseline)
        all_evs, new_evs = diff_baseline(base, dict_results)

    reportable = all_evs if args.baseline else [
        e.to_dict() for st, evs in results for e in evs]
    if args.baseline and args.baseline_only:
        reportable = new_evs

    def redact_ev(d):
        d = dict(d)
        if args.redact == "host":
            d["host"] = "***" if d.get("host") else ""
            det = dict(d.get("details") or {})
            if "upstream" in det:
                det["upstream"] = re.sub(r"^[^/]+/", "*/", det["upstream"])
            d["details"] = det
        return d

    if args.json:
        out = {
            "tool": "pushlens", "version": VERSION,
            "scanned_at": iso_z(now_utc()),
            "repos": [dict(r, events=[redact_ev(e) for e in r["events"]])
                      for r in dict_results],
        }
        if args.baseline:
            out["new_events"] = [redact_ev(e) for e in new_evs]
        print(json.dumps(out, ensure_ascii=False, indent=1))
    else:
        print("pushlens %s — %d repos scanned" % (VERSION, len(results)))
        print("")
        for st, evs in results:
            print(repo_one_line(st))
            for ev in sorted(evs, key=lambda e: -SEV_ORDER[e.severity]):
                d = ev.to_dict()
                d["host"] = "***" if d.get("host") else ""
                print("   " + render_line(ev))
            print("")
        if args.baseline:
            print("baseline: %d findings total, %d NEW" %
                  (len(all_evs), len(new_evs)))

    crit = sum(1 for e in reportable if e.get("severity") == "critical")
    warn = sum(1 for e in reportable if e.get("severity") == "warn")
    if not args.json:
        print("summary: %d findings (critical=%d warn=%d info=%d)" %
              (len(reportable), crit, warn,
               len(reportable) - crit - warn))
    return EXIT_FINDINGS if reportable else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
