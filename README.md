# pushlens

**A post-commit watchdog for git working trees.** One file, zero dependencies,
read-only on your repos.

Committing is not the same as being safe. Work hides in places `git status`
never shows you:

- commits that were **never pushed** to the remote
- a branch that **drifted** from its upstream (both ahead AND behind)
- head commits that literally say **WIP**, **fixup!**, **draft**
- commits **overwritten by amend** — the old work is still in reflog, but no
  branch reaches it anymore
- **stashes** parked weeks ago
- local branches with **no upstream** at all
- whole repos with **no remote** configured
- repos that are **broken on disk** (`.git` present, unusable)

`pushlens` walks a forest of repositories (or a single repo) and prints one
readable line per finding. Save a baseline on day one; every later run tells
you exactly what changed since.

```
$ pushlens ~/code
pushlens 0.1.0 — 81 repos scanned

archsnap          main                     a1b2c3d 12d
   ! WARN    archsnap; 6 uncommitted files; last HEAD operation was an
             amend (parent content overwritten); 1 commit(s) abandoned by
             last history edit (amend/reset/rebase)
   . info    6 untracked files

creator-studio    main     +2/-0           9f8e7d6 3d
   ! WARN    2 commit(s) never pushed to origin/main
```

## Why not `git status`?

`git status` answers "is my *working tree* clean?" — a file-level question.
`pushlens` answers "is my *work* safe?" — a commit-level question. Those are
different questions: a tree can be perfectly clean while two days of work
sit in local commits that no remote has ever seen, or in an amend graveyard
that only reflog remembers.

## Findings (16 types, 3 severities)

| Type | Severity | Meaning |
|---|---|---|
| `BRANCH_DRIFT` | **critical** | branch diverged from upstream (ahead AND behind) — push will be rejected, history forked |
| `AHEAD` | warn | N local commits never pushed |
| `BEHIND` | info | upstream moved ahead |
| `DIRTY` | warn | uncommitted modified files |
| `UNTRACKED` | info | untracked files |
| `STASH` | info | entries in the stash |
| `UNSHARED` | warn | current branch has no upstream — never pushed anywhere |
| `BRANCH_AHEAD` | warn | other local branch ahead of its upstream |
| `WIP` | warn | head subject starts with wip/todo/draft/tmp/fixme/草稿… |
| `FIXUP` | warn | head subject is a fixup!/squash!/amend! commit |
| `AMEND` | warn | last HEAD operation was an amend |
| `GHOST` | warn | N commits abandoned by the last history edit (amend/reset/rebase) — reachable only via reflog |
| `STALE` | warn | untouched for more than N days (default 180) |
| `DETACHED` | warn | detached HEAD (compares against origin/HEAD) |
| `NOREMOTE` | info | repo has no remote configured |
| `BROKEN` | warn | `.git` exists but the repo is unreadable |
| `TAGGED` | info | HEAD pinned at a tag |
| `NOCOMMITS` | info | initialized but zero commits |

Exit codes: `0` clean · `4` findings (or NEW findings under `--baseline-only`)
· `2` usage · `3` environment (bad target) · `5` internal. Cron-friendly:
alert on non-zero, ignore zero.

## Install

No dependencies beyond Python 3.8+ and `git`.

```bash
curl -LO https://gitee.com/tomlen/pushlens/raw/main/pushlens.py
chmod +x pushlens.py
./pushlens.py --selftest        # 23 invariant checks, expect ALL PASS
```

Or clone:

```bash
git clone https://gitee.com/tomlen/pushlens.git
cd pushlens && python3 pushlens.py --selftest
```

## Usage

```bash
# scan one repo
python3 pushlens.py ~/code/myproject

# scan a whole forest (finds every repo up to depth 3)
python3 pushlens.py ~/code

# day-one: save a baseline, then only report NEW findings afterwards
python3 pushlens.py ~/code --baseline ~/pushlens-dx.json
python3 pushlens.py ~/code --baseline ~/pushlens-dx.json --baseline-only

# machine output for cron / pipelines
python3 pushlens.py ~/code --json --baseline-only

# hide remote hosts in output (default: host), or everything (full)
python3 pushlens.py ~/code --redact full

# report only repos untouched for a year+
python3 pushlens.py ~/code --stale-days 365
```

### The baseline workflow

```bash
# Monday: accept today's state as normal
python3 pushlens.py ~/code --baseline ~/code/.pushlens-baseline.json
# ... baseline saved (81 repos)

# Friday: what changed this week?
python3 pushlens.py ~/code --baseline ~/code/.pushlens-baseline.json
# baseline: 128 findings total, 7 NEW
```

An event is **NEW** when its *type* did not exist for that repo in the
baseline — new dirt on a repo that was already dirty is not news; a repo
that was clean and now has unpushed commits is.

### Cron (macOS launchd / Linux crontab)

```cron
# weekday 18:00 — flag anything new; exit 4 means "worth looking at"
0 18 * * 1-5  /usr/bin/python3 /opt/pushlens.py ~/code --baseline /opt/bl.json --baseline-only --redact full
```

`--json` gives you per-repo state plus a `new_events` array, so the same run
can feed both a human report and a bot.

## Design boundaries (read this before trusting it)

1. **Read-only.** pushlens runs `git log/rev-list/status/stash list/reflog`
   and friends. It never commits, pushes, fetches, resets, or writes inside
   your repos. The only files it writes are the baseline JSON you point it at.
2. **Network-free.** All comparisons are against the last-fetched state of
   your remote-tracking refs. Run `git fetch --all` first if you want drift
   detection to see yesterday's server-side changes — fetching is an
   operator decision, not a scanner's.
3. **Redaction by default.** Remote hosts are masked in findings (`host`,
   `full`, `none`); credential-bearing URLs are stripped wherever a URL is
   echoed; your home directory is collapsed to `~`. Output is safe to paste
   into issues and group chats.
4. **GHOST counts are per-operation.** `GHOST` reports commits orphaned by
   the *latest* history edit (`HEAD@{1}` unreachable from any branch/tag),
   not a survey of your whole reflog. It answers "did my last amend/reset/
   rebase strand anything?" — run it right after risky history edits.
5. **WIP/FIXUP detection is subject-prefix based.** `wip:`, `fixup!`,
   `squash!`, `draft`, `tmp`, `草稿` and friends. It will not catch a commit
   titled `stuff` — no tool can.

## Self-test

`--selftest` builds throwaway fixture repos in a temp dir (bare remotes,
force-pushed teammates, amended-over commits, stashes, a broken repo) and
checks 23 invariants:

- pristine repo with pushed upstream → zero findings
- every finding type fires on its exact fixture (AHEAD/DIRTY/WIP/FIXUP/
  STASH/AMEND/BRANCH_DRIFT/NOREMOTE/UNTRACKED/UNSHARED/GHOST…)
- baseline round-trip; second scan → 0 NEW; injected DIRTY → flagged NEW
- credential stripping (`https://user:pass@`, `ssh://user@`, tokens) and
  path redaction; `git@host:` convention preserved
- non-repo directories are reported `BROKEN`, never crash the scan
- detached HEAD compares against `origin/HEAD` instead of silently skipping

## Bugs the self-test caught during development

Kept here as evidence the fixture suite does real work:

1. `ahead/behind` was probed with `git rev-parse --left-right --count` —
   `--left-right` belongs to `rev-list`; every AHEAD count was silently 0.
2. `GHOST` counted commits on HEAD unreachable from branches — after an
   amend the orphan is *not* reachable from HEAD, so the count was always 0.
   Fixed: count from `HEAD@{1}`.
3. `AMEND` guessed by comparing tree hashes of the last two commits —
   replaced with the reflog subject (`commit (amend …)`), which git
   maintains for us.
4. `collect_state` skipped ahead/behind entirely when HEAD was detached —
   now falls back to `origin/HEAD`.
5. `redact_url` masked scp-style users but not `ssh://user@host` URL-form
   users — both are masked now; `git@host:` (hosting convention, not a
   secret) is preserved.
6. The JSON-snapshot probe (`.pushlens.json`, for scanning *non-git* backup
   copies of repos) ignored flat `ahead`/`behind` keys — accepts both flat
   and nested forms now.
7. Two fixture bugs (`git commit -am` does not stage *new* files; a
   non-fast-forward fixture push needed an explicit fetch to become visible
   drift).

## Comparison with neighbors

| Tool | Question it answers |
|---|---|
| `git status` | is my working tree clean? (files) |
| `gitwatch` (bash) | auto-commit my files as they change |
| `etckeeper` | version-control /etc |
| `git-fresh` / cleanup scripts | tidy branches automatically |
| **pushlens** | **is my committed work actually safe, and what changed since I last looked?** |

pushlens never writes to your repos, so it is safe to point at production
checkouts, teammates' machines (with their consent), and backup copies.

## Scanning non-git backup copies

A plain copy of a repo (rsync/tar) keeps its files but loses nothing
pushlens needs *except* a working `.git`. For those, drop a snapshot next
to the copy:

```bash
cd myproject && git log -1 --pretty='{"head":{"commit":"%H","author":"%an","ts":"%aI","commit_ts":"%cI","subject":"%s"},"branch":"main"}' > /tmp/snap.json
# merge with: ahead/behind, dirty, untracked, stash counts (any JSON tool)
```

and point pushlens at the copy's `.pushlens.json`. It scores the snapshot
with the same evaluator — useful for auditors who receive *archives*, not
live checkouts.

## License

MIT
