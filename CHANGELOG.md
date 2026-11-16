# Changelog — pushlens

## 0.1.0 — 2026-11-16

First release.

- 18 finding types across 3 severities (working-tree / commit / history /
  remote / state layers), one readable line each
- Forest walker: point it at a root, it finds every repo up to depth N
  (skips node_modules/.git internals, does not descend into nested repos)
- Baseline mode: `--baseline` (save) → later runs report total vs NEW;
  `--baseline-only` + exit 4 for cron alerting
- Deterministic probes: git working repo > `.pushlens.json` snapshot >
  filesystem fallback (broken `.git` reported as BROKEN, never crashes)
- Redaction: remote hosts masked by default, credential URLs stripped
  (`https://user:pass@`, `ssh://user@`, tokens), home paths collapsed to `~`
- JSON output with per-repo state + `new_events` for pipelines
- `--selftest`: 23 invariant checks on throwaway fixture forests
  (bare remotes, force-pushed teammates, amended-over commits, stashes,
  broken repos)
- 7 real bugs caught by the self-test during development (see README)
