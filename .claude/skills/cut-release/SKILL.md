---
name: cut-release
description: Cuts a release of the iseo-argo-ble HACS integration — verifies the clone is current, bumps both version files, tags, publishes the GitHub release, and confirms the PyPI publish actually succeeded. Use when asked to cut, ship, or publish a release, or to bump the version.
---

# Cut a release of iseo-argo-ble

Repo: `FezVrasta/iseo-argo-ble`, cloned at `~/Developer/hass/iseo_ble` (the
directory is **not** named after the repo). Ships to two channels: HACS reads
`manifest.json`, PyPI reads `pyproject.toml`.

## Gotchas & non-obvious constraints

- **Two version files, and they silently drift.** `pyproject.toml` (`version =`,
  near line 7) and `custom_components/iseo_argo_ble/manifest.json` (`"version"`).
  Only the manifest was bumped for v0.6.6 through v0.7.5, so *every* PyPI publish
  in that range failed on an already-published version while HACS users saw the
  new release. A green HACS release proves nothing about PyPI. Bump both, always.
- **The publish is only verified by watching the workflow.** `gh release create`
  triggers `.github/workflows/publish-pypi.yml` (`on: release: published`). A
  failure there is invisible unless you look. Never report a release as done
  before that run goes green.
- **This clone goes stale for months.** It has been found 18 commits behind
  `origin/master` while holding five-month-old uncommitted feature work. Fetch
  and compare before touching anything, or you will build a release on dead code
  and clobber real work.
- **`.env` is untracked and NOT gitignored.** Never `git add -A` without
  excluding it — `git add -A -- . ':!.env'`.
- **No git credential helper is configured.** Pushes fail with "could not read
  Password". Push with:
  `git -c credential.helper='!gh auth git-credential' push origin <ref>`
- **`validate.sh` runs mypy, which currently fails** on a Python 3.14 syntax
  error inside the installed `homeassistant` package — not on this repo's code.
  Don't chase it; run `ruff check` and the tests directly.

## Workflow

### Phase A — make sure the ground is solid
- [ ] `git fetch --all --tags`, then `git status -sb` and
      `git rev-list --left-right --count origin/master...HEAD`. If behind,
      fast-forward. If local commits or uncommitted changes exist, stop and ask
      what they are — never fold unrelated work into a release.
- [ ] Confirm what the last release actually was:
      `gh release list --repo FezVrasta/iseo-argo-ble --limit 5`. Local tags can
      lag the remote badly.

### Phase B — the change itself
- [ ] Commit the fix and its tests separately from the version bump, so the
      release commit stays a pure bump. Message style: imperative subject, body
      explaining the mechanism, then the `Co-Authored-By:` / `Claude-Session:`
      trailers used elsewhere in the history.
- [ ] **Prove new regression tests are not vacuous.** Check the previous tag's
      version of the file in, run the suite, confirm the new tests fail, restore:
      ```
      cp <file> /tmp/keep.py
      git checkout v<previous> -- <file>
      uv run --no-sync pytest -q tests      # new tests must FAIL here
      cp /tmp/keep.py <file>
      ```
- [ ] Green gates: `uv run --no-sync pytest -q tests`, `uvx ruff check .`,
      `uvx ruff format --check .`.

### Phase C — release
- [ ] Bump **both** version files to the same `X.Y.Z`.
- [ ] Commit as `Release X.Y.Z: <one-line summary>`.
- [ ] Push master, then create and push the tag `vX.Y.Z` on that commit.
- [ ] `gh release create vX.Y.Z --title "vX.Y.Z" --notes "..."` — notes describe
      the user-visible symptom and the mechanism, and link the issue and the
      `compare/vPREV...vX.Y.Z` changelog.

### Phase D — confirm it landed
- [ ] Watch the publish, in the background rather than by polling in-band:
      ```
      until [ "$(gh run list --repo FezVrasta/iseo-argo-ble \
        --workflow publish-pypi.yml --limit 1 --json status --jq '.[0].status')" = "completed" ]
      do sleep 15; done
      gh run list --repo FezVrasta/iseo-argo-ble --workflow publish-pypi.yml --limit 1
      ```
- [ ] Confirm the artifact exists:
      `curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/iseo-argo-ble/X.Y.Z/json`
      → 200. The `/pypi/iseo-argo-ble/json` "latest" field caches and lags; don't
      trust it as the check.
- [ ] If the release fixes a reported issue, comment on it asking the reporter to
      update through HACS and retest, and say exactly which debug lines you need
      if it still fails.

## When a fix is speculative

Bugs here are often diagnosed from a traceback without access to the user's
hardware. Ship the diagnostic alongside the fix — a debug log that reveals the
device's actual state is worth more than another guess, and say plainly in the
issue comment which parts are inference.
