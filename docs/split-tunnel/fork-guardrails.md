# Fork guardrails

Operational guardrails for `alexsherkhan/netbird-split`. This document records
policy only; it does not change workflows or repository settings.

## Remotes

| Remote | URL | Use |
| --- | --- | --- |
| `origin` | `git@github.com:alexsherkhan/netbird-split.git` | All fork pushes and PR branches |
| `upstream` | `https://github.com/netbirdio/netbird.git` | Read-only source of upstream changes |

Fetch from both. Push only to `origin`. Never push branches or tags to
`upstream`, and never push directly to `origin/main` or a release branch.

## Upstream sync flow

1. `git fetch origin --prune --tags`
2. `git fetch upstream --prune --tags`
3. Confirm the upstream default branch with `git remote show upstream`.
4. Create a sync branch from the fork integration branch:
   `git switch -c sync/upstream-YYYYMMDD origin/develop`.
5. Merge the upstream default branch into it, for example
   `git merge upstream/main`. Resolve conflicts on the sync branch.
6. Run the host-safe checks (`make test-unit`, `make lint` on a host with the GUI
   prerequisites, and the Linux client build).
7. Push the sync branch to `origin` and open a PR into `develop`.
8. Merge only after review and green checks.

Do not merge upstream directly into `main` or a release branch. Upstream code
and fork changes mix without review there, and a broken upstream commit would
reach the release line first.

Keep sync PRs separate from feature PRs. Do not force-push shared branches; add
commits for review fixes.

## Branch model

| Branch | Purpose | Rules |
| --- | --- | --- |
| `develop` | Integration branch for fork work and upstream syncs | Default PR target; always buildable and tested; no direct pushes |
| `main` | Release-stable branch | Only reviewed merges from `develop`; protected; no direct pushes |
| `release-<version>` | Stabilization for one release | Cut from `main` when a release is agreed; only release fixes; protected |
| `feature/<milestone>-<name>` | Milestone work | Branch from `develop`; PR back into `develop` |
| `sync/upstream-<date>` | Upstream merge review | Branch from `develop`; PR back into `develop` |

Release fixes land on the release branch and are cherry-picked or merged back
into `develop` so the next release keeps them. Tag a release only from a reviewed
release branch commit, and only after the release credential review below.

## Release and publishing credentials

Upstream release automation is not safe to leave armed in a fork without review.
Relevant workflows include `release.yml` (`v*` tags, `main`, and `release-*`
branches), `sync-main.yml` (`main`), `sync-tag.yml` (`v*` tags),
`update-docs.yml` (`v*` tags), `discord-release.yml` (published releases), and
`redhat-certify.yml` (workflow call or manual dispatch).

- Disable publishing workflows in the fork's repository settings (Actions
  workflow disable) instead of editing workflow files. Workflow changes are out
  of scope for this milestone.
- Upstream workflows reference secrets including `NC_GITHUB_TOKEN`,
  `SIGN_GITHUB_TOKEN`, `UPSTREAM_REPO`, `GITHUB_TOKEN`, `DOCKER_USER`,
  `DOCKER_TOKEN`, `CI_DOCKER_PUSH_GITHUB_TOKEN`, `HOMEBREW_TAP_GITHUB_TOKEN`,
  `PKG_UPLOAD_SECRET`, `GPG_RPM_PRIVATE_KEY`, `GPG_RPM_PASSPHRASE`, and
  `PYXIS_API_TOKEN`. These are upstream credentials. Do not copy them into the
  fork.
- If the fork ever publishes, use dedicated least-privilege credentials scoped to
  an environment with required reviewers. Never reuse upstream tokens.
- Never put secrets in a PR, commit, branch, issue, log, or build artifact. Do
  not print secrets or add debugging that dumps environment variables.
- Do not push a `v*` tag until the release policy is agreed. A tag push can
  trigger publish, sync, docs, and notification workflows.
- Never use `pull_request_target` with untrusted PR code or grant a broad PAT to
  forked pull requests.
- Rotate a credential immediately if it appears in a diff, a log, or a fork
  secret store.

## Branch protection checklist

Apply to `main` and every `release-*` branch. Protect `develop` similarly, with
at least the PR and status-check requirements.

- [ ] Require a pull request before merging.
- [ ] Require at least one approval; require two approvals for release branches.
- [ ] Dismiss stale approvals when new commits are pushed.
- [ ] Require review from code owners when a `CODEOWNERS` file exists.
- [ ] Require status checks and branches to be up to date before merging.
- [ ] Require the Go test workflows, `golangci-lint`, and `pr-title-check`.
- [ ] Require conversation resolution before merging.
- [ ] Restrict pushes to maintainers and block direct pushes.
- [ ] Block force pushes and branch deletion.
- [ ] Require linear history or squash merges.
- [ ] Include administrators in the rules.
- [ ] Protect `v*` and release tags; restrict tag creation to release managers.
- [ ] Use a protected release environment with required reviewers for publishing.
- [ ] Keep auto-merge from bypassing required checks.

## License, attribution, and trademark checklist

The root `LICENSE` applies BSD-3-Clause except to directories that carry their
own license. At this commit `management/LICENSE`, `signal/LICENSE`,
`relay/LICENSE`, `combined/LICENSE`, and `proxy/LICENSE` contain AGPL-3.0 text,
while `LICENSES/REUSE.toml` lists only `management/`, `signal/`, and `relay/`.
Treat the per-directory license files as authoritative, and re-check them at the
pinned commit before distribution.

- [ ] Preserve `LICENSE`, per-directory licenses, `LICENSES/`, `AUTHORS`, and
      source copyright headers.
- [ ] Keep the BSD-3-Clause copyright notice, conditions, and disclaimer in
      source and binary distributions.
- [ ] Do not use NetBird GmbH names or contributor names to endorse the fork.
- [ ] If distributing or operating AGPL-covered server components, provide the
      complete corresponding source to network users.
- [ ] Mark fork modifications and their dates where the license requires it, and
      keep a fork change log.
- [ ] Review new dependencies with the license dependency check; do not add a
      dependency with an incompatible license.
- [ ] Treat the NetBird name and logo as upstream branding. Add a clear "fork of
      NetBird, not affiliated with NetBird GmbH" notice, or rebrand before public
      distribution, and obtain permission before using upstream logos.
- [ ] Follow the WireGuard trademark policy for the WireGuard name and logo.
- [ ] Complete legal review before publishing binaries, container images, or
      hosted services from the fork.

## Source of truth

This document records required guardrails only. Actual branch protection,
environment rules, workflow disabling, and secret provisioning are configured in
GitHub repository settings by maintainers.
