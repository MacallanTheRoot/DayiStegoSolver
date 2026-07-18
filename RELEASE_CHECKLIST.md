# Dayı Stego Solver 4.0.0 Release Checklist

This checklist prepares the 2026-07-18 release. Until the final release-status
commit is made, it does not record a completed tag, GitHub release, or package
publication.

## Pre-release

- [ ] Confirm the intended release commit with `git rev-parse HEAD`.
- [ ] Confirm `git status --short` is empty after release-documentation changes
      are reviewed and committed.
- [ ] Confirm every required GitHub Actions job, including Python 3.10–3.13,
      completed successfully for the intended release commit.
- [ ] Confirm `pyproject.toml`, `dayi.__version__`, CLI output, release notes,
      changelog, and distribution metadata all report `4.0.0`.
- [ ] Confirm the Beta classifier and Python `>=3.10` requirement remain correct.
- [ ] Confirm the changelog records the release date as `2026-07-18`.
- [ ] Remove release-pending wording from README and release notes at release
      time.
- [ ] Finalize `CHANGELOG.md` and `RELEASE_NOTES_v4.0.0.md`.
- [ ] Review documentation and built metadata for placeholder or stale URLs.
- [ ] Confirm the repository URL is
      `https://github.com/MacallanTheRoot/DayiStegoSolver`.

## Verification

Run from the repository root:

```bash
python -m pip install -e '.[dev]'
./scripts/check.sh
python -m build
python scripts/validate_distribution.py --dist-dir dist
```

- [ ] Confirm the full test suite, pyflakes, compileall, diff check, build, and
      archive validator pass.
- [ ] Confirm exactly one versioned wheel and one source distribution exist.
- [ ] Install the wheel with `--no-deps` in a clean virtual environment and run
      all console-script smoke checks from outside the repository checkout.
- [ ] Repeat the clean installation and import-path check with the source
      distribution.
- [ ] Confirm the installed console entry point is `dayi = dayi.cli:main`.
- [ ] Confirm the installed package imports from the clean environment's
      `site-packages`, not the source checkout.
- [ ] Validate isolated JSON output:

```bash
dayi doctor --json | python -m json.tool >/dev/null
dayi plugins list --json | python -m json.tool >/dev/null
```

- [ ] Confirm doctor and plugin-inspection schema versions remain 1.
- [ ] If release checksums are generated, verify them before attaching or
      publishing the checksum file.

## Tagging

Choose one tag form only after all checks pass. A signed tag requires a
configured GPG key:

```bash
git tag -s v4.0.0 -m "Dayı Stego Solver 4.0.0"
git push origin v4.0.0
```

Unsigned annotated alternative:

```bash
git tag -a v4.0.0 -m "Dayı Stego Solver 4.0.0"
git push origin v4.0.0
```

- [ ] Verify the chosen tag points to the intended release commit before push.
- [ ] Do not create both signed and unsigned tags with the same name.

## GitHub release

- [ ] Target tag: `v4.0.0`.
- [ ] Release title: `Dayı Stego Solver 4.0.0`.
- [ ] Paste the finalized release notes.
- [ ] Attach the wheel and source distribution from successful CI.
- [ ] Attach and verify checksums if they were generated.
- [ ] Decide explicitly whether to mark the GitHub release as a prerelease.
      The package's Beta classifier does not require GitHub prerelease status.
- [ ] Verify asset names, metadata, and download availability before announcing.

## Post-release

- [ ] Install and smoke-test the published release asset in a clean environment.
- [ ] Verify all release assets and any published checksums.
- [ ] Move subsequent changes into `[Unreleased]` in `CHANGELOG.md`.
- [ ] Open the next development section when its version is known.
- [ ] Monitor the issue tracker for installation and regression reports.
