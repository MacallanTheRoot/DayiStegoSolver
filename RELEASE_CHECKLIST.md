# Dayı Stego Solver Release Checklist

Reusable checklist for every release of
https://github.com/MacallanTheRoot/DayiStegoSolver. Replace `<version>` with
the release version (for example in `v<version>`) and `<previous>` with the
last published version. Copy the list into the release record and check items
there; keep this template unchecked.

## Version synchronization

- [ ] `pyproject.toml` `version` and `dayi.__version__` report `<version>`.
- [ ] `scripts/validate_distribution.py` `EXPECTED_VERSION`, the smoke-test
      assertions in `.github/workflows/ci.yml` and the version constants in
      `tests/` report `<version>`.
- [ ] `CHANGELOG.md` has a `## [<version>] - YYYY-MM-DD` section without
      release-pending wording, and its compare links read
      `[Unreleased]: …/compare/v<version>...HEAD` and
      `[<version>]: …/compare/v<previous>...v<version>`.
- [ ] `RELEASE_NOTES_v<version>.md` exists and is listed in `MANIFEST.in` and
      in the required sdist files of `scripts/validate_distribution.py`.
- [ ] Searching the repository for the previous version string returns only
      historical changelog and release-note entries.
- [ ] README links to the canonical latest-release page and does not claim a
      version is published before publication.

## Supported Python compatibility matrix

- [ ] Full test suite passes on every supported CPython version (currently
      3.10, 3.11, 3.12 and 3.13); record passed, skipped and subtest counts.
- [ ] `requires-python`, the classifiers and `dayi.MIN_SUPPORTED_PYTHON` /
      `dayi.MAX_SUPPORTED_PYTHON` agree.
- [ ] Any change in test or skip counts compared with the previous release is
      explained.

## Static analysis

```bash
python -m pyflakes dayi tests scripts/validate_distribution.py
python -m compileall -q dayi tests scripts/validate_distribution.py
git diff --check
```

- [ ] pyflakes, compileall and `git diff --check` pass.

## Documentation verification

- [ ] README (English and Turkish sections), CHANGELOG and release notes agree
      on features, limits, supported Python versions and known limitations.
- [ ] Documentation contract tests (`tests/test_readme_*.py`,
      `tests/test_package_metadata.py`) pass.
- [ ] No placeholder, stale or private URLs in documentation or built metadata.
- [ ] No unverified benchmark, safety or detection claims.

## Repository hygiene

- [ ] `git status --short` is clean after the reviewed release commit.
- [ ] Only reviewed files were staged, by explicit path.
- [ ] The tracked `.gitignore` is unchanged unless the change was reviewed.
- [ ] No personal configuration, planning notes, logs or credentials are
      tracked or packaged.

## Security review

- [ ] The release diff was reviewed for changes to untrusted-input parsing,
      subprocess execution, extraction paths, regex handling and integrations.
- [ ] Size, time, recursion and extraction limits are unchanged or the change
      is documented.
- [ ] Known residual risks are listed in the release notes.

## Remote CI verification

- [ ] Every required GitHub Actions job (tests on all supported Python versions
      and the build and smoke job) succeeded for the exact release commit.
- [ ] After merging, CI on the default branch succeeded for the merged commit.

## Clean source checkout

- [ ] Artifacts are built from a clean checkout or worktree of the exact
      merged commit that will be tagged, not from a development working tree.
- [ ] `git rev-parse HEAD` in that checkout matches the intended release
      commit.

## Wheel and sdist build

```bash
python -m build --outdir <dist-dir>
```

- [ ] Exactly one wheel and one source distribution named for `<version>`.

## Distribution validation

```bash
python scripts/validate_distribution.py --dist-dir <dist-dir>
```

- [ ] The validator passes for both archives.
- [ ] Archives contain the license and documentation files and no private
      development files or credentials.

## Clean-install smoke tests

- [ ] Install the wheel with `--no-deps` into a fresh virtual environment and,
      from a directory outside the checkout, run `dayi --version`,
      `dayi --help`, `dayi doctor --json` and `dayi plugins list --json`.
- [ ] Repeat with the source distribution.
- [ ] The package imports from the environment's `site-packages`, the entry
      point is `dayi = dayi.cli:main` and there are no mandatory runtime
      dependencies.
- [ ] Doctor and plugin-inspection JSON report `schema_version` 1 and the
      expected plugin count.

## SHA-256 checksums

```bash
cd <dist-dir>
sha256sum dayi_stego_solver-<version>-py3-none-any.whl \
  dayi_stego_solver-<version>.tar.gz > SHA256SUMS
sha256sum -c SHA256SUMS
```

- [ ] `SHA256SUMS` is generated from the final artifacts and verifies.

## Annotated or signed tag

Choose one form. A signed tag requires a configured signing key:

```bash
git tag -s v<version> -m "Dayı Stego Solver <version>"
git tag -a v<version> -m "Dayı Stego Solver <version>"
```

- [ ] No local or remote tag `v<version>` exists before tagging; never move or
      delete a published tag.
- [ ] `git rev-parse v<version>^{commit}` equals the commit the artifacts were
      built from, before and after `git push origin v<version>`.

## GitHub Release publication

- [ ] Create the release as a draft for tag `v<version>` with the finalized
      release notes.
- [ ] Attach the wheel, the source distribution and `SHA256SUMS`.
- [ ] Inspect the draft title, notes, target tag and asset names and sizes.
- [ ] Decide explicitly whether the release is a prerelease; the Beta
      classifier does not require GitHub prerelease status.
- [ ] Publish the draft.

## Post-publication verification

- [ ] The release is published, not a draft, and shown as the latest release
      when intended.
- [ ] The tag on GitHub points to the intended commit.
- [ ] Download the published assets into an empty directory and verify them
      with `sha256sum -c SHA256SUMS`.
- [ ] Install the downloaded wheel in a clean environment and run the smoke
      checks.
- [ ] Open the next `[Unreleased]` work in `CHANGELOG.md` and monitor the issue
      tracker for installation and regression reports.
