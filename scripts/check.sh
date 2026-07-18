#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")
cd "$repo_root"

python -m pytest -q
python -m pyflakes dayi tests scripts/validate_distribution.py
python -m compileall -q dayi tests scripts/validate_distribution.py
git diff --check
python -m build
python scripts/validate_distribution.py --dist-dir dist
