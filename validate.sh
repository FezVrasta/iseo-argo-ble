#!/bin/bash
set -e

echo "--- Running Syntax Check ---"
python3 -m py_compile custom_components/iseo_argo_ble/*.py iseo_cli.py

echo -e "
--- Running Ruff (Linter) ---"
pipenv run ruff check .

echo -e "
--- Running Mypy (Type Checker) ---"
pipenv run mypy custom_components/iseo_argo_ble iseo_cli.py

echo -e "
✅ All checks passed!"
