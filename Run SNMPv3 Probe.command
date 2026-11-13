#!/bin/zsh
set -eu

cd -- "$(dirname -- "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  print "Python 3 is required. Install Python 3.11 or newer, then run this launcher again."
  read -r "reply?Press Enter to close..."
  exit 1
fi

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
  print "Python 3.11 or newer is required."
  read -r "reply?Press Enter to close..."
  exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
  print "Creating the local Python environment..."
  if ! python3 -m venv .venv; then
    print "Could not create the local Python environment."
    read -r "reply?Press Enter to close..."
    exit 1
  fi
fi

if ! .venv/bin/python -c 'import importlib.metadata as m; assert m.version("pysnmp") == "7.1.32"; assert m.version("pyasn1") == "0.6.5"; assert m.version("cryptography") == "50.0.2"; assert m.version("cffi") == "2.1.1"; assert m.version("pycparser") == "3.12"' >/dev/null 2>&1; then
  print "Installing the probe's pinned Python packages (first run or package update)..."
  if ! .venv/bin/python -m pip install --no-input --no-cache-dir --disable-pip-version-check -r requirements.txt; then
    print "Dependency installation failed. Check network access, then run this launcher again."
    read -r "reply?Press Enter to close..."
    exit 1
  fi
fi

print "Starting the local SNMPv3 read test..."
print "Close it with Control-C in this Terminal window."
exec .venv/bin/python app.py
