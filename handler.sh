#!/bin/sh
# kraken tentacle — ledger. See tentacle.yaml.
set -eu
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "${KRAKEN_PYTHON:-python3}" "$DIR/handler.py"
