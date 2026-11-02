#!/usr/bin/env bash
# One command: fetch data + Hayabusa if missing, build samples, run all conditions, print the table.
# Cached per-sample results in results/raw/ are reused; pass --fresh to redo every LLM call.
set -euo pipefail
cd "$(dirname "$0")"

HAYABUSA_VER=4.3.1
BASELINE_VER=v0.8.5

[ -d .venv ] || { uv venv -q -p 3.12 .venv && uv pip install -q -p .venv -r requirements.txt; }

mkdir -p data/raw tools
[ -d data/raw/EVTX-ATTACK-SAMPLES ] || \
  git clone -q https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data/raw/EVTX-ATTACK-SAMPLES
if [ ! -d data/raw/evtx-baseline/Logs_Client ]; then
  mkdir -p data/raw/evtx-baseline
  curl -sL -o data/raw/evtx-baseline/win10-client.tgz \
    "https://github.com/NextronSystems/evtx-baseline/releases/download/$BASELINE_VER/win10-client.tgz"
  tar -xzf data/raw/evtx-baseline/win10-client.tgz -C data/raw/evtx-baseline
fi
if [ ! -d tools/hayabusa ]; then
  arch=$([ "$(uname -m)" = arm64 ] && echo aarch64 || echo x64)
  curl -sL -o tools/hayabusa.zip \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v$HAYABUSA_VER/hayabusa-$HAYABUSA_VER-mac-$arch.zip"
  unzip -q tools/hayabusa.zip -d tools/hayabusa && rm tools/hayabusa.zip
  chmod +x tools/hayabusa/hayabusa-*
fi

# building samples parses an 800 MB EVTX (~5 min), so only when missing
[ -d data/samples/benign ] || .venv/bin/python src/build_samples.py

.venv/bin/python src/run_experiment.py "$@"
