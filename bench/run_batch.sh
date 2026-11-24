#!/usr/bin/env bash
# Run the bench for several LM Studio models in turn: load each with a 32k context, smoke-test one tool
# call, run the scenarios, unload.  Optional hooks free the GPU before and give it back after, always:
#   BENCH_PRE_CMD="systemctl stop my-gpu-service"  BENCH_POST_CMD="systemctl start my-gpu-service"
# usage: run_batch.sh <trials> <model-id> [model-id ...]
set -u
LMS=${LMS:-lms}
PY=${PYTHON:-python}
cd "$(dirname "$0")"
trials=$1; shift

finish() {
  for m in "$@"; do $LMS unload "$m" >/dev/null 2>&1; done
  [ -n "${BENCH_POST_CMD:-}" ] && bash -c "$BENCH_POST_CMD"
  echo "BATCH: done"
}
trap 'finish "$@"' EXIT
[ -n "${BENCH_PRE_CMD:-}" ] && bash -c "$BENCH_PRE_CMD"

for m in "$@"; do
  echo "BATCH: === $m"
  $LMS unload --all >/dev/null 2>&1   # a just-in-time load left behind would block the GPU
  $LMS load "$m" --context-length 32768 --gpu max -y >/dev/null 2>&1 || { echo "BATCH: $m LOAD FAILED"; continue; }
  $PY - "$m" <<'EOF'
import os, sys, requests
from bench import LMS, openai_tools
r = requests.post(LMS, timeout=600, json={"model": sys.argv[1], "temperature": 0.2, "max_tokens": 2048,
    "tools": openai_tools(), "messages": [{"role": "user", "content": "What firmware is my router running? Use the tools."}]}).json()
calls = ((r.get("choices") or [{}])[0].get("message") or {}).get("tool_calls") or []
print("BATCH: smoke tool_call=" + (calls[0]["function"]["name"] if calls else "NONE"),
      "prompt_tokens=" + str((r.get("usage") or {}).get("prompt_tokens")))
EOF
  $PY bench.py model "$m" "$trials" 2>&1 | grep -E '"scenario"|^== '
  $LMS unload "$m" >/dev/null 2>&1
done
