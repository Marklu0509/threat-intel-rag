#!/usr/bin/env bash
# Image size, cold start and peak memory of the demo API image under the planned Azure limits
# (2 vCPU, 4 GiB — grill-decisions Q44). Usage: bash deploy/measure.sh <image>
set -euo pipefail
IMAGE="$1"; PORT=8001; NAME=tia-measure
now() { python3 -c 'import time; print(time.time())'; }
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "## Demo API measurement"
docker image inspect "$IMAGE" --format '{{.Size}}' | python3 -c 'import sys; print(f"- image size: {int(sys.stdin.read())/1e9:.2f} GB")'
start=$(now)
# The LLM is never called here (off-topic question below), so no real key is needed
docker run -d --name "$NAME" --memory=4g --cpus=2 -p "$PORT:8000" -e GROQ_API_KEY=unused "$IMAGE" >/dev/null
until curl -sf "http://127.0.0.1:$PORT/health" >/dev/null; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
    echo "- container stopped (OOM killed: $(docker inspect -f '{{.State.OOMKilled}}' "$NAME"))"
    docker logs "$NAME" 2>&1 | tail -30; exit 1
  fi
  sleep 0.5
done
ready=$(now)
python3 -c "print(f'- cold start, container start to /health: {$ready - $start:.1f} s (image already pulled)')"
curl -s -o gate.json -w "- off-topic question (retrieval + relevance gate, no LLM): HTTP %{http_code} in %{time_total} s\n" \
  -H 'Content-Type: application/json' -d '{"question":"How do I bake sourdough bread?"}' "http://127.0.0.1:$PORT/ask"
python3 -c "import json; b=json.load(open('gate.json')); print(f\"  - status {b.get('status')}, refused by {b.get('refused_by')}\")"
docker exec "$NAME" sh -c 'echo "- memory: peak $(( $(cat /sys/fs/cgroup/memory.peak) / 1048576 )) MiB, now $(( $(cat /sys/fs/cgroup/memory.current) / 1048576 )) MiB (limit 4096 MiB)"'
docker rm -f "$NAME" >/dev/null
