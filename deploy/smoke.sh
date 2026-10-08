#!/usr/bin/env bash
# After a deploy (grill-decisions Q51): wait until the new version is the one answering,
# then check the LLM link and one real, cited answer. Usage: bash deploy/smoke.sh <url> <version>
set -euo pipefail
URL="$1"; WANT="$2"; DEADLINE=$((SECONDS + 600))

version() { curl -s --max-time 20 "$URL/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", ""))' 2>/dev/null || true; }

# "Settings updated" is not "new container serving" (Q56), so wait for the version itself
until [ "$(version)" = "$WANT" ]; do
  if [ "$SECONDS" -ge "$DEADLINE" ]; then echo "- version $WANT still not serving after 10 minutes"; exit 1; fi
  sleep 10
done
echo "- version $WANT is serving"

curl -s --max-time 30 "$URL/health?check=llm" | python3 -c '
import json, sys
llm = json.load(sys.stdin)["llm"]
assert llm["ok"] is True, f"LLM not reachable from the server: {llm}"
print("- LLM reachable from the server")'

curl -s --max-time 90 -H "Content-Type: application/json" -d '{"question":"How do I detect T1086?"}' "$URL/ask" | python3 -c '
import json, sys
b = json.load(sys.stdin)
assert b.get("status") == "answered" and b.get("claims"), f"no cited answer: {b}"
assert b.get("substitutions") == {"T1086": "T1059.001"}, f"revoked-ID rewrite missing: {b}"
claims, ms = len(b["claims"]), b["elapsed_ms"]  # no backslashes inside f-strings before Python 3.12
print(f"- real question answered with {claims} cited claims in {ms} ms")'
