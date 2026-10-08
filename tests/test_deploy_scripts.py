"""The deploy safety net: the smoke test must fail on a bad deploy, and the workflow must notice."""
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
VERSION = "abc123def456"
GOOD_ANSWER = {
    "status": "answered",
    "claims": [{"text": "a", "passage_ids": ["p1"]}, {"text": "b", "passage_ids": ["p2"]}],
    "substitutions": {"T1086": "T1059.001"},
    "elapsed_ms": 843,
}


def _piped_steps():
    for path in WORKFLOWS:
        workflow = yaml.safe_load(path.read_text())
        workflow_shell = workflow.get("defaults", {}).get("run", {}).get("shell")
        for job_name, job in workflow["jobs"].items():
            job_shell = job.get("defaults", {}).get("run", {}).get("shell", workflow_shell)
            for step in job.get("steps", []):
                if "|" in step.get("run", ""):
                    yield f"{path.name}:{job_name}:{step.get('name', step['run'][:40])}", step.get("shell", job_shell)


@pytest.mark.parametrize(("step", "shell"), list(_piped_steps()))
def test_piped_steps_fail_when_the_first_command_fails(step, shell):
    # GitHub's default shell is `bash -e`, without pipefail: in `smoke.sh | tee` only tee's exit
    # code counts, so a failed smoke test passes and the rollback never runs.
    # `shell: bash` runs `bash --noprofile --norc -eo pipefail`.
    assert shell == "bash", f"{step} pipes output but would ignore a failure before the pipe"


def _fake_api(answer):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, body):
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send({"status": "ok", "version": VERSION, "llm": {"ok": True}})

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self._send(answer)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _smoke(answer):
    server = _fake_api(answer)
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        return subprocess.run(["bash", str(ROOT / "deploy" / "smoke.sh"), url, VERSION],
                              capture_output=True, text=True, timeout=60)
    finally:
        server.shutdown()


def test_smoke_test_passes_a_healthy_deploy():
    result = _smoke(GOOD_ANSWER)
    assert result.returncode == 0, result.stderr
    assert "real question answered with 2 cited claims in 843 ms" in result.stdout


@pytest.mark.parametrize("answer", [
    {**GOOD_ANSWER, "status": "refused", "claims": []},
    {**GOOD_ANSWER, "substitutions": {}},
])
def test_smoke_test_fails_a_deploy_without_a_cited_answer(answer):
    assert _smoke(answer).returncode != 0
