"""Serve site/ over HTTP for the browser tests; the API is faked per test with page.route."""

import functools
import http.server
import threading
from pathlib import Path

import pytest

SITE = Path(__file__).resolve().parents[1] / "site"


@pytest.fixture(scope="session")
def site_url():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
