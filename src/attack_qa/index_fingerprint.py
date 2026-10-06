"""Fingerprint a Passage index by its content, to prove an attack run left it unchanged (Q29).

Every new Chroma client that opens an index adds a row to its `acquire_write` table, so hashing
raw file bytes raised a false alarm when another evaluation opened the production index mid-run.
The sqlite file is hashed by its table contents, minus that bookkeeping table; other files by
their bytes.
"""

import hashlib
import sqlite3
from pathlib import Path

_SQLITE_SIDE_FILES = ("-wal", "-shm", "-journal")
_BOOKKEEPING_TABLES = frozenset({"acquire_write"})  # one row per client that opened the index


def _sqlite_content(path: Path) -> bytes:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [t for (t,) in con.execute(
            "select name from sqlite_master where type='table' order by name")]
        parts = []
        for table in tables:
            if table in _BOOKKEEPING_TABLES:
                continue
            rows = sorted(repr(row) for row in con.execute(f'select * from "{table}"'))
            parts.append(f"{table}\n" + "\n".join(rows))
        return "\n\n".join(parts).encode()
    finally:
        con.close()


def fingerprint(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        if path.name.endswith(_SQLITE_SIDE_FILES):
            continue
        digest.update(str(path.relative_to(directory)).encode())
        digest.update(_sqlite_content(path) if path.suffix == ".sqlite3" else path.read_bytes())
    return digest.hexdigest()
