"""Download the pinned ATT&CK release and verify it byte-for-byte."""

import hashlib
import logging
import urllib.request
from pathlib import Path

from attack_qa.config import ATTACK_SHA256, ATTACK_URL

logger = logging.getLogger(__name__)


class ChecksumMismatchError(Exception):
    """The downloaded file is not the pinned ATT&CK release."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(path: Path, expected: str = ATTACK_SHA256) -> None:
    actual = sha256_of(path)
    if actual != expected:
        raise ChecksumMismatchError(
            f"{path.name}: expected sha256 {expected}, got {actual}"
        )


def download(dest: Path, url: str = ATTACK_URL) -> Path:
    """Download to dest unless an already-verified copy is there."""
    if dest.exists():
        verify(dest)
        logger.info("Using verified copy at %s", dest)
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    logger.info("Downloading %s", url)
    urllib.request.urlretrieve(url, tmp)
    try:
        verify(tmp)
    except ChecksumMismatchError:
        tmp.unlink()
        raise
    tmp.rename(dest)
    return dest
