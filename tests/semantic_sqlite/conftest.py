"""Test-local conftest: redirect on-disk caches into $TMPDIR for sandboxed runs."""

import os
import tempfile
from pathlib import Path

from sigma.data import mitre_attack, mitre_d3fend

_cache_root = Path(os.environ.get("TMPDIR", tempfile.gettempdir())) / "pysigma-test-cache"
mitre_attack.set_cache_dir(str(_cache_root / "mitre_attack"))
mitre_d3fend.set_cache_dir(str(_cache_root / "mitre_d3fend"))
