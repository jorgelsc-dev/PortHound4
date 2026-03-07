#!/usr/bin/env python3
import json
from functools import lru_cache
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
COUNTRY_CENTROIDS_PATH = PROJECT_ROOT / "data" / "country_centroids.json"


@lru_cache(maxsize=1)
def load_country_centroids(path=None):
    target = Path(path).expanduser().resolve() if path else COUNTRY_CENTROIDS_PATH
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return {}
    output = {}
    for key, value in dict(payload or {}).items():
        code = str(key or "").strip().upper()
        if len(code) != 2:
            continue
        if not isinstance(value, (list, tuple)) or len(value) < 2:
            continue
        try:
            output[code] = (float(value[0]), float(value[1]))
        except Exception:
            continue
    return output


def get_country_centroid(country_code, path=None):
    code = str(country_code or "").strip().upper()
    if len(code) != 2:
        return None
    return load_country_centroids(path).get(code)
