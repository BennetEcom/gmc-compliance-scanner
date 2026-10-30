"""
Scan-Keys: Einlösen statt Bezahlen.

Ein Key berechtigt zu genau einem Scan auf genau einer Domain. Die Domain
wird erst beim Einlösen festgelegt, nicht beim Kauf.

Warum nur Prüfsummen im Code liegen: das GitHub-Repo ist öffentlich. Stünden
die Keys im Klartext darin, könnte sie jeder mitlesen. Gespeichert ist
deshalb ausschließlich der SHA-256-Abdruck jedes Keys (app/key_hashes.json) –
daraus lässt sich der Key nicht zurückrechnen, die Prüfung funktioniert aber
genauso. Die Klartext-Liste existiert nur beim Betreiber.

Welcher Key schon verbraucht ist, steht auf der Render-Disk neben
stats.json. Geht die Disk verloren, sind alle Keys wieder gültig – die
Gültigkeit selbst hängt am Repo, nur der Verbrauch an der Disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Optional

HASHES_FILE = os.path.join(os.path.dirname(__file__), "key_hashes.json")
USED_KEYS_FILE = os.getenv(
    "USED_KEYS_FILE",
    os.path.join(os.path.dirname(os.getenv("STATS_FILE", "/var/data/stats.json")), "keys_used.json"),
)

# Beim Abtippen rutschen Leerzeichen, Kleinbuchstaben und fehlende
# Bindestriche rein. Das ist kein Grund, einen gültigen Key abzulehnen.
_CLEAN_RE = re.compile(r"[^A-Z0-9]")


def normalize(raw: str) -> str:
    cleaned = _CLEAN_RE.sub("", (raw or "").upper())
    if cleaned.startswith("GMCA"):
        cleaned = cleaned[4:]
    if len(cleaned) != 15:
        return ""
    return f"GMCA-{cleaned[0:5]}-{cleaned[5:10]}-{cleaned[10:15]}"


def _fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _load_valid_hashes() -> set[str]:
    try:
        with open(HASHES_FILE) as f:
            return set(json.load(f).get("hashes", []))
    except (OSError, json.JSONDecodeError):
        return set()


_VALID_HASHES = _load_valid_hashes()


def _load_used() -> dict:
    try:
        with open(USED_KEYS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


_used: dict = _load_used()


def _save_used() -> None:
    try:
        os.makedirs(os.path.dirname(USED_KEYS_FILE), exist_ok=True)
        tmp = USED_KEYS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_used, f)
        os.replace(tmp, USED_KEYS_FILE)
    except OSError:
        pass  # keine Disk gemountet (lokale Entwicklung) -> nur im Speicher


class KeyStatus:
    OK = "ok"
    UNKNOWN = "unknown"
    USED = "used"


def check(raw: str) -> tuple[str, Optional[str]]:
    """Prüft einen Key, ohne ihn zu verbrauchen.
    Gibt (status, bereits_gescannte_domain) zurück."""
    key = normalize(raw)
    if not key:
        return KeyStatus.UNKNOWN, None
    fp = _fingerprint(key)
    if fp not in _VALID_HASHES:
        return KeyStatus.UNKNOWN, None
    entry = _used.get(fp)
    if entry:
        return KeyStatus.USED, entry.get("url")
    return KeyStatus.OK, None


def redeem(raw: str, store_url: str) -> bool:
    """Verbraucht den Key für diese Domain. Schreibt sofort auf die Disk,
    damit ein Neustart den Verbrauch nicht vergisst."""
    key = normalize(raw)
    if not key:
        return False
    fp = _fingerprint(key)
    if fp not in _VALID_HASHES or fp in _used:
        return False
    _used[fp] = {"url": store_url, "at": datetime.now(timezone.utc).isoformat()}
    _save_used()
    return True


def stats() -> dict:
    return {"total": len(_VALID_HASHES), "used": len(_used), "left": len(_VALID_HASHES) - len(_used)}
