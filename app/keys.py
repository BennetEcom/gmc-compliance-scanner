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

Daneben gibt es Dauer-Codes (GMCP-...): die gelten unbegrenzt, für beliebig
viele Scans und beliebige Domains – bis sie gesperrt werden. Gedacht für
Leute, die dauerhaft Zugang haben sollen, nicht für den Verkauf.

Die Sperre liegt bewusst auf der Disk, nicht im Repo: so wirkt ein Widerruf
sofort, ohne Deploy. Jeder Dauer-Code trägt zusätzlich eine kurze ID (P01,
P02, ...), damit er sich sperren lässt, ohne ihn im Klartext zu nennen.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Optional

_DISK_DIR = os.path.dirname(os.getenv("STATS_FILE", "/var/data/stats.json"))

HASHES_FILE = os.path.join(os.path.dirname(__file__), "key_hashes.json")
USED_KEYS_FILE = os.getenv(
    "USED_KEYS_FILE",
    os.path.join(_DISK_DIR, "keys_used.json"),
)

PASS_HASHES_FILE = os.path.join(os.path.dirname(__file__), "pass_hashes.json")
PASS_STATE_FILE = os.getenv(
    "PASS_STATE_FILE",
    os.path.join(_DISK_DIR, "passes_state.json"),
)

# Beim Abtippen rutschen Leerzeichen, Kleinbuchstaben und fehlende
# Bindestriche rein. Das ist kein Grund, einen gültigen Key abzulehnen.
_CLEAN_RE = re.compile(r"[^A-Z0-9]")


def _core(raw: str) -> str:
    """Die 15 Zeichen ohne Präfix und Trenner. Leer, wenn es keine 15 sind."""
    cleaned = _CLEAN_RE.sub("", (raw or "").upper())
    for prefix in ("GMCA", "GMCP"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[4:]
            break
    return cleaned if len(cleaned) == 15 else ""


def _group(prefix: str, core: str) -> str:
    return f"{prefix}-{core[0:5]}-{core[5:10]}-{core[10:15]}"


def normalize(raw: str) -> str:
    core = _core(raw)
    return _group("GMCA", core) if core else ""


def normalize_pass(raw: str) -> str:
    core = _core(raw)
    return _group("GMCP", core) if core else ""


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


# ---------------------------------------------------------------------------
# Dauer-Codes
# ---------------------------------------------------------------------------


class PassStatus:
    OK = "ok"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


def _load_pass_hashes() -> dict[str, str]:
    """hash -> id. Die ID ist die Kurzkennung, unter der gesperrt wird."""
    try:
        with open(PASS_HASHES_FILE) as f:
            data = json.load(f)
        return {p["hash"]: p["id"] for p in data.get("passes", []) if p.get("hash") and p.get("id")}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


_PASS_IDS = _load_pass_hashes()
_PASS_BY_ID = {pid: h for h, pid in _PASS_IDS.items()}


def _load_pass_state() -> dict:
    try:
        with open(PASS_STATE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


_pass_state: dict = _load_pass_state()


def _save_pass_state() -> None:
    try:
        os.makedirs(os.path.dirname(PASS_STATE_FILE), exist_ok=True)
        tmp = PASS_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_pass_state, f)
        os.replace(tmp, PASS_STATE_FILE)
    except OSError:
        pass  # keine Disk gemountet (lokale Entwicklung) -> nur im Speicher


def _entry(pass_id: str) -> dict:
    return _pass_state.setdefault(pass_id, {"revoked": False, "uses": 0, "label": ""})


def _resolve(ident: str) -> Optional[str]:
    """Nimmt entweder die Kurz-ID (P07) oder den Code im Klartext und gibt
    die ID zurück. So lässt sich sperren, ohne den Code zu kennen."""
    if not ident:
        return None
    cleaned = (ident or "").strip().upper()
    if cleaned in _PASS_BY_ID:
        return cleaned
    code = normalize_pass(cleaned)
    if code:
        return _PASS_IDS.get(_fingerprint(code))
    return None


def check_pass(raw: str) -> tuple[str, Optional[str]]:
    """Prüft einen Dauer-Code. Gibt (status, id) zurück. Verbraucht nichts –
    ein Dauer-Code wird durch Benutzen nicht weniger wert."""
    code = normalize_pass(raw)
    if not code:
        return PassStatus.UNKNOWN, None
    pass_id = _PASS_IDS.get(_fingerprint(code))
    if not pass_id:
        return PassStatus.UNKNOWN, None
    if _pass_state.get(pass_id, {}).get("revoked"):
        return PassStatus.REVOKED, pass_id
    return PassStatus.OK, pass_id


def note_pass_use(pass_id: str, store_url: str) -> None:
    """Zählt die Nutzung mit. Rein zur Auswertung: ob der Scan erlaubt ist,
    hängt allein an der Sperre."""
    if pass_id not in _PASS_BY_ID:
        return
    e = _entry(pass_id)
    e["uses"] = int(e.get("uses", 0)) + 1
    e["last_at"] = datetime.now(timezone.utc).isoformat()
    e["last_url"] = store_url
    _save_pass_state()


def revoke_pass(ident: str) -> Optional[str]:
    """Sperrt einen Dauer-Code. Wirkt sofort, ohne Deploy."""
    pass_id = _resolve(ident)
    if not pass_id:
        return None
    e = _entry(pass_id)
    e["revoked"] = True
    e["revoked_at"] = datetime.now(timezone.utc).isoformat()
    _save_pass_state()
    return pass_id


def restore_pass(ident: str) -> Optional[str]:
    """Hebt die Sperre wieder auf."""
    pass_id = _resolve(ident)
    if not pass_id:
        return None
    e = _entry(pass_id)
    e["revoked"] = False
    e.pop("revoked_at", None)
    _save_pass_state()
    return pass_id


def label_pass(ident: str, label: str) -> Optional[str]:
    """Hinterlegt, wer den Code hat – damit beim Sperren klar ist, wen es
    trifft. Der Code selbst steht hier nie."""
    pass_id = _resolve(ident)
    if not pass_id:
        return None
    _entry(pass_id)["label"] = (label or "").strip()[:80]
    _save_pass_state()
    return pass_id


def pass_list() -> list[dict]:
    out = []
    for pass_id in sorted(_PASS_BY_ID):
        e = _pass_state.get(pass_id, {})
        out.append({
            "id": pass_id,
            "label": e.get("label", ""),
            "revoked": bool(e.get("revoked")),
            "revoked_at": e.get("revoked_at"),
            "uses": int(e.get("uses", 0)),
            "last_at": e.get("last_at"),
            "last_url": e.get("last_url"),
        })
    return out


def pass_stats() -> dict:
    liste = pass_list()
    gesperrt = sum(1 for p in liste if p["revoked"])
    return {
        "total": len(liste),
        "revoked": gesperrt,
        "active": len(liste) - gesperrt,
        "scans": sum(p["uses"] for p in liste),
    }
