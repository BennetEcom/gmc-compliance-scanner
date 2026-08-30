import json
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import (
    STRIPE_PUBLISHABLE_KEY,
    OWNER_BYPASS_CODE,
    STATS_ACCESS_CODE,
    SCAN_PACKAGES,
)
from app.i18n import resolve_lang, t
from app.payments import (
    is_stripe_configured,
    create_package_checkout_session,
    verify_paid_session,
    cache_result,
    get_cached_result,
)
from app.scanner import run_scan, normalize_url, domain_key

app = FastAPI(title="GMC Compliance Scanner")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def _asset_version(*paths: str) -> str:
    """mtime-basierte Cache-Busting-Version: ändert sich automatisch bei jedem
    Deploy, in dem sich CSS/JS geändert haben, ohne dass wir eine Versionsnummer
    manuell pflegen müssen. Verhindert, dass Besucher:innen nach einem Redesign
    die alte, vom Browser gecachte CSS-Datei weiter ausgeliefert bekommen."""
    newest = 0.0
    for p in paths:
        try:
            newest = max(newest, os.path.getmtime(p))
        except OSError:
            pass
    return str(int(newest)) or "1"


ASSET_VERSION = _asset_version(
    "app/static/css/style.css",
    "app/static/js/app.js",
    "app/static/js/i18n.js",
)

# Zähler + "schon gescannt"-Liste + Scan-Guthaben pro Domain (kein Tracking
# von Besucher:innen, keine IPs/Cookies, kein Login). Ein gekauftes Paket gilt
# nur für die Domain, für die es gekauft wurde. Wird auf einer Render
# Persistent Disk gespeichert (falls gemountet), damit die "erster Scan pro
# Domain gratis"-Regel und gekauftes Guthaben Deploys/Neustarts überstehen.
# Ohne gemountete Disk (z.B. lokal) läuft es automatisch im reinen
# In-Memory-Fallback weiter.
STATS_FILE = os.getenv("STATS_FILE", "/var/data/stats.json")

# Für die Statistik-Ansicht reicht ein kurzer Verlauf; die Gate-Prüfung selbst
# läuft über die vollständige Menge in scanned_domains.
RECENT_DOMAINS_LIMIT = 50


def _empty_stats() -> dict:
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "page_views": 0,
        "scans_started": 0,
        "scans_completed": 0,
        "scanned_domains": set(),
        "recent_domains": [],
        "credits": {},
    }


def _load_stats() -> dict:
    """Lädt die persistierten Zähler und normalisiert dabei alles auf den
    kanonischen Domain-Schlüssel.

    Ältere Stände haben volle URLs gespeichert ("https://www.shop.de") und
    scanned_domains als wachsende Liste geführt, in der jeder Scan erneut
    auftauchte. Beides wird hier migriert: die Gate-Prüfung braucht eine
    Menge eindeutiger Schlüssel, und Guthaben derselben Domain unter
    verschiedenen Schreibweisen wird zusammengezählt statt verworfen.
    """
    data = _empty_stats()
    try:
        with open(STATS_FILE) as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return data

    for field in ("started_at", "page_views", "scans_started", "scans_completed"):
        if field in raw:
            data[field] = raw[field]

    for entry in raw.get("scanned_domains", []) or []:
        try:
            data["scanned_domains"].add(domain_key(entry))
        except ValueError:
            continue

    for entry in reversed(raw.get("scanned_domains", []) or []):
        try:
            key = domain_key(entry)
        except ValueError:
            continue
        if key not in data["recent_domains"]:
            data["recent_domains"].append(key)
        if len(data["recent_domains"]) >= RECENT_DOMAINS_LIMIT:
            break
    data["recent_domains"].reverse()

    for entry, amount in (raw.get("credits", {}) or {}).items():
        try:
            key = domain_key(entry)
        except ValueError:
            continue
        try:
            data["credits"][key] = data["credits"].get(key, 0) + int(amount)
        except (TypeError, ValueError):
            continue

    return data


def _save_stats() -> None:
    try:
        os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
        tmp_path = STATS_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            # scanned_domains ist im Speicher eine Menge (O(1)-Prüfung, keine
            # Duplikate) - JSON kennt keine Mengen, also sortierte Liste.
            json.dump({**_stats, "scanned_domains": sorted(_stats["scanned_domains"])}, f)
        os.replace(tmp_path, STATS_FILE)
    except OSError:
        pass  # keine Disk gemountet (z.B. lokale Entwicklung) -> nur In-Memory


def _mark_scanned(key: str) -> None:
    """Verbraucht den Gratis-Scan dieser Domain und schreibt sofort auf die
    Disk - sonst ließe sich die Regel durch einen Neustart aushebeln."""
    _stats["scanned_domains"].add(key)
    _stats["scans_completed"] += 1
    recent = _stats["recent_domains"]
    if key in recent:
        recent.remove(key)
    recent.append(key)
    del recent[:-RECENT_DOMAINS_LIMIT]
    _save_stats()


_stats = _load_stats()


def _cheapest_price_label(lang: str) -> str:
    """Günstigster Preis pro Scan über alle Pakete – als Text für den Hinweis
    im Report. Wird aus SCAN_PACKAGES berechnet statt fest verdrahtet, damit
    eine Preisänderung nicht an zwei Stellen gepflegt werden muss."""
    per_scan = [p["eur"] / p["scans"] for p in SCAN_PACKAGES.values() if p["scans"]]
    cheapest = min(per_scan) if per_scan else 0.0
    text = f"{cheapest:.2f}"
    return text.replace(".", ",") if lang == "de" else text


class StartScanRequest(BaseModel):
    url: str
    promo_owner_code: Optional[str] = None
    lang: str = "de"


class BuyPackageRequest(BaseModel):
    url: str
    package: str
    lang: str = "de"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _stats["page_views"] += 1
    lang = resolve_lang(request.headers.get("accept-language"))
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stripe_configured": is_stripe_configured(),
            "asset_v": ASSET_VERSION,
            "pending_session_id": None,
            "initial_lang": lang,
        },
    )


@app.post("/api/start-scan")
async def api_start_scan(payload: StartScanRequest):
    try:
        normalized = normalize_url(payload.url)
    except ValueError:
        raise HTTPException(status_code=400, detail="Ungültige URL")

    lang = resolve_lang(payload.lang)
    key = domain_key(normalized)
    _stats["scans_started"] += 1

    # 1) Owner-Bypass: kostenlos scannen, kein Stripe nötig
    if OWNER_BYPASS_CODE and payload.promo_owner_code and payload.promo_owner_code == OWNER_BYPASS_CODE:
        result = await run_scan(normalized, lang)
        _mark_scanned(key)
        return {"mode": "direct", "result": result}

    # 2) Diese Domain wurde noch nie gescannt -> genau dieser eine Scan ist
    #    gratis. Gezählt wird pro Store (siehe domain_key), nicht pro
    #    Schreibweise: www./ohne www., http/https und Port zählen als eine
    #    Domain, sonst wäre die Regel durch eine andere Eingabe umgehbar.
    if key not in _stats["scanned_domains"]:
        result = await run_scan(normalized, lang)
        result["_notice"] = t("notice.first_free", lang, price=_cheapest_price_label(lang))
        _mark_scanned(key)
        return {"mode": "direct", "result": result}

    # 3) Bereits gescannt -> vorhandenes Guthaben DIESER Domain verbrauchen
    credits = _stats["credits"].get(key, 0)
    if credits > 0:
        result = await run_scan(normalized, lang)
        _stats["credits"][key] = credits - 1
        result["_notice"] = t("notice.credit_used", lang, remaining=credits - 1)
        _mark_scanned(key)
        return {"mode": "direct", "result": result}

    # 4) Kein Gratis-Scan, kein Guthaben -> es kostet. Ohne konfiguriertes
    #    Stripe können wir nicht kassieren; dann wird der Scan abgelehnt statt
    #    verschenkt, sonst wäre eine fehlende Umgebungsvariable ein stiller
    #    Gratis-Modus für alle.
    if not is_stripe_configured():
        raise HTTPException(status_code=503, detail=t("err.payment_unavailable", lang))

    return {
        "mode": "choose_package",
        "packages": {k: {"scans": v["scans"], "eur": v["eur"]} for k, v in SCAN_PACKAGES.items()},
    }


@app.post("/api/buy-package")
async def api_buy_package(payload: BuyPackageRequest):
    if payload.package not in SCAN_PACKAGES:
        raise HTTPException(status_code=400, detail="Ungültiges Paket")
    try:
        normalized = normalize_url(payload.url)
    except ValueError:
        raise HTTPException(status_code=400, detail="Ungültige URL")

    lang = resolve_lang(payload.lang)
    session = create_package_checkout_session(normalized, payload.package, lang)
    return {"mode": "redirect", **session}


@app.get("/scan/result", response_class=HTMLResponse)
async def scan_result_page(request: Request, session_id: Optional[str] = None, lang: Optional[str] = None):
    resolved_lang = resolve_lang(lang or request.headers.get("accept-language"))
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stripe_configured": is_stripe_configured(),
            "asset_v": ASSET_VERSION,
            "pending_session_id": session_id,
            "initial_lang": resolved_lang,
        },
    )


@app.get("/api/scan/result")
async def api_scan_result(session_id: str):
    cached = get_cached_result(session_id)
    if cached:
        return cached

    paid = verify_paid_session(session_id)
    if not paid.store_url:
        raise HTTPException(status_code=402, detail="Zahlung nicht bestätigt oder Session ungültig.")

    result = await run_scan(paid.store_url, paid.lang)
    # Guthaben hängt am selben kanonischen Schlüssel wie das Gate - sonst
    # würde ein Paket, das für "https://www.shop.de" gekauft wurde, bei einer
    # Eingabe von "shop.de" nicht gefunden.
    key = domain_key(paid.store_url)
    remaining_credits = paid.scans_granted - 1
    if remaining_credits > 0:
        _stats["credits"][key] = _stats["credits"].get(key, 0) + remaining_credits
        result["_notice"] = t("notice.package_bought", paid.lang, remaining=_stats["credits"][key])
    cache_result(session_id, result)
    _mark_scanned(key)
    return result


@app.get("/api/config")
async def api_config():
    return {
        "stripe_publishable_key": STRIPE_PUBLISHABLE_KEY,
        "stripe_configured": is_stripe_configured(),
        "packages": {k: {"scans": v["scans"], "eur": v["eur"]} for k, v in SCAN_PACKAGES.items()},
    }


@app.get("/api/stats")
async def api_stats(code: str = ""):
    if not STATS_ACCESS_CODE or code != STATS_ACCESS_CODE:
        raise HTTPException(status_code=404)
    return {
        **{k: v for k, v in _stats.items() if k not in ("scanned_domains", "recent_domains", "credits")},
        "unique_domains_scanned": len(_stats["scanned_domains"]),
        "most_recent_domains": list(reversed(_stats["recent_domains"]))[:20],
        "domains_with_credit": len([1 for c in _stats["credits"].values() if c > 0]),
        "note": "Wird auf einer Render Persistent Disk gespeichert (falls gemountet) und übersteht damit Deploys/Neustarts.",
    }


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})
