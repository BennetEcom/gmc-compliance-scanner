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
from app.scanner import run_scan, normalize_url

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


ASSET_VERSION = _asset_version("app/static/css/style.css", "app/static/js/app.js")

# Zähler + "schon gescannt"-Liste + Scan-Guthaben pro Domain (kein Tracking
# von Besucher:innen, keine IPs/Cookies, kein Login). Ein gekauftes Paket gilt
# nur für die Domain, für die es gekauft wurde. Wird auf einer Render
# Persistent Disk gespeichert (falls gemountet), damit die "erster Scan pro
# Domain gratis"-Regel und gekauftes Guthaben Deploys/Neustarts überstehen.
# Ohne gemountete Disk (z.B. lokal) läuft es automatisch im reinen
# In-Memory-Fallback weiter.
STATS_FILE = os.getenv("STATS_FILE", "/var/data/stats.json")


def _load_stats() -> dict:
    try:
        with open(STATS_FILE) as f:
            data = json.load(f)
        data.setdefault("started_at", datetime.now(timezone.utc).isoformat())
        data.setdefault("page_views", 0)
        data.setdefault("scans_started", 0)
        data.setdefault("scans_completed", 0)
        data.setdefault("scanned_domains", [])
        data.setdefault("credits", {})
        return data
    except (OSError, json.JSONDecodeError):
        return {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "page_views": 0,
            "scans_started": 0,
            "scans_completed": 0,
            "scanned_domains": [],
            "credits": {},
        }


def _save_stats() -> None:
    try:
        os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
        tmp_path = STATS_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(_stats, f)
        os.replace(tmp_path, STATS_FILE)
    except OSError:
        pass  # keine Disk gemountet (z.B. lokale Entwicklung) -> nur In-Memory


_stats = _load_stats()


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
    _stats["scans_started"] += 1

    # 1) Owner-Bypass: kostenlos scannen, kein Stripe nötig
    if OWNER_BYPASS_CODE and payload.promo_owner_code and payload.promo_owner_code == OWNER_BYPASS_CODE:
        result = await run_scan(normalized, lang)
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        _save_stats()
        return {"mode": "direct", "result": result}

    # 2) Kein Stripe konfiguriert -> Scan ist aktuell kostenlos
    if not is_stripe_configured():
        result = await run_scan(normalized, lang)
        result["_notice"] = t("notice.free_mode", lang)
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        _save_stats()
        return {"mode": "direct", "result": result}

    # 3) Diese Domain wurde noch nie gescannt -> erster Scan ist gratis
    if normalized not in _stats["scanned_domains"]:
        result = await run_scan(normalized, lang)
        result["_notice"] = t("notice.first_free", lang, price="10,00" if lang == "de" else "10.00")
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        _save_stats()
        return {"mode": "direct", "result": result}

    # 4) Domain wurde bereits gescannt -> vorhandenes Guthaben DIESER Domain
    #    verbrauchen, sonst zur Paket-Auswahl auffordern
    credits = _stats["credits"].get(normalized, 0)
    if credits > 0:
        result = await run_scan(normalized, lang)
        _stats["credits"][normalized] = credits - 1
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        _save_stats()
        result["_notice"] = t("notice.credit_used", lang, remaining=credits - 1)
        return {"mode": "direct", "result": result}

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
    remaining_credits = paid.scans_granted - 1
    if remaining_credits > 0:
        _stats["credits"][paid.store_url] = _stats["credits"].get(paid.store_url, 0) + remaining_credits
        result["_notice"] = t("notice.package_bought", paid.lang, remaining=_stats["credits"][paid.store_url])
    cache_result(session_id, result)
    _stats["scans_completed"] += 1
    _stats["scanned_domains"].append(paid.store_url)
    _save_stats()
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
    domains = _stats["scanned_domains"]
    recent = list(reversed(domains))[:20]
    return {
        **{k: v for k, v in _stats.items() if k not in ("scanned_domains", "credits")},
        "unique_domains_scanned": len(set(domains)),
        "most_recent_domains": recent,
        "domains_with_credit": len([1 for c in _stats["credits"].values() if c > 0]),
        "note": "Wird auf einer Render Persistent Disk gespeichert (falls gemountet) und übersteht damit Deploys/Neustarts.",
    }


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})
