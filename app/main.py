from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import (
    STRIPE_PUBLISHABLE_KEY,
    OWNER_BYPASS_CODE,
    STATS_ACCESS_CODE,
    SCAN_PRICE_EUR,
)
from app.payments import (
    is_stripe_configured,
    create_checkout_session,
    verify_paid_session,
    cache_result,
    get_cached_result,
)
from app.scanner import run_scan, normalize_url

app = FastAPI(title="GMC Compliance Scanner")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Nur In-Memory-Zähler für den Betreiber (kein Tracking von Besucher:innen,
# keine IPs/Cookies) – setzt sich bei jedem Deploy/Neustart zurück, passt zur
# "keine Datenspeicherung"-Zusage der Seite.
_stats = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "page_views": 0,
    "scans_started": 0,
    "scans_completed": 0,
    "scanned_domains": [],
}


class StartScanRequest(BaseModel):
    url: str
    promo_owner_code: str | None = None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    _stats["page_views"] += 1
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stripe_configured": is_stripe_configured(),
            "pending_session_id": None,
        },
    )


@app.post("/api/start-scan")
async def api_start_scan(payload: StartScanRequest):
    try:
        normalized = normalize_url(payload.url)
    except ValueError:
        raise HTTPException(status_code=400, detail="Ungültige URL")

    _stats["scans_started"] += 1

    # 1) Owner-Bypass: kostenlos scannen, kein Stripe nötig
    if OWNER_BYPASS_CODE and payload.promo_owner_code and payload.promo_owner_code == OWNER_BYPASS_CODE:
        result = await run_scan(normalized)
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        return {"mode": "direct", "result": result}

    # 2) Kein Stripe konfiguriert -> Scan ist aktuell kostenlos
    if not is_stripe_configured():
        result = await run_scan(normalized)
        result["_notice"] = "Aktuell komplett kostenlos."
        _stats["scans_completed"] += 1
        _stats["scanned_domains"].append(normalized)
        return {"mode": "direct", "result": result}

    # 3) Normalfall: Stripe Checkout Session (10 EUR, Promo-Code-Feld aktiv)
    session = create_checkout_session(normalized)
    return {"mode": "redirect", **session}


@app.get("/scan/result", response_class=HTMLResponse)
async def scan_result_page(request: Request, session_id: str | None = None):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stripe_configured": is_stripe_configured(),
            "pending_session_id": session_id,
        },
    )


@app.get("/api/scan/result")
async def api_scan_result(session_id: str):
    cached = get_cached_result(session_id)
    if cached:
        return cached

    store_url = verify_paid_session(session_id)
    if not store_url:
        raise HTTPException(status_code=402, detail="Zahlung nicht bestätigt oder Session ungültig.")

    result = await run_scan(store_url)
    cache_result(session_id, result)
    return result


@app.get("/api/config")
async def api_config():
    return {
        "stripe_publishable_key": STRIPE_PUBLISHABLE_KEY,
        "stripe_configured": is_stripe_configured(),
        "price_eur": SCAN_PRICE_EUR,
    }


@app.get("/api/stats")
async def api_stats(code: str = ""):
    if not STATS_ACCESS_CODE or code != STATS_ACCESS_CODE:
        raise HTTPException(status_code=404)
    domains = _stats["scanned_domains"]
    recent = list(reversed(domains))[:20]
    return {
        **{k: v for k, v in _stats.items() if k != "scanned_domains"},
        "unique_domains_scanned": len(set(domains)),
        "most_recent_domains": recent,
        "note": "In-Memory-Zähler, setzt sich bei jedem Deploy/Neustart zurück.",
    }


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})
