from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import (
    STRIPE_PUBLISHABLE_KEY,
    OWNER_BYPASS_CODE,
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


class StartScanRequest(BaseModel):
    url: str
    promo_owner_code: str | None = None


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
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

    # 1) Owner-Bypass: kostenlos scannen, kein Stripe nötig
    if OWNER_BYPASS_CODE and payload.promo_owner_code and payload.promo_owner_code == OWNER_BYPASS_CODE:
        result = await run_scan(normalized)
        return {"mode": "direct", "result": result}

    # 2) Kein Stripe konfiguriert -> Scan ist aktuell kostenlos
    if not is_stripe_configured():
        result = await run_scan(normalized)
        result["_notice"] = "Aktuell komplett kostenlos."
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


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})
