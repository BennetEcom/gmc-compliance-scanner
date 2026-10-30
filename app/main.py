import json
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import (
    STRIPE_PUBLISHABLE_KEY,
    OWNER_BYPASS_CODE,
    STATS_ACCESS_CODE,
    SALES_ENABLED,
    KEY_SHOP_URL,
    KEY_SHOP_NAME,
    SCAN_PACKAGES,
)
from app import keys as scan_keys
from app.i18n import resolve_lang, t
from app.payments import (
    AllocationTooLargeError,
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
        # Scan-Verlauf mit Zeitpunkt. Früher wurde nur die URL angehängt,
        # ohne jedes Datum – Fragen wie "welche Stores letzte Woche?" waren
        # damit nicht beantwortbar. Altbestand wandert einmalig mit at=None
        # in den Verlauf, damit die Historie nicht bei null anfängt.
        if "scan_log" not in data:
            data["scan_log"] = [{"url": u, "at": None, "via": "unbekannt"} for u in data["scanned_domains"]]
        return data
    except (OSError, json.JSONDecodeError):
        return {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "page_views": 0,
            "scans_started": 0,
            "scans_completed": 0,
            "scanned_domains": [],
            "scan_log": [],
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


def _record_scan(url: str, via: str) -> None:
    """Hält einen abgeschlossenen Scan fest: für das Bezahl-Gate (Liste der
    Domains) und für die Auswertung (Verlauf mit Zeitpunkt und Anlass).
    via ist einer von: free, key, credit, owner, paket."""
    _stats["scanned_domains"].append(url)
    _stats["scan_log"].append({
        "url": url,
        "at": datetime.now(timezone.utc).isoformat(),
        "via": via,
    })
    _stats["scans_completed"] += 1
    _save_stats()


class StartScanRequest(BaseModel):
    url: str
    promo_owner_code: Optional[str] = None
    key: Optional[str] = None
    lang: str = "de"


class PackageAllocation(BaseModel):
    """Eine Domain und die Anzahl Scans, die ihr aus dem Paket zufallen."""
    url: str
    scans: int


class BuyPackageRequest(BaseModel):
    package: str
    allocations: list[PackageAllocation]
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
            "sales_enabled": SALES_ENABLED,
            "key_shop_url": KEY_SHOP_URL,
            "key_shop_name": KEY_SHOP_NAME,
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
        _record_scan(normalized, "owner")
        return {"mode": "direct", "result": result}

    # 2) Key eingelöst -> Scan unabhängig davon, ob die Domain ihren
    #    kostenlosen Scan schon verbraucht hat. Der Key wird erst NACH dem
    #    erfolgreichen Scan verbucht: stirbt der Scan unterwegs, ist der Key
    #    nicht verloren.
    if payload.key:
        status, bound_url = scan_keys.check(payload.key)
        if status == scan_keys.KeyStatus.UNKNOWN:
            raise HTTPException(status_code=400, detail=t("err.key_unknown", lang))
        if status == scan_keys.KeyStatus.USED:
            raise HTTPException(
                status_code=400,
                detail=t("err.key_used", lang, url=urlparse(bound_url or "").netloc or "?"),
            )
        result = await run_scan(normalized, lang)
        scan_keys.redeem(payload.key, normalized)
        left = scan_keys.stats()["left"]
        result["_notice"] = t("notice.key_redeemed", lang, left=left)
        _record_scan(normalized, "key")
        return {"mode": "direct", "result": result}

    # 3) Diese Domain wurde noch nie gescannt -> erster Scan ist gratis
    if normalized not in _stats["scanned_domains"]:
        result = await run_scan(normalized, lang)
        result["_notice"] = t("notice.first_free_key", lang)
        _record_scan(normalized, "free")
        return {"mode": "direct", "result": result}

    # 4) Domain wurde bereits gescannt -> vorhandenes Guthaben DIESER Domain
    #    verbrauchen, sonst zur Paket-Auswahl auffordern
    credits = _stats["credits"].get(normalized, 0)
    if credits > 0:
        result = await run_scan(normalized, lang)
        _stats["credits"][normalized] = credits - 1
        _record_scan(normalized, "credit")
        result["_notice"] = t("notice.credit_used", lang, remaining=credits - 1)
        return {"mode": "direct", "result": result}

    # 5) Kein Gratis-Scan, kein Guthaben, kein Key -> es braucht einen Key.
    #    Solange der Verkauf aus ist, gibt es keine Paket-Auswahl mehr.
    if not SALES_ENABLED:
        return {"mode": "need_key", "message": t("notice.need_key", lang)}

    return {
        "mode": "choose_package",
        "packages": {k: {"scans": v["scans"], "eur": v["eur"]} for k, v in SCAN_PACKAGES.items()},
    }


@app.post("/api/buy-package")
async def api_buy_package(payload: BuyPackageRequest):
    if not SALES_ENABLED:
        raise HTTPException(status_code=403, detail=t("err.sales_disabled", resolve_lang(payload.lang)))
    if payload.package not in SCAN_PACKAGES:
        raise HTTPException(status_code=400, detail="Ungültiges Paket")

    lang = resolve_lang(payload.lang)
    total_scans = SCAN_PACKAGES[payload.package]["scans"]

    if not payload.allocations:
        raise HTTPException(status_code=400, detail=t("err.alloc_empty", lang))

    # Serverseitig gegenpruefen statt dem Browser zu vertrauen: sonst liesse
    # sich mit einer manipulierten Anfrage mehr Guthaben buchen als bezahlt.
    normalized: list[tuple[str, int]] = []
    seen: set[str] = set()
    for entry in payload.allocations:
        try:
            url = normalize_url(entry.url)
        except ValueError:
            raise HTTPException(status_code=400, detail=t("err.alloc_bad_url", lang, url=entry.url[:80]))
        if entry.scans < 1:
            raise HTTPException(status_code=400, detail=t("err.alloc_min_one", lang, url=url))
        if url in seen:
            raise HTTPException(status_code=400, detail=t("err.alloc_duplicate", lang, url=url))
        seen.add(url)
        normalized.append((url, entry.scans))

    assigned = sum(n for _, n in normalized)
    if assigned != total_scans:
        raise HTTPException(
            status_code=400,
            detail=t("err.alloc_sum", lang, assigned=assigned, total=total_scans),
        )

    try:
        session = create_package_checkout_session(normalized, payload.package, lang)
    except AllocationTooLargeError:
        raise HTTPException(status_code=400, detail=t("err.alloc_too_long", lang))
    return {"mode": "redirect", **session}


@app.get("/scan/result", response_class=HTMLResponse)
async def scan_result_page(request: Request, session_id: Optional[str] = None, lang: Optional[str] = None):
    resolved_lang = resolve_lang(lang or request.headers.get("accept-language"))
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stripe_configured": is_stripe_configured(),
            "sales_enabled": SALES_ENABLED,
            "key_shop_url": KEY_SHOP_URL,
            "key_shop_name": KEY_SHOP_NAME,
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

    # Der erste Eintrag der Aufteilung wird sofort gescannt, der Rest wird als
    # Guthaben je Domain gutgeschrieben. Genau ein Scan des Pakets ist damit
    # direkt verbraucht.
    allocations = paid.allocations or [(paid.store_url, paid.scans_granted)]
    first_url, first_scans = allocations[0]

    result = await run_scan(first_url, paid.lang)

    for url, scans in allocations:
        extra = scans - 1 if url == first_url else scans
        if extra > 0:
            _stats["credits"][url] = _stats["credits"].get(url, 0) + extra

    if len(allocations) > 1:
        overview = " · ".join(
            f"{urlparse(u).netloc}: {_stats['credits'].get(u, 0)}" for u, _ in allocations
        )
        result["_notice"] = t("notice.package_bought_split", paid.lang, overview=overview)
    elif first_scans > 1:
        result["_notice"] = t("notice.package_bought", paid.lang, remaining=_stats["credits"].get(first_url, 0))

    cache_result(session_id, result)
    _record_scan(first_url, "paket")
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
    from collections import Counter
    from datetime import timedelta

    log = _stats.get("scan_log", [])
    now = datetime.now(timezone.utc)

    def _within(days: int) -> list:
        grenze = now - timedelta(days=days)
        out = []
        for e in log:
            if not e.get("at"):
                continue  # Altbestand ohne Zeitpunkt zaehlt nicht mit
            try:
                if datetime.fromisoformat(e["at"]) >= grenze:
                    out.append(e)
            except ValueError:
                continue
        return out

    def _auswertung(days: int) -> dict:
        eintraege = _within(days)
        zaehler = Counter(urlparse(e["url"]).netloc.lower().removeprefix("www.") for e in eintraege)
        return {
            "scans": len(eintraege),
            "domains": len(zaehler),
            "je_domain": dict(zaehler.most_common()),
        }

    return {
        **{k: v for k, v in _stats.items() if k not in ("scanned_domains", "scan_log", "credits")},
        "letzte_7_tage": _auswertung(7),
        "letzte_30_tage": _auswertung(30),
        "letzte_scans": list(reversed(log))[:25],
        "ohne_zeitstempel": sum(1 for e in log if not e.get("at")),
        "unique_domains_scanned": len(set(domains)),
        "most_recent_domains": recent,
        "domains_with_credit": len([1 for c in _stats["credits"].values() if c > 0]),
        "note": "Wird auf einer Render Persistent Disk gespeichert (falls gemountet) und übersteht damit Deploys/Neustarts.",
    }


@app.get("/healthz")
async def healthz():
    return JSONResponse({"status": "ok"})
