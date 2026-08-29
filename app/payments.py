"""
Stripe-Checkout für GMC-Compliance-Scan-Pakete.

Ablauf:
  1. Erster Scan pro Domain ist immer kostenlos (siehe main.py).
  2. Jeder weitere Scan verlangt entweder vorhandenes Scan-Guthaben für GENAU
     DIESE Domain (siehe main.py: _stats["credits"][store_url]) oder den Kauf
     eines Pakets (2/5/10 Scans) über Stripe Checkout. Ein gekauftes Paket
     gilt bewusst nur für die Domain, für die es gekauft wurde, nicht
     domainübergreifend.
  3. Store-URL, Sprache und Anzahl gekaufter Scans werden als Metadata an die
     Checkout Session gehängt.
  4. Nach erfolgreicher Zahlung leitet Stripe zurück auf
     /scan/result?session_id=... -> wir verifizieren payment_status == 'paid'
     (oder amount_total == 0 bei 100%-Rabatt), führen DANN den ersten Scan
     des Pakets aus und schreiben die restlichen Scans als Guthaben für diese
     Domain gut.

In-Memory Cache verhindert doppelten Scan/Mehrfachnutzung derselben Session.
"""

from typing import NamedTuple, Optional

import stripe

from app.config import STRIPE_SECRET_KEY, APP_BASE_URL, SCAN_PACKAGES
from app.i18n import DEFAULT_LANG, resolve_lang

stripe.api_key = STRIPE_SECRET_KEY

# session_id -> scan result dict (einfacher In-Memory-Cache, reicht für einen
# einzelnen Render-Worker; für mehrere Instanzen ggf. durch Redis ersetzen)
_scan_cache: dict = {}


def is_stripe_configured() -> bool:
    return bool(STRIPE_SECRET_KEY) and all(p["price_id"] for p in SCAN_PACKAGES.values())


def create_package_checkout_session(store_url: str, package: str, lang: str = DEFAULT_LANG) -> dict:
    pkg = SCAN_PACKAGES[package]
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": pkg["price_id"], "quantity": 1}],
        allow_promotion_codes=True,
        success_url=f"{APP_BASE_URL}/scan/result?session_id={{CHECKOUT_SESSION_ID}}&lang={lang}",
        cancel_url=f"{APP_BASE_URL}/?canceled=1",
        metadata={
            "store_url": store_url,
            "lang": lang,
            "scans_granted": str(pkg["scans"]),
        },
    )
    return {"checkout_url": session.url, "session_id": session.id}


class PaidSession(NamedTuple):
    store_url: Optional[str]
    lang: str
    scans_granted: int


def verify_paid_session(session_id: str) -> PaidSession:
    """Liest Store-URL, Sprache und gekaufte Scan-Anzahl aus der Session, wenn
    sie bezahlt (oder durch 100%-Promo-Code auf 0 reduziert) wurde. store_url
    ist None, wenn (noch) nicht bezahlt."""
    session = stripe.checkout.Session.retrieve(session_id)
    meta = session.metadata or {}
    lang = resolve_lang(meta.get("lang"))
    paid_or_free = session.payment_status in ("paid", "no_payment_required")
    if not paid_or_free:
        return PaidSession(None, lang, 0)
    return PaidSession(meta.get("store_url"), lang, int(meta.get("scans_granted", 1)))


def cache_result(session_id: str, result: dict) -> None:
    _scan_cache[session_id] = result


def get_cached_result(session_id: str) -> Optional[dict]:
    return _scan_cache.get(session_id)
