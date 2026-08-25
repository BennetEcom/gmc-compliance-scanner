"""
Stripe-Checkout für den GMC Compliance Scan.

Ablauf:
  1. Nutzer gibt Shop-URL ein -> POST /api/checkout
  2. Wir legen eine Stripe Checkout Session an (10 EUR, einmalig),
     mit allow_promotion_codes=True -> Nutzer kann im Stripe-Checkout
     einen Rabattcode eingeben (z.B. dein 100%-Owner-Code).
  3. Die Ziel-URL wird als Metadata an die Session gehängt.
  4. Nach erfolgreicher Zahlung leitet Stripe zurück auf
     /scan/result?session_id=... -> wir verifizieren payment_status == 'paid'
     (oder amount_total == 0 bei 100%-Rabatt) und starten erst DANN den Scan.

In-Memory Cache verhindert doppelten Scan/Mehrfachnutzung derselben Session.
"""

import stripe

from app.config import (
    STRIPE_SECRET_KEY,
    STRIPE_PRICE_ID,
    APP_BASE_URL,
)

stripe.api_key = STRIPE_SECRET_KEY

# session_id -> scan result dict (einfacher In-Memory-Cache, reicht für einen
# einzelnen Render-Worker; für mehrere Instanzen ggf. durch Redis ersetzen)
_scan_cache: dict[str, dict] = {}


def is_stripe_configured() -> bool:
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)


def create_checkout_session(store_url: str) -> dict:
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        allow_promotion_codes=True,
        success_url=f"{APP_BASE_URL}/scan/result?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{APP_BASE_URL}/?canceled=1",
        metadata={"store_url": store_url},
    )
    return {"checkout_url": session.url, "session_id": session.id}


def verify_paid_session(session_id: str) -> str | None:
    """Gibt die gescannte store_url zurück, wenn die Session bezahlt (oder durch
    100%-Promo-Code auf 0 reduziert) wurde, sonst None."""
    session = stripe.checkout.Session.retrieve(session_id)
    paid_or_free = session.payment_status in ("paid", "no_payment_required")
    if not paid_or_free:
        return None
    return (session.metadata or {}).get("store_url")


def cache_result(session_id: str, result: dict) -> None:
    _scan_cache[session_id] = result


def get_cached_result(session_id: str) -> dict | None:
    return _scan_cache.get(session_id)
