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

import json
from typing import List, NamedTuple, Optional, Tuple

import stripe

from app.config import STRIPE_SECRET_KEY, APP_BASE_URL, SCAN_PACKAGES
from app.i18n import DEFAULT_LANG, resolve_lang

stripe.api_key = STRIPE_SECRET_KEY

# session_id -> scan result dict (einfacher In-Memory-Cache, reicht für einen
# einzelnen Render-Worker; für mehrere Instanzen ggf. durch Redis ersetzen)
_scan_cache: dict = {}


def is_stripe_configured() -> bool:
    return bool(STRIPE_SECRET_KEY) and all(p["price_id"] for p in SCAN_PACKAGES.values())


# Stripe erlaubt 500 Zeichen je Metadata-Wert. Die Aufteilung reist als
# kompaktes JSON durch den Bezahlvorgang, weil wir nach der Rueckkehr aus
# dem Checkout keine andere verlaessliche Quelle dafuer haben.
STRIPE_METADATA_VALUE_LIMIT = 500


class AllocationTooLargeError(ValueError):
    """Die Domain-Aufteilung passt nicht in die Stripe-Metadaten."""


def _serialize_allocations(allocations: List[Tuple[str, int]]) -> str:
    return json.dumps([[u, n] for u, n in allocations], separators=(",", ":"))


def create_package_checkout_session(
    allocations: List[Tuple[str, int]], package: str, lang: str = DEFAULT_LANG
) -> dict:
    """allocations ist eine Liste (store_url, anzahl_scans). Die Summe muss
    der Paketgroesse entsprechen; das prueft der Aufrufer in main.py."""
    pkg = SCAN_PACKAGES[package]
    packed = _serialize_allocations(allocations)
    if len(packed) > STRIPE_METADATA_VALUE_LIMIT:
        raise AllocationTooLargeError(len(packed))

    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": pkg["price_id"], "quantity": 1}],
        allow_promotion_codes=True,
        success_url=f"{APP_BASE_URL}/scan/result?session_id={{CHECKOUT_SESSION_ID}}&lang={lang}",
        cancel_url=f"{APP_BASE_URL}/?canceled=1",
        metadata={
            # store_url bleibt erhalten: aeltere, noch offene Checkout-Sessions
            # ohne allocations muessen weiter einloesbar sein.
            "store_url": allocations[0][0],
            "lang": lang,
            "scans_granted": str(pkg["scans"]),
            "allocations": packed,
        },
    )
    return {"checkout_url": session.url, "session_id": session.id}


class PaidSession(NamedTuple):
    store_url: Optional[str]
    lang: str
    scans_granted: int
    allocations: List[Tuple[str, int]]


def verify_paid_session(session_id: str) -> PaidSession:
    """Liest Store-URLs, Sprache und gekaufte Scan-Anzahl aus der Session, wenn
    sie bezahlt (oder durch 100%-Promo-Code auf 0 reduziert) wurde. store_url
    ist None, wenn (noch) nicht bezahlt."""
    session = stripe.checkout.Session.retrieve(session_id)
    meta = session.metadata or {}
    lang = resolve_lang(meta.get("lang"))
    paid_or_free = session.payment_status in ("paid", "no_payment_required")
    if not paid_or_free:
        return PaidSession(None, lang, 0, [])

    store_url = meta.get("store_url")
    scans_granted = int(meta.get("scans_granted", 1))

    allocations: List[Tuple[str, int]] = []
    raw = meta.get("allocations")
    if raw:
        try:
            allocations = [(str(u), int(n)) for u, n in json.loads(raw)]
        except (ValueError, TypeError):
            allocations = []
    if not allocations and store_url:
        # Sessions aus der Zeit vor der Mehrfach-Domain-Aufteilung
        allocations = [(store_url, scans_granted)]

    return PaidSession(store_url, lang, scans_granted, allocations)


def cache_result(session_id: str, result: dict) -> None:
    _scan_cache[session_id] = result


def get_cached_result(session_id: str) -> Optional[dict]:
    return _scan_cache.get(session_id)
