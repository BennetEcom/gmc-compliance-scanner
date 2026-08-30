"""
GMC Compliance Scanner
=======================
Führt echte, live Checks gegen einen Shopify-Store (oder generisch jede
Website) durch und bewertet die Wahrscheinlichkeit einer Google Merchant
Center (GMC) Sperrung anhand von 8 Kategorien. Die Checks sind gegen die
"GMC Master Checklist" des Betreibers abgeglichen (Kategorien A-H davon,
soweit ohne GMC-Login automatisiert prüfbar):

1. Trust & Domain-Metriken (SSL, Domain-Alter, Erreichbarkeit)
2. Broken Links (über die gesamte per Sitemap erkannte Seite, nicht nur die Startseite)
3. Policy-Seiten (Impressum, Datenschutz, AGB, Widerruf, Versand, Kontakt, Über uns,
   FAQ, Zahlungsarten, Sendungsverfolgung) - inklusive Inhaltsprüfung: eine leere
   oder unvollständige Pflichtseite zählt wie eine fehlende
4. Kontakt & Rechtliches (geschäftliche E-Mail, Telefon, vollständige Adresse,
   NAP-Konsistenz über E-Mail/Telefon/PLZ, Kontaktwege + Servicezeiten auf einer
   Seite, Platzhalter-Content, Standard-URLs, Klickbarkeit)
5. Produkt-Feed-Qualität (GTIN inkl. Prüfziffer, Brand, Preis, SKU, Streichpreis,
   Condition, Farb-/Größen-Variantenattribute, Verfügbarkeit, Produktkategorie,
   Wirkversprechen, Materialangaben, doppelte Beschreibungen, leere Nav-Kollektionen)
6. Bild-Compliance (Auflösung, erreichbar, Dubletten, Anzahl pro Produkt, Gewicht,
   Lieferanten-CDN)
7. Bewertungen & Social Proof (verifizierbare Plattform vs. nicht nachprüfbare/duplizierte Reviews)
8. Künstliche Dringlichkeit/Verknappung ("Fake Urgency": Countdown-Apps, "nur noch X"-Behauptungen ohne echten Lagerbestand)
9. Trust-Red-Flags (Fake-Trust-Badges, Presse-/Partner-Claims ohne Beleg, Popup-Apps,
   Bestseller-Auszeichnungen ohne Datenbasis)
10. Technik & Google-Signale (Google-Site-Verification, Startseiten-Titel, Theme-Fehler,
    Footer auf jeder Seite, schema.org-Preis/Verfügbarkeit gegen die Shop-Daten)
11. Page Speed (eigene Messung: Ladezeit + HTML-Größe der Startseite, ohne externe API)

Nicht prüfbar und deshalb im Report ausdrücklich als solches ausgewiesen: alles, was
einen Merchant-Center-Login braucht (Kategorie I der Checkliste) sowie die
Betreiber-Selbstauskunft (Kategorie J).

Kein Login nötig, keine Datenspeicherung – alles läuft pro Request live.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

try:
    import whois as pywhois
except Exception:  # pragma: no cover
    pywhois = None

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

from app.i18n import DEFAULT_LANG, more_suffix, t

# Viele Shopify-Stores blocken generische Scraper-User-Agents per Firewall
# (403). Ein realistischer Browser-UA + Standard-Browser-Header reduzieren
# False-Positives ("Shop nicht erreichbar", obwohl er es ist) deutlich.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
}

REQUEST_TIMEOUT = httpx.Timeout(10.0, connect=6.0)

# Viele Shops haben Bot-/Rate-Limit-Schutz, der bei zu vielen gleichzeitigen
# Anfragen von derselben IP legitime Seiten fälschlich blockiert. Wir
# begrenzen deshalb, wie viele Requests gleichzeitig rausgehen, statt alle
# Links auf einmal abzufeuern. Lazy erzeugt (statt beim Modul-Import), damit
# das Semaphore garantiert an den tatsächlich laufenden Event-Loop gebunden
# wird, nicht an einen zur Import-Zeit ggf. noch nicht existierenden.
_http_concurrency: Optional[asyncio.Semaphore] = None
_http_concurrency_loop: Optional[asyncio.AbstractEventLoop] = None


def _get_http_concurrency() -> asyncio.Semaphore:
    """Ein asyncio.Semaphore ist an den Event-Loop gebunden, in dem es zum
    ersten Mal benutzt wird. Wird der Loop ersetzt - Worker-Neustart, ein
    Skript mit mehreren asyncio.run()-Aufrufen, Tests - wirft das gecachte
    Semaphore "attached to a different loop". Deshalb merken wir uns den Loop
    und legen bei einem Wechsel ein frisches an."""
    global _http_concurrency, _http_concurrency_loop
    loop = asyncio.get_running_loop()
    if _http_concurrency is None or _http_concurrency_loop is not loop:
        _http_concurrency = asyncio.Semaphore(4)
        _http_concurrency_loop = loop
    return _http_concurrency

# --- Policy-Seiten: Keywords, nach denen wir in Footer-Links & URLs suchen ---
POLICY_PATTERNS = {
    "impressum": {
        "label_key": "policy.impressum",
        "keywords": ["impressum", "legal-notice", "legal notice", "imprint"],
        "severity": "critical",
    },
    "privacy": {
        "label_key": "policy.privacy",
        "keywords": ["datenschutz", "privacy-policy", "privacy policy", "privacypolicy"],
        "severity": "critical",
    },
    "terms": {
        "label_key": "policy.terms",
        "keywords": ["agb", "terms-of-service", "terms-and-conditions", "terms of service", "nutzungsbedingungen"],
        "severity": "high",
    },
    "refund": {
        "label_key": "policy.refund",
        "keywords": ["widerruf", "ruckgabe", "rückgabe", "refund-policy", "return-policy", "refund policy", "return policy"],
        "severity": "critical",
    },
    "shipping": {
        "label_key": "policy.shipping",
        "keywords": ["versand", "shipping-policy", "shipping policy", "lieferzeit", "delivery"],
        "severity": "medium",
    },
    "contact": {
        "label_key": "policy.contact",
        "keywords": ["kontakt", "contact-us", "contact us", "contact"],
        "severity": "high",
    },
    # Kategorie C der Master-Checklist verlangt diese Seiten ebenfalls -
    # sie fehlten bisher komplett und wurden nur als 404-Sonde mitgeprueft.
    "about": {
        "label_key": "policy.about",
        "keywords": ["ueber uns", "über uns", "about-us", "about us", "unsere geschichte", "our story"],
        "severity": "medium",
    },
    "faq": {
        "label_key": "policy.faq",
        "keywords": ["faq", "haeufige fragen", "häufige fragen", "fragen und antworten", "hilfe", "help center"],
        "severity": "medium",
    },
    "payment": {
        "label_key": "policy.payment",
        "keywords": ["zahlung", "zahlungsarten", "zahlungsbedingungen", "payment-policy", "payment policy", "billing terms"],
        "severity": "medium",
    },
    "track_order": {
        "label_key": "policy.track_order",
        "keywords": ["sendungsverfolgung", "bestellung verfolgen", "track-order", "track your order", "track order", "paket verfolgen"],
        "severity": "low",
    },
}

MIN_TRUSTED_DOMAIN_AGE_DAYS = 90  # unter 3 Monate = klassisches Dropshipping-Rot-Flag
MIN_IMAGE_EDGE_PX = 250
RECOMMENDED_IMAGE_EDGE_PX = 800
MAX_LINKS_TO_CHECK = 1000  # praktisch ungedeckelt: alle gefundenen Seiten werden geprüft, nichts wird übersprungen
MAX_PRODUCTS_TO_SAMPLE = 25
MAX_PRODUCT_PAGES_TO_FETCH = 18
MAX_SITEMAP_ENTRIES = 500

# --- Bekannte, seriöse Bewertungs-Plattformen (Script-/Domain-Signaturen) ---
# Wird ein solcher Anbieter erkannt, gelten angezeigte Sternebewertungen als
# über Dritte verifizierbar (Google verlangt genau das für Testimonials/Reviews).
KNOWN_REVIEW_PLATFORMS = {
    "judge.me": "Judge.me",
    "loox.io": "Loox",
    "loox.app": "Loox",
    "stamped.io": "Stamped.io",
    "yotpo.com": "Yotpo",
    "okendo.io": "Okendo",
    "trustpilot.com": "Trustpilot",
    "reviews.io": "Reviews.io",
    "fera.ai": "Fera",
    "ryviu.com": "Ryviu",
    "opinew.com": "Opinew",
    "google.com/shopping/consumer": "Google Customer Reviews",
    "verified-reviews.com": "Avis Vérifiés / Verified Reviews",
}

# --- Text-Muster für künstliche Dringlichkeit / Verknappung ---
# Google Ads "Misrepresentation"-Richtlinie verbietet u.a. vorgetäuschte
# Knappheit ("nur noch X verfügbar") und falsche Countdown-Timer.
URGENCY_TEXT_PATTERNS = [
    r"nur noch\s+\d+\s*(stück|st\.?|auf lager|verfügbar|übrig)",
    r"only\s+\d+\s*(left|in stock|remaining)",
    r"noch\s+\d+\s*(stück|auf lager)\s*verfügbar",
    r"\d+\s*(people|personen)\s*(kaufen|schauen|viewing|bought)",
    r"angebot endet in",
    r"deal ends in",
    r"nur noch heute",
    r"fast ausverkauft",
    r"selling fast",
    r"selling out",
    r"limited time (offer|only)",
    r"\d+\s*%\s*(bereits\s*)?verkauft",
]

# --- Bekannte Shopify-Apps für künstliche Dringlichkeit/Countdowns ---
URGENCY_APP_SIGNATURES = [
    "hurrify", "fomo.com", "salespop", "sales-pop", "countdown-cart",
    "ultimatesalesboost", "zoorix", "kaching-bundles", "hextom",
    "countdown-timer-bar", "cartcountdown",
]

# --- Aus der GMC-Master-Checklist (Kategorie C/E): Kontakt- & Rechtstexte ---
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.de", "hotmail.com",
    "hotmail.de", "outlook.com", "outlook.de", "gmx.de", "gmx.net", "web.de",
    "icloud.com", "aol.com", "t-online.de",
}
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(\+?\d[\d\s()/\-]{7,}\d)")

# Platzhalter-/Template-Reste, die laut Google-Support-Ticket (misrep 2026-07)
# explizit als Ablehnungsgrund genannt wurden.
PLACEHOLDER_PATTERNS = [
    r"\[[a-z0-9 _\-]{2,40}\]",  # [Firmenname], [Adresse] etc.
    r"lorem ipsum",
    r"you@email\.com",
    r"example\.com",
    r"sample order",
    r"john\s?doe",
    r"123 main st",
    r"your company name",
    r"yourname@",
]

# Häufig unlinkte, aber von Google-Reviewern erratene Standard-URLs – müssen
# auf eine echte Seite weiterleiten, dürfen niemals auf einem 404 enden.
GUESSED_PATHS = [
    "/pages/contact-us", "/pages/get-in-touch", "/pages/contact",
    "/pages/about-us", "/pages/shipping", "/pages/shipping-policy",
    "/pages/faq", "/pages/returns",
]

USED_CONDITION_KEYWORDS = [
    "refurbished", "second-hand", "secondhand", "pre-owned", "preowned",
    "gebraucht", "generalüberholt", "occasion",
]


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("Ungültige URL")
    return f"{parsed.scheme}://{parsed.netloc}"


def domain_key(raw: str) -> str:
    """Kanonischer Schlüssel für "ein Store" – Grundlage für das Bezahl-Gate
    und für gekauftes Guthaben.

    normalize_url() behält Schema und Port und liefert deshalb für ein und
    denselben Shop mehrere verschiedene Zeichenketten:
    https://shop.de, http://shop.de, https://www.shop.de und
    https://shop.de:443 wären vier Schlüssel – und damit vier Gratis-Scans.
    Hier bleibt nur der Host übrig: klein geschrieben, ohne Standard-Port,
    ohne führendes "www." und ohne abschließenden Punkt der DNS-Wurzel.
    """
    parsed = urlparse(normalize_url(raw))
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    port = parsed.port
    if port and port not in (80, 443):
        return f"{host}:{port}"
    return host


@dataclass
class Finding:
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str


@dataclass
class CategoryResult:
    key: str
    label: str
    score: int  # 0-100
    status: str = field(init=False)  # green/yellow/red
    findings: list = field(default_factory=list)

    def __post_init__(self):
        if self.score >= 80:
            self.status = "green"
        elif self.score >= 50:
            self.status = "yellow"
        else:
            self.status = "red"

    def to_dict(self):
        return {
            "key": self.key,
            "label": self.label,
            "score": self.score,
            "status": self.status,
            "findings": [f.__dict__ for f in self.findings],
        }


async def fetch(client: httpx.AsyncClient, url: str, method: str = "GET", timeout: Optional[httpx.Timeout] = None, **kw):
    async with _get_http_concurrency():
        try:
            resp = await client.request(method, url, timeout=timeout or REQUEST_TIMEOUT, follow_redirects=True, **kw)
            return resp
        except Exception as exc:  # noqa: BLE001
            return exc


# ---------------------------------------------------------------------------
# 1) Trust & Domain
# ---------------------------------------------------------------------------
async def check_trust_domain(client: httpx.AsyncClient, base_url: str, lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100
    parsed = urlparse(base_url)
    host = parsed.netloc

    # HTTPS erreichbar?
    resp = await fetch(client, base_url)
    if isinstance(resp, Exception):
        findings.append(Finding("critical", t("trust.unreachable_title", lang),
                                 t("trust.unreachable_detail_exc", lang, error=resp)))
        score -= 60
    elif resp.status_code == 403:
        findings.append(Finding("info", t("trust.bot_blocked_title", lang),
                                 t("trust.bot_blocked_detail", lang)))
    elif resp.status_code >= 400:
        findings.append(Finding("critical", t("trust.unreachable_title", lang),
                                 t("trust.unreachable_detail_status", lang, status=resp.status_code)))
        score -= 60
    else:
        if str(resp.url).startswith("https://"):
            findings.append(Finding("info", t("trust.https_active_title", lang), t("trust.https_active_detail", lang)))
        else:
            findings.append(Finding("critical", t("trust.no_https_title", lang), t("trust.no_https_detail", lang)))
            score -= 30

    # SSL-Zertifikat Details (Ablaufdatum)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(Finding("critical", t("trust.ssl_expired_title", lang), t("trust.ssl_expired_detail", lang, days=abs(days_left))))
            score -= 30
        elif days_left < 14:
            findings.append(Finding("medium", t("trust.ssl_expiring_title", lang), t("trust.ssl_expiring_detail", lang, days=days_left)))
            score -= 10
        else:
            findings.append(Finding("info", t("trust.ssl_valid_title", lang), t("trust.ssl_valid_detail", lang, days=days_left)))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding("info", t("trust.ssl_unchecked_title", lang), t("trust.ssl_unchecked_detail", lang, error=exc)))

    # Domain-Alter via WHOIS
    domain_age_days: Optional[int] = None
    if pywhois is not None:
        try:
            w = await asyncio.to_thread(pywhois.whois, host)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - created).days
        except Exception:
            domain_age_days = None

    if domain_age_days is None:
        findings.append(Finding("info", t("trust.domain_age_unknown_title", lang), t("trust.domain_age_unknown_detail", lang)))
    elif domain_age_days < MIN_TRUSTED_DOMAIN_AGE_DAYS:
        findings.append(Finding("high", t("trust.domain_young_title", lang),
                                 t("trust.domain_young_detail", lang, days=domain_age_days)))
        score -= 20
    else:
        findings.append(Finding("info", t("trust.domain_age_ok_title", lang), t("trust.domain_age_ok_detail", lang, days=domain_age_days)))

    score = max(0, min(100, score))
    return CategoryResult("trust", t("cat.trust", lang), score, findings)


# ---------------------------------------------------------------------------
# Seiten-Erkennung: nicht nur Startseite, sondern möglichst der ganze Shop
# ---------------------------------------------------------------------------
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


async def _fetch_sitemap_locs(client: httpx.AsyncClient, sitemap_url: str) -> list[str]:
    resp = await fetch(client, sitemap_url)
    if isinstance(resp, Exception) or resp.status_code >= 400:
        return []
    return _LOC_RE.findall(resp.text)[:MAX_SITEMAP_ENTRIES]


async def discover_site_urls(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str]) -> dict:
    """Sammelt möglichst alle Seiten des Shops (nicht nur die Startseite):
    zuerst über die Shopify-Sitemap (sitemap.xml -> sitemap_pages/products/
    collections_*.xml), sonst Fallback über Homepage-Links + products.json.
    Gibt {"all": [...], "product_urls": [...], "total_discovered": int} zurück.
    """
    host = urlparse(base_url).netloc
    all_urls: set[str] = set()
    product_urls: set[str] = set()

    index_locs = await _fetch_sitemap_locs(client, urljoin(base_url + "/", "sitemap.xml"))
    sub_sitemaps = [
        loc for loc in index_locs
        if any(k in loc for k in ("sitemap_pages", "sitemap_products", "sitemap_collections"))
    ][:8]

    if sub_sitemaps:
        results = await asyncio.gather(*(_fetch_sitemap_locs(client, sm) for sm in sub_sitemaps))
        for sm_url, locs in zip(sub_sitemaps, results):
            for loc in locs:
                if urlparse(loc).netloc == host:
                    all_urls.add(loc)
                    if "/products/" in loc:
                        product_urls.add(loc)

    # Fallback / Ergänzung: Homepage-Links direkt einsammeln
    if homepage_html:
        soup = BeautifulSoup(homepage_html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(base_url + "/", href)
            if urlparse(full).netloc == host:
                all_urls.add(full)
                if "/products/" in full:
                    product_urls.add(full)

    # Fallback: products.json, falls Sitemap keine Produkte lieferte
    if not product_urls:
        resp = await fetch(client, urljoin(base_url, "/products.json?limit=" + str(MAX_PRODUCTS_TO_SAMPLE)))
        if not isinstance(resp, Exception) and resp.status_code < 400:
            try:
                for p in resp.json().get("products", [])[:MAX_PRODUCTS_TO_SAMPLE]:
                    handle = p.get("handle")
                    if handle:
                        url = urljoin(base_url + "/", f"products/{handle}")
                        all_urls.add(url)
                        product_urls.add(url)
            except Exception:
                pass

    total_discovered = len(all_urls)
    return {
        "all": list(all_urls)[:MAX_LINKS_TO_CHECK],
        "product_urls": list(product_urls)[:MAX_PRODUCT_PAGES_TO_FETCH],
        "total_discovered": total_discovered,
    }


# ---------------------------------------------------------------------------
# 2) Broken Links (über die gesamte erkannte Seite, nicht nur die Startseite)
# ---------------------------------------------------------------------------
async def check_broken_links(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], site_urls: dict, lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not homepage_html:
        findings.append(Finding("info", t("links.unavailable_title", lang), t("links.unavailable_detail", lang)))
        return CategoryResult("broken_links", t("cat.broken_links", lang), 100, findings)

    links = list(site_urls.get("all", []))
    total_discovered = site_urls.get("total_discovered", len(links))

    # Nur ein echtes "404 Not Found" gilt als Broken Link – wie bei
    # deadlinkchecker.com & Co. Alle anderen Fehlerstatus (403/429/5xx,
    # Timeouts) werden separat ausgewiesen statt fälschlich mitgezählt zu
    # werden, z. B. weil ein Scan selbst ein Rate-Limit auslöst.
    CONFIRMED_BROKEN_STATUSES = {404}

    broken: list[tuple[str, object]] = []
    other_errors: list[tuple[str, object]] = []

    async def classify(url: str):
        async def attempt(method: str):
            resp = await fetch(client, url, method=method)
            if isinstance(resp, Exception):
                return "error"
            if resp.status_code >= 400:
                return resp.status_code
            return None

        status = await attempt("HEAD")
        if status is None:
            return
        status = await attempt("GET")
        if status is None:
            return
        # Zwei Fehlversuche direkt hintereinander können ein Rate-Limit-Blip
        # sein – mit steigendem Abstand nochmal gegenprüfen, bevor wir urteilen.
        for delay in (1.5, 3.0):
            await asyncio.sleep(delay)
            status = await attempt("GET")
            if status is None:
                return

        if status in CONFIRMED_BROKEN_STATUSES:
            broken.append((url, status))
        else:
            other_errors.append((url, status))

    await asyncio.gather(*(classify(u) for u in links))

    coverage_note = (
        t("links.coverage_note", lang, checked=len(links), total=total_discovered, max_entries=MAX_SITEMAP_ENTRIES)
        if total_discovered > len(links) else ""
    )

    if links:
        ratio_broken = len(broken) / len(links)
        score = round(100 * (1 - ratio_broken))

        if broken:
            shown = broken[:25]
            preview = "\n".join(f"• {u}" for u, _ in shown)
            if len(broken) > len(shown):
                preview += more_suffix(len(broken) - len(shown), lang)
            findings.append(Finding(
                "high" if ratio_broken > 0.15 else "medium",
                t("links.broken_found_title", lang, broken=len(broken), total=len(links), coverage=coverage_note),
                preview,
            ))
        elif not other_errors:
            findings.append(Finding("info", t("links.none_broken_title", lang), t("links.none_broken_detail", lang, total=len(links), coverage=coverage_note)))
        else:
            findings.append(Finding("info", t("links.no_real_404_title", lang), t("links.no_real_404_detail", lang, total=len(links), coverage=coverage_note)))

        if other_errors:
            shown = other_errors[:15]
            preview = "\n".join(f"• {u} ({status})" for u, status in shown)
            if len(other_errors) > len(shown):
                preview += more_suffix(len(other_errors) - len(shown), lang)
            findings.append(Finding(
                "info", t("links.other_errors_title", lang, count=len(other_errors), total=len(links), coverage=coverage_note),
                t("links.other_errors_detail", lang, preview=preview),
            ))
    else:
        findings.append(Finding("info", t("links.no_internal_links_title", lang), t("links.no_internal_links_detail", lang)))
        score = 100

    return CategoryResult("broken_links", t("cat.broken_links", lang), max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 3) Policy-Seiten
# ---------------------------------------------------------------------------
async def check_policy_pages(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], lang: str = DEFAULT_LANG) -> tuple[CategoryResult, dict[str, str]]:
    findings: list[Finding] = []
    found_keys = set()
    found_urls: dict[str, str] = {}

    link_texts = []
    if homepage_html:
        soup = BeautifulSoup(homepage_html, "html.parser")
        for a in soup.find_all("a", href=True):
            link_texts.append((a.get_text(" ", strip=True).lower(), a["href"]))

    for key, meta in POLICY_PATTERNS.items():
        for text, href in link_texts:
            if any(kw in text for kw in meta["keywords"]) or any(kw.replace(" ", "-") in href.lower() for kw in meta["keywords"]):
                found_keys.add(key)
                found_urls[key] = urljoin(base_url + "/", href)
                break

    # Fallback: gängige Shopify-URL-Pfade direkt testen für nicht gefundene Policies
    guess_paths = {
        "impressum": ["/pages/impressum", "/policies/legal-notice"],
        "privacy": ["/policies/privacy-policy", "/pages/datenschutz"],
        "terms": ["/policies/terms-of-service", "/pages/agb"],
        "refund": ["/policies/refund-policy", "/pages/widerrufsrecht"],
        "shipping": ["/pages/versand", "/pages/shipping"],
        "contact": ["/pages/contact", "/pages/kontakt"],
        "about": ["/pages/about-us", "/pages/ueber-uns", "/pages/about"],
        "faq": ["/pages/faq", "/pages/haeufige-fragen", "/pages/help"],
        "payment": ["/pages/zahlungsarten", "/pages/payment", "/policies/terms-of-sale"],
        "track_order": ["/pages/sendungsverfolgung", "/pages/track-order", "/apps/track123"],
    }

    async def try_guess(key: str):
        if key in found_keys:
            return
        for path in guess_paths.get(key, []):
            url = urljoin(base_url, path)
            resp = await fetch(client, url)
            if not isinstance(resp, Exception) and resp.status_code < 400:
                found_keys.add(key)
                found_urls[key] = url
                return

    await asyncio.gather(*(try_guess(k) for k in POLICY_PATTERNS))

    total_weight = 0
    lost_weight = 0
    weight_by_severity = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    for key, meta in POLICY_PATTERNS.items():
        w = weight_by_severity.get(meta["severity"], 10)
        total_weight += w
        label = t(meta["label_key"], lang)
        if key in found_keys:
            findings.append(Finding("info", t("policy.found_title", lang, label=label), t("policy.found_detail", lang)))
        else:
            lost_weight += w
            findings.append(Finding(meta["severity"], t("policy.missing_title", lang, label=label),
                                     t("policy.missing_detail", lang)))

    score = round(100 * (1 - lost_weight / total_weight)) if total_weight else 100

    # Existenz allein reicht nicht: eine leere oder inhaltlich unvollstaendige
    # Pflichtseite wird von Google wie eine fehlende gewertet (Kategorie C/D).
    content_findings, content_penalty = await check_policy_content(client, found_urls, lang)
    findings.extend(content_findings)
    score -= content_penalty

    return CategoryResult("policy_pages", t("cat.policy_pages", lang), max(0, min(100, score)), findings), found_urls


# ---------------------------------------------------------------------------
# 4) Kontakt & Rechtliches (aus der GMC-Master-Checklist, Kategorie C/E)
# ---------------------------------------------------------------------------
async def check_contact_legal(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], policy_urls: dict[str, str], lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    # Kontakt-/Rechtsseiten zusätzlich laden (Startseite reicht oft nicht für
    # E-Mail/Telefon/NAP-Konsistenz-Checks).
    extra_keys = ("contact", "impressum", "privacy", "about", "terms", "shipping")
    extra_urls = [u for k, u in policy_urls.items() if k in extra_keys]
    extra_pages = await fetch_product_pages(client, extra_urls[:6])  # generischer HTML-Fetch, Name passt trotzdem

    pages_html: dict[str, str] = {"Startseite": homepage_html or ""}
    for url, html in extra_pages:
        pages_html[url] = html

    combined_html = "\n".join(pages_html.values())
    if not combined_html.strip():
        findings.append(Finding("info", t("contact.unavailable_title", lang), t("contact.unavailable_detail", lang)))
        return CategoryResult("contact_legal", t("cat.contact_legal", lang), 100, findings)

    # 1) Geschäftliche E-Mail statt privatem Anbieter
    emails_by_page = {url: set(EMAIL_RE.findall(html)) for url, html in pages_html.items()}
    all_emails = set().union(*emails_by_page.values()) if emails_by_page else set()
    host = urlparse(base_url).netloc.replace("www.", "")
    if all_emails:
        personal = {e for e in all_emails if e.split("@")[-1].lower() in PERSONAL_EMAIL_DOMAINS}
        if personal and len(personal) == len(all_emails):
            findings.append(Finding(
                "medium", t("contact.only_personal_email_title", lang),
                t("contact.only_personal_email_detail", lang, emails=", ".join(sorted(personal)), host=host),
            ))
            score -= 15
        else:
            findings.append(Finding("info", t("contact.business_email_title", lang), f"{', '.join(sorted(all_emails))[:200]}"))
    else:
        findings.append(Finding("high", t("contact.no_email_title", lang), t("contact.no_email_detail", lang)))
        score -= 20

    # 2) Telefonnummer sichtbar
    if not PHONE_RE.search(combined_html):
        findings.append(Finding("medium", t("contact.no_phone_title", lang), t("contact.no_phone_detail", lang)))
        score -= 10
    else:
        findings.append(Finding("info", t("contact.phone_found_title", lang), t("contact.phone_found_detail", lang)))

    # 3) NAP-Konsistenz: identische E-Mail über alle geprüften Seiten hinweg
    non_empty_pages = {url: emails for url, emails in emails_by_page.items() if emails}
    if len(non_empty_pages) >= 2:
        distinct = set().union(*non_empty_pages.values())
        if len(distinct) > 1:
            findings.append(Finding(
                "high", t("contact.nap_mismatch_title", lang),
                t("contact.nap_mismatch_detail", lang, emails=", ".join(sorted(distinct))),
            ))
            score -= 20

    # 4) Platzhalter-/Template-Reste
    lower_combined = combined_html.lower()
    placeholder_hits = {p for p in PLACEHOLDER_PATTERNS if re.search(p, lower_combined)}
    if placeholder_hits:
        findings.append(Finding(
            "critical", t("contact.placeholder_title", lang), t("contact.placeholder_detail", lang),
        ))
        score -= 25

    # 5) Erratbare Standard-Pfade dürfen nicht auf 404 enden
    async def check_guess(path: str):
        resp = await fetch(client, urljoin(base_url, path))
        if isinstance(resp, Exception) or resp.status_code >= 400:
            return path
        return None

    dead_ends = [p for p in await asyncio.gather(*(check_guess(p) for p in GUESSED_PATHS)) if p]
    if dead_ends:
        listing = "\n".join(f"• {base_url}{p}" for p in dead_ends)
        findings.append(Finding(
            "low", t("contact.dead_ends_title", lang, count=len(dead_ends), total=len(GUESSED_PATHS)),
            t("contact.dead_ends_detail", lang, listing=listing),
        ))
        score -= min(10, len(dead_ends) * 2)

    # 6) Adresse, Kontaktwege, Servicezeiten, NAP ueber Telefon + PLZ
    extra_findings, extra_penalty = check_contact_extras(
        pages_html, policy_urls.get("contact"), lang
    )
    findings.extend(extra_findings)
    score -= extra_penalty

    score = max(0, min(100, score))
    return CategoryResult("contact_legal", t("cat.contact_legal", lang), score, findings)


# ---------------------------------------------------------------------------
# 5) Produkt-Feed-Qualität (Shopify products.json)
# ---------------------------------------------------------------------------
MAX_NAV_COLLECTIONS_TO_CHECK = 15
EMPTY_COLLECTION_THRESHOLD = 3


async def check_nav_collections(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], lang: str = DEFAULT_LANG) -> list[Finding]:
    """Prüft im Hauptmenü verlinkte Kollektionen: eine Nav-Kachel, die auf eine
    leere/fast leere Kollektion zeigt, wirkt für Google-Reviewer wie ein
    unfertiger Store (Source: misrep 2026-07, Google-Support-Runde)."""
    if not homepage_html:
        return []

    soup = BeautifulSoup(homepage_html, "html.parser")
    handles: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        m = re.search(r"/collections/([a-z0-9\-]+)", href, re.I)
        if m and m.group(1) not in ("all", "frontpage"):
            handles.add(m.group(1))
    handles = list(handles)[:MAX_NAV_COLLECTIONS_TO_CHECK]

    if not handles:
        return []

    empty: list[str] = []

    async def check_one(handle: str):
        resp = await fetch(client, urljoin(base_url, f"/collections/{handle}/products.json?limit=10"))
        if isinstance(resp, Exception) or resp.status_code >= 400:
            return
        try:
            count = len(resp.json().get("products", []))
        except Exception:
            return
        if count <= EMPTY_COLLECTION_THRESHOLD:
            empty.append(f"{handle} ({count})")

    await asyncio.gather(*(check_one(h) for h in handles))

    if not empty:
        return []
    return [Finding(
        "medium", t("feed.empty_collections_title", lang, count=len(empty), threshold=EMPTY_COLLECTION_THRESHOLD),
        t("feed.empty_collections_detail", lang, list=", ".join(empty)),
    )]


async def check_product_feed(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str] = None, lang: str = DEFAULT_LANG) -> tuple[CategoryResult, list[dict]]:
    findings: list[Finding] = []
    products_sample: list[dict] = []
    score = 100

    resp = await fetch(client, urljoin(base_url, "/products.json?limit=" + str(MAX_PRODUCTS_TO_SAMPLE)))
    if isinstance(resp, Exception) or resp.status_code >= 400:
        findings.append(Finding("info", t("feed.no_feed_title", lang), t("feed.no_feed_detail", lang)))
        return CategoryResult("product_feed", t("cat.product_feed", lang), 100, findings), products_sample

    try:
        data = resp.json()
        products = data.get("products", [])[:MAX_PRODUCTS_TO_SAMPLE]
    except Exception:
        findings.append(Finding("info", t("feed.unparseable_title", lang), t("feed.unparseable_detail", lang)))
        return CategoryResult("product_feed", t("cat.product_feed", lang), 100, findings), products_sample

    if not products:
        findings.append(Finding("info", t("feed.no_products_title", lang), t("feed.no_products_detail", lang)))
        return CategoryResult("product_feed", t("cat.product_feed", lang), 100, findings), products_sample

    missing_brand = 0
    missing_gtin = 0
    missing_price = 0
    missing_desc = 0
    thin_desc = 0
    inverted_compare_at = 0
    used_wording = 0
    sku_counts: dict[str, int] = {}

    for p in products:
        products_sample.append(p)
        vendor = (p.get("vendor") or "").strip()
        if not vendor or vendor.lower() in {"unbranded", "no brand"}:
            missing_brand += 1

        variants = p.get("variants", [])
        has_gtin = any((v.get("barcode") or "").strip() for v in variants)
        if not has_gtin:
            missing_gtin += 1

        has_price = any(float(v.get("price") or 0) > 0 for v in variants)
        if not has_price:
            missing_price += 1

        for v in variants:
            sku = (v.get("sku") or "").strip()
            if sku:
                sku_counts[sku] = sku_counts.get(sku, 0) + 1
            price = float(v.get("price") or 0)
            compare_at = v.get("compare_at_price")
            if compare_at:
                try:
                    if float(compare_at) <= price:
                        inverted_compare_at += 1
                except (TypeError, ValueError):
                    pass

        desc = re.sub("<[^<]+?>", "", p.get("body_html") or "").strip()
        if not desc:
            missing_desc += 1
        elif len(desc) < 100:
            thin_desc += 1
        if any(re.search(rf"\b{kw}\b", desc, re.I) for kw in USED_CONDITION_KEYWORDS):
            used_wording += 1

    duplicate_skus = {sku: c for sku, c in sku_counts.items() if c > 1}
    n = len(products)

    def pct(x):
        return round(100 * x / n)

    if missing_gtin:
        findings.append(Finding("critical", t("feed.missing_gtin_title", lang, pct=pct(missing_gtin)),
                                 t("feed.missing_gtin_detail", lang)))
        score -= min(35, missing_gtin * 6)
    if missing_brand:
        findings.append(Finding("high", t("feed.missing_brand_title", lang, pct=pct(missing_brand)),
                                 t("feed.missing_brand_detail", lang)))
        score -= min(25, missing_brand * 4)
    if missing_price:
        findings.append(Finding("high", t("feed.missing_price_title", lang, pct=pct(missing_price)), t("feed.missing_price_detail", lang)))
        score -= min(20, missing_price * 5)
    if missing_desc:
        findings.append(Finding("medium", t("feed.missing_desc_title", lang, pct=pct(missing_desc)), t("feed.missing_desc_detail", lang)))
        score -= min(15, missing_desc * 3)
    elif thin_desc:
        findings.append(Finding("low", t("feed.thin_desc_title", lang, pct=pct(thin_desc)), t("feed.thin_desc_detail", lang)))
        score -= min(10, thin_desc * 2)

    if duplicate_skus:
        listing = "\n".join(f"• {sku} ({c}×)" for sku, c in duplicate_skus.items())
        findings.append(Finding("high", t("feed.duplicate_skus_title", lang, count=len(duplicate_skus)), t("feed.duplicate_skus_detail", lang, listing=listing)))
        score -= min(20, len(duplicate_skus) * 5)

    if inverted_compare_at:
        findings.append(Finding(
            "high", t("feed.inverted_compare_title", lang, count=inverted_compare_at),
            t("feed.inverted_compare_detail", lang),
        ))
        score -= min(20, inverted_compare_at * 5)

    if used_wording:
        findings.append(Finding(
            "medium", t("feed.used_wording_title", lang, count=used_wording),
            t("feed.used_wording_detail", lang),
        ))
        score -= min(15, used_wording * 5)

    if not missing_gtin and not missing_brand and not missing_price and not missing_desc and not duplicate_skus and not inverted_compare_at and not used_wording:
        findings.append(Finding("info", t("feed.sample_ok_title", lang), t("feed.sample_ok_detail", lang, n=n)))

    # Feed-Attribute + Content-Checks aus Kategorie F/G2 (Variantenattribute,
    # Verfuegbarkeit, Claims, Materialangaben, GTIN-Plausibilitaet ...)
    extra_findings, extra_penalty = check_feed_extras(products, lang)
    findings.extend(extra_findings)
    score -= extra_penalty

    collection_findings = await check_nav_collections(client, base_url, homepage_html, lang)
    if collection_findings:
        findings.extend(collection_findings)
        score -= 10

    return CategoryResult("product_feed", t("cat.product_feed", lang), max(0, min(100, score)), findings), products_sample


# ---------------------------------------------------------------------------
# 6) Bild-Compliance
# ---------------------------------------------------------------------------
async def check_images(client: httpx.AsyncClient, base_url: str, products_sample: list[dict], lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    image_urls = []
    for p in products_sample:
        for img in (p.get("images") or [])[:3]:
            src = img.get("src")
            if src:
                # Shopify liefert Bild-URLs oft absolut, protocol-relativ ("//cdn...")
                # oder relativ zur Domain - alle Fälle auf eine absolute URL normalisieren.
                image_urls.append(urljoin(base_url + "/", src))
    image_urls = image_urls[:50]

    if not image_urls:
        findings.append(Finding("info", t("images.none_found_title", lang), t("images.none_found_detail", lang)))
        return CategoryResult("images", t("cat.images", lang), 100, findings)

    broken = 0
    too_small = 0
    checked = 0
    sizes_bytes: list[int] = []

    async def check_one(url: str):
        nonlocal broken, too_small, checked
        resp = await fetch(client, url)
        if isinstance(resp, Exception) or resp.status_code >= 400:
            broken += 1
            return
        checked += 1
        sizes_bytes.append(len(resp.content))
        if Image is not None:
            try:
                img = Image.open(BytesIO(resp.content))
                w, h = img.size
                if min(w, h) < MIN_IMAGE_EDGE_PX:
                    too_small += 1
            except Exception:
                pass

    await asyncio.gather(*(check_one(u) for u in image_urls))

    n = len(image_urls)
    if broken:
        findings.append(Finding("high", t("images.broken_title", lang, broken=broken, n=n), t("images.broken_detail", lang)))
        score -= min(40, broken * 8)
    if too_small:
        findings.append(Finding("medium", t("images.too_small_title", lang, count=too_small, min_px=MIN_IMAGE_EDGE_PX),
                                 t("images.too_small_detail", lang, rec_px=RECOMMENDED_IMAGE_EDGE_PX)))
        score -= min(25, too_small * 5)
    if not broken and not too_small:
        findings.append(Finding("info", t("images.ok_title", lang), t("images.ok_detail", lang, checked=checked)))

    # Dubletten, Bildanzahl pro Produkt, Gewicht, Lieferanten-CDN (Kategorie F)
    extra_findings, extra_penalty = check_image_extras(products_sample, sizes_bytes, lang)
    findings.extend(extra_findings)
    score -= extra_penalty

    findings.append(Finding("info", t("images.note_title", lang), t("images.note_detail", lang)))

    return CategoryResult("images", t("cat.images", lang), max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 9) Page Speed (eigene Messung, ohne externe API/Key)
# ---------------------------------------------------------------------------
GOOD_LOAD_TIME_S = 1.5
OK_LOAD_TIME_S = 3.0
GOOD_HTML_SIZE_KB = 300
OK_HTML_SIZE_KB = 800


async def check_page_speed(client: httpx.AsyncClient, base_url: str, lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    label = t("cat.page_speed", lang)

    started = time.monotonic()
    resp = await fetch(client, base_url, timeout=httpx.Timeout(20.0, connect=8.0))
    load_time_s = time.monotonic() - started

    if isinstance(resp, Exception) or resp.status_code >= 400:
        findings.append(Finding("info", t("speed.unavailable_title", lang), t("speed.unavailable_detail", lang)))
        return CategoryResult("page_speed", label, 100, findings)

    html_kb = len(resp.content) / 1024
    score = 100

    if load_time_s <= GOOD_LOAD_TIME_S:
        findings.append(Finding("info", t("speed.load_time_title", lang, seconds=f"{load_time_s:.2f}"),
                                 t("speed.load_fast_detail", lang)))
    elif load_time_s <= OK_LOAD_TIME_S:
        findings.append(Finding(
            "medium", t("speed.load_time_title", lang, seconds=f"{load_time_s:.2f}"),
            t("speed.load_medium_detail", lang),
        ))
        score -= 20
    else:
        findings.append(Finding(
            "high", t("speed.load_time_title", lang, seconds=f"{load_time_s:.2f}"),
            t("speed.load_slow_detail", lang),
        ))
        score -= 35

    if html_kb <= GOOD_HTML_SIZE_KB:
        findings.append(Finding("info", t("speed.html_size_title", lang, kb=f"{html_kb:.0f}"), t("speed.html_compact_detail", lang)))
    elif html_kb <= OK_HTML_SIZE_KB:
        findings.append(Finding(
            "low", t("speed.html_size_title", lang, kb=f"{html_kb:.0f}"),
            t("speed.html_large_detail", lang),
        ))
        score -= 5
    else:
        findings.append(Finding(
            "medium", t("speed.html_size_title", lang, kb=f"{html_kb:.0f}"),
            t("speed.html_toolarge_detail", lang),
        ))
        score -= 10

    findings.append(Finding("info", t("speed.methodology_title", lang), t("speed.methodology_detail", lang)))

    score = max(0, min(100, score))
    return CategoryResult("page_speed", label, score, findings)


# ---------------------------------------------------------------------------
# Produktseiten laden (für Bewertungs- und Urgency-Checks brauchen wir das
# tatsächlich gerenderte HTML, nicht nur products.json)
# ---------------------------------------------------------------------------
async def fetch_product_pages(client: httpx.AsyncClient, product_urls: list[str]) -> list[tuple[str, str]]:
    pages: list[tuple[str, str]] = []
    cache: dict[str, str] = getattr(client, "_page_cache", None)
    if cache is None:
        cache = {}
        client._page_cache = cache  # lebt genau einen Scan lang (Client pro run_scan)

    async def fetch_one(url: str):
        cached = cache.get(url)
        if cached is not None:
            pages.append((url, cached))
            return
        resp = await fetch(client, url)
        if not isinstance(resp, Exception) and resp.status_code < 400:
            cache[url] = resp.text
            pages.append((url, resp.text))

    await asyncio.gather(*(fetch_one(u) for u in product_urls))
    return pages


_REVIEW_CLAIM_RE = re.compile(
    r"(\d(?:[.,]\d)?)\s*(?:/|von)\s*5|(\d[\d.,]{0,6})\s*(bewertungen|reviews|rezensionen)",
    re.I,
)
_REVIEW_BLOCK_RE = re.compile(
    r'(?:itemprop=["\']reviewBody["\']|class=["\'][^"\']*review[^"\']*["\'])[^>]*>([^<]{15,300})<',
    re.I,
)


# ---------------------------------------------------------------------------
# 7) Bewertungen & Social Proof
# ---------------------------------------------------------------------------
async def check_reviews(homepage_html: Optional[str], product_pages: list[tuple[str, str]], lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    all_html = (homepage_html or "") + "".join(html for _, html in product_pages)
    if not all_html.strip():
        findings.append(Finding("info", t("reviews.unavailable_title", lang), t("reviews.unavailable_detail", lang)))
        return CategoryResult("reviews", t("cat.reviews", lang), 100, findings)

    lower_html = all_html.lower()
    detected_platforms = sorted({name for sig, name in KNOWN_REVIEW_PLATFORMS.items() if sig in lower_html})
    claims_reviews = bool(_REVIEW_CLAIM_RE.search(all_html))

    if detected_platforms:
        findings.append(Finding(
            "info", t("reviews.platform_found_title", lang),
            t("reviews.platform_found_detail", lang, platforms=", ".join(detected_platforms)),
        ))
    elif claims_reviews:
        findings.append(Finding(
            "high", t("reviews.unverifiable_title", lang),
            t("reviews.unverifiable_detail", lang),
        ))
        score -= 35
    else:
        findings.append(Finding("info", t("reviews.none_found_title", lang), t("reviews.none_found_detail", lang)))

    # Identische Review-Texte über mehrere Produktseiten hinweg = klassisches
    # Fake-Review-Muster (kopierte Templates statt echter Kundenstimmen).
    texts_by_url: dict[str, set[str]] = {}
    for url, html in product_pages:
        texts_by_url[url] = {m.strip() for m in _REVIEW_BLOCK_RE.findall(html)}

    seen: dict[str, str] = {}
    duplicates = set()
    for url, texts in texts_by_url.items():
        for txt in texts:
            if txt in seen and seen[txt] != url:
                duplicates.add(txt)
            seen[txt] = url

    if duplicates:
        example = next(iter(duplicates))[:120]
        findings.append(Finding(
            "critical", t("reviews.duplicates_title", lang, count=len(duplicates)),
            t("reviews.duplicates_detail", lang, example=example),
        ))
        score -= 40

    score = max(0, min(100, score))
    return CategoryResult("reviews", t("cat.reviews", lang), score, findings)


# ---------------------------------------------------------------------------
# 8) Künstliche Dringlichkeit / Verknappung ("Fake Urgency")
# ---------------------------------------------------------------------------
async def check_urgency_patterns(product_pages: list[tuple[str, str]], products_sample: list[dict], lang: str = DEFAULT_LANG) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not product_pages:
        findings.append(Finding("info", t("urgency.unavailable_title", lang), t("urgency.unavailable_detail", lang)))
        return CategoryResult("urgency", t("cat.urgency", lang), 100, findings)

    text_hits: set[str] = set()
    app_hits: set[str] = set()
    for _, html in product_pages:
        lower = html.lower()
        for pattern in URGENCY_TEXT_PATTERNS:
            if re.search(pattern, lower):
                text_hits.add(pattern)
        for sig in URGENCY_APP_SIGNATURES:
            if sig in lower:
                app_hits.add(sig)

    if not text_hits and not app_hits:
        findings.append(Finding("info", t("urgency.none_found_title", lang), t("urgency.none_found_detail", lang)))
        return CategoryResult("urgency", t("cat.urgency", lang), 100, findings)

    if app_hits:
        findings.append(Finding(
            "medium", t("urgency.app_found_title", lang),
            t("urgency.app_found_detail", lang, apps=", ".join(sorted(app_hits))),
        ))
        score -= 15

    if text_hits:
        findings.append(Finding(
            "high", t("urgency.text_found_title", lang),
            t("urgency.text_found_detail", lang),
        ))
        score -= 30

    # Grobe Plausibilitätsprüfung: wird Lagerbestand in Shopify überhaupt
    # getrackt? Falls nicht, sind angezeigte "Nur noch X"-Zahlen zwangsläufig
    # frei erfunden.
    untracked = 0
    for p in products_sample:
        variants = p.get("variants", [])
        if variants and all(v.get("inventory_management") in (None, "") for v in variants):
            untracked += 1
    if text_hits and products_sample and untracked == len(products_sample):
        findings.append(Finding(
            "critical", t("urgency.untracked_title", lang),
            t("urgency.untracked_detail", lang),
        ))
        score -= 25

    score = max(0, min(100, score))
    return CategoryResult("urgency", t("cat.urgency", lang), score, findings)


# ---------------------------------------------------------------------------
# Orchestrierung
# ---------------------------------------------------------------------------
async def run_scan(raw_url: str, lang: str = DEFAULT_LANG) -> dict:
    base_url = normalize_url(raw_url)

    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        home_resp = await fetch(client, base_url)
        homepage_html = None
        if not isinstance(home_resp, Exception) and home_resp.status_code < 400:
            homepage_html = home_resp.text

        site_urls = await discover_site_urls(client, base_url, homepage_html)

        trust_task = check_trust_domain(client, base_url, lang)
        links_task = check_broken_links(client, base_url, homepage_html, site_urls, lang)
        policy_task = check_policy_pages(client, base_url, homepage_html, lang)
        feed_task = check_product_feed(client, base_url, homepage_html, lang)
        speed_task = check_page_speed(client, base_url, lang)

        trust_res, links_res, (policy_res, policy_urls), (feed_res, products_sample), speed_res = await asyncio.gather(
            trust_task, links_task, policy_task, feed_task, speed_task
        )
        images_res = await check_images(client, base_url, products_sample, lang)
        contact_res = await check_contact_legal(client, base_url, homepage_html, policy_urls, lang)

        product_pages = await fetch_product_pages(client, site_urls.get("product_urls", []))
        reviews_res = await check_reviews(homepage_html, product_pages, lang)
        # Die Startseite gehoert mit in den Urgency-Check: Countdown-Banner und
        # "Angebot endet in" stehen typischerweise in der Announcement-Bar,
        # nicht auf der Produktseite.
        home_page_entry = [(base_url, homepage_html)] if homepage_html else []
        urgency_res = await check_urgency_patterns(home_page_entry + product_pages, products_sample, lang)
        reviews_platform_detected = any(
            f.title == t("reviews.platform_found_title", lang) for f in reviews_res.findings
        )
        red_flags_res = await check_red_flags(homepage_html, product_pages, reviews_platform_detected, lang)
        technical_res = await check_technical(
            client, base_url, homepage_html, product_pages, products_sample, policy_urls, lang
        )

    categories = [
        trust_res, links_res, policy_res, contact_res, feed_res, images_res,
        reviews_res, urgency_res, red_flags_res, technical_res, speed_res,
    ]

    weights = {
        "trust": 0.08,
        "broken_links": 0.10,
        "policy_pages": 0.14,
        "contact_legal": 0.11,
        "product_feed": 0.14,
        "images": 0.07,
        "reviews": 0.07,
        "urgency": 0.07,
        "red_flags": 0.07,
        "technical": 0.10,
        "page_speed": 0.05,
    }
    overall = round(sum(c.score * weights[c.key] for c in categories))

    if overall >= 80:
        risk_label = t("risk.low", lang)
    elif overall >= 50:
        risk_label = t("risk.medium", lang)
    else:
        risk_label = t("risk.high", lang)

    critical_count = sum(1 for c in categories for f in c.findings if f.severity == "critical")

    return {
        "url": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "risk_label": risk_label,
        "critical_issues": critical_count,
        "categories": [c.to_dict() for c in categories],
    }


# ===========================================================================
# Erweiterung 2026-08 — zusätzliche Prüfpunkte aus der GMC-Master-Checklist
# ---------------------------------------------------------------------------
# Bis hierhin prüfte der Scanner überwiegend Existenz (Seite erreichbar?
# Link tot? GTIN gesetzt?). Die Master-Checkliste bewertet aber vor allem
# Inhalte: was auf der Versandseite steht, ob die Adresse überall gleich ist,
# ob das Preis-Markup zum Shop passt. Genau diese Punkte kommen hier dazu.
# ===========================================================================

_TAG_RE = re.compile(r"<(script|style|noscript)[^>]*>.*?</\1>", re.S | re.I)


def visible_text(html: str) -> str:
    """HTML -> reiner Fließtext (ohne Script-/Style-Inhalte). Bewusst ohne
    BeautifulSoup-Vollparse, weil das hier auf bis zu 40 Seiten läuft."""
    if not html:
        return ""
    stripped = _TAG_RE.sub(" ", html)
    text = re.sub(r"<[^>]+>", " ", stripped)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
                .replace("&#39;", "'").replace("&euro;", "€"))
    return re.sub(r"\s+", " ", text).strip()


def _listing(items, lang: str, limit: int = 8) -> str:
    items = list(items)
    out = "\n".join(f"• {i}" for i in items[:limit])
    if len(items) > limit:
        out += more_suffix(len(items) - limit, lang)
    return out


# ---------------------------------------------------------------------------
# C/D) Policy-Seiten: Inhalt statt nur Existenz
# ---------------------------------------------------------------------------
MIN_POLICY_TEXT_CHARS = 350

# Pro Seitentyp: welche Aussagen MÜSSEN im Text vorkommen. Jede Gruppe ist
# eine Aussage; erfüllt gilt sie, sobald EINES ihrer Muster greift (DE|EN).
POLICY_CONTENT_REQUIREMENTS: dict[str, list[tuple[str, list[str]]]] = {
    "shipping": [
        ("req.shipping_time", [
            r"liefer(zeit|frist|dauer)", r"versanddauer", r"bearbeitungszeit",
            r"\d+\s*(?:-|–|bis|to)\s*\d+\s*(?:werktag|arbeitstag|tage|business day|working day|day)",
            r"delivery time", r"handling time", r"transit time", r"ships? within",
        ]),
        ("req.shipping_cost", [
            r"versandkosten", r"versandkosten\s*frei", r"kostenlose?r?\s+versand",
            r"shipping (?:cost|rate|fee|charge)", r"free shipping",
            r"\d+[.,]\d{2}\s*(?:€|\$|eur|usd)", r"(?:€|\$)\s*\d+[.,]\d{2}",
        ]),
        ("req.shipping_tracking", [
            r"sendungsverfolg", r"tracking", r"trackingnummer", r"versandbestätigung",
            r"versanddienstleister", r"versandpartner", r"carrier", r"shipping partner",
        ]),
    ],
    "refund": [
        ("req.refund_period", [
            r"\d{1,3}\s*(?:tage|tagen|kalendertage|werktage|days)", r"innerhalb von \d+",
            r"within \d+\s*days", r"rückgabefrist", r"return (?:period|window)", r"widerrufsfrist",
        ]),
        ("req.refund_who_pays", [
            r"rücksendekosten", r"rückversandkosten", r"kosten der rücksendung",
            r"return (?:shipping|postage) (?:cost|fee)", r"wer (?:trägt|zahlt)",
            r"we (?:cover|pay)", r"trägst? du", r"trägt der käufer", r"at your (?:own )?expense",
        ]),
        ("req.refund_process", [
            r"erstatt", r"rückerstatt", r"gutschrift", r"refund(?:ed)?", r"reimburse",
            r"ursprüngliche[sn]? zahlungsmittel", r"original payment method",
        ]),
        ("req.refund_cases", [
            r"beschädigt", r"defekt", r"falsche[sn]? (?:artikel|produkt)", r"falsch geliefert",
            r"damaged", r"defective", r"wrong item", r"change of mind", r"nicht gefallen",
        ]),
    ],
    "impressum": [
        ("req.legal_entity", [
            r"\b(?:gmbh|ug|ohg|kg|ag|e\.k\.|einzelunternehmen|ltd|llc|inc\.?|corp)\b",
            r"vertreten durch", r"inhaber", r"geschäftsführer", r"owner", r"managing director",
        ]),
        ("req.legal_address", [r"\b\d{4,5}\s+[A-ZÄÖÜ]", r"\b[A-Z]{2}\s+\d{5}"]),
    ],
    "payment": [
        ("req.payment_methods", [
            r"paypal", r"kreditkarte", r"credit card", r"visa", r"mastercard",
            r"klarna", r"sofort", r"apple pay", r"google pay", r"rechnung", r"vorkasse",
            r"sepa", r"lastschrift", r"amex", r"american express",
        ]),
    ],
}


async def check_policy_content(
    client: httpx.AsyncClient,
    policy_urls: dict[str, str],
    lang: str = DEFAULT_LANG,
) -> tuple[list[Finding], int]:
    """Lädt die gefundenen Policy-Seiten und prüft, ob dort tatsächlich etwas
    steht — und zwar das Richtige. Eine leere AGB-Seite besteht sonst jede
    reine Existenzprüfung, wird von Google aber wie eine fehlende gewertet.
    Gibt (Findings, Score-Abzug) zurück."""
    findings: list[Finding] = []
    penalty = 0

    targets = {k: u for k, u in policy_urls.items() if k in POLICY_CONTENT_REQUIREMENTS or k in ("privacy", "terms", "about", "faq")}
    if not targets:
        return findings, 0

    pages = await fetch_product_pages(client, list(targets.values()))
    html_by_url = dict(pages)

    label_by_key = {
        "impressum": "policy.impressum", "privacy": "policy.privacy", "terms": "policy.terms",
        "refund": "policy.refund", "shipping": "policy.shipping", "contact": "policy.contact",
        "about": "policy.about", "faq": "policy.faq", "payment": "policy.payment",
        "track_order": "policy.track_order",
    }

    pages_without_contact: list[str] = []

    for key, url in targets.items():
        html = html_by_url.get(url)
        if not html:
            continue
        label = t(label_by_key.get(key, "policy.contact"), lang)
        text = visible_text(html)

        # Shopify rendert Header/Footer mit — der Seitentext allein ist das,
        # was über den Boilerplate hinausgeht. Grobe, aber stabile Näherung:
        # alles unter MIN_POLICY_TEXT_CHARS ist auch inkl. Chrome zu dünn.
        if len(text) < MIN_POLICY_TEXT_CHARS:
            findings.append(Finding(
                "high", t("policy.empty_title", lang, label=label, chars=len(text)),
                t("policy.empty_detail", lang, min_chars=MIN_POLICY_TEXT_CHARS),
            ))
            penalty += 12
            continue

        lower = text.lower()
        requirements = POLICY_CONTENT_REQUIREMENTS.get(key, [])
        missing = [
            t(req_key, lang) for req_key, patterns in requirements
            if not any(re.search(p, lower, re.I) for p in patterns)
        ]
        if missing:
            findings.append(Finding(
                "high" if len(missing) > 1 else "medium",
                t("policy.missing_content_title", lang, label=label, count=len(missing)),
                t("policy.missing_content_detail", lang, listing=_listing(missing, lang)),
            ))
            penalty += min(15, 5 * len(missing))
        elif requirements:
            findings.append(Finding(
                "info", t("policy.content_ok_title", lang, label=label),
                t("policy.content_ok_detail", lang),
            ))

        # "Every policy page carries contact + company info" (Kategorie D)
        if key in ("shipping", "refund", "terms", "privacy") and not (
            EMAIL_RE.search(text) or "mailto:" in html.lower() or "tel:" in html.lower()
        ):
            pages_without_contact.append(url)

    if pages_without_contact:
        findings.append(Finding(
            "medium", t("policy.no_contact_on_page_title", lang, count=len(pages_without_contact)),
            t("policy.no_contact_on_page_detail", lang, listing=_listing(pages_without_contact, lang)),
        ))
        penalty += 8

    return findings, penalty


# ---------------------------------------------------------------------------
# B) Kontakt: Adresse, Kontaktwege, Servicezeiten, NAP über Telefon/Adresse
# ---------------------------------------------------------------------------
STREET_RE = re.compile(
    r"([A-ZÄÖÜ][\wäöüßA-Za-z.\-]{2,30}\s*(?:stra(?:ß|ss)e|str\.|weg|allee|platz|gasse|ring|damm|ufer)\s*\d+\s*[a-z]?)"
    r"|(\b\d{1,5}\s+[A-Z][A-Za-z0-9.\-]{1,25}(?:\s+[A-Z][A-Za-z0-9.\-]{1,25})?\s+"
    r"(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|lane|ln\.?|drive|dr\.?|court|ct\.?|way|suite|ste\.?)\b)",
    re.I,
)
POSTAL_RE = re.compile(r"\b(?:[A-Z]{1,2}-)?(\d{4,5})\s+[A-ZÄÖÜ][a-zäöüß]{2,}|\b([A-Z]{2})\s+(\d{5})(?:-\d{4})?\b")
TEL_LINK_RE = re.compile(r"tel:\s*([+0-9()\s.\-/]{6,})", re.I)
EMAIL_TRAILING_DOT_RE = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\.(?![A-Za-z0-9])")
SERVICE_HOURS_PATTERNS = [
    r"(?:mo|mon|montag)[a-zäöü.]*\s*(?:-|–|bis|to|through)\s*(?:fr|fri|freitag|sa|sat|so|sun)",
    r"\d{1,2}[:.]\d{2}\s*(?:uhr|am|pm|h)\b",
    r"öffnungszeiten", r"servicezeiten", r"erreichbarkeit", r"business hours", r"support hours",
    r"antwort(?:zeit)?\s*(?:innerhalb|binnen)", r"(?:reply|respond|response)\s*(?:within|time)",
    r"innerhalb von \d+\s*(?:stunden|std|werktagen)", r"within \d+\s*(?:hours|business days)",
]


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return digits[-9:] if len(digits) >= 9 else digits


def check_contact_extras(
    pages_html: dict[str, str],
    contact_url: Optional[str],
    lang: str = DEFAULT_LANG,
) -> tuple[list[Finding], int]:
    """Adresse, Kontaktwege, Servicezeiten und NAP-Konsistenz über Telefon +
    Postleitzahl. Arbeitet auf bereits geladenen Seiten, macht keine eigenen
    Requests. Gibt (Findings, Score-Abzug) zurück."""
    findings: list[Finding] = []
    penalty = 0

    text_by_page = {url: visible_text(html) for url, html in pages_html.items() if html}
    combined_text = " ".join(text_by_page.values())
    combined_html = " ".join(h for h in pages_html.values() if h)
    if not combined_text:
        return findings, 0

    # 1) Vollständige Adresse (Straße + Hausnummer UND PLZ + Ort)
    street_hit = STREET_RE.search(combined_text)
    postal_hits_all = POSTAL_RE.findall(combined_text)
    if street_hit and postal_hits_all:
        snippet = next(g for g in street_hit.groups() if g).strip()
        findings.append(Finding("info", t("contact.address_found_title", lang), snippet[:160]))
    else:
        findings.append(Finding(
            "high", t("contact.no_address_title", lang), t("contact.no_address_detail", lang),
        ))
        penalty += 20

    # 2) NAP: dieselbe PLZ auf allen Seiten, die überhaupt eine nennen
    postal_by_page: dict[str, set[str]] = {}
    for url, text in text_by_page.items():
        codes = {m[0] or m[2] for m in POSTAL_RE.findall(text)}
        codes = {c for c in codes if c}
        if codes:
            postal_by_page[url] = codes
    if len(postal_by_page) >= 2:
        distinct = set().union(*postal_by_page.values())
        if len(distinct) > 1:
            findings.append(Finding(
                "high", t("contact.address_mismatch_title", lang),
                t("contact.address_mismatch_detail", lang, listing=_listing(sorted(distinct), lang)),
            ))
            penalty += 15

    # 3) NAP: Telefonnummern. Bewusst nur tel:-Links auswerten — freier Text
    #    liefert zu viele Falschtreffer (Bestellnummern, Datumsangaben, IDs).
    tel_numbers = {_normalize_phone(m) for m in TEL_LINK_RE.findall(combined_html)}
    tel_numbers = {n for n in tel_numbers if n}
    if len(tel_numbers) > 1:
        findings.append(Finding(
            "high", t("contact.phone_mismatch_title", lang),
            t("contact.phone_mismatch_detail", lang, listing=_listing(sorted(tel_numbers), lang)),
        ))
        penalty += 15

    # 4) E-Mail mit angehängtem Satzpunkt ("info@shop.com.")
    # Drei Varianten, weil der Satzpunkt je nach Markup woanders landet:
    # im Fließtext ("info@x.de."), im rohen HTML (href="mailto:info@x.de.")
    # und hinter einem schließenden Tag ("<a>info@x.de</a>."). Beim Entfernen
    # der Tags darf hier - anders als in visible_text() - kein Leerzeichen
    # eingesetzt werden, sonst geht genau dieser Fall verloren.
    tagless = re.sub(r"<[^>]+>", "", _TAG_RE.sub(" ", combined_html))
    trailing = set(EMAIL_TRAILING_DOT_RE.findall(combined_text))
    trailing |= set(EMAIL_TRAILING_DOT_RE.findall(combined_html))
    trailing |= set(EMAIL_TRAILING_DOT_RE.findall(tagless))
    if trailing:
        findings.append(Finding(
            "medium", t("contact.trailing_dot_title", lang),
            t("contact.trailing_dot_detail", lang, emails=", ".join(sorted(trailing))[:200]),
        ))
        penalty += 8

    # 5) Klickbarkeit: mailto:/tel: statt reinem Text
    missing_links = []
    if EMAIL_RE.search(combined_text) and "mailto:" not in combined_html.lower():
        missing_links.append("mailto:")
    if PHONE_RE.search(combined_text) and "tel:" not in combined_html.lower():
        missing_links.append("tel:")
    if missing_links:
        findings.append(Finding(
            "low", t("contact.not_clickable_title", lang),
            t("contact.not_clickable_detail", lang, missing=", ".join(missing_links)),
        ))
        penalty += 5

    # 6) Kontaktseite: mindestens zwei Kontaktwege + Servicezeiten, beides auf
    #    EINER Seite (Checklist B: "contact page complete on ONE page")
    contact_html = pages_html.get(contact_url) if contact_url else None
    if contact_html:
        contact_text = visible_text(contact_html)
        lower_html = contact_html.lower()
        options = []
        if EMAIL_RE.search(contact_text) or "mailto:" in lower_html:
            options.append("E-Mail" if lang == "de" else "Email")
        if PHONE_RE.search(contact_text) or "tel:" in lower_html:
            options.append("Telefon" if lang == "de" else "Phone")
        if "<form" in lower_html and ("textarea" in lower_html or "type=\"email\"" in lower_html):
            options.append("Formular" if lang == "de" else "Form")
        if STREET_RE.search(contact_text):
            options.append("Adresse" if lang == "de" else "Address")

        if len(options) < 2:
            findings.append(Finding(
                "medium", t("contact.few_options_title", lang, count=len(options)),
                t("contact.few_options_detail", lang, found=", ".join(options) or "–"),
            ))
            penalty += 10
        else:
            findings.append(Finding(
                "info", t("contact.options_ok_title", lang, count=len(options)),
                t("contact.options_ok_detail", lang, found=", ".join(options)),
            ))

        if not any(re.search(p, contact_text, re.I) for p in SERVICE_HOURS_PATTERNS):
            findings.append(Finding(
                "medium", t("contact.no_hours_title", lang), t("contact.no_hours_detail", lang),
            ))
            penalty += 10

    return findings, penalty


# ---------------------------------------------------------------------------
# F/G2) Produkt-Feed: Variantenattribute, Verfügbarkeit, Claims, GTIN-Plausibilität
# ---------------------------------------------------------------------------
COLOR_OPTION_NAMES = {"color", "colour", "farbe", "farben", "farbton"}
SIZE_OPTION_NAMES = {"size", "größe", "groesse", "grösse", "sizes", "konfektionsgröße"}
GENDER_HINTS = [
    "damen", "herren", "unisex", "women", "men", "womens", "mens", "kinder", "kids",
    "baby", "jungen", "mädchen", "girls", "boys", "female", "male", "adult", "erwachsene",
]
TRADEMARK_RE = re.compile(r"[™®©]")
DESC_SCRIPT_RE = re.compile(r"<\s*(script|iframe)\b", re.I)

UNSUBSTANTIATED_CLAIM_PATTERNS = [
    r"heilt\b", r"heilung", r"lindert\s+(?:schmerzen|beschwerden)", r"schmerzfrei\b",
    r"klinisch (?:bewiesen|getestet|erwiesen)", r"clinically (?:proven|tested)",
    r"wissenschaftlich bewiesen", r"scientifically proven", r"fda[- ]approved",
    r"garantierte? (?:wirkung|erfolg|ergebnis)", r"guaranteed results?",
    r"\bcures?\b", r"\btreats?\s+(?:pain|anxiety|acne)", r"100\s*%\s*(?:wirksam|effective)",
    r"beseitigt (?:falten|cellulite)", r"removes? (?:wrinkles|cellulite)",
    r"wunder(?:mittel|kur)", r"miracle (?:cure|product)",
    # "Unverifiable operational claims" (Checklist D, fixlist A3)
    r"jedes (?:stück|teil|produkt) wird (?:einzeln|von hand|vor dem versand)",
    r"handgeprüft", r"einzeln (?:geprüft|kontrolliert)", r"quality[- ]checked before",
    r"in unserer (?:manufaktur|werkstatt)", r"made in our (?:atelier|workshop)",
]

PREMIUM_MATERIALS = [
    "kaschmir", "cashmere", "merino", "seide", "silk", "leinen", "linen",
    "leder", "leather", "alpaka", "alpaca", "daune", "goose down",
]
MATERIAL_QUALIFIERS = [
    "optik", "look", "feel", "haptik", "imitat", "artig", "ähnlich", "style",
    "-like", "faux", "kunst", "vegan", "alternative", "touch",
]

MIN_IMAGES_PER_PRODUCT = 3
SUPPLIER_CDN_SIGNATURES = ["alicdn.com", "aliexpress", "dhgate", "1688.com", "temu", "cjdropshipping"]


def _gtin_is_plausible(barcode: str) -> bool:
    code = re.sub(r"\s|-", "", barcode)
    if not code.isdigit() or len(code) not in (8, 12, 13, 14):
        return False
    if len(set(code)) == 1:  # 0000000000000 & Co.
        return False
    digits = [int(c) for c in code]
    check = digits[-1]
    body = digits[:-1][::-1]
    total = sum(d * (3 if i % 2 == 0 else 1) for i, d in enumerate(body))
    return (10 - total % 10) % 10 == check


def check_feed_extras(products: list[dict], lang: str = DEFAULT_LANG) -> tuple[list[Finding], int]:
    """Feed-Attribute, die Google item-für-item ablehnt, plus die Content-
    Prüfungen aus Kategorie F. Rein aus products.json, keine Requests."""
    findings: list[Finding] = []
    penalty = 0
    if not products:
        return findings, 0

    n = len(products)
    no_variant_attrs = 0
    sold_out: list[str] = []
    missing_type = 0
    handle_mismatch: list[str] = []
    trademark: list[str] = []
    scripted = 0
    claim_hits: set[str] = set()
    material_hits: set[str] = set()
    fake_gtins: list[str] = []
    desc_index: dict[str, list[str]] = {}
    gender_signal = False

    for p in products:
        title = (p.get("title") or "").strip()
        handle = (p.get("handle") or "").strip()
        options = p.get("options") or []
        option_names = {(o.get("name") or "").strip().lower() for o in options}
        variants = p.get("variants") or []

        # Variantenattribute: Google leitet color/size aus den Optionsnamen ab
        if not (option_names & COLOR_OPTION_NAMES) and not (option_names & SIZE_OPTION_NAMES):
            no_variant_attrs += 1

        haystack = " ".join([title, p.get("product_type") or "", " ".join(p.get("tags") or [])]).lower()
        if any(h in haystack for h in GENDER_HINTS):
            gender_signal = True

        # Verfügbarkeit: komplett ausverkauft, aber weiterhin online
        if variants and all(v.get("available") is False for v in variants):
            sold_out.append(title or handle)

        if not (p.get("product_type") or "").strip():
            missing_type += 1

        # Titel vs. URL-Handle: erste zwei signifikanten Wörter müssen sich
        # im Handle wiederfinden, sonst stammt die URL noch vom Lieferanten
        title_words = [w for w in re.findall(r"[a-zäöüß0-9]{4,}", title.lower())][:2]
        if title_words and handle and not any(w in handle.lower() for w in title_words):
            handle_mismatch.append(f"{title[:45]} → /products/{handle}")

        if TRADEMARK_RE.search(title):
            trademark.append(title[:60])

        body = p.get("body_html") or ""
        if DESC_SCRIPT_RE.search(body):
            scripted += 1

        desc = visible_text(body)
        norm = re.sub(r"\W+", "", desc.lower())[:400]
        if norm:
            desc_index.setdefault(norm, []).append(title[:45])

        blob = f"{title} {desc}".lower()
        for pattern in UNSUBSTANTIATED_CLAIM_PATTERNS:
            m = re.search(pattern, blob, re.I)
            if m:
                claim_hits.add(m.group(0).strip())
        for material in PREMIUM_MATERIALS:
            for m in re.finditer(rf"\b{re.escape(material)}\b", blob):
                tail = blob[m.end():m.end() + 14]
                head = blob[max(0, m.start() - 14):m.start()]
                if not any(q in tail or q in head for q in MATERIAL_QUALIFIERS):
                    material_hits.add(material)
                    break

        for v in variants:
            barcode = (v.get("barcode") or "").strip()
            if barcode and not _gtin_is_plausible(barcode):
                fake_gtins.append(f"{title[:40]}: {barcode}")

    def pct(x):
        return round(100 * x / n)

    if no_variant_attrs:
        findings.append(Finding(
            "high", t("feed.missing_variant_attrs_title", lang, pct=pct(no_variant_attrs)),
            t("feed.missing_variant_attrs_detail", lang),
        ))
        penalty += min(20, no_variant_attrs * 3)

    if not gender_signal:
        findings.append(Finding(
            "medium", t("feed.no_gender_hint_title", lang), t("feed.no_gender_hint_detail", lang),
        ))
        penalty += 8

    if sold_out:
        findings.append(Finding(
            "high", t("feed.unavailable_shown_title", lang, count=len(sold_out)),
            t("feed.unavailable_shown_detail", lang) + "\n\n" + _listing(sold_out, lang),
        ))
        penalty += min(15, len(sold_out) * 4)

    if missing_type:
        findings.append(Finding(
            "medium", t("feed.missing_type_title", lang, pct=pct(missing_type)),
            t("feed.missing_type_detail", lang),
        ))
        penalty += min(12, missing_type * 2)

    if handle_mismatch:
        findings.append(Finding(
            "low", t("feed.handle_mismatch_title", lang, count=len(handle_mismatch)),
            t("feed.handle_mismatch_detail", lang, listing=_listing(handle_mismatch, lang)),
        ))
        penalty += min(8, len(handle_mismatch) * 2)

    if trademark:
        findings.append(Finding(
            "high", t("feed.trademark_title", lang, count=len(trademark)),
            t("feed.trademark_detail", lang, listing=_listing(trademark, lang)),
        ))
        penalty += min(15, len(trademark) * 5)

    duplicate_desc = [titles for titles in desc_index.values() if len(titles) > 1]
    if duplicate_desc:
        affected = sum(len(g) for g in duplicate_desc)
        findings.append(Finding(
            "medium", t("feed.duplicate_desc_title", lang, count=affected),
            t("feed.duplicate_desc_detail", lang) + "\n\n" + _listing(
                [", ".join(g) for g in duplicate_desc], lang, limit=5),
        ))
        penalty += min(15, affected * 3)

    if scripted:
        findings.append(Finding(
            "high", t("feed.desc_script_title", lang, count=scripted),
            t("feed.desc_script_detail", lang),
        ))
        penalty += min(15, scripted * 5)

    if claim_hits:
        findings.append(Finding(
            "critical", t("feed.claims_title", lang, count=len(claim_hits)),
            t("feed.claims_detail", lang, listing=_listing(sorted(claim_hits), lang)),
        ))
        penalty += 25

    if material_hits:
        findings.append(Finding(
            "medium", t("feed.material_title", lang, count=len(material_hits)),
            t("feed.material_detail", lang, listing=", ".join(sorted(material_hits))),
        ))
        penalty += 10

    if fake_gtins:
        findings.append(Finding(
            "high", t("feed.fake_gtin_title", lang, count=len(fake_gtins)),
            t("feed.fake_gtin_detail", lang, listing=_listing(fake_gtins, lang)),
        ))
        penalty += min(20, len(fake_gtins) * 5)

    return findings, penalty


# ---------------------------------------------------------------------------
# F) Bilder: Dubletten, Anzahl pro Produkt, Gewicht, Lieferanten-CDN
# ---------------------------------------------------------------------------
IMAGE_SIZE_LIMIT_KB = 900


def _normalize_image_src(src: str) -> str:
    """Shopify liefert dasselbe Bild unter vielen Größen-/Cache-Varianten aus.
    Für den Dublettenvergleich zählt der Dateiname ohne Größensuffix."""
    path = src.split("?")[0].rsplit("/", 1)[-1]
    return re.sub(r"_\d{2,4}x\d{0,4}(?=\.)", "", path).lower()


def check_image_extras(
    products_sample: list[dict],
    image_sizes_bytes: list[int],
    lang: str = DEFAULT_LANG,
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    penalty = 0
    if not products_sample:
        return findings, 0

    owners: dict[str, set[str]] = {}
    too_few: list[str] = []
    supplier_cdn: set[str] = set()

    for p in products_sample:
        title = (p.get("title") or p.get("handle") or "?")[:45]
        images = p.get("images") or []
        if len(images) < MIN_IMAGES_PER_PRODUCT:
            too_few.append(f"{title} ({len(images)})")
        for img in images:
            src = img.get("src") or ""
            if not src:
                continue
            owners.setdefault(_normalize_image_src(src), set()).add(title)
            for sig in SUPPLIER_CDN_SIGNATURES:
                if sig in src.lower():
                    supplier_cdn.add(sig)

    duplicates = {name: titles for name, titles in owners.items() if len(titles) > 1}
    if duplicates:
        listing = [f"{name} → {', '.join(sorted(titles))}" for name, titles in duplicates.items()]
        findings.append(Finding(
            "high", t("images.duplicates_title", lang, count=len(duplicates)),
            t("images.duplicates_detail", lang, listing=_listing(listing, lang, limit=6)),
        ))
        penalty += min(25, len(duplicates) * 5)

    if too_few:
        findings.append(Finding(
            "medium", t("images.too_few_title", lang, count=len(too_few), min=MIN_IMAGES_PER_PRODUCT),
            t("images.too_few_detail", lang, listing=_listing(too_few, lang)),
        ))
        penalty += min(15, len(too_few) * 3)

    heavy = [b for b in image_sizes_bytes if b > IMAGE_SIZE_LIMIT_KB * 1024]
    if heavy:
        findings.append(Finding(
            "medium", t("images.heavy_title", lang, count=len(heavy), limit_kb=IMAGE_SIZE_LIMIT_KB),
            t("images.heavy_detail", lang, max_kb=round(max(heavy) / 1024)),
        ))
        penalty += min(15, len(heavy) * 3)

    if supplier_cdn:
        findings.append(Finding(
            "critical", t("images.supplier_cdn_title", lang),
            t("images.supplier_cdn_detail", lang, listing=", ".join(sorted(supplier_cdn))),
        ))
        penalty += 30

    return findings, penalty


# ---------------------------------------------------------------------------
# E) Trust-Red-Flags: Fake-Badges, Presse-/Partner-Claims, Popups, Bestseller
# ---------------------------------------------------------------------------
FAKE_BADGE_PATTERNS = [
    r"trust[-_]?badge", r"secure[-_]?checkout[-_]?badge", r"guarantee[-_]?badge",
    r"norton[-_]?secure", r"mcafee[-_]?secure", r"ssl[-_]?seal", r"payment[-_]?badge",
    r"100\s*%\s*(?:sicher|secure|safe)\b", r"garantiert sicher", r"money[- ]back[- ]guarantee[-_ ]badge",
    r"geprüfter?\s+(?:online[- ]?shop|händler)", r"verified[- ]seller[- ]badge",
]
PRESS_PARTNER_PATTERNS = [
    r"bekannt aus", r"as seen (?:on|in)", r"featured in", r"gesehen bei",
    r"offizielle[rn]? (?:partner|händler|distributor)", r"official (?:partner|retailer|reseller)",
    r"zertifizierte[rn]? (?:händler|partner)", r"certified (?:reseller|partner|dealer)",
    r"authorized (?:dealer|reseller)", r"autorisierte[rn]? händler",
]
POPUP_APP_SIGNATURES = [
    "privy.com", "optinmonster", "wisepops", "poptin", "justuno", "spin-to-win",
    "spinawheel", "wheelio", "sumo.com", "getsitecontrol", "gluecksrad",
]
BESTSELLER_CLAIM_PATTERNS = [
    r"\bbestseller\b", r"\bbest[- ]seller\b", r"kundenliebling", r"customers? (?:love|favou?rite)",
    r"meistverkauft", r"most popular", r"beliebteste[srn]?\b", r"\btop[- ]seller\b",
    r"#\s?1\s+(?:in|für|for)\b",
]


async def check_red_flags(
    homepage_html: Optional[str],
    product_pages: list[tuple[str, str]],
    reviews_platform_detected: bool,
    lang: str = DEFAULT_LANG,
) -> CategoryResult:
    """Kategorie E der Master-Checkliste, soweit sie im ausgelieferten HTML
    sichtbar ist. Ein Treffer hier heißt: das Verbotene wurde gefunden."""
    findings: list[Finding] = []
    score = 100

    all_html = (homepage_html or "") + "".join(html for _, html in product_pages)
    if not all_html.strip():
        findings.append(Finding("info", t("flags.unavailable_title", lang), t("flags.unavailable_detail", lang)))
        return CategoryResult("red_flags", t("cat.red_flags", lang), 100, findings)

    lower_html = all_html.lower()
    text = visible_text(all_html).lower()

    badges = {m.group(0) for p in FAKE_BADGE_PATTERNS for m in [re.search(p, lower_html, re.I)] if m}
    press = {m.group(0) for p in PRESS_PARTNER_PATTERNS for m in [re.search(p, text, re.I)] if m}
    popups = {s for s in POPUP_APP_SIGNATURES if s in lower_html}
    bestseller = {m.group(0) for p in BESTSELLER_CLAIM_PATTERNS for m in [re.search(p, text, re.I)] if m}

    if badges:
        findings.append(Finding(
            "high", t("flags.badges_title", lang),
            t("flags.badges_detail", lang, listing=_listing(sorted(badges), lang)),
        ))
        score -= 25
    if press:
        findings.append(Finding(
            "high", t("flags.press_title", lang),
            t("flags.press_detail", lang, listing=_listing(sorted(press), lang)),
        ))
        score -= 25
    if popups:
        findings.append(Finding(
            "medium", t("flags.popup_title", lang),
            t("flags.popup_detail", lang, listing=", ".join(sorted(popups))),
        ))
        score -= 15
    # "Bestseller"/"Kundenliebling" ist nur dann unbelegt, wenn es gar keine
    # verifizierbare Bewertungs-/Verkaufsbasis im Store gibt.
    if bestseller and not reviews_platform_detected:
        findings.append(Finding(
            "medium", t("flags.bestseller_title", lang),
            t("flags.bestseller_detail", lang, listing=_listing(sorted(bestseller), lang)),
        ))
        score -= 15

    if not findings:
        findings.append(Finding("info", t("flags.none_title", lang), t("flags.none_detail", lang)))

    return CategoryResult("red_flags", t("cat.red_flags", lang), max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# H) Technik & Google-Signale
# ---------------------------------------------------------------------------
GOOGLE_VERIFICATION_RE = re.compile(r"google-site-verification", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
THEME_ERROR_RE = re.compile(r"liquid error|translation missing|\{\{\s*[a-z_.]+\s*\}\}", re.I)
FOOTER_RE = re.compile(r"<footer\b|role=[\"']contentinfo[\"']|class=[\"'][^\"']*\bfooter\b", re.I)
JSONLD_RE = re.compile(r"<script[^>]+application/ld\+json[^>]*>(.*?)</script>", re.S | re.I)
MIN_TITLE_CHARS = 25


def _extract_offers(html: str) -> list[dict]:
    """Zieht alle schema.org-Offer-Knoten aus dem JSON-LD einer Produktseite."""
    import json

    offers: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            node_type = node.get("@type")
            types = node_type if isinstance(node_type, list) else [node_type]
            if any(isinstance(x, str) and x.lower() in ("offer", "aggregateoffer") for x in types):
                offers.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for block in JSONLD_RE.findall(html):
        try:
            walk(json.loads(block.strip()))
        except Exception:
            continue
    return offers


async def check_technical(
    client: httpx.AsyncClient,
    base_url: str,
    homepage_html: Optional[str],
    product_pages: list[tuple[str, str]],
    products_sample: list[dict],
    policy_urls: dict[str, str],
    lang: str = DEFAULT_LANG,
) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not homepage_html:
        findings.append(Finding("info", t("tech.unavailable_title", lang), t("tech.unavailable_detail", lang)))
        findings.append(Finding("info", t("tech.gmc_note_title", lang), t("tech.gmc_note_detail", lang)))
        return CategoryResult("technical", t("cat.technical", lang), 100, findings)

    # 1) Google-Site-Verification im <head>
    head = homepage_html[:20000]
    if GOOGLE_VERIFICATION_RE.search(head):
        findings.append(Finding("info", t("tech.verification_found_title", lang), t("tech.verification_found_detail", lang)))
    else:
        findings.append(Finding("high", t("tech.no_verification_title", lang), t("tech.no_verification_detail", lang)))
        score -= 20

    # 2) Startseiten-Titel
    host = urlparse(base_url).netloc.replace("www.", "")
    brand = host.split(".")[0]
    title_match = TITLE_RE.search(homepage_html)
    title = visible_text(title_match.group(1)) if title_match else ""
    if not title:
        findings.append(Finding("medium", t("tech.title_missing_title", lang), t("tech.title_missing_detail", lang)))
        score -= 10
    elif len(title) < MIN_TITLE_CHARS or re.sub(r"\W", "", title.lower()) in (
        re.sub(r"\W", "", host.lower()), brand.lower()
    ):
        findings.append(Finding("medium", t("tech.title_weak_title", lang, title=title[:80]), t("tech.title_weak_detail", lang)))
        score -= 10
    else:
        findings.append(Finding("info", t("tech.title_ok_title", lang), title[:120]))

    # 3) Theme-Fehler + 4) Footer auf jeder Seite — über einen breiten
    #    Seitenquerschnitt: Startseite, alle Policy-Seiten, Produktseiten.
    sampled: dict[str, str] = {base_url: homepage_html}
    policy_pages = await fetch_product_pages(client, list(policy_urls.values())[:8])
    sampled.update(dict(policy_pages))
    sampled.update(dict(product_pages[:5]))

    theme_errors = [url for url, html in sampled.items() if html and THEME_ERROR_RE.search(visible_text(html))]
    if theme_errors:
        findings.append(Finding(
            "high", t("tech.liquid_errors_title", lang, count=len(theme_errors)),
            t("tech.liquid_errors_detail", lang, listing=_listing(theme_errors, lang)),
        ))
        score -= min(20, len(theme_errors) * 7)

    footerless = [url for url, html in sampled.items() if html and not FOOTER_RE.search(html)]
    if footerless:
        findings.append(Finding(
            "high", t("tech.no_footer_title", lang, count=len(footerless), total=len(sampled)),
            t("tech.no_footer_detail", lang, listing=_listing(footerless, lang)),
        ))
        score -= min(20, len(footerless) * 6)
    elif sampled:
        findings.append(Finding(
            "info", t("tech.footer_ok_title", lang), t("tech.footer_ok_detail", lang, total=len(sampled)),
        ))

    # 5) schema.org Offer vs. tatsächliche Shop-Daten. Laut Checkliste die
    #    klassische Quelle für "automatische Artikel-Updates" -> Sperre.
    price_by_handle: dict[str, set[str]] = {}
    availability_by_handle: dict[str, bool] = {}
    for p in products_sample:
        handle = (p.get("handle") or "").lower()
        if not handle:
            continue
        variants = p.get("variants") or []
        price_by_handle[handle] = {f"{float(v.get('price') or 0):.2f}" for v in variants}
        availability_by_handle[handle] = any(v.get("available") for v in variants)

    checked = 0
    price_mismatches: list[str] = []
    availability_mismatches: list[str] = []
    for url, html in product_pages:
        offers = _extract_offers(html)
        if not offers:
            continue
        checked += 1
        handle = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0].lower()
        expected_prices = price_by_handle.get(handle)
        expected_available = availability_by_handle.get(handle)

        for offer in offers:
            raw_price = offer.get("price") or offer.get("lowPrice")
            if raw_price is not None and expected_prices:
                try:
                    markup_price = f"{float(str(raw_price).replace(',', '.')):.2f}"
                except (TypeError, ValueError):
                    markup_price = None
                if markup_price and markup_price not in expected_prices:
                    price_mismatches.append(
                        f"{url} — Markup: {markup_price} / Shop: {', '.join(sorted(expected_prices))}"
                    )
            raw_avail = str(offer.get("availability") or "").lower()
            if raw_avail and expected_available is not None:
                markup_available = "instock" in raw_avail.replace("_", "")
                if markup_available != expected_available:
                    availability_mismatches.append(
                        f"{url} — Markup: {'InStock' if markup_available else 'OutOfStock'} / "
                        f"Shop: {'verfügbar' if expected_available else 'ausverkauft'}"
                    )

    if product_pages and checked == 0:
        findings.append(Finding(
            "medium", t("tech.no_structured_data_title", lang), t("tech.no_structured_data_detail", lang),
        ))
        score -= 12
    elif checked:
        if price_mismatches:
            findings.append(Finding(
                "critical", t("tech.price_mismatch_title", lang),
                t("tech.price_mismatch_detail", lang, listing=_listing(sorted(set(price_mismatches)), lang)),
            ))
            score -= 30
        if availability_mismatches:
            findings.append(Finding(
                "high", t("tech.availability_mismatch_title", lang),
                t("tech.availability_mismatch_detail", lang, listing=_listing(sorted(set(availability_mismatches)), lang)),
            ))
            score -= 20
        if not price_mismatches and not availability_mismatches:
            findings.append(Finding(
                "info", t("tech.structured_data_ok_title", lang),
                t("tech.structured_data_ok_detail", lang, count=checked),
            ))

    # 6) Transparenz: was von außen prinzipiell nicht prüfbar ist, wird
    #    ausgewiesen statt stillschweigend weggelassen (Kategorie I/J).
    findings.append(Finding("info", t("tech.gmc_note_title", lang), t("tech.gmc_note_detail", lang)))

    return CategoryResult("technical", t("cat.technical", lang), max(0, min(100, score)), findings)
