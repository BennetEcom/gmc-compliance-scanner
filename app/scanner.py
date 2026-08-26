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
3. Policy-Seiten (Impressum, Datenschutz, AGB, Widerruf, Versand, Kontakt)
4. Kontakt & Rechtliches (geschäftliche E-Mail, Telefon, NAP-Konsistenz, Platzhalter-Content, Standard-URLs)
5. Produkt-Feed-Qualität (GTIN/Brand/Preis/SKU/Streichpreis/Condition via Shopify products.json, leere Nav-Kollektionen)
6. Bild-Compliance (Auflösung, Alt-Text, erreichbar)
7. Bewertungen & Social Proof (verifizierbare Plattform vs. nicht nachprüfbare/duplizierte Reviews)
8. Künstliche Dringlichkeit/Verknappung ("Fake Urgency": Countdown-Apps, "nur noch X"-Behauptungen ohne echten Lagerbestand)
9. Page Speed (Google PageSpeed Insights/Lighthouse: Performance-Score, LCP, CLS, TBT – mobil)

Kein Login nötig, keine Datenspeicherung – alles läuft pro Request live.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import PAGESPEED_API_KEY

try:
    import whois as pywhois
except Exception:  # pragma: no cover
    pywhois = None

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

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


def _get_http_concurrency() -> asyncio.Semaphore:
    global _http_concurrency
    if _http_concurrency is None:
        _http_concurrency = asyncio.Semaphore(4)
    return _http_concurrency

# --- Policy-Seiten: Keywords, nach denen wir in Footer-Links & URLs suchen ---
POLICY_PATTERNS = {
    "impressum": {
        "label": "Impressum / Legal Notice",
        "keywords": ["impressum", "legal-notice", "legal notice", "imprint"],
        "severity": "critical",
    },
    "privacy": {
        "label": "Datenschutzerklärung",
        "keywords": ["datenschutz", "privacy-policy", "privacy policy", "privacypolicy"],
        "severity": "critical",
    },
    "terms": {
        "label": "AGB / Terms of Service",
        "keywords": ["agb", "terms-of-service", "terms-and-conditions", "terms of service", "nutzungsbedingungen"],
        "severity": "high",
    },
    "refund": {
        "label": "Widerrufsrecht / Rückgaberecht",
        "keywords": ["widerruf", "ruckgabe", "rückgabe", "refund-policy", "return-policy", "refund policy", "return policy"],
        "severity": "critical",
    },
    "shipping": {
        "label": "Versandinformationen",
        "keywords": ["versand", "shipping-policy", "shipping policy", "lieferzeit", "delivery"],
        "severity": "medium",
    },
    "contact": {
        "label": "Kontaktmöglichkeit",
        "keywords": ["kontakt", "contact-us", "contact us", "contact"],
        "severity": "high",
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
async def check_trust_domain(client: httpx.AsyncClient, base_url: str) -> CategoryResult:
    findings: list[Finding] = []
    score = 100
    parsed = urlparse(base_url)
    host = parsed.netloc

    # HTTPS erreichbar?
    resp = await fetch(client, base_url)
    if isinstance(resp, Exception):
        findings.append(Finding("critical", "Shop nicht erreichbar",
                                 f"Die Startseite konnte nicht geladen werden ({resp})."))
        score -= 60
    elif resp.status_code == 403:
        findings.append(Finding("info", "Zugriff durch Bot-Schutz blockiert (403)",
                                 "Der Shop hat eine Firewall/Bot-Schutz aktiv, die automatisierte Anfragen blockiert. Das ist kein GMC-Compliance-Problem, verhindert aber weitere automatische Checks auf dieser Seite – bitte einzelne Bereiche manuell prüfen."))
    elif resp.status_code >= 400:
        findings.append(Finding("critical", "Shop nicht erreichbar",
                                 f"Die Startseite antwortet mit Fehlercode {resp.status_code}."))
        score -= 60
    else:
        if str(resp.url).startswith("https://"):
            findings.append(Finding("info", "HTTPS aktiv", "Die Seite wird korrekt über HTTPS ausgeliefert."))
        else:
            findings.append(Finding("critical", "Kein HTTPS", "Google Merchant Center verlangt eine verschlüsselte Verbindung (HTTPS)."))
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
            findings.append(Finding("critical", "SSL-Zertifikat abgelaufen", f"Das Zertifikat ist seit {abs(days_left)} Tagen abgelaufen."))
            score -= 30
        elif days_left < 14:
            findings.append(Finding("medium", "SSL-Zertifikat läuft bald ab", f"Nur noch {days_left} Tage gültig."))
            score -= 10
        else:
            findings.append(Finding("info", "SSL-Zertifikat gültig", f"Noch {days_left} Tage gültig."))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding("info", "SSL-Zertifikat konnte nicht geprüft werden", "Technische Prüfung war nicht möglich – kein bestätigtes Problem: " + str(exc)))

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
        findings.append(Finding("info", "Domain-Alter unbekannt", "WHOIS-Daten waren nicht auslesbar (kein Rot-Flag, aber auch kein Vertrauensbonus)."))
    elif domain_age_days < MIN_TRUSTED_DOMAIN_AGE_DAYS:
        findings.append(Finding("high", "Sehr junge Domain",
                                 f"Domain ist erst {domain_age_days} Tage alt. Junge Domains werden von GMC häufiger streng geprüft ('73% der neuen Dropshipping-Stores scheitern an mind. einem Check')."))
        score -= 20
    else:
        findings.append(Finding("info", "Domain-Alter unauffällig", f"Domain ist {domain_age_days} Tage alt."))

    score = max(0, min(100, score))
    return CategoryResult("trust", "Trust & Domain-Metriken", score, findings)


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
async def check_broken_links(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], site_urls: dict) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not homepage_html:
        findings.append(Finding("info", "Broken-Link-Check nicht möglich", "Startseite konnte nicht geladen werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("broken_links", "Broken Links", 100, findings)

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
        f" ({len(links)} von {total_discovered} gefundenen Seiten geprüft; die Sitemap-Erkennung selbst ist auf {MAX_SITEMAP_ENTRIES} Einträge begrenzt)"
        if total_discovered > len(links) else ""
    )

    if links:
        ratio_broken = len(broken) / len(links)
        score = round(100 * (1 - ratio_broken))

        if broken:
            shown = broken[:25]
            preview = "\n".join(f"• {u}" for u, _ in shown)
            if len(broken) > len(shown):
                preview += f"\n… und {len(broken) - len(shown)} weitere"
            findings.append(Finding(
                "high" if ratio_broken > 0.15 else "medium",
                f"{len(broken)} von {len(links)} geprüften Seiten mit 404 (Broken Link){coverage_note}",
                preview,
            ))
        elif not other_errors:
            findings.append(Finding("info", "Keine Broken Links (404) gefunden", f"{len(links)} Seiten/interne Links geprüft{coverage_note}, alle erreichbar."))
        else:
            findings.append(Finding("info", "Keine echten 404-Fehler gefunden", f"{len(links)} Seiten geprüft{coverage_note} – kein einziger 404, siehe unten für andere Statuscodes."))

        if other_errors:
            shown = other_errors[:15]
            preview = "\n".join(f"• {u} ({status})" for u, status in shown)
            if len(other_errors) > len(shown):
                preview += f"\n… und {len(other_errors) - len(shown)} weitere"
            findings.append(Finding(
                "info", f"{len(other_errors)} von {len(links)} Seiten mit anderem Fehlerstatus, kein 404 (nicht als Broken Link gewertet){coverage_note}",
                f"Statuscodes wie 403/429/5xx oder Timeouts bedeuten nicht \"Seite existiert nicht\", sondern meist Firewall-/Rate-Limit-Reaktionen auf den Scan selbst – kein bestätigtes Problem, deshalb hier separat und ohne Punktabzug:\n{preview}",
            ))
    else:
        findings.append(Finding("info", "Keine internen Links gefunden", "Es konnten keine prüfbaren internen Seiten gefunden werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        score = 100

    return CategoryResult("broken_links", "Broken Links", max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 3) Policy-Seiten
# ---------------------------------------------------------------------------
async def check_policy_pages(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str]) -> tuple[CategoryResult, dict[str, str]]:
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
        if key in found_keys:
            findings.append(Finding("info", f"{meta['label']} gefunden", "Seite/Link wurde erkannt."))
        else:
            lost_weight += w
            findings.append(Finding(meta["severity"], f"{meta['label']} fehlt",
                                     "Häufigster Ablehnungsgrund bei GMC: fehlende oder nicht auffindbare Policy-Seite."))

    score = round(100 * (1 - lost_weight / total_weight)) if total_weight else 100
    return CategoryResult("policy_pages", "Policy-Seiten", max(0, min(100, score)), findings), found_urls


# ---------------------------------------------------------------------------
# 4) Kontakt & Rechtliches (aus der GMC-Master-Checklist, Kategorie C/E)
# ---------------------------------------------------------------------------
async def check_contact_legal(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str], policy_urls: dict[str, str]) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    # Kontakt-/Rechtsseiten zusätzlich laden (Startseite reicht oft nicht für
    # E-Mail/Telefon/NAP-Konsistenz-Checks).
    extra_urls = [u for k, u in policy_urls.items() if k in ("contact", "impressum", "privacy")]
    extra_pages = await fetch_product_pages(client, extra_urls[:3])  # generischer HTML-Fetch, Name passt trotzdem

    pages_html: dict[str, str] = {"Startseite": homepage_html or ""}
    for url, html in extra_pages:
        pages_html[url] = html

    combined_html = "\n".join(pages_html.values())
    if not combined_html.strip():
        findings.append(Finding("info", "Kontakt-Check nicht möglich", "Keine Seiteninhalte zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("contact_legal", "Kontakt & Rechtliches", 100, findings)

    # 1) Geschäftliche E-Mail statt privatem Anbieter
    emails_by_page = {url: set(EMAIL_RE.findall(html)) for url, html in pages_html.items()}
    all_emails = set().union(*emails_by_page.values()) if emails_by_page else set()
    host = urlparse(base_url).netloc.replace("www.", "")
    if all_emails:
        personal = {e for e in all_emails if e.split("@")[-1].lower() in PERSONAL_EMAIL_DOMAINS}
        if personal and len(personal) == len(all_emails):
            findings.append(Finding(
                "medium", "Nur private E-Mail-Adresse(n) gefunden (z. B. Gmail/GMX)",
                f"Gefunden: {', '.join(sorted(personal))}. GMC-Reviewer werten eine geschäftliche Adresse (info@{host}) als Vertrauenssignal.",
            ))
            score -= 15
        else:
            findings.append(Finding("info", "Geschäftliche E-Mail-Adresse gefunden", f"{', '.join(sorted(all_emails))[:200]}"))
    else:
        findings.append(Finding("high", "Keine E-Mail-Adresse im Seitentext gefunden", "Weder Startseite noch Kontakt-/Rechtsseiten enthalten eine erkennbare E-Mail-Adresse."))
        score -= 20

    # 2) Telefonnummer sichtbar
    if not PHONE_RE.search(combined_html):
        findings.append(Finding("medium", "Keine Telefonnummer gefunden", "Google-Reviewer werten eine sichtbare Telefonnummer als Vertrauenssignal (Checklist-Punkt C)."))
        score -= 10
    else:
        findings.append(Finding("info", "Telefonnummer gefunden", "Eine Telefonnummer ist im Footer/Kontakt-Bereich erkennbar."))

    # 3) NAP-Konsistenz: identische E-Mail über alle geprüften Seiten hinweg
    non_empty_pages = {url: emails for url, emails in emails_by_page.items() if emails}
    if len(non_empty_pages) >= 2:
        distinct = set().union(*non_empty_pages.values())
        if len(distinct) > 1:
            findings.append(Finding(
                "high", "Unterschiedliche E-Mail-Adressen auf verschiedenen Seiten",
                f"Gefunden: {', '.join(sorted(distinct))}. Google verlangt identische Kontaktdaten auf Footer, Kontaktseite und Rechtstexten (NAP-Konsistenz).",
            ))
            score -= 20

    # 4) Platzhalter-/Template-Reste
    lower_combined = combined_html.lower()
    placeholder_hits = {p for p in PLACEHOLDER_PATTERNS if re.search(p, lower_combined)}
    if placeholder_hits:
        findings.append(Finding(
            "critical", "Platzhalter-/Beispieltext auf der Seite gefunden",
            "Erkannte Muster wie eckige Klammern, 'Lorem Ipsum' oder Formular-Vorbelegungen (z. B. 'you@email.com'). Google hat das in einem Support-Ticket 2026-07 explizit als Ablehnungsgrund genannt.",
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
            "low", f"{len(dead_ends)} von {len(GUESSED_PATHS)} typischen Standard-URLs enden auf 404",
            f"{listing}\nNicht kritisch, wenn diese Seiten nie existiert haben – idealerweise leiten geratene Standard-URLs auf eine echte Seite weiter statt auf einen Fehler.",
        ))
        score -= min(10, len(dead_ends) * 2)

    score = max(0, min(100, score))
    return CategoryResult("contact_legal", "Kontakt & Rechtliches", score, findings)


# ---------------------------------------------------------------------------
# 5) Produkt-Feed-Qualität (Shopify products.json)
# ---------------------------------------------------------------------------
MAX_NAV_COLLECTIONS_TO_CHECK = 15
EMPTY_COLLECTION_THRESHOLD = 3


async def check_nav_collections(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str]) -> list[Finding]:
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
        "medium", f"{len(empty)} im Menü verlinkte Kollektion(en) mit ≤{EMPTY_COLLECTION_THRESHOLD} Produkten",
        f"Betroffen: {', '.join(empty)}. Eine Navigation, die auf eine leere/fast leere Kategorie zeigt, wirkt für Google-Reviewer wie ein unfertiger Store.",
    )]


async def check_product_feed(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str] = None) -> tuple[CategoryResult, list[dict]]:
    findings: list[Finding] = []
    products_sample: list[dict] = []
    score = 100

    resp = await fetch(client, urljoin(base_url, "/products.json?limit=" + str(MAX_PRODUCTS_TO_SAMPLE)))
    if isinstance(resp, Exception) or resp.status_code >= 400:
        findings.append(Finding("info", "Kein Shopify products.json-Feed gefunden",
                                 "Store scheint nicht auf Shopify zu laufen oder der Feed ist deaktiviert – Feed-Qualität kann nicht automatisch geprüft werden. Kein bestätigtes Problem."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 100, findings), products_sample

    try:
        data = resp.json()
        products = data.get("products", [])[:MAX_PRODUCTS_TO_SAMPLE]
    except Exception:
        findings.append(Finding("info", "Produkt-Feed nicht auswertbar", "products.json konnte nicht als JSON gelesen werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 100, findings), products_sample

    if not products:
        findings.append(Finding("info", "Keine Produkte im Feed gefunden", "Store hat aktuell keine sichtbaren Produkte über products.json – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 100, findings), products_sample

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
        findings.append(Finding("critical", f"{pct(missing_gtin)}% der Produkte ohne GTIN/Barcode",
                                 "Fehlende eindeutige Produktkennung (GTIN/MPN) ist einer der häufigsten GMC-Ablehnungsgründe für Produktdaten."))
        score -= min(35, missing_gtin * 6)
    if missing_brand:
        findings.append(Finding("high", f"{pct(missing_brand)}% der Produkte ohne erkennbare Marke (Vendor-Feld)",
                                 "GMC verlangt in der Regel Brand + GTIN oder eine Ausnahmekennzeichnung."))
        score -= min(25, missing_brand * 4)
    if missing_price:
        findings.append(Finding("high", f"{pct(missing_price)}% der Produkte ohne gültigen Preis", "Preis muss > 0 und konsistent mit der Produktseite sein."))
        score -= min(20, missing_price * 5)
    if missing_desc:
        findings.append(Finding("medium", f"{pct(missing_desc)}% der Produkte ohne Produktbeschreibung", "Leere Beschreibungen gelten als 'Thin Content'."))
        score -= min(15, missing_desc * 3)
    elif thin_desc:
        findings.append(Finding("low", f"{pct(thin_desc)}% der Produkte mit sehr kurzer Beschreibung (<100 Zeichen)", "Kurze/duplizierte Texte erhöhen das Risiko einer Ablehnung wegen 'Thin Content'."))
        score -= min(10, thin_desc * 2)

    if duplicate_skus:
        listing = "\n".join(f"• {sku} ({c}×)" for sku, c in duplicate_skus.items())
        findings.append(Finding("high", f"{len(duplicate_skus)} SKU(s) mehrfach vergeben", f"{listing}\nSKUs müssen pro Variante eindeutig sein."))
        score -= min(20, len(duplicate_skus) * 5)

    if inverted_compare_at:
        findings.append(Finding(
            "high", f"{inverted_compare_at} Variante(n) mit unglaubwürdigem Streichpreis",
            "Der 'Compare-at'-Preis (Streichpreis) ist kleiner oder gleich dem aktuellen Preis. Ein Streichpreis, der keinen echten Rabatt zeigt, ist ein klassisches Fake-Sale-Muster.",
        ))
        score -= min(20, inverted_compare_at * 5)

    if used_wording:
        findings.append(Finding(
            "medium", f"{used_wording} Produktbeschreibung(en) mit 'gebraucht/refurbished'-Wortlaut",
            "GMC verlangt condition=new für neue Ware; Wörter wie 'refurbished' oder 'gebraucht' in der Beschreibung widersprechen dem.",
        ))
        score -= min(15, used_wording * 5)

    if not missing_gtin and not missing_brand and not missing_price and not missing_desc and not duplicate_skus and not inverted_compare_at and not used_wording:
        findings.append(Finding("info", "Stichprobe unauffällig", f"{n} Produkte geprüft, keine offensichtlichen Feed-Probleme gefunden."))

    collection_findings = await check_nav_collections(client, base_url, homepage_html)
    if collection_findings:
        findings.extend(collection_findings)
        score -= 10

    return CategoryResult("product_feed", "Produkt-Feed-Qualität", max(0, min(100, score)), findings), products_sample


# ---------------------------------------------------------------------------
# 6) Bild-Compliance
# ---------------------------------------------------------------------------
async def check_images(client: httpx.AsyncClient, base_url: str, products_sample: list[dict]) -> CategoryResult:
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
        findings.append(Finding("info", "Keine Produktbilder zum Prüfen gefunden", "Bild-Compliance konnte nicht automatisch bewertet werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("images", "Bild-Compliance", 100, findings)

    broken = 0
    too_small = 0
    checked = 0

    async def check_one(url: str):
        nonlocal broken, too_small, checked
        resp = await fetch(client, url)
        if isinstance(resp, Exception) or resp.status_code >= 400:
            broken += 1
            return
        checked += 1
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
        findings.append(Finding("high", f"{broken} von {n} Produktbildern nicht ladbar", "Nicht erreichbare Bilder führen zur Ablehnung einzelner Produkte im Feed."))
        score -= min(40, broken * 8)
    if too_small:
        findings.append(Finding("medium", f"{too_small} Bilder unter {MIN_IMAGE_EDGE_PX}px Kantenlänge",
                                 f"Google empfiehlt mindestens {RECOMMENDED_IMAGE_EDGE_PX}px für die kürzere Bildkante."))
        score -= min(25, too_small * 5)
    if not broken and not too_small:
        findings.append(Finding("info", "Bilder unauffällig", f"{checked} Bilder geprüft, erreichbar und ausreichend groß."))

    findings.append(Finding("info", "Hinweis", "Text-Overlays, Wasserzeichen und Rabatt-Banner in Bildern können nicht automatisiert erkannt werden – bitte manuell stichprobenartig prüfen."))

    return CategoryResult("images", "Bild-Compliance", max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 9) Page Speed (Google PageSpeed Insights / Lighthouse)
# ---------------------------------------------------------------------------
PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
# Lighthouse läuft serverseitig bei Google einen vollen Audit-Durchlauf – das
# dauert deutlich länger als ein normaler HTTP-Request.
PAGESPEED_TIMEOUT = httpx.Timeout(45.0, connect=10.0)


async def check_page_speed(client: httpx.AsyncClient, base_url: str) -> CategoryResult:
    findings: list[Finding] = []
    label = "Page Speed (Google PageSpeed Insights)"

    if not PAGESPEED_API_KEY:
        findings.append(Finding(
            "info", "PageSpeed-Check nicht konfiguriert",
            "Für diesen Check ist kein Google-PageSpeed-API-Key hinterlegt – wird übersprungen (kein bestätigtes Problem).",
        ))
        return CategoryResult("page_speed", label, 100, findings)

    resp = await fetch(
        client, PAGESPEED_API_URL,
        params={"url": base_url, "key": PAGESPEED_API_KEY, "strategy": "mobile", "category": "performance"},
        timeout=PAGESPEED_TIMEOUT,
    )

    if isinstance(resp, Exception) or resp.status_code >= 400:
        detail = str(resp) if isinstance(resp, Exception) else f"HTTP {resp.status_code}: {resp.text[:200]}"
        findings.append(Finding(
            "info", "PageSpeed-Check nicht möglich",
            f"Google PageSpeed Insights konnte nicht abgefragt werden ({detail}) – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        ))
        return CategoryResult("page_speed", label, 100, findings)

    try:
        data = resp.json()
        lighthouse = data["lighthouseResult"]
        perf_score = round(lighthouse["categories"]["performance"]["score"] * 100)
        audits = lighthouse["audits"]
        lcp_s = audits["largest-contentful-paint"]["numericValue"] / 1000
        cls = audits["cumulative-layout-shift"]["numericValue"]
        tbt_ms = audits["total-blocking-time"]["numericValue"]
    except (KeyError, TypeError, ValueError) as exc:
        findings.append(Finding(
            "info", "PageSpeed-Ergebnis nicht auswertbar",
            f"Antwort von Google PageSpeed Insights konnte nicht gelesen werden ({exc}).",
        ))
        return CategoryResult("page_speed", label, 100, findings)

    # Der Lighthouse-Performance-Score ist bereits eine gewichtete
    # Zusammenfassung von LCP/CLS/TBT & Co. – wird 1:1 als Kategorie-Score
    # übernommen. Die einzelnen Core-Web-Vitals-Werte darunter sind rein
    # informativ und ändern den Score nicht zusätzlich (sonst würde derselbe
    # Effekt doppelt gewichtet).
    score = perf_score

    if perf_score >= 90:
        findings.append(Finding("info", f"Performance-Score (mobil): {perf_score}/100",
                                 "Google Lighthouse stuft die Ladegeschwindigkeit als gut ein."))
    elif perf_score >= 50:
        findings.append(Finding("medium", f"Performance-Score (mobil): {perf_score}/100",
                                 "Google Lighthouse stuft die Ladegeschwindigkeit als verbesserungswürdig ein – eine langsame Seite verschlechtert Nutzererfahrung und Conversion."))
    else:
        findings.append(Finding("high", f"Performance-Score (mobil): {perf_score}/100",
                                 "Google Lighthouse stuft die Ladegeschwindigkeit als schlecht ein."))

    if lcp_s <= 2.5:
        findings.append(Finding("info", f"Largest Contentful Paint: {lcp_s:.1f}s",
                                 "Innerhalb des von Google empfohlenen Bereichs (≤2,5s)."))
    elif lcp_s <= 4.0:
        findings.append(Finding("medium", f"Largest Contentful Paint: {lcp_s:.1f}s",
                                 "Über dem empfohlenen Wert von 2,5s – bei den Core Web Vitals als 'verbesserungswürdig' eingestuft."))
    else:
        findings.append(Finding("high", f"Largest Contentful Paint: {lcp_s:.1f}s",
                                 "Deutlich über dem empfohlenen Wert von 2,5s – bei den Core Web Vitals als 'schlecht' eingestuft."))

    if cls <= 0.1:
        findings.append(Finding("info", f"Cumulative Layout Shift: {cls:.2f}",
                                 "Innerhalb des von Google empfohlenen Bereichs (≤0,1)."))
    elif cls <= 0.25:
        findings.append(Finding("medium", f"Cumulative Layout Shift: {cls:.2f}",
                                 "Über dem empfohlenen Wert von 0,1 – die Seite \"springt\" beim Laden spürbar."))
    else:
        findings.append(Finding("high", f"Cumulative Layout Shift: {cls:.2f}",
                                 "Deutlich über dem empfohlenen Wert – bei den Core Web Vitals als 'schlecht' eingestuft."))

    if tbt_ms <= 200:
        findings.append(Finding("info", f"Total Blocking Time: {tbt_ms:.0f}ms",
                                 "Innerhalb des von Google empfohlenen Bereichs."))
    elif tbt_ms <= 600:
        findings.append(Finding("medium", f"Total Blocking Time: {tbt_ms:.0f}ms",
                                 "Über dem empfohlenen Wert – die Seite reagiert während des Ladens spürbar verzögert auf Eingaben."))
    else:
        findings.append(Finding("high", f"Total Blocking Time: {tbt_ms:.0f}ms",
                                 "Deutlich über dem empfohlenen Wert – spürbar verzögerte Reaktion auf Eingaben während des Ladens."))

    score = max(0, min(100, score))
    return CategoryResult("page_speed", label, score, findings)


# ---------------------------------------------------------------------------
# Produktseiten laden (für Bewertungs- und Urgency-Checks brauchen wir das
# tatsächlich gerenderte HTML, nicht nur products.json)
# ---------------------------------------------------------------------------
async def fetch_product_pages(client: httpx.AsyncClient, product_urls: list[str]) -> list[tuple[str, str]]:
    pages: list[tuple[str, str]] = []

    async def fetch_one(url: str):
        resp = await fetch(client, url)
        if not isinstance(resp, Exception) and resp.status_code < 400:
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
async def check_reviews(homepage_html: Optional[str], product_pages: list[tuple[str, str]]) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    all_html = (homepage_html or "") + "".join(html for _, html in product_pages)
    if not all_html.strip():
        findings.append(Finding("info", "Bewertungen konnten nicht geprüft werden", "Keine Seiteninhalte zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("reviews", "Bewertungen & Social Proof", 100, findings)

    lower_html = all_html.lower()
    detected_platforms = sorted({name for sig, name in KNOWN_REVIEW_PLATFORMS.items() if sig in lower_html})
    claims_reviews = bool(_REVIEW_CLAIM_RE.search(all_html))

    if detected_platforms:
        findings.append(Finding(
            "info", "Verifizierbare Bewertungsplattform erkannt",
            f"Erkannt: {', '.join(detected_platforms)}. Über Dritte nachprüfbare Bewertungen sind für Google unkritisch.",
        ))
    elif claims_reviews:
        findings.append(Finding(
            "high", "Sternebewertungen/Rezensionszahlen ohne erkennbare Drittanbieter-Plattform",
            "Es werden Bewertungen bzw. Ratings angezeigt, aber kein bekannter Bewertungs-Dienst (z. B. Trustpilot, Judge.me, Loox) konnte im Code gefunden werden. Nicht verifizierbare Testimonials verstoßen gegen Googles Richtlinie zu 'Misrepresentation'.",
        ))
        score -= 35
    else:
        findings.append(Finding("info", "Keine Bewertungen auf der Seite gefunden", "Weder Rating-Claims noch eine Bewertungsplattform erkannt – kein bestätigtes Problem."))

    # Identische Review-Texte über mehrere Produktseiten hinweg = klassisches
    # Fake-Review-Muster (kopierte Templates statt echter Kundenstimmen).
    texts_by_url: dict[str, set[str]] = {}
    for url, html in product_pages:
        texts_by_url[url] = {m.strip() for m in _REVIEW_BLOCK_RE.findall(html)}

    seen: dict[str, str] = {}
    duplicates = set()
    for url, texts in texts_by_url.items():
        for t in texts:
            if t in seen and seen[t] != url:
                duplicates.add(t)
            seen[t] = url

    if duplicates:
        example = next(iter(duplicates))[:120]
        findings.append(Finding(
            "critical", f"{len(duplicates)} identische Bewertungstexte auf mehreren Produktseiten",
            f"Beispieltext: \"{example}...\". Wortgleiche 'Kundenstimmen' auf unterschiedlichen Produkten sind ein starkes Indiz für gefälschte Bewertungen.",
        ))
        score -= 40

    score = max(0, min(100, score))
    return CategoryResult("reviews", "Bewertungen & Social Proof", score, findings)


# ---------------------------------------------------------------------------
# 8) Künstliche Dringlichkeit / Verknappung ("Fake Urgency")
# ---------------------------------------------------------------------------
async def check_urgency_patterns(product_pages: list[tuple[str, str]], products_sample: list[dict]) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not product_pages:
        findings.append(Finding("info", "Urgency-Check nicht möglich", "Keine Produktseiten zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks."))
        return CategoryResult("urgency", "Künstliche Dringlichkeit", 100, findings)

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
        findings.append(Finding("info", "Keine künstlichen Dringlichkeits-Trigger gefunden", "Keine Fake-Countdown-/Verknappungs-Muster auf den geprüften Produktseiten entdeckt."))
        return CategoryResult("urgency", "Künstliche Dringlichkeit", 100, findings)

    if app_hits:
        findings.append(Finding(
            "medium", "Countdown-/Verknappungs-App erkannt",
            f"Erkannte Skripte: {', '.join(sorted(app_hits))}. Solche Apps sind nicht automatisch verboten, aber die angezeigten Werte müssen real sein.",
        ))
        score -= 15

    if text_hits:
        findings.append(Finding(
            "high", "Formulierungen mit künstlicher Dringlichkeit/Verknappung gefunden",
            "z. B. 'nur noch X auf Lager', 'Angebot endet in...', Verkaufszähler. Google Ads' Misrepresentation-Richtlinie verbietet vorgetäuschte Knappheit/Dringlichkeit, wenn die Angaben nicht der Realität entsprechen – bitte manuell gegen den echten Lagerbestand prüfen.",
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
            "critical", "Lagerbestand wird laut Shopify gar nicht getrackt",
            "Für keines der geprüften Produkte ist Bestandsverfolgung aktiv – angezeigte 'Nur noch X verfügbar'-Hinweise können daher nicht auf echten Zahlen beruhen.",
        ))
        score -= 25

    score = max(0, min(100, score))
    return CategoryResult("urgency", "Künstliche Dringlichkeit", score, findings)


# ---------------------------------------------------------------------------
# Orchestrierung
# ---------------------------------------------------------------------------
async def run_scan(raw_url: str) -> dict:
    base_url = normalize_url(raw_url)

    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        home_resp = await fetch(client, base_url)
        homepage_html = None
        if not isinstance(home_resp, Exception) and home_resp.status_code < 400:
            homepage_html = home_resp.text

        site_urls = await discover_site_urls(client, base_url, homepage_html)

        trust_task = check_trust_domain(client, base_url)
        links_task = check_broken_links(client, base_url, homepage_html, site_urls)
        policy_task = check_policy_pages(client, base_url, homepage_html)
        feed_task = check_product_feed(client, base_url, homepage_html)
        speed_task = check_page_speed(client, base_url)

        trust_res, links_res, (policy_res, policy_urls), (feed_res, products_sample), speed_res = await asyncio.gather(
            trust_task, links_task, policy_task, feed_task, speed_task
        )
        images_res = await check_images(client, base_url, products_sample)
        contact_res = await check_contact_legal(client, base_url, homepage_html, policy_urls)

        product_pages = await fetch_product_pages(client, site_urls.get("product_urls", []))
        reviews_res = await check_reviews(homepage_html, product_pages)
        urgency_res = await check_urgency_patterns(product_pages, products_sample)

    categories = [trust_res, links_res, policy_res, contact_res, feed_res, images_res, reviews_res, urgency_res, speed_res]

    weights = {
        "trust": 0.10,
        "broken_links": 0.12,
        "policy_pages": 0.15,
        "contact_legal": 0.12,
        "product_feed": 0.15,
        "images": 0.08,
        "reviews": 0.09,
        "urgency": 0.09,
        "page_speed": 0.10,
    }
    overall = round(sum(c.score * weights[c.key] for c in categories))

    if overall >= 80:
        risk_label = "Niedriges Sperrrisiko"
    elif overall >= 50:
        risk_label = "Mittleres Sperrrisiko"
    else:
        risk_label = "Hohes Sperrrisiko"

    critical_count = sum(1 for c in categories for f in c.findings if f.severity == "critical")

    return {
        "url": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": overall,
        "risk_label": risk_label,
        "critical_issues": critical_count,
        "categories": [c.to_dict() for c in categories],
    }
