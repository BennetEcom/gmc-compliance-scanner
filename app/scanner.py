"""
GMC Compliance Scanner
=======================
Führt echte, live Checks gegen einen Shopify-Store (oder generisch jede
Website) durch und bewertet die Wahrscheinlichkeit einer Google Merchant
Center (GMC) Sperrung anhand von 5 Kategorien:

1. Trust & Domain-Metriken (SSL, Domain-Alter, Erreichbarkeit)
2. Broken Links
3. Policy-Seiten (Impressum, Datenschutz, AGB, Widerruf, Versand, Kontakt)
4. Produkt-Feed-Qualität (GTIN/Brand/Preis/Verfügbarkeit via Shopify products.json)
5. Bild-Compliance (Auflösung, Alt-Text, erreichbar)

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
MAX_LINKS_TO_CHECK = 25
MAX_PRODUCTS_TO_SAMPLE = 8


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


async def fetch(client: httpx.AsyncClient, url: str, method: str = "GET", **kw):
    try:
        resp = await client.request(method, url, timeout=REQUEST_TIMEOUT, follow_redirects=True, **kw)
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
        findings.append(Finding("medium", "Zugriff durch Bot-Schutz blockiert (403)",
                                 "Der Shop hat eine Firewall/Bot-Schutz aktiv, die automatisierte Anfragen blockiert. Das ist kein GMC-Compliance-Problem, verhindert aber weitere automatische Checks auf dieser Seite – bitte einzelne Bereiche manuell prüfen."))
        score -= 15
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
        findings.append(Finding("medium", "SSL-Zertifikat konnte nicht geprüft werden", str(exc)))
        score -= 10

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
        findings.append(Finding("low", "Domain-Alter unbekannt", "WHOIS-Daten waren nicht auslesbar (kein Rot-Flag, aber auch kein Vertrauensbonus)."))
    elif domain_age_days < MIN_TRUSTED_DOMAIN_AGE_DAYS:
        findings.append(Finding("high", "Sehr junge Domain",
                                 f"Domain ist erst {domain_age_days} Tage alt. Junge Domains werden von GMC häufiger streng geprüft ('73% der neuen Dropshipping-Stores scheitern an mind. einem Check')."))
        score -= 20
    else:
        findings.append(Finding("info", "Domain-Alter unauffällig", f"Domain ist {domain_age_days} Tage alt."))

    score = max(0, min(100, score))
    return CategoryResult("trust", "Trust & Domain-Metriken", score, findings)


# ---------------------------------------------------------------------------
# 2) Broken Links
# ---------------------------------------------------------------------------
async def check_broken_links(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str]) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    if not homepage_html:
        findings.append(Finding("medium", "Broken-Link-Check nicht möglich", "Startseite konnte nicht geladen werden."))
        return CategoryResult("broken_links", "Broken Links", 40, findings)

    soup = BeautifulSoup(homepage_html, "html.parser")
    host = urlparse(base_url).netloc
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urljoin(base_url + "/", href)
        if urlparse(full).netloc == host:
            links.add(full)
    links = list(links)[:MAX_LINKS_TO_CHECK]

    broken = []
    async def check_one(url: str):
        resp = await fetch(client, url, method="HEAD")
        if isinstance(resp, Exception) or resp.status_code >= 400:
            resp2 = await fetch(client, url, method="GET")
            if isinstance(resp2, Exception) or resp2.status_code >= 400:
                broken.append(url)

    await asyncio.gather(*(check_one(u) for u in links))

    if links:
        ratio_broken = len(broken) / len(links)
        score = round(100 * (1 - ratio_broken))
        if broken:
            preview = ", ".join(broken[:5])
            findings.append(Finding(
                "high" if ratio_broken > 0.15 else "medium",
                f"{len(broken)} von {len(links)} geprüften internen Links fehlerhaft",
                f"Beispiele: {preview}",
            ))
        else:
            findings.append(Finding("info", "Keine Broken Links gefunden", f"{len(links)} interne Links geprüft, alle erreichbar."))
    else:
        findings.append(Finding("low", "Keine internen Links gefunden", "Startseite enthält keine prüfbaren internen Links."))
        score = 70

    return CategoryResult("broken_links", "Broken Links", max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 3) Policy-Seiten
# ---------------------------------------------------------------------------
async def check_policy_pages(client: httpx.AsyncClient, base_url: str, homepage_html: Optional[str]) -> CategoryResult:
    findings: list[Finding] = []
    found_keys = set()

    link_texts = []
    if homepage_html:
        soup = BeautifulSoup(homepage_html, "html.parser")
        for a in soup.find_all("a", href=True):
            link_texts.append((a.get_text(" ", strip=True).lower(), a["href"].lower()))

    for key, meta in POLICY_PATTERNS.items():
        matched = False
        for text, href in link_texts:
            if any(kw in text for kw in meta["keywords"]) or any(kw.replace(" ", "-") in href for kw in meta["keywords"]):
                matched = True
                break
        if matched:
            found_keys.add(key)

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
            resp = await fetch(client, urljoin(base_url, path))
            if not isinstance(resp, Exception) and resp.status_code < 400:
                found_keys.add(key)
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
    return CategoryResult("policy_pages", "Policy-Seiten", max(0, min(100, score)), findings)


# ---------------------------------------------------------------------------
# 4) Produkt-Feed-Qualität (Shopify products.json)
# ---------------------------------------------------------------------------
async def check_product_feed(client: httpx.AsyncClient, base_url: str) -> tuple[CategoryResult, list[dict]]:
    findings: list[Finding] = []
    products_sample: list[dict] = []
    score = 100

    resp = await fetch(client, urljoin(base_url, "/products.json?limit=" + str(MAX_PRODUCTS_TO_SAMPLE)))
    if isinstance(resp, Exception) or resp.status_code >= 400:
        findings.append(Finding("low", "Kein Shopify products.json-Feed gefunden",
                                 "Store scheint nicht auf Shopify zu laufen oder der Feed ist deaktiviert – Feed-Qualität kann nicht automatisch geprüft werden."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 60, findings), products_sample

    try:
        data = resp.json()
        products = data.get("products", [])[:MAX_PRODUCTS_TO_SAMPLE]
    except Exception:
        findings.append(Finding("low", "Produkt-Feed nicht auswertbar", "products.json konnte nicht als JSON gelesen werden."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 60, findings), products_sample

    if not products:
        findings.append(Finding("medium", "Keine Produkte im Feed gefunden", "Store hat aktuell keine sichtbaren Produkte über products.json."))
        return CategoryResult("product_feed", "Produkt-Feed-Qualität", 50, findings), products_sample

    missing_brand = 0
    missing_gtin = 0
    missing_price = 0
    missing_desc = 0
    thin_desc = 0

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

        desc = re.sub("<[^<]+?>", "", p.get("body_html") or "").strip()
        if not desc:
            missing_desc += 1
        elif len(desc) < 100:
            thin_desc += 1

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

    if not missing_gtin and not missing_brand and not missing_price and not missing_desc:
        findings.append(Finding("info", "Stichprobe unauffällig", f"{n} Produkte geprüft, keine offensichtlichen Feed-Probleme gefunden."))

    return CategoryResult("product_feed", "Produkt-Feed-Qualität", max(0, min(100, score)), findings), products_sample


# ---------------------------------------------------------------------------
# 5) Bild-Compliance
# ---------------------------------------------------------------------------
async def check_images(client: httpx.AsyncClient, base_url: str, products_sample: list[dict]) -> CategoryResult:
    findings: list[Finding] = []
    score = 100

    image_urls = []
    for p in products_sample:
        for img in (p.get("images") or [])[:2]:
            src = img.get("src")
            if src:
                # Shopify liefert Bild-URLs oft absolut, protocol-relativ ("//cdn...")
                # oder relativ zur Domain - alle Fälle auf eine absolute URL normalisieren.
                image_urls.append(urljoin(base_url + "/", src))
    image_urls = image_urls[:15]

    if not image_urls:
        findings.append(Finding("low", "Keine Produktbilder zum Prüfen gefunden", "Bild-Compliance konnte nicht automatisch bewertet werden."))
        return CategoryResult("images", "Bild-Compliance", 60, findings)

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
# Orchestrierung
# ---------------------------------------------------------------------------
async def run_scan(raw_url: str) -> dict:
    base_url = normalize_url(raw_url)

    async with httpx.AsyncClient(headers=DEFAULT_HEADERS) as client:
        home_resp = await fetch(client, base_url)
        homepage_html = None
        if not isinstance(home_resp, Exception) and home_resp.status_code < 400:
            homepage_html = home_resp.text

        trust_task = check_trust_domain(client, base_url)
        links_task = check_broken_links(client, base_url, homepage_html)
        policy_task = check_policy_pages(client, base_url, homepage_html)
        feed_task = check_product_feed(client, base_url)

        trust_res, links_res, policy_res, (feed_res, products_sample) = await asyncio.gather(
            trust_task, links_task, policy_task, feed_task
        )
        images_res = await check_images(client, base_url, products_sample)

    categories = [trust_res, links_res, policy_res, feed_res, images_res]

    weights = {
        "trust": 0.20,
        "broken_links": 0.15,
        "policy_pages": 0.30,
        "product_feed": 0.25,
        "images": 0.10,
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
