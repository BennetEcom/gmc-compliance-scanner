"""Zentrale DE/EN-Übersetzungstabelle für alle Nutzer-sichtbaren Texte im
Scanner-Backend (Finding-Titel/-Details, Kategorie-Labels, Risiko-Label,
Notices). Templates nutzen Python str.format()-Platzhalter für dynamische
Werte (Zahlen, URLs, Prozente etc.), damit an keiner Stelle Strings
dupliziert werden müssen.
"""

from __future__ import annotations

from typing import Optional

DEFAULT_LANG = "de"
SUPPORTED_LANGS = ("de", "en")


def resolve_lang(value: Optional[str]) -> str:
    """Nimmt einen Accept-Language-Header ODER einen einfachen Sprachcode
    ("de"/"en") entgegen und gibt immer "de" oder "en" zurück."""
    if not value:
        return DEFAULT_LANG
    primary = value.split(",")[0].strip().lower()
    if primary.startswith("de"):
        return "de"
    if primary.startswith("en"):
        return "en"
    return DEFAULT_LANG


def more_suffix(count: int, lang: str) -> str:
    return f"\n… und {count} weitere" if lang == "de" else f"\n… and {count} more"


_T: dict[str, dict[str, str]] = {
    # --- Kategorie-Labels ---
    "cat.trust": {"de": "Trust & Domain-Metriken", "en": "Trust & Domain Metrics"},
    "cat.broken_links": {"de": "Broken Links", "en": "Broken Links"},
    "cat.policy_pages": {"de": "Policy-Seiten", "en": "Policy Pages"},
    "cat.contact_legal": {"de": "Kontakt & Rechtliches", "en": "Contact & Legal"},
    "cat.product_feed": {"de": "Produkt-Feed-Qualität", "en": "Product Feed Quality"},
    "cat.images": {"de": "Bild-Compliance", "en": "Image Compliance"},
    "cat.reviews": {"de": "Bewertungen & Social Proof", "en": "Reviews & Social Proof"},
    "cat.urgency": {"de": "Künstliche Dringlichkeit", "en": "Artificial Urgency"},
    "cat.page_speed": {"de": "Page Speed", "en": "Page Speed"},

    # --- Risiko-Label ---
    "risk.low": {"de": "Niedriges Sperrrisiko", "en": "Low suspension risk"},
    "risk.medium": {"de": "Mittleres Sperrrisiko", "en": "Medium suspension risk"},
    "risk.high": {"de": "Hohes Sperrrisiko", "en": "High suspension risk"},

    # --- Notices ---
    "notice.free_mode": {"de": "Aktuell komplett kostenlos.", "en": "Currently completely free."},
    "notice.first_free": {
        "de": "Der erste Scan für diesen Store ist kostenlos. Ein erneuter Scan kostet {price} €.",
        "en": "The first scan for this store is free. A repeat scan costs €{price}.",
    },
    "notice.credit_used": {
        "de": "1 Scan aus deinem Guthaben verwendet. Noch {remaining} Scan(s) übrig.",
        "en": "1 scan used from your credit. {remaining} scan(s) left.",
    },
    "notice.package_bought": {
        "de": "Danke für deinen Kauf! Dein Scan-Guthaben: {remaining} weitere Scan(s).",
        "en": "Thanks for your purchase! Your scan credit: {remaining} more scan(s).",
    },

    # --- 1) Trust & Domain ---
    "trust.unreachable_title": {"de": "Shop nicht erreichbar", "en": "Store unreachable"},
    "trust.unreachable_detail_exc": {
        "de": "Die Startseite konnte nicht geladen werden ({error}).",
        "en": "The homepage could not be loaded ({error}).",
    },
    "trust.bot_blocked_title": {"de": "Zugriff durch Bot-Schutz blockiert (403)", "en": "Access blocked by bot protection (403)"},
    "trust.bot_blocked_detail": {
        "de": "Der Shop hat eine Firewall/Bot-Schutz aktiv, die automatisierte Anfragen blockiert. Das ist kein GMC-Compliance-Problem, verhindert aber weitere automatische Checks auf dieser Seite – bitte einzelne Bereiche manuell prüfen.",
        "en": "The store has an active firewall/bot protection that blocks automated requests. This is not a GMC compliance issue, but it prevents further automated checks on this site – please check individual areas manually.",
    },
    "trust.unreachable_detail_status": {
        "de": "Die Startseite antwortet mit Fehlercode {status}.",
        "en": "The homepage responds with error code {status}.",
    },
    "trust.https_active_title": {"de": "HTTPS aktiv", "en": "HTTPS active"},
    "trust.https_active_detail": {"de": "Die Seite wird korrekt über HTTPS ausgeliefert.", "en": "The site is correctly served over HTTPS."},
    "trust.no_https_title": {"de": "Kein HTTPS", "en": "No HTTPS"},
    "trust.no_https_detail": {
        "de": "Google Merchant Center verlangt eine verschlüsselte Verbindung (HTTPS).",
        "en": "Google Merchant Center requires an encrypted connection (HTTPS).",
    },
    "trust.ssl_expired_title": {"de": "SSL-Zertifikat abgelaufen", "en": "SSL certificate expired"},
    "trust.ssl_expired_detail": {"de": "Das Zertifikat ist seit {days} Tagen abgelaufen.", "en": "The certificate has been expired for {days} days."},
    "trust.ssl_expiring_title": {"de": "SSL-Zertifikat läuft bald ab", "en": "SSL certificate expiring soon"},
    "trust.ssl_expiring_detail": {"de": "Nur noch {days} Tage gültig.", "en": "Only {days} days left."},
    "trust.ssl_valid_title": {"de": "SSL-Zertifikat gültig", "en": "SSL certificate valid"},
    "trust.ssl_valid_detail": {"de": "Noch {days} Tage gültig.", "en": "Valid for {days} more days."},
    "trust.ssl_unchecked_title": {"de": "SSL-Zertifikat konnte nicht geprüft werden", "en": "SSL certificate could not be checked"},
    "trust.ssl_unchecked_detail": {
        "de": "Technische Prüfung war nicht möglich – kein bestätigtes Problem: {error}",
        "en": "Technical check was not possible – not a confirmed issue: {error}",
    },
    "trust.domain_age_unknown_title": {"de": "Domain-Alter unbekannt", "en": "Domain age unknown"},
    "trust.domain_age_unknown_detail": {
        "de": "WHOIS-Daten waren nicht auslesbar (kein Rot-Flag, aber auch kein Vertrauensbonus).",
        "en": "WHOIS data could not be read (not a red flag, but no trust bonus either).",
    },
    "trust.domain_young_title": {"de": "Sehr junge Domain", "en": "Very young domain"},
    "trust.domain_young_detail": {
        "de": "Domain ist erst {days} Tage alt. Junge Domains werden von GMC häufiger streng geprüft ('73% der neuen Dropshipping-Stores scheitern an mind. einem Check').",
        "en": "The domain is only {days} days old. Young domains are reviewed more strictly by GMC ('73% of new dropshipping stores fail at least one check').",
    },
    "trust.domain_age_ok_title": {"de": "Domain-Alter unauffällig", "en": "Domain age unremarkable"},
    "trust.domain_age_ok_detail": {"de": "Domain ist {days} Tage alt.", "en": "The domain is {days} days old."},

    # --- 2) Broken Links ---
    "links.unavailable_title": {"de": "Broken-Link-Check nicht möglich", "en": "Broken link check not possible"},
    "links.unavailable_detail": {
        "de": "Startseite konnte nicht geladen werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "Homepage could not be loaded – not a confirmed issue, just a technical limitation of the check.",
    },
    "links.coverage_note": {
        "de": " ({checked} von {total} gefundenen Seiten geprüft; die Sitemap-Erkennung selbst ist auf {max_entries} Einträge begrenzt)",
        "en": " ({checked} of {total} discovered pages checked; sitemap discovery itself is capped at {max_entries} entries)",
    },
    "links.broken_found_title": {
        "de": "{broken} von {total} geprüften Seiten mit 404 (Broken Link){coverage}",
        "en": "{broken} of {total} checked pages return 404 (broken link){coverage}",
    },
    "links.none_broken_title": {"de": "Keine Broken Links (404) gefunden", "en": "No broken links (404) found"},
    "links.none_broken_detail": {
        "de": "{total} Seiten/interne Links geprüft{coverage}, alle erreichbar.",
        "en": "{total} pages/internal links checked{coverage}, all reachable.",
    },
    "links.no_real_404_title": {"de": "Keine echten 404-Fehler gefunden", "en": "No real 404 errors found"},
    "links.no_real_404_detail": {
        "de": "{total} Seiten geprüft{coverage} – kein einziger 404, siehe unten für andere Statuscodes.",
        "en": "{total} pages checked{coverage} – not a single 404, see below for other status codes.",
    },
    "links.other_errors_title": {
        "de": "{count} von {total} Seiten mit anderem Fehlerstatus, kein 404 (nicht als Broken Link gewertet){coverage}",
        "en": "{count} of {total} pages with a different error status, not 404 (not counted as broken link){coverage}",
    },
    "links.other_errors_detail": {
        "de": "Statuscodes wie 403/429/5xx oder Timeouts bedeuten nicht \"Seite existiert nicht\", sondern meist Firewall-/Rate-Limit-Reaktionen auf den Scan selbst – kein bestätigtes Problem, deshalb hier separat und ohne Punktabzug:\n{preview}",
        "en": "Status codes like 403/429/5xx or timeouts don't mean \"page doesn't exist\", but usually firewall/rate-limit reactions to the scan itself – not a confirmed issue, therefore listed separately here without score penalty:\n{preview}",
    },
    "links.no_internal_links_title": {"de": "Keine internen Links gefunden", "en": "No internal links found"},
    "links.no_internal_links_detail": {
        "de": "Es konnten keine prüfbaren internen Seiten gefunden werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "No checkable internal pages could be found – not a confirmed issue, just a technical limitation of the check.",
    },

    # --- 3) Policy-Seiten ---
    "policy.found_title": {"de": "{label} gefunden", "en": "{label} found"},
    "policy.found_detail": {"de": "Seite/Link wurde erkannt.", "en": "Page/link was detected."},
    "policy.missing_title": {"de": "{label} fehlt", "en": "{label} missing"},
    "policy.missing_detail": {
        "de": "Häufigster Ablehnungsgrund bei GMC: fehlende oder nicht auffindbare Policy-Seite.",
        "en": "Most common GMC rejection reason: missing or undiscoverable policy page.",
    },
    "policy.impressum": {"de": "Impressum / Legal Notice", "en": "Legal Notice (Impressum)"},
    "policy.privacy": {"de": "Datenschutzerklärung", "en": "Privacy Policy"},
    "policy.terms": {"de": "AGB / Terms of Service", "en": "Terms of Service"},
    "policy.refund": {"de": "Widerrufsrecht / Rückgaberecht", "en": "Right of Withdrawal / Return Policy"},
    "policy.shipping": {"de": "Versandinformationen", "en": "Shipping Information"},
    "policy.contact": {"de": "Kontaktmöglichkeit", "en": "Contact Page"},

    # --- 4) Kontakt & Rechtliches ---
    "contact.unavailable_title": {"de": "Kontakt-Check nicht möglich", "en": "Contact check not possible"},
    "contact.unavailable_detail": {
        "de": "Keine Seiteninhalte zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "No page content loaded to analyze – not a confirmed issue, just a technical limitation of the check.",
    },
    "contact.only_personal_email_title": {
        "de": "Nur private E-Mail-Adresse(n) gefunden (z. B. Gmail/GMX)",
        "en": "Only personal email address(es) found (e.g. Gmail/GMX)",
    },
    "contact.only_personal_email_detail": {
        "de": "Gefunden: {emails}. GMC-Reviewer werten eine geschäftliche Adresse (info@{host}) als Vertrauenssignal.",
        "en": "Found: {emails}. GMC reviewers consider a business address (info@{host}) a trust signal.",
    },
    "contact.business_email_title": {"de": "Geschäftliche E-Mail-Adresse gefunden", "en": "Business email address found"},
    "contact.no_email_title": {"de": "Keine E-Mail-Adresse im Seitentext gefunden", "en": "No email address found in the page text"},
    "contact.no_email_detail": {
        "de": "Weder Startseite noch Kontakt-/Rechtsseiten enthalten eine erkennbare E-Mail-Adresse.",
        "en": "Neither the homepage nor contact/legal pages contain a recognizable email address.",
    },
    "contact.no_phone_title": {"de": "Keine Telefonnummer gefunden", "en": "No phone number found"},
    "contact.no_phone_detail": {
        "de": "Google-Reviewer werten eine sichtbare Telefonnummer als Vertrauenssignal (Checklist-Punkt C).",
        "en": "Google reviewers consider a visible phone number a trust signal (checklist item C).",
    },
    "contact.phone_found_title": {"de": "Telefonnummer gefunden", "en": "Phone number found"},
    "contact.phone_found_detail": {
        "de": "Eine Telefonnummer ist im Footer/Kontakt-Bereich erkennbar.",
        "en": "A phone number is visible in the footer/contact area.",
    },
    "contact.nap_mismatch_title": {"de": "Unterschiedliche E-Mail-Adressen auf verschiedenen Seiten", "en": "Different email addresses across pages"},
    "contact.nap_mismatch_detail": {
        "de": "Gefunden: {emails}. Google verlangt identische Kontaktdaten auf Footer, Kontaktseite und Rechtstexten (NAP-Konsistenz).",
        "en": "Found: {emails}. Google requires identical contact details across footer, contact page, and legal pages (NAP consistency).",
    },
    "contact.placeholder_title": {"de": "Platzhalter-/Beispieltext auf der Seite gefunden", "en": "Placeholder/sample text found on the page"},
    "contact.placeholder_detail": {
        "de": "Erkannte Muster wie eckige Klammern, 'Lorem Ipsum' oder Formular-Vorbelegungen (z. B. 'you@email.com'). Google hat das in einem Support-Ticket 2026-07 explizit als Ablehnungsgrund genannt.",
        "en": "Detected patterns like square brackets, 'Lorem Ipsum', or form placeholders (e.g. 'you@email.com'). Google explicitly named this as a rejection reason in a support ticket in July 2026.",
    },
    "contact.dead_ends_title": {
        "de": "{count} von {total} typischen Standard-URLs enden auf 404",
        "en": "{count} of {total} typical standard URLs end in 404",
    },
    "contact.dead_ends_detail": {
        "de": "{listing}\nNicht kritisch, wenn diese Seiten nie existiert haben – idealerweise leiten geratene Standard-URLs auf eine echte Seite weiter statt auf einen Fehler.",
        "en": "{listing}\nNot critical if these pages never existed – ideally, guessed standard URLs should redirect to a real page instead of an error.",
    },

    # --- 5) Produkt-Feed ---
    "feed.no_feed_title": {"de": "Kein Shopify products.json-Feed gefunden", "en": "No Shopify products.json feed found"},
    "feed.no_feed_detail": {
        "de": "Store scheint nicht auf Shopify zu laufen oder der Feed ist deaktiviert – Feed-Qualität kann nicht automatisch geprüft werden. Kein bestätigtes Problem.",
        "en": "Store doesn't seem to run on Shopify or the feed is disabled – feed quality can't be checked automatically. Not a confirmed issue.",
    },
    "feed.unparseable_title": {"de": "Produkt-Feed nicht auswertbar", "en": "Product feed not parseable"},
    "feed.unparseable_detail": {
        "de": "products.json konnte nicht als JSON gelesen werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "products.json could not be read as JSON – not a confirmed issue, just a technical limitation of the check.",
    },
    "feed.no_products_title": {"de": "Keine Produkte im Feed gefunden", "en": "No products found in the feed"},
    "feed.no_products_detail": {
        "de": "Store hat aktuell keine sichtbaren Produkte über products.json – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "The store currently has no visible products via products.json – not a confirmed issue, just a technical limitation of the check.",
    },
    "feed.missing_gtin_title": {"de": "{pct}% der Produkte ohne GTIN/Barcode", "en": "{pct}% of products without GTIN/barcode"},
    "feed.missing_gtin_detail": {
        "de": "Fehlende eindeutige Produktkennung (GTIN/MPN) ist einer der häufigsten GMC-Ablehnungsgründe für Produktdaten.",
        "en": "A missing unique product identifier (GTIN/MPN) is one of the most common GMC rejection reasons for product data.",
    },
    "feed.missing_brand_title": {"de": "{pct}% der Produkte ohne erkennbare Marke (Vendor-Feld)", "en": "{pct}% of products without a recognizable brand (vendor field)"},
    "feed.missing_brand_detail": {
        "de": "GMC verlangt in der Regel Brand + GTIN oder eine Ausnahmekennzeichnung.",
        "en": "GMC generally requires brand + GTIN or an exemption flag.",
    },
    "feed.missing_price_title": {"de": "{pct}% der Produkte ohne gültigen Preis", "en": "{pct}% of products without a valid price"},
    "feed.missing_price_detail": {"de": "Preis muss > 0 und konsistent mit der Produktseite sein.", "en": "Price must be > 0 and consistent with the product page."},
    "feed.missing_desc_title": {"de": "{pct}% der Produkte ohne Produktbeschreibung", "en": "{pct}% of products without a product description"},
    "feed.missing_desc_detail": {"de": "Leere Beschreibungen gelten als 'Thin Content'.", "en": "Empty descriptions are considered 'thin content'."},
    "feed.thin_desc_title": {
        "de": "{pct}% der Produkte mit sehr kurzer Beschreibung (<100 Zeichen)",
        "en": "{pct}% of products with a very short description (<100 characters)",
    },
    "feed.thin_desc_detail": {
        "de": "Kurze/duplizierte Texte erhöhen das Risiko einer Ablehnung wegen 'Thin Content'.",
        "en": "Short/duplicated texts increase the risk of rejection due to 'thin content'.",
    },
    "feed.duplicate_skus_title": {"de": "{count} SKU(s) mehrfach vergeben", "en": "{count} SKU(s) used more than once"},
    "feed.duplicate_skus_detail": {"de": "{listing}\nSKUs müssen pro Variante eindeutig sein.", "en": "{listing}\nSKUs must be unique per variant."},
    "feed.inverted_compare_title": {
        "de": "{count} Variante(n) mit unglaubwürdigem Streichpreis",
        "en": "{count} variant(s) with an implausible strikethrough price",
    },
    "feed.inverted_compare_detail": {
        "de": "Der 'Compare-at'-Preis (Streichpreis) ist kleiner oder gleich dem aktuellen Preis. Ein Streichpreis, der keinen echten Rabatt zeigt, ist ein klassisches Fake-Sale-Muster.",
        "en": "The 'compare-at' price (strikethrough price) is less than or equal to the current price. A strikethrough price that shows no real discount is a classic fake-sale pattern.",
    },
    "feed.used_wording_title": {
        "de": "{count} Produktbeschreibung(en) mit 'gebraucht/refurbished'-Wortlaut",
        "en": "{count} product description(s) with 'used/refurbished' wording",
    },
    "feed.used_wording_detail": {
        "de": "GMC verlangt condition=new für neue Ware; Wörter wie 'refurbished' oder 'gebraucht' in der Beschreibung widersprechen dem.",
        "en": "GMC requires condition=new for new merchandise; words like 'refurbished' or 'used' in the description contradict that.",
    },
    "feed.sample_ok_title": {"de": "Stichprobe unauffällig", "en": "Sample unremarkable"},
    "feed.sample_ok_detail": {"de": "{n} Produkte geprüft, keine offensichtlichen Feed-Probleme gefunden.", "en": "{n} products checked, no obvious feed issues found."},
    "feed.empty_collections_title": {
        "de": "{count} im Menü verlinkte Kollektion(en) mit ≤{threshold} Produkten",
        "en": "{count} nav-linked collection(s) with ≤{threshold} products",
    },
    "feed.empty_collections_detail": {
        "de": "Betroffen: {list}. Eine Navigation, die auf eine leere/fast leere Kategorie zeigt, wirkt für Google-Reviewer wie ein unfertiger Store.",
        "en": "Affected: {list}. A navigation item pointing to an empty/nearly empty category looks like an unfinished store to Google reviewers.",
    },

    # --- 6) Bild-Compliance ---
    "images.none_found_title": {"de": "Keine Produktbilder zum Prüfen gefunden", "en": "No product images found to check"},
    "images.none_found_detail": {
        "de": "Bild-Compliance konnte nicht automatisch bewertet werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "Image compliance could not be automatically assessed – not a confirmed issue, just a technical limitation of the check.",
    },
    "images.broken_title": {"de": "{broken} von {n} Produktbildern nicht ladbar", "en": "{broken} of {n} product images not loadable"},
    "images.broken_detail": {
        "de": "Nicht erreichbare Bilder führen zur Ablehnung einzelner Produkte im Feed.",
        "en": "Unreachable images lead to the rejection of individual products in the feed.",
    },
    "images.too_small_title": {"de": "{count} Bilder unter {min_px}px Kantenlänge", "en": "{count} images below {min_px}px edge length"},
    "images.too_small_detail": {
        "de": "Google empfiehlt mindestens {rec_px}px für die kürzere Bildkante.",
        "en": "Google recommends at least {rec_px}px for the shorter image edge.",
    },
    "images.ok_title": {"de": "Bilder unauffällig", "en": "Images unremarkable"},
    "images.ok_detail": {"de": "{checked} Bilder geprüft, erreichbar und ausreichend groß.", "en": "{checked} images checked, reachable and large enough."},
    "images.note_title": {"de": "Hinweis", "en": "Note"},
    "images.note_detail": {
        "de": "Text-Overlays, Wasserzeichen und Rabatt-Banner in Bildern können nicht automatisiert erkannt werden – bitte manuell stichprobenartig prüfen.",
        "en": "Text overlays, watermarks, and discount banners in images can't be detected automatically – please spot-check manually.",
    },

    # --- 7) Bewertungen ---
    "reviews.unavailable_title": {"de": "Bewertungen konnten nicht geprüft werden", "en": "Reviews could not be checked"},
    "reviews.unavailable_detail": {
        "de": "Keine Seiteninhalte zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "No page content loaded to analyze – not a confirmed issue, just a technical limitation of the check.",
    },
    "reviews.platform_found_title": {"de": "Verifizierbare Bewertungsplattform erkannt", "en": "Verifiable review platform detected"},
    "reviews.platform_found_detail": {
        "de": "Erkannt: {platforms}. Über Dritte nachprüfbare Bewertungen sind für Google unkritisch.",
        "en": "Detected: {platforms}. Reviews verifiable via a third party are unproblematic for Google.",
    },
    "reviews.unverifiable_title": {
        "de": "Sternebewertungen/Rezensionszahlen ohne erkennbare Drittanbieter-Plattform",
        "en": "Star ratings/review counts without a recognizable third-party platform",
    },
    "reviews.unverifiable_detail": {
        "de": "Es werden Bewertungen bzw. Ratings angezeigt, aber kein bekannter Bewertungs-Dienst (z. B. Trustpilot, Judge.me, Loox) konnte im Code gefunden werden. Nicht verifizierbare Testimonials verstoßen gegen Googles Richtlinie zu 'Misrepresentation'.",
        "en": "Reviews or ratings are displayed, but no known review service (e.g. Trustpilot, Judge.me, Loox) could be found in the code. Unverifiable testimonials violate Google's 'misrepresentation' policy.",
    },
    "reviews.none_found_title": {"de": "Keine Bewertungen auf der Seite gefunden", "en": "No reviews found on the page"},
    "reviews.none_found_detail": {
        "de": "Weder Rating-Claims noch eine Bewertungsplattform erkannt – kein bestätigtes Problem.",
        "en": "Neither rating claims nor a review platform detected – not a confirmed issue.",
    },
    "reviews.duplicates_title": {
        "de": "{count} identische Bewertungstexte auf mehreren Produktseiten",
        "en": "{count} identical review texts across multiple product pages",
    },
    "reviews.duplicates_detail": {
        "de": "Beispieltext: \"{example}...\". Wortgleiche 'Kundenstimmen' auf unterschiedlichen Produkten sind ein starkes Indiz für gefälschte Bewertungen.",
        "en": "Example text: \"{example}...\". Word-for-word identical 'customer testimonials' on different products are a strong indicator of fake reviews.",
    },

    # --- 8) Künstliche Dringlichkeit ---
    "urgency.unavailable_title": {"de": "Urgency-Check nicht möglich", "en": "Urgency check not possible"},
    "urgency.unavailable_detail": {
        "de": "Keine Produktseiten zum Analysieren geladen – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "No product pages loaded to analyze – not a confirmed issue, just a technical limitation of the check.",
    },
    "urgency.none_found_title": {"de": "Keine künstlichen Dringlichkeits-Trigger gefunden", "en": "No artificial urgency triggers found"},
    "urgency.none_found_detail": {
        "de": "Keine Fake-Countdown-/Verknappungs-Muster auf den geprüften Produktseiten entdeckt.",
        "en": "No fake countdown/scarcity patterns detected on the checked product pages.",
    },
    "urgency.app_found_title": {"de": "Countdown-/Verknappungs-App erkannt", "en": "Countdown/scarcity app detected"},
    "urgency.app_found_detail": {
        "de": "Erkannte Skripte: {apps}. Solche Apps sind nicht automatisch verboten, aber die angezeigten Werte müssen real sein.",
        "en": "Detected scripts: {apps}. Such apps aren't automatically forbidden, but the displayed values must be real.",
    },
    "urgency.text_found_title": {
        "de": "Formulierungen mit künstlicher Dringlichkeit/Verknappung gefunden",
        "en": "Wording with artificial urgency/scarcity found",
    },
    "urgency.text_found_detail": {
        "de": "z. B. 'nur noch X auf Lager', 'Angebot endet in...', Verkaufszähler. Google Ads' Misrepresentation-Richtlinie verbietet vorgetäuschte Knappheit/Dringlichkeit, wenn die Angaben nicht der Realität entsprechen – bitte manuell gegen den echten Lagerbestand prüfen.",
        "en": "e.g. 'only X left in stock', 'offer ends in...', sales counters. Google Ads' misrepresentation policy forbids fake scarcity/urgency when the claims don't match reality – please check manually against the real stock levels.",
    },
    "urgency.untracked_title": {"de": "Lagerbestand wird laut Shopify gar nicht getrackt", "en": "Inventory is not tracked at all according to Shopify"},
    "urgency.untracked_detail": {
        "de": "Für keines der geprüften Produkte ist Bestandsverfolgung aktiv – angezeigte 'Nur noch X verfügbar'-Hinweise können daher nicht auf echten Zahlen beruhen.",
        "en": "Inventory tracking is not active for any of the checked products – displayed 'only X left' notices can therefore not be based on real numbers.",
    },

    # --- 9) Page Speed ---
    "speed.unavailable_title": {"de": "Page-Speed-Check nicht möglich", "en": "Page speed check not possible"},
    "speed.unavailable_detail": {
        "de": "Startseite konnte für die Ladezeitmessung nicht abgerufen werden – kein bestätigtes Problem, nur eine technische Einschränkung des Checks.",
        "en": "The homepage could not be fetched for the load time measurement – not a confirmed issue, just a technical limitation of the check.",
    },
    "speed.load_time_title": {"de": "Ladezeit Startseite: {seconds}s", "en": "Homepage load time: {seconds}s"},
    "speed.load_fast_detail": {"de": "Schnell – innerhalb eines guten Bereichs.", "en": "Fast – within a good range."},
    "speed.load_medium_detail": {
        "de": "Spürbar langsam – eine langsame Seite verschlechtert Nutzererfahrung und Conversion.",
        "en": "Noticeably slow – a slow page worsens user experience and conversion.",
    },
    "speed.load_slow_detail": {
        "de": "Sehr langsam. Nutzer springen bei Ladezeiten über 3 Sekunden überdurchschnittlich häufig ab.",
        "en": "Very slow. Users abandon pages disproportionately often when load times exceed 3 seconds.",
    },
    "speed.html_size_title": {"de": "HTML-Größe Startseite: {kb} KB", "en": "Homepage HTML size: {kb} KB"},
    "speed.html_compact_detail": {"de": "Kompakt.", "en": "Compact."},
    "speed.html_large_detail": {
        "de": "Etwas groß – kann auf langsamen Verbindungen spürbar sein.",
        "en": "A bit large – may be noticeable on slow connections.",
    },
    "speed.html_toolarge_detail": {
        "de": "Sehr groß für reines HTML – ggf. prüfen, ob unnötig viel Inline-Code/Markup mitgeliefert wird.",
        "en": "Very large for plain HTML – consider checking whether unnecessary inline code/markup is being shipped.",
    },
    "speed.methodology_title": {"de": "Hinweis zur Messmethode", "en": "Note on measurement method"},
    "speed.methodology_detail": {
        "de": "Basiert auf einem einzelnen Server-Request unserer Scan-Engine (Ladezeit + reine HTML-Größe), nicht auf einer echten Lighthouse-Analyse im Browser (kein LCP/CLS/JS-Rendering enthalten). Für eine vollständige Web-Vitals-Analyse: pagespeed.web.dev.",
        "en": "Based on a single server request from our scan engine (load time + plain HTML size), not a real Lighthouse analysis in the browser (no LCP/CLS/JS rendering included). For a full Web Vitals analysis: pagespeed.web.dev.",
    },
}


def t(key: str, lang: str, **kwargs) -> str:
    entry = _T.get(key)
    if entry is None:
        return key
    text = entry.get(lang) or entry.get(DEFAULT_LANG) or key
    return text.format(**kwargs) if kwargs else text
