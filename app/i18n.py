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
    "notice.first_free": {
        "de": "Der erste Scan für diesen Store ist kostenlos – dieser hier war es. Jeder weitere Scan derselben Domain läuft über ein Scan-Paket, ab {price} € pro Scan.",
        "en": "The first scan for this store is free – this was it. Every further scan of the same domain runs on a scan package, from €{price} per scan.",
    },
    "err.payment_unavailable": {
        "de": "Für diesen Store wurde der kostenlose Scan bereits genutzt. Ein weiterer Scan ist kostenpflichtig, die Bezahlung ist aktuell aber nicht verfügbar. Bitte versuch es später noch einmal.",
        "en": "The free scan for this store has already been used. A further scan requires payment, but payment is currently unavailable. Please try again later.",
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


# ---------------------------------------------------------------------------
# Erweiterung 2026-08: zusätzliche Checks aus der GMC-Master-Checklist
# (Kategorien C-Inhalt, D, E, F, G2, H). Als separates update()-Block gehalten,
# damit der ursprüngliche Katalog oben unverändert lesbar bleibt.
# ---------------------------------------------------------------------------
_T.update({
    # --- Neue Kategorie-Labels ---
    "cat.red_flags": {"de": "Trust-Red-Flags", "en": "Trust Red Flags"},
    "cat.technical": {"de": "Technik & Google-Signale", "en": "Technical & Google Signals"},

    # --- Zusätzliche Pflichtseiten (Kategorie C) ---
    "policy.about": {"de": "Über uns", "en": "About Us"},
    "policy.faq": {"de": "FAQ", "en": "FAQ"},
    "policy.payment": {"de": "Zahlungsbedingungen", "en": "Payment Terms"},
    "policy.track_order": {"de": "Sendungsverfolgung", "en": "Track Order"},

    # --- Policy-Inhaltsprüfung (Kategorie C/D) ---
    "policy.empty_title": {
        "de": "„{label}“ ist leer oder zu dünn ({chars} Zeichen)",
        "en": "\"{label}\" is empty or too thin ({chars} characters)",
    },
    "policy.empty_detail": {
        "de": "Die Seite existiert, enthält aber kaum Text. Google wertet eine leere Pflichtseite wie eine fehlende Seite – „no empty policy pages“ ist ein eigener Prüfpunkt im Review. Mindestens {min_chars} Zeichen echter, seitenspezifischer Inhalt.",
        "en": "The page exists but contains almost no text. Google treats an empty required page like a missing one – \"no empty policy pages\" is its own review criterion. Aim for at least {min_chars} characters of real, page-specific content.",
    },
    "policy.missing_content_title": {
        "de": "„{label}“: {count} Pflichtangabe(n) fehlen",
        "en": "\"{label}\": {count} required statement(s) missing",
    },
    "policy.missing_content_detail": {
        "de": "Auf der Seite ist Folgendes nicht auffindbar:\n{listing}\n\nGoogle prüft bei Misrepresentation-Reviews nicht, ob die Seite existiert, sondern ob sie die Frage des Kunden beantwortet.",
        "en": "The following could not be found on the page:\n{listing}\n\nIn misrepresentation reviews Google does not check whether the page exists, but whether it answers the customer's question.",
    },
    "policy.content_ok_title": {"de": "„{label}“ inhaltlich vollständig", "en": "\"{label}\" is complete in content"},
    "policy.content_ok_detail": {
        "de": "Alle erwarteten Pflichtangaben sind im Seitentext auffindbar.",
        "en": "All expected required statements were found in the page text.",
    },
    "policy.no_contact_on_page_title": {
        "de": "Kontaktdaten fehlen auf {count} Policy-Seite(n)",
        "en": "Contact details missing on {count} policy page(s)",
    },
    "policy.no_contact_on_page_detail": {
        "de": "Betroffen:\n{listing}\n\nJede Rechts-/Policy-Seite sollte Firmenname und mindestens eine Kontaktmöglichkeit (E-Mail oder Telefon) tragen – ein Reviewer, der direkt auf einer Unterseite landet, muss dich erreichen können.",
        "en": "Affected:\n{listing}\n\nEvery legal/policy page should carry the company name and at least one contact option (email or phone) – a reviewer landing directly on a subpage must be able to reach you.",
    },

    # --- Inhaltsanforderungen: Bezeichner ---
    "req.shipping_time": {"de": "Konkrete Lieferzeit / Bearbeitungsdauer", "en": "Specific delivery time / handling time"},
    "req.shipping_cost": {"de": "Versandkosten oder Freigrenze", "en": "Shipping cost or free-shipping threshold"},
    "req.shipping_tracking": {"de": "Sendungsverfolgung / Versandprozess", "en": "Tracking / shipping process"},
    "req.refund_period": {"de": "Rückgabefrist (z. B. „14 Tage“)", "en": "Return period (e.g. \"14 days\")"},
    "req.refund_who_pays": {"de": "Wer die Rücksendekosten trägt", "en": "Who pays the return shipping"},
    "req.refund_process": {"de": "Ablauf der Erstattung", "en": "How the refund is processed"},
    "req.refund_cases": {"de": "Fälle: beschädigt / falsch geliefert / Widerruf", "en": "Cases: damaged / wrong item / change of mind"},
    "req.legal_entity": {"de": "Firmenname / Rechtsform", "en": "Company name / legal entity"},
    "req.legal_address": {"de": "Ladungsfähige Anschrift", "en": "Full postal address"},
    "req.payment_methods": {"de": "Aufzählung der Zahlungsarten", "en": "List of payment methods"},

    # --- Kontakt & NAP (Kategorie B) ---
    "contact.no_address_title": {"de": "Keine vollständige Adresse gefunden", "en": "No complete address found"},
    "contact.no_address_detail": {
        "de": "Auf Startseite, Kontakt- und Rechtsseiten war kein Muster „Straße + Hausnummer, PLZ, Ort“ auffindbar. Google verlangt eine überprüfbare Geschäftsadresse, die exakt der im Merchant Center hinterlegten entspricht.",
        "en": "No \"street + number, ZIP, city\" pattern was found on the homepage, contact or legal pages. Google requires a verifiable business address that exactly matches the one filed in Merchant Center.",
    },
    "contact.address_found_title": {"de": "Adresse gefunden", "en": "Address found"},
    "contact.address_mismatch_title": {"de": "Unterschiedliche Adressen auf mehreren Seiten", "en": "Different addresses across pages"},
    "contact.address_mismatch_detail": {
        "de": "Gefunden:\n{listing}\n\nNAP-Konsistenz (Name/Adresse/Telefon) ist einer der meistgeprüften Misrepresentation-Punkte – die Adresse muss auf jeder Seite zeichengleich stehen.",
        "en": "Found:\n{listing}\n\nNAP consistency (name/address/phone) is one of the most-checked misrepresentation points – the address must be character-identical on every page.",
    },
    "contact.phone_mismatch_title": {"de": "Unterschiedliche Telefonnummern gefunden", "en": "Different phone numbers found"},
    "contact.phone_mismatch_detail": {
        "de": "Gefunden:\n{listing}\n\nEine einzige, überall identische Telefonnummer – abweichende Nummern gelten als Inkonsistenz im Business-Profil.",
        "en": "Found:\n{listing}\n\nUse one single phone number everywhere – differing numbers count as an inconsistency in the business profile.",
    },
    "contact.trailing_dot_title": {"de": "E-Mail-Adresse mit angehängtem Punkt", "en": "Email address with trailing dot"},
    "contact.trailing_dot_detail": {
        "de": "Betroffen: {emails}\n\nEin Satzpunkt direkt hinter der Adresse („info@shop.com.“) wird von Mail-Clients und Prüf-Bots mitkopiert – die Adresse ist dann nicht zustellbar. Punkt entfernen oder Leerzeichen setzen.",
        "en": "Affected: {emails}\n\nA sentence period directly after the address (\"info@shop.com.\") gets copied along by mail clients and validation bots – the address is then undeliverable. Remove the dot or add a space.",
    },
    "contact.few_options_title": {"de": "Kontaktseite bietet nur {count} Kontaktweg(e)", "en": "Contact page offers only {count} contact option(s)"},
    "contact.few_options_detail": {
        "de": "Gefunden: {found}\n\nDie Checkliste verlangt mindestens zwei Wege (E-Mail, Telefon, Formular, Adresse) auf ein und derselben Kontaktseite.",
        "en": "Found: {found}\n\nThe checklist requires at least two options (email, phone, form, address) on one and the same contact page.",
    },
    "contact.options_ok_title": {"de": "Kontaktseite mit {count} Kontaktwegen", "en": "Contact page with {count} contact options"},
    "contact.options_ok_detail": {"de": "Gefunden: {found}", "en": "Found: {found}"},
    "contact.no_hours_title": {"de": "Keine Servicezeiten angegeben", "en": "No service hours stated"},
    "contact.no_hours_detail": {
        "de": "Auf der Kontaktseite steht keine Erreichbarkeit (z. B. „Mo–Fr 9–17 Uhr“) und keine Antwortzeit („Antwort innerhalb von 24 Stunden“). Beides ist ein Standard-Vertrauenssignal im GMC-Review.",
        "en": "The contact page states neither availability (e.g. \"Mon–Fri 9am–5pm\") nor a response time (\"reply within 24 hours\"). Both are standard trust signals in the GMC review.",
    },
    "contact.not_clickable_title": {"de": "E-Mail/Telefon nicht klickbar verlinkt", "en": "Email/phone not linked as clickable"},
    "contact.not_clickable_detail": {
        "de": "Fehlend: {missing}\n\nKontaktdaten müssen als echte Links ausgezeichnet sein (mailto: bzw. tel:), nicht nur als Text – die Checkliste führt das als eigenen Punkt („all links clickable, esp. email, phone, address“).",
        "en": "Missing: {missing}\n\nContact details must be marked up as real links (mailto: / tel:), not just plain text – the checklist lists this as its own item (\"all links clickable, esp. email, phone, address\").",
    },

    # --- Produkt-Feed (Kategorie F/G2) ---
    "feed.missing_variant_attrs_title": {
        "de": "{pct}% der Produkte ohne Farb-/Größen-Variantenattribute",
        "en": "{pct}% of products lack colour/size variant attributes",
    },
    "feed.missing_variant_attrs_detail": {
        "de": "Google leitet die Feed-Attribute color und size direkt aus den Shopify-Variantenoptionen ab. Heißt eine Option „Title“/„Default“ statt „Farbe“/„Größe“, fehlen die Attribute im Feed – bei Bekleidung ist das der häufigste Item-Level-Disapproval.",
        "en": "Google derives the feed attributes colour and size directly from the Shopify variant options. If an option is named \"Title\"/\"Default\" instead of \"Color\"/\"Size\", those attributes are missing from the feed – for apparel this is the most common item-level disapproval.",
    },
    "feed.no_gender_hint_title": {"de": "Keine Hinweise auf gender/age_group erkennbar", "en": "No gender/age_group signals detectable"},
    "feed.no_gender_hint_detail": {
        "de": "Weder Produkttyp, Tags noch Titel enthalten Angaben zu Zielgruppe (Damen/Herren/Unisex, Erwachsene/Kinder). Bei Bekleidung sind gender und age_group Pflichtattribute im Feed. Hinweis: die eigentlichen mm-google-shopping-Metafelder sind von außen nicht lesbar – bitte im Shopify-Admin gegenprüfen.",
        "en": "Neither product type, tags nor titles contain audience information (women/men/unisex, adult/kids). For apparel, gender and age_group are required feed attributes. Note: the actual mm-google-shopping metafields are not readable from outside – please verify in the Shopify admin.",
    },
    "feed.unavailable_shown_title": {"de": "{count} Produkt(e) komplett ausverkauft, aber online", "en": "{count} product(s) fully sold out but still online"},
    "feed.unavailable_shown_detail": {
        "de": "Keine einzige Variante ist kaufbar. Google crawlt diese Seiten und meldet „availability mismatch“ bzw. „landing page error“. Solche Produkte archivieren (nicht nur auf Entwurf setzen – Entwürfe werden von Google trotzdem erfasst).",
        "en": "Not a single variant is purchasable. Google crawls these pages and reports \"availability mismatch\" or \"landing page error\". Archive such products (do not merely set them to draft – drafts still get picked up by Google).",
    },
    "feed.missing_type_title": {"de": "{pct}% der Produkte ohne Produktkategorie", "en": "{pct}% of products without a product category"},
    "feed.missing_type_detail": {
        "de": "Das Feld product_type ist leer. Ohne Kategorie ordnet Google das Produkt selbst zu – das führt zu falschen Kategorien und damit zu Feed-Fehlern und teurerem Traffic.",
        "en": "The product_type field is empty. Without a category Google assigns one itself – causing wrong categories, feed errors and more expensive traffic.",
    },
    "feed.handle_mismatch_title": {"de": "{count} Produkt(e): Titel passt nicht zur URL", "en": "{count} product(s): title does not match the URL"},
    "feed.handle_mismatch_detail": {
        "de": "{listing}\n\nDie URL stammt meist noch vom ursprünglichen Lieferantentitel. Eine URL, die etwas anderes sagt als der Titel, ist ein klassisches Dropshipping-Signal – Handle im Shopify-Admin anpassen und Weiterleitung anlegen.",
        "en": "{listing}\n\nThe URL usually still carries the original supplier title. A URL saying something different from the title is a classic dropshipping signal – adjust the handle in the Shopify admin and set up a redirect.",
    },
    "feed.trademark_title": {"de": "{count} Produkt(e) mit ™/®/© im Titel", "en": "{count} product(s) with ™/®/© in the title"},
    "feed.trademark_detail": {
        "de": "{listing}\n\nSchutzrechtszeichen darfst du nur führen, wenn die Marke dir gehört. Bei übernommenen Lieferantentiteln ist das fast nie der Fall – Google wertet das als Markenanmaßung.",
        "en": "{listing}\n\nYou may only use trademark symbols if you own the mark. With copied supplier titles that is almost never the case – Google treats it as brand impersonation.",
    },
    "feed.duplicate_desc_title": {"de": "{count} Produkt(e) mit identischer Beschreibung", "en": "{count} product(s) with identical descriptions"},
    "feed.duplicate_desc_detail": {
        "de": "Mehrere Produkte teilen sich wortgleichen Beschreibungstext. Das liest sich als Lieferanten-Copy-Paste und ist einer der Punkte, an denen manuelle Reviewer einen Store als „nicht eigenständig“ einstufen.",
        "en": "Several products share word-for-word identical description text. This reads as supplier copy-paste and is one of the points where manual reviewers classify a store as \"not original\".",
    },
    "feed.desc_script_title": {"de": "{count} Beschreibung(en) enthalten Script-/iframe-Code", "en": "{count} description(s) contain script/iframe code"},
    "feed.desc_script_detail": {
        "de": "In der Produktbeschreibung steckt <script> oder <iframe>. Google liest Beschreibungen als Feed-Inhalt – eingebetteter Fremdcode gilt dort als Tracking-/Manipulationsversuch und kann die Item-Ablehnung auslösen.",
        "en": "The product description contains <script> or <iframe>. Google reads descriptions as feed content – embedded third-party code counts as a tracking/manipulation attempt there and can trigger item disapproval.",
    },
    "feed.claims_title": {"de": "{count} Produkt(e) mit nicht belegbaren Wirkversprechen", "en": "{count} product(s) with unsubstantiated claims"},
    "feed.claims_detail": {
        "de": "Gefundene Formulierungen:\n{listing}\n\nMedizinische Aussagen, Heilversprechen oder Wirkgarantien brauchen einen Nachweis. Ohne Beleg fällt das unter Misrepresentation – entweder streichen oder korrekt einschränken.",
        "en": "Phrases found:\n{listing}\n\nMedical statements, healing promises or guaranteed effects require evidence. Without proof this falls under misrepresentation – either remove or qualify them correctly.",
    },
    "feed.material_title": {"de": "{count} Produkt(e) mit ungesicherten Materialangaben", "en": "{count} product(s) with unverified material claims"},
    "feed.material_detail": {
        "de": "Gefunden: {listing}\n\nEdelfaser-Begriffe (Kaschmir, Merino, Seide, Leinen, Leder …) dürfen nur stehen, wenn das Material beim Lieferanten belegt ist. Sonst die -Optik/-Haptik-Form verwenden („Kaschmir-Optik“, „Leder-Look“) – in Titel, Beschreibung und Materialfeld gleichermaßen.",
        "en": "Found: {listing}\n\nPremium-fibre terms (cashmere, merino, silk, linen, leather …) may only be used when the material is verifiable from the supplier. Otherwise use the -feel/-look form (\"cashmere-feel\", \"leather-look\") – in title, description and material field alike.",
    },
    "feed.fake_gtin_title": {"de": "{count} Produkt(e) mit unplausibler GTIN", "en": "{count} product(s) with implausible GTIN"},
    "feed.fake_gtin_detail": {
        "de": "{listing}\n\nEine GTIN hat 8, 12, 13 oder 14 Ziffern und eine gültige Prüfziffer. Platzhalter oder erfundene Barcodes sind schlimmer als gar keine – ohne echte GTIN gehört ins Feld identifier_exists = false statt einer Fantasienummer.",
        "en": "{listing}\n\nA GTIN has 8, 12, 13 or 14 digits and a valid check digit. Placeholder or invented barcodes are worse than none – without a real GTIN the feed needs identifier_exists = false instead of a made-up number.",
    },

    # --- Bilder (Kategorie F) ---
    "images.duplicates_title": {"de": "{count} Bild(er) auf mehreren Produkten identisch", "en": "{count} image(s) identical across several products"},
    "images.duplicates_detail": {
        "de": "{listing}\n\nDasselbe Bild bei mehreren Produkten führt im Feed zu „duplicate image“ und wirkt im manuellen Review wie ein Katalog-Import ohne eigene Fotos.",
        "en": "{listing}\n\nThe same image on several products causes \"duplicate image\" in the feed and reads like a catalogue import without own photography in a manual review.",
    },
    "images.too_few_title": {"de": "{count} Produkt(e) mit weniger als {min} Bildern", "en": "{count} product(s) with fewer than {min} images"},
    "images.too_few_detail": {
        "de": "{listing}\n\nDie Checkliste setzt 3–4 hochauflösende Bilder pro Produkt/Variante an (Mode). Ein einzelnes Lieferantenbild ist eines der sichtbarsten Dropshipping-Merkmale.",
        "en": "{listing}\n\nThe checklist expects 3–4 high-resolution images per product/variant (fashion). A single supplier image is one of the most visible dropshipping markers.",
    },
    "images.heavy_title": {"de": "{count} Bild(er) über {limit_kb} KB", "en": "{count} image(s) over {limit_kb} KB"},
    "images.heavy_detail": {
        "de": "Größtes gefundenes Bild: {max_kb} KB. Schwere Bilder sind der häufigste Grund für schlechte Mobile-PageSpeed-Werte – und Mobile entscheidet über CPC und Freigabe. Vor dem Upload auf ~200–400 KB komprimieren.",
        "en": "Largest image found: {max_kb} KB. Heavy images are the most common cause of poor mobile PageSpeed scores – and mobile drives both CPC and approval. Compress to ~200–400 KB before upload.",
    },
    "images.supplier_cdn_title": {"de": "Bilder von Lieferanten-CDN eingebunden", "en": "Images served from a supplier CDN"},
    "images.supplier_cdn_detail": {
        "de": "Gefunden: {listing}\n\nBilder werden direkt von einem Lieferanten-/Marktplatz-CDN (z. B. AliExpress) geladen statt aus dem eigenen Shopify-CDN. Das ist für Google eindeutig als Dropshipping erkennbar und bricht zudem, sobald der Lieferant das Bild löscht.",
        "en": "Found: {listing}\n\nImages are loaded directly from a supplier/marketplace CDN (e.g. AliExpress) instead of your own Shopify CDN. This is unambiguously identifiable as dropshipping by Google and breaks as soon as the supplier deletes the image.",
    },

    # --- Trust-Red-Flags (Kategorie E) ---
    "flags.unavailable_title": {"de": "Red-Flag-Prüfung nicht möglich", "en": "Red flag check not possible"},
    "flags.unavailable_detail": {"de": "Es konnte kein Seiteninhalt geladen werden.", "en": "No page content could be loaded."},
    "flags.none_title": {"de": "Keine Trust-Red-Flags gefunden", "en": "No trust red flags found"},
    "flags.none_detail": {
        "de": "Keine gefälschten Trust-Badges, Presse-/Partner-Behauptungen, Popup-Apps oder unbelegten Bestseller-Auszeichnungen im geprüften HTML.",
        "en": "No fake trust badges, press/partner claims, popup apps or unsubstantiated bestseller labels in the HTML checked.",
    },
    "flags.badges_title": {"de": "Mögliche Fake-Trust-Badges", "en": "Possible fake trust badges"},
    "flags.badges_detail": {
        "de": "Gefunden: {listing}\n\nSicherheits-/Garantie-Siegel dürfen nur stehen, wenn es das zertifizierende Verhältnis wirklich gibt. Frei aus dem Netz kopierte Badges (McAfee, Norton, „100% Secure“, Trustpilot-Sterne ohne Trustpilot-Anbindung) sind ein ausdrücklich benannter Misrepresentation-Grund.",
        "en": "Found: {listing}\n\nSecurity/guarantee seals may only appear when the certifying relationship actually exists. Badges copied from the web (McAfee, Norton, \"100% Secure\", Trustpilot stars without a Trustpilot integration) are an explicitly named misrepresentation reason.",
    },
    "flags.press_title": {"de": "Presse- oder Partner-Behauptungen ohne Beleg", "en": "Press or partner claims without proof"},
    "flags.press_detail": {
        "de": "Gefunden: {listing}\n\n„Bekannt aus“, „offizieller Partner“, „zertifizierter Händler“ und Presse-Logos brauchen einen nachweisbaren Beleg (Vertrag, Artikel-Link). Ohne Nachweis fällt das unter „unsubstantiated endorsement“.",
        "en": "Found: {listing}\n\n\"As seen on\", \"official partner\", \"certified reseller\" and press logos need verifiable proof (contract, article link). Without evidence this falls under \"unsubstantiated endorsement\".",
    },
    "flags.popup_title": {"de": "Popup-/Spin-to-Win-App erkannt", "en": "Popup / spin-to-win app detected"},
    "flags.popup_detail": {
        "de": "Gefunden: {listing}\n\nAggressive Popups (besonders Glücksrad-/Spin-to-Win-Widgets) zählen zu den Punkten, die im manuellen Review als Druckdesign gewertet werden. Falls ein Rabattcode im Popup beworben wird: sicherstellen, dass er im Checkout tatsächlich einlösbar ist – ein nicht funktionierender Code ist ein „unavailable offer“.",
        "en": "Found: {listing}\n\nAggressive popups (especially spin-to-win widgets) are among the items counted as pressure design in a manual review. If the popup advertises a discount code: make sure it actually works at checkout – a non-working code is an \"unavailable offer\".",
    },
    "flags.bestseller_title": {"de": "Bestseller-/Beliebtheits-Auszeichnungen ohne Datenbasis", "en": "Bestseller / popularity labels without a data basis"},
    "flags.bestseller_detail": {
        "de": "Gefunden: {listing}\n\nLabels wie „Bestseller“ oder „Kundenliebling“ setzen echte Verkaufs-/Traffic-Historie voraus. In einem neuen Store ohne Bewertungsplattform sind sie nicht belegbar – bis GMC stabil freigegeben ist besser entfernen.",
        "en": "Found: {listing}\n\nLabels like \"bestseller\" or \"customer favourite\" presuppose real sales/traffic history. In a new store without a review platform they cannot be substantiated – better removed until GMC approval is stable.",
    },

    # --- Technik & Google-Signale (Kategorie H) ---
    "tech.unavailable_title": {"de": "Technik-Prüfung nicht möglich", "en": "Technical check not possible"},
    "tech.unavailable_detail": {"de": "Die Startseite konnte nicht geladen werden.", "en": "The homepage could not be loaded."},
    "tech.no_verification_title": {"de": "Kein Google-Site-Verification-Tag gefunden", "en": "No Google site verification tag found"},
    "tech.no_verification_detail": {
        "de": "Im <head> steht kein <meta name=\"google-site-verification\">. Ohne bestätigte Domain kannst du die Website im Merchant Center nicht beanspruchen – das blockiert die Freigabe komplett. Alternativ ist eine Bestätigung über die Search Console oder DNS möglich; die ist von außen nicht sichtbar, deshalb bitte gegenprüfen.",
        "en": "There is no <meta name=\"google-site-verification\"> in the <head>. Without a verified domain you cannot claim the website in Merchant Center – that blocks approval entirely. Verification via Search Console or DNS is also possible; that is not visible from the outside, so please double-check.",
    },
    "tech.verification_found_title": {"de": "Google-Site-Verification vorhanden", "en": "Google site verification present"},
    "tech.verification_found_detail": {"de": "Das Verifizierungs-Tag liegt im <head> der Startseite.", "en": "The verification tag is present in the homepage <head>."},
    "tech.title_missing_title": {"de": "Startseite ohne <title>", "en": "Homepage without a <title>"},
    "tech.title_missing_detail": {
        "de": "Die Startseite hat keinen Seitentitel. Der Titel ist das erste, was Crawler und Reviewer sehen.",
        "en": "The homepage has no page title. The title is the first thing crawlers and reviewers see.",
    },
    "tech.title_weak_title": {"de": "Startseiten-Titel wenig aussagekräftig: „{title}“", "en": "Homepage title not descriptive: \"{title}\""},
    "tech.title_weak_detail": {
        "de": "Der Titel besteht praktisch nur aus dem Domainnamen bzw. ist sehr kurz. Erwartet wird Marke + Sortiment/Nutzenversprechen, z. B. „Marke – Damenmode aus Naturfasern“.",
        "en": "The title is essentially just the domain name or very short. Expected is brand + assortment/value proposition, e.g. \"Brand – Women's fashion in natural fibres\".",
    },
    "tech.title_ok_title": {"de": "Startseiten-Titel gesetzt", "en": "Homepage title set"},
    "tech.liquid_errors_title": {"de": "Theme-Fehler im gerenderten HTML ({count} Seite(n))", "en": "Theme errors in the rendered HTML ({count} page(s))"},
    "tech.liquid_errors_detail": {
        "de": "{listing}\n\nSichtbare „Liquid error“- oder „translation missing“-Meldungen sind für einen Reviewer der Beweis eines unfertigen Stores. Vor der GMC-Einreichung beheben.",
        "en": "{listing}\n\nVisible \"Liquid error\" or \"translation missing\" messages are proof of an unfinished store to a reviewer. Fix before submitting to GMC.",
    },
    "tech.no_footer_title": {"de": "Footer fehlt auf {count} von {total} geprüften Seiten", "en": "Footer missing on {count} of {total} pages checked"},
    "tech.no_footer_detail": {
        "de": "{listing}\n\nEine Unterseite ohne Footer heißt: der Reviewer landet dort und findet weder Impressum noch Kontakt noch Policies. Der Footer muss auf jeder Seite stehen – inklusive Policy-, Rückgabe- und Tracking-Seiten.",
        "en": "{listing}\n\nA subpage without a footer means: the reviewer lands there and finds neither legal notice, contact nor policies. The footer must appear on every page – including policy, returns and tracking pages.",
    },
    "tech.footer_ok_title": {"de": "Footer auf allen geprüften Seiten vorhanden", "en": "Footer present on all pages checked"},
    "tech.footer_ok_detail": {"de": "{total} Seiten geprüft.", "en": "{total} pages checked."},
    "tech.no_structured_data_title": {"de": "Keine Produkt-Strukturdaten auf der Produktseite", "en": "No product structured data on the product page"},
    "tech.no_structured_data_detail": {
        "de": "Auf den geprüften Produktseiten wurde kein schema.org-Product/Offer-Markup gefunden. Google zieht daraus Preis und Verfügbarkeit für automatische Artikel-Updates – fehlt es, fällt der Feed auf reines Crawling zurück und Abweichungen werden schneller zur Ablehnung.",
        "en": "No schema.org Product/Offer markup was found on the product pages checked. Google uses it to derive price and availability for automatic item updates – without it the feed falls back to plain crawling and mismatches turn into disapprovals faster.",
    },
    "tech.structured_data_ok_title": {"de": "Strukturdaten stimmen mit den Shop-Preisen überein", "en": "Structured data matches the store prices"},
    "tech.structured_data_ok_detail": {"de": "{count} Produktseite(n) geprüft: Preis und Verfügbarkeit im schema.org-Markup entsprechen den Shop-Daten.", "en": "{count} product page(s) checked: price and availability in the schema.org markup match the store data."},
    "tech.price_mismatch_title": {"de": "Preisabweichung zwischen Strukturdaten und Shop", "en": "Price mismatch between structured data and store"},
    "tech.price_mismatch_detail": {
        "de": "{listing}\n\nDas ist der klassische Auslöser für „automatische Artikel-Updates“ und darauf folgende Sperren: Google liest im Markup einen anderen Preis als im Feed/auf der Seite. Meist stammt das aus einer Rabatt-App oder einem veralteten Theme-Snippet.",
        "en": "{listing}\n\nThis is the classic trigger for \"automatic item updates\" and subsequent suspensions: Google reads a different price in the markup than in the feed/on the page. It usually comes from a discount app or an outdated theme snippet.",
    },
    "tech.availability_mismatch_title": {"de": "Verfügbarkeit in Strukturdaten weicht ab", "en": "Availability in structured data differs"},
    "tech.availability_mismatch_detail": {
        "de": "{listing}\n\nDas Markup meldet eine andere Verfügbarkeit als der tatsächliche Lagerstatus. Google gleicht beides ab und stuft die Abweichung als Falschangabe ein.",
        "en": "{listing}\n\nThe markup reports a different availability than the actual stock status. Google compares both and treats the deviation as a misstatement.",
    },
    "tech.gmc_note_title": {"de": "Nicht prüfbar ohne Merchant-Center-Login", "en": "Not verifiable without a Merchant Center login"},
    "tech.gmc_note_detail": {
        "de": "Diese Punkte der Master-Checkliste lassen sich von außen grundsätzlich nicht prüfen und bleiben deine Aufgabe: Domain im GMC beansprucht & bestätigt, Geschäftsdaten im GMC identisch zur Website, Versand-/Rückgabe-/Steuereinstellungen deckungsgleich mit den Policies, „Produkte → Handlungsbedarf“ ohne offene Meldungen, Store-Quality-Report, AI-Kennzeichnung für KI-Bilder sowie die Betreiber-Punkte (eigene Gmail/IP pro Store, Identität nach Freigabe nicht mehr ändern, Retouren tatsächlich wie veröffentlicht abwickeln).",
        "en": "These items from the master checklist fundamentally cannot be verified from the outside and remain your responsibility: domain claimed & verified in GMC, business data in GMC identical to the website, shipping/return/tax settings matching the policies, \"Products → Needs attention\" with no open issues, store quality report, AI labelling for AI images, plus the operator items (dedicated Gmail/IP per store, never change identity after approval, actually handle returns as published).",
    },
})
