# GMC Compliance Scanner

Landingpage + echter, live laufender Scanner, der einen Shopify-Store (oder
generisch jede Website) gegen die wichtigsten Google-Merchant-Center-Regeln
prüft. Der erste Scan pro Store-Domain ist kostenlos, jeder weitere Scan
derselben Domain kostet (Stripe Checkout). Ohne gesetzte Stripe-Keys läuft
der Scanner komplett kostenlos (Testmodus).

Die Checks sind gegen die interne "GMC Master Checklist" abgeglichen (die
Kategorien A-H davon, soweit ohne GMC-Login automatisiert prüfbar).

## Was der Scanner wirklich prüft

1. **Trust & Domain** – HTTPS, SSL-Zertifikat-Gültigkeit, Domain-Alter (WHOIS)
2. **Broken Links** – nicht nur die Startseite: Seiten werden zuerst über die Shopify-Sitemap (`sitemap.xml`) gesammelt (Fallback: Homepage-Links + `products.json`) und dann auf Fehlerstatus geprüft
3. **Policy-Seiten** – Impressum, Datenschutz, AGB, Widerruf, Versand, Kontakt (häufigster GMC-Ablehnungsgrund)
4. **Kontakt & Rechtliches** – geschäftliche E-Mail statt Gmail/GMX, sichtbare Telefonnummer, NAP-Konsistenz (identische Kontaktdaten über alle Seiten), Platzhalter-/Lorem-Ipsum-Reste, erratbare Standard-URLs (`/pages/contact-us` etc.), die nicht auf 404 enden dürfen
5. **Produkt-Feed-Qualität** – liest Shopifys öffentliches `/products.json` aus und prüft GTIN/Barcode, Marke, Preis, Beschreibungslänge, eindeutige SKUs, Streichpreis-Plausibilität (Compare-at > Preis), "gebraucht/refurbished"-Wortlaut sowie leere/fast leere Kollektionen, die im Hauptmenü verlinkt sind
6. **Bild-Compliance** – prüft, ob Produktbilder erreichbar sind und die von Google empfohlene Mindestauflösung erfüllen
7. **Bewertungen & Social Proof** – erkennt bekannte Bewertungsplattformen (Trustpilot, Judge.me, Loox, Yotpo, …); fehlt eine solche trotz angezeigter Sternebewertungen, oder tauchen identische Rezensionstexte auf mehreren Produktseiten auf, wird das als nicht verifizierbar/möglich gefälscht markiert
8. **Künstliche Dringlichkeit ("Fake Urgency")** – sucht nach Countdown-/Verknappungs-Apps und Formulierungen wie "nur noch X auf Lager"; wenn Shopify für die geprüften Produkte gar keinen Lagerbestand trackt, können solche Angaben nicht real sein (Verstoß gegen Googles Misrepresentation-Richtlinie)
9. **Page Speed** – misst Ladezeit und HTML-Größe der Startseite direkt beim Scan (kein externer API-Key nötig). Liefert keine echten Lighthouse-Werte wie LCP/CLS, aber eine grobe, sofort verfügbare Einschätzung der Ladegeschwindigkeit

Alles läuft live pro Anfrage, es werden keine Scan-Ergebnisse dauerhaft
gespeichert (nur ein kurzlebiger In-Memory-Cache pro Zahlungs-Session, damit
ein Reload nicht doppelt berechnet).

**Wichtige Einschränkung:** Ohne GMC-/API-Zugriff kann kein Tool von außen
100% dieselben Signale sehen wie Google selbst (z.B. Bild-Overlays,
Rabatt-Banner, tatsächliche Feed-Ablehnungsgründe aus dem Merchant Center).
Der Score ist eine fundierte Risiko-Einschätzung, keine Garantie.

## Bezahlung & Promo-Code

- **Erster Scan pro Domain gratis:** Wurde eine Store-Domain noch nie gescannt,
  läuft der Scan direkt und kostenlos, mit einem Hinweisbanner im Report.
  Erst der zweite Scan derselben Domain (egal von wem) verlangt Bezahlung.
  Die Zuordnung läuft ohne Cookie/Login beim Besucher, wird aber auf einer
  **Render Persistent Disk** gespeichert (`STATS_FILE`, Standard
  `/var/data/stats.json`) – sonst könnte man die Regel durch einen einfachen
  Server-Neustart/Redeploy aushebeln. Ohne gemountete Disk (z.B. lokale
  Entwicklung) läuft es automatisch als reiner In-Memory-Fallback weiter.
- Checkout läuft über **Stripe Checkout** (einmaliger Kauf, 10&nbsp;€).
- `allow_promotion_codes=True` ist aktiviert → jeder Nutzer kann im
  Stripe-Checkout ein Rabattcode-Feld sehen und einlösen.
- Für dich als Owner gibt es zusätzlich einen **direkten Bypass ohne
  Stripe**: Trag im Feld "Rabatt-/Promo-Code" auf der Website den Wert aus
  `OWNER_BYPASS_CODE` (siehe `.env`) ein → der Scan startet sofort, ganz ohne
  Bezahlvorgang.

### Stripe einrichten (einmalig)

1. Account auf https://dashboard.stripe.com anlegen (falls noch nicht vorhanden).
2. **Product Catalog → + Add product**: Name "GMC Compliance Scan", Preis
   10,00&nbsp;€, "One time". Die erzeugte `price_...`-ID kopieren.
3. **Developers → API keys**: `Secret key` (sk_live_... bzw. sk_test_... zum
   Testen) und `Publishable key` kopieren.
4. Optional: **Product Catalog → Coupons** → neuen Coupon mit **100% off**
   anlegen, dann unter **Promotion codes** einen Code dafür erstellen (z.B.
   `BENNETFREE`). Diesen Code kann jeder Nutzer im Stripe-Checkout eingeben,
   um kostenlos zu scannen – nützlich z.B. für Test-Kunden oder Partner.
5. Werte in `.env` eintragen (siehe `.env.example`):
   - `STRIPE_SECRET_KEY`
   - `STRIPE_PUBLISHABLE_KEY`
   - `STRIPE_PRICE_ID`
   - `APP_BASE_URL` (die öffentliche URL deiner App, z.B. `https://gmc-compliance-scanner.onrender.com`)
   - `OWNER_BYPASS_CODE` (ein selbst gewähltes Geheimnis, NICHT das gleiche wie ein Stripe-Coupon-Code)
   - `APP_SECRET` (beliebiger zufälliger String)

Ohne gesetzte Stripe-Keys läuft die App automatisch im **Testmodus**: jeder
Scan wird direkt ausgeführt, ohne Bezahlung, mit einem gelben Hinweisbanner.
So kannst du lokal alles durchklicken, ohne echtes Geld zu bewegen.

## Lokal starten

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # dann Werte eintragen (oder leer lassen für Testmodus)
uvicorn app.main:app --reload --port 8000
```

Dann `http://localhost:8000` im Browser öffnen.

### Ohne echten Internetzugriff testen

Im Ordner `test_fixture/` liegt ein winziger Fake-Shop-Server mit absichtlich
eingebauten Problemen (fehlende AGB, 1 kaputter Link, 1 Produkt ohne
GTIN/Marke, 1 zu kleines Bild). Damit lässt sich die komplette Scan-Logik
verifizieren, ohne einen echten Store zu belasten:

```bash
python3 test_fixture/server.py &
# dann auf der Website http://127.0.0.1:8010 als Ziel-URL eingeben
```

## Deployment auf Render

1. Repo zu GitHub pushen (oder Render direkt per "Deploy from existing image"
   nutzen).
2. Auf https://render.com **New → Web Service** → Repo verbinden.
3. Render erkennt automatisch die `render.yaml` in diesem Projekt
   (Build: `pip install -r requirements.txt`, Start:
   `uvicorn app.main:app --host 0.0.0.0 --port $PORT`).
4. Unter **Environment** die Variablen aus `.env.example` eintragen (echte
   Werte, keine Platzhalter). `APP_BASE_URL` = die von Render vergebene URL.
5. Deploy auslösen. Nach dem ersten erfolgreichen Deploy in Stripe unter
   **Developers → Webhooks** optional einen Endpoint einrichten, falls du
   später zusätzliche Zahlungsarten (z.B. SEPA mit Verzögerung) unterstützen
   willst – für Kartenzahlung reicht der aktuelle Ablauf ohne Webhook.

### Andere Hosting-Optionen

- **Railway**: `railway init`, dann Environment-Variablen im Dashboard
  setzen, Start Command wie oben.
- **Fly.io / eigener Server**: `Dockerfile` fehlt aktuell – bei Bedarf sag
  Bescheid, dann lege ich eins an. Ansonsten reicht ein simpler Python-Host
  mit den obigen Umgebungsvariablen.

## Bekannte Grenzen / ehrliche Hinweise

- Manche Shops blocken automatisierte Anfragen (Bot-/Firewall-Schutz, HTTP
  403). Der Scanner erkennt das und meldet es separat als "Zugriff durch
  Bot-Schutz blockiert" statt es fälschlich als generelles GMC-Problem zu
  werten.
- Die Produkt-Feed- und Bild-Checks basieren auf Shopifys öffentlichem
  `/products.json`-Endpoint. Läuft der Store nicht auf Shopify oder ist der
  Endpoint deaktiviert, wird das transparent als "nicht prüfbar" ausgewiesen
  statt einen falschen Score zu erzeugen.
- Text-Overlays/Wasserzeichen in Bildern und die tatsächliche GMC-Entscheidung
  können nicht 1:1 automatisiert vorhergesagt werden – der Report ist eine
  Risiko-Einschätzung basierend auf den bekanntesten Ablehnungsgründen.
