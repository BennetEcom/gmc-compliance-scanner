"""
Winziger Fake-Shop-Server, um die Scanner-Logik ohne echten Internetzugriff
end-to-end zu testen. Baut absichtlich bekannte Probleme ein:
- Impressum & Datenschutz vorhanden, aber Widerruf/AGB fehlen
- 1 kaputter interner Link
- products.json mit 3 Produkten: 1x fehlender Barcode, 1x fehlender Vendor,
  1x vollständig korrekt
- 1 Produktbild zu klein (150x150), 1 in Ordnung (900x900)
"""
import json
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from PIL import Image

HOME_HTML = """
<html><body>
<h1>Fake Shop</h1>
<footer>
  <a href="/pages/impressum">Impressum</a>
  <a href="/policies/privacy-policy">Datenschutz</a>
  <a href="/pages/kontakt">Kontakt</a>
  <a href="/products/widget-a">Produkt A</a>
  <a href="/products/does-not-exist">Kaputter Link</a>
</footer>
</body></html>
"""

PRODUCTS_JSON = {
    "products": [
        {
            "id": 1,
            "title": "Widget A (vollstaendig)",
            "vendor": "AcmeBrand",
            "body_html": "<p>" + ("Eine ausfuehrliche Produktbeschreibung. " * 10) + "</p>",
            "variants": [{"price": "19.99", "barcode": "1234567890123"}],
            "images": [{"src": "/images/big.jpg"}],
        },
        {
            "id": 2,
            "title": "Widget B (kein Barcode)",
            "vendor": "AcmeBrand",
            "body_html": "<p>Kurz.</p>",
            "variants": [{"price": "9.99", "barcode": ""}],
            "images": [{"src": "/images/small.jpg"}],
        },
        {
            "id": 3,
            "title": "Widget C (kein Vendor, kein Preis)",
            "vendor": "",
            "body_html": "",
            "variants": [{"price": "0", "barcode": ""}],
            "images": [{"src": "/images/small.jpg"}],
        },
    ]
}


def make_image_bytes(size):
    buf = BytesIO()
    Image.new("RGB", size, color=(200, 50, 50)).save(buf, format="JPEG")
    return buf.getvalue()


BIG_JPG = make_image_bytes((900, 900))
SMALL_JPG = make_image_bytes((150, 150))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence

    def _send(self, code, body: bytes, content_type="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, HOME_HTML.encode())
        elif path == "/pages/impressum":
            self._send(200, b"<html><body>Impressum Inhalt</body></html>")
        elif path == "/policies/privacy-policy":
            self._send(200, b"<html><body>Datenschutz Inhalt</body></html>")
        elif path == "/pages/kontakt":
            self._send(200, b"<html><body>Kontakt Inhalt</body></html>")
        elif path == "/products/widget-a":
            self._send(200, b"<html><body>Produkt A Detailseite</body></html>")
        elif path == "/products.json":
            self._send(200, json.dumps(PRODUCTS_JSON).encode(), "application/json")
        elif path == "/images/big.jpg":
            self._send(200, BIG_JPG, "image/jpeg")
        elif path == "/images/small.jpg":
            self._send(200, SMALL_JPG, "image/jpeg")
        else:
            self._send(404, b"Not Found")

    def do_HEAD(self):
        path = self.path.split("?")[0]
        known = {
            "/", "/pages/impressum", "/policies/privacy-policy", "/pages/kontakt",
            "/products/widget-a", "/products.json", "/images/big.jpg", "/images/small.jpg",
        }
        self.send_response(200 if path in known else 404)
        self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8010), Handler)
    print("Fake shop running on http://127.0.0.1:8010")
    server.serve_forever()
