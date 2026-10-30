import os
from dotenv import load_dotenv

load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
OWNER_BYPASS_CODE = os.getenv("OWNER_BYPASS_CODE", "")
APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
STATS_ACCESS_CODE = os.getenv("STATS_ACCESS_CODE", "")

# Verkauf über Stripe ist vorerst abgeschaltet: gescannt wird über Keys.
# Zum Wiedereinschalten SALES_ENABLED=true setzen – der gesamte Paket- und
# Checkout-Code bleibt dafür erhalten.
SALES_ENABLED = os.getenv("SALES_ENABLED", "false").strip().lower() in ("1", "true", "yes")

# Wo es die Scan-Keys zu kaufen gibt. Steht KEY_SHOP_URL nicht, erscheint der
# Hinweis ohne Link - so stimmt der Satz auch, solange der Shop noch keine
# Adresse hat. Beides sind reine Anzeigewerte, nichts hängt funktional daran.
KEY_SHOP_URL = os.getenv("KEY_SHOP_URL", "").strip()
KEY_SHOP_NAME = os.getenv("KEY_SHOP_NAME", "").strip()

# Scan-Pakete: jeder weitere Scan nach dem kostenlosen Erst-Scan wird über
# eines dieser Pakete bezahlt. "scans" Guthaben wird pro Käufer (Browser-
# Token, kein Login) über beliebig viele Domains hinweg verbraucht.
SCAN_PACKAGES = {
    "2": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK2", ""), "scans": 2, "eur": 10.00},
    "5": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK5", ""), "scans": 5, "eur": 20.00},
    "10": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK10", ""), "scans": 10, "eur": 35.00},
}
