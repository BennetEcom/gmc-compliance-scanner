import os
from dotenv import load_dotenv

load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
OWNER_BYPASS_CODE = os.getenv("OWNER_BYPASS_CODE", "")
APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
STATS_ACCESS_CODE = os.getenv("STATS_ACCESS_CODE", "")

# Scan-Pakete: jeder weitere Scan nach dem kostenlosen Erst-Scan wird über
# eines dieser Pakete bezahlt. "scans" Guthaben wird pro Käufer (Browser-
# Token, kein Login) über beliebig viele Domains hinweg verbraucht.
SCAN_PACKAGES = {
    "2": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK2", ""), "scans": 2, "eur": 10.00},
    "5": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK5", ""), "scans": 5, "eur": 20.00},
    "10": {"price_id": os.getenv("STRIPE_PRICE_ID_PACK10", ""), "scans": 10, "eur": 35.00},
}
