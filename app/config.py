import os
from dotenv import load_dotenv

load_dotenv()

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
OWNER_BYPASS_CODE = os.getenv("OWNER_BYPASS_CODE", "")
APP_SECRET = os.getenv("APP_SECRET", "dev-secret-change-me")
STATS_ACCESS_CODE = os.getenv("STATS_ACCESS_CODE", "")
PAGESPEED_API_KEY = os.getenv("PAGESPEED_API_KEY", "")

SCAN_PRICE_EUR = 10.00
