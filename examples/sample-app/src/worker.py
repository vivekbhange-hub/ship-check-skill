import os

DEBUG = os.environ.get("DEBUG", "0") == "1"
REDIS_URL = os.environ["REDIS_URL"]
SENTRY_DSN = os.getenv("SENTRY_DSN")
