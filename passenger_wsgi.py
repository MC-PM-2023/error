# passenger_wsgi.py (put in ERROR_TRACKER/)
import os, sys

APP_ROOT = os.path.dirname(__file__)
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

# (optional) load .env if you keep secrets there
try:
    from dotenv import load_dotenv
    envp = os.path.join(APP_ROOT, ".env")
    if os.path.exists(envp):
        load_dotenv(envp)
except Exception:
    pass

# IMPORTANT: import Flask app instance as "application"
from app import app as application
