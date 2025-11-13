# db_config.py
import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine

INSTANCE = os.getenv("INSTANCE_CONNECTION_NAME")
DB_USER  = os.getenv("DB_USER", "appsadmin")
DB_PASS  = os.getenv("DB_PASS", "")
PASS_Q   = quote_plus(DB_PASS)

def make_engine(db_name: str):
    """
    App Engine Standard: connect via Cloud SQL unix socket.
    """
    return create_engine(
        f"mysql+pymysql://{DB_USER}:{PASS_Q}@/{db_name}?charset=utf8mb4",
        connect_args={"unix_socket": f"/cloudsql/{INSTANCE}"},
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_size=5,
        max_overflow=10,
    )

# expose your three engines
enginea    = make_engine(os.getenv("DB_NAME_ANALYTICA", "elicita"))
engine     = make_engine(os.getenv("DB_NAME_INSOLVO",   "mc"))
tgt_engine = make_engine(os.getenv("DB_NAME_TRACKER",   "InSolvo_Documents"))
