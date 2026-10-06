# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-fallback-key")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", "subhunter.db")
    DEFAULT_WORDLIST = "wordlists.txt"
    DEFAULT_THREADS = int(os.environ.get(DEFAULT_THREADS=10))
    MAX_THREADS = 50
    VERSION = "1.0"
    TOOL_NAME = "SubHunter"