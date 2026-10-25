import os
from pathlib import Path
DB_PATH = os.getenv("DB_PATH", "scanner.db")
OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
