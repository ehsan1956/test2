from urllib.parse import urlparse
from datetime import timedelta
import os

STDIN_MARKER = "-"
COMMA = ","
NEW_LINE = "\n"

def lines_in_file(file_name: str) -> List[str]:
    if not os.path.exists(file_name):
        raise ValueError(f"File {file_name} not found")
    with open(file_name, 'r') as f:
        return f.read().splitlines()

def is_url(to_test: str) -> bool:
    parsed = urlparse(to_test)
    return bool(parsed.scheme and parsed.netloc)

def extract_domain(url_str: str) -> str:
    parsed = urlparse(url_str)
    return parsed.hostname or ""

def prepare_resolver(resolver: str) -> str:
    resolver = resolver.strip()
    if ":" not in resolver:
        resolver += ":53"
    return resolver

def fmt_duration(d: timedelta) -> str:
    seconds = int(d.total_seconds())
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return f"{hours}:{minutes:02d}:{seconds:02d}"