"""Shared setup for the refresh modules: data locations, optional tqdm, HTTP JSON fetch."""

import time
import warnings

import requests

from cvegraphs.paths import DATA, PROCESSED

try:
    from tqdm import tqdm
except ImportError:  # tqdm is optional; degrade to a no-op iterator
    def tqdm(it=None, **kwargs):
        return it if it is not None else iter(())

warnings.filterwarnings("ignore")

DATA_DIR = DATA
OUTPUT_DIR = PROCESSED


def _fetch_json(urls, retries=3):
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                print(f"  fetching {url} (attempt {attempt}/{retries}) ...")
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                return r.json()
            except Exception as e:  # noqa: BLE001
                print(f"    could not fetch {url}: {e}")
                if attempt < retries:
                    time.sleep(3 * attempt)
    return None
