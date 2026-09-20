import os

import yaml

API_KEY = os.environ.get("API_KEY", "")
PLACEHOLDER = "changeme"


def load_config(text: str) -> dict:
    return yaml.safe_load(text)
