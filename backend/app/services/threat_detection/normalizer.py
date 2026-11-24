
import re
import unicodedata


def normalize_username(value: str) -> str:
    """Normalize a social media username for comparison."""
    if not value:
        return ""

    value = unicodedata.normalize("NFKC", value)
    value = value.strip().lower()
    value = value.removeprefix("@")

    return re.sub(r"[\s._-]+", "", value)


def normalize_text(value: str) -> str:
    """Normalize display names and bios for text comparison."""
    if not value:
        return ""

    value = unicodedata.normalize("NFKC", value)
    value = value.lower()

    value = re.sub(r"https?://\S+|www\.\S+", " ", value)
    value = re.sub(r"[^a-z0-9\s]", " ", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip()
