"""Perceptual hashing of avatar thumbnail images.

Fallback for users whose avatar ID/name isn't reliably extractable via the
API (e.g. a VRC+ custom profile picture override, or an avatar with cloning
disabled) - the thumbnail image URL is still fetchable even then, so we hash
its pixels instead of relying on an ID string. Also doubles as a way to catch
a known-bad avatar that's been re-uploaded under a new ID, since a perceptual
hash tracks the image, not the upload.
"""
import io

import imagehash
import requests
from PIL import Image

REQUEST_TIMEOUT_SECONDS = 10
HTTP_HEADERS = {"User-Agent": "Mozilla/5.0", "Accept": "image/jpeg, image/png, image/*"}


def fetch_and_hash(image_url: str):
    """Downloads `image_url` and returns its perceptual hash (imagehash.ImageHash),
    or None if it couldn't be fetched/decoded."""
    if not image_url:
        return None
    try:
        response = requests.get(
            image_url, headers=HTTP_HEADERS, timeout=REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        image = Image.open(io.BytesIO(response.content))
        return imagehash.phash(image)
    except Exception:
        return None


def hash_to_str(image_hash) -> str:
    return str(image_hash)


def hamming_distance(hash_str_a: str, hash_str_b: str) -> int:
    return imagehash.hex_to_hash(hash_str_a) - imagehash.hex_to_hash(hash_str_b)
