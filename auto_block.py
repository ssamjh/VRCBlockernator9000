"""Auto-block decision engine: not-a-friend + Visitor trust rank -> block.
Also blocks non-friends wearing a user-curated "known bad" avatar, regardless
of their trust rank - matched either by exact avatar ID, or (when the API
hides the ID, e.g. a VRC+ custom profile picture override or cloning-disabled
avatar) by perceptual hash of the avatar's thumbnail image.

No Tkinter and no direct networking here except the optional avatar_hash
image fetch - everything else routes through a VrcClient instance so this
stays independently testable.
"""
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

import avatar_hash
from vrc_client import VrcClient, VrcApiError

PROCESSED_CACHE_FILE = "processed_users.json"
AVATAR_BLOCKLIST_FILE = "avatar_blocklist.json"
AVATAR_NAME_BLOCKLIST_FILE = "avatar_name_blocklist.json"
FRIEND_CACHE_TTL_SECONDS = 10 * 60

# Perceptual hashes are 64-bit; a Hamming distance this low means "visually
# the same image" for our purposes (identical avatar, most likely just
# re-uploaded/re-thumbnailed). Raise it to catch more near-duplicates at the
# cost of more false positives.
AVATAR_HASH_MAX_DISTANCE = 8


@dataclass
class Decision:
    action: str  # "block" | "skip"
    reason: str
    trust_rank: Optional[str] = None
    is_friend: bool = False


class ProcessedCache:
    """Tracks user IDs we've already decided about, so a user who stays in
    an instance for hours isn't re-evaluated/re-blocked on every log tail."""

    def __init__(self, path: str = PROCESSED_CACHE_FILE):
        self.path = path
        self._entries = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass

    def get(self, user_id: str) -> Optional[dict]:
        return self._entries.get(user_id)

    def set(self, user_id: str, action: str, reason: str):
        self._entries[user_id] = {"action": action, "reason": reason, "ts": time.time()}
        self._save()

    def seed_blocked(self, user_ids):
        for uid in user_ids:
            if uid not in self._entries:
                self._entries[uid] = {"action": "blocked", "reason": "pre-existing block", "ts": time.time()}
        self._save()


class AvatarBlockList:
    """User-curated list of "known bad" avatars that should trigger an
    auto-block for any non-friend wearing them, regardless of trust rank.

    Entries are keyed by avatar ID (id_<uuid>) when one was available at add
    time. When it wasn't (API hides it), the entry is keyed by a synthetic
    "phash:<hash>" key instead - either way, an entry can carry a "phash"
    field used for fuzzy image matching as a fallback/supplement."""

    def __init__(self, path: str = AVATAR_BLOCKLIST_FILE):
        self.path = path
        self._entries = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass

    def contains(self, avatar_id: Optional[str]) -> bool:
        return bool(avatar_id) and avatar_id in self._entries

    def add(self, avatar_id: Optional[str] = None, note: str = "", phash: Optional[str] = None):
        if not avatar_id and not phash:
            raise ValueError("Must provide an avatar_id and/or a phash")
        key = avatar_id or f"phash:{phash}"
        self._entries[key] = {"note": note, "ts": time.time(), "phash": phash}
        self._save()

    def remove(self, key: str):
        if key in self._entries:
            del self._entries[key]
            self._save()

    def items(self) -> dict:
        return dict(self._entries)

    def has_any_hash_entries(self) -> bool:
        return any(entry.get("phash") for entry in self._entries.values())

    def find_matching_hash(self, candidate_hash: str, max_distance: int = AVATAR_HASH_MAX_DISTANCE):
        """Returns (key, entry, distance) for the closest hash entry within
        max_distance, or None if nothing matches closely enough."""
        best = None
        for key, entry in self._entries.items():
            stored_hash = entry.get("phash")
            if not stored_hash:
                continue
            distance = avatar_hash.hamming_distance(candidate_hash, stored_hash)
            if distance <= max_distance and (best is None or distance < best[2]):
                best = (key, entry, distance)
        return best


class AvatarNameBlockList:
    """User-curated list of "known bad" avatar display names. Weaker than
    ID/image matching (names aren't unique or immutable) but the only signal
    obtainable purely from the log with no network call and no dependence on
    the API exposing anything about the target user at all - VRChat logs
    every avatar switch your client renders, self or remote, regardless of
    any privacy setting."""

    def __init__(self, path: str = AVATAR_NAME_BLOCKLIST_FILE):
        self.path = path
        self._entries = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def _normalize(avatar_name: str) -> str:
        return avatar_name.strip().casefold()

    def contains(self, avatar_name: Optional[str]) -> bool:
        return bool(avatar_name) and self._normalize(avatar_name) in self._entries

    def add(self, avatar_name: str, note: str = ""):
        self._entries[self._normalize(avatar_name)] = {
            "display": avatar_name,
            "note": note,
            "ts": time.time(),
        }
        self._save()

    def remove(self, avatar_name: str):
        key = self._normalize(avatar_name)
        if key in self._entries:
            del self._entries[key]
            self._save()

    def items(self) -> dict:
        return dict(self._entries)


class AutoBlockEngine:
    def __init__(
        self,
        client: VrcClient,
        cache: ProcessedCache,
        avatar_blocklist: AvatarBlockList,
        avatar_name_blocklist: AvatarNameBlockList,
    ):
        self.client = client
        self.cache = cache
        self.avatar_blocklist = avatar_blocklist
        self.avatar_name_blocklist = avatar_name_blocklist
        self.friend_ids = set()
        self._friends_refreshed_at = 0.0
        self.enabled = False  # master safety switch, default off

    def seed_from_existing_moderations(self):
        try:
            self.cache.seed_blocked(self.client.get_existing_block_ids())
        except VrcApiError:
            pass

    def refresh_friends(self, force: bool = False):
        stale = (time.time() - self._friends_refreshed_at) > FRIEND_CACHE_TTL_SECONDS
        if not force and not stale and self.friend_ids:
            return
        self.friend_ids = self.client.get_friend_ids()
        self._friends_refreshed_at = time.time()

    def evaluate(self, user_id: str, name: str) -> Decision:
        if self.client.current_user and user_id == self.client.current_user.id:
            return Decision(action="skip", reason="self")

        cached = self.cache.get(user_id)
        if cached:
            return Decision(action="skip", reason=f"already handled: {cached['reason']}")

        if user_id in self.friend_ids:
            return Decision(action="skip", reason="friend", is_friend=True)

        user = self.client.get_user(user_id)
        trust_rank = VrcClient.resolve_trust_rank(user)
        avatar_id = VrcClient.extract_avatar_id(user)

        if self.avatar_blocklist.contains(avatar_id):
            return Decision(
                action="block",
                reason=f"not friend, blocklisted avatar ({avatar_id})",
                trust_rank=trust_rank,
            )

        if self.avatar_blocklist.has_any_hash_entries():
            thumbnail_url = getattr(user, "current_avatar_thumbnail_image_url", None)
            candidate_hash = avatar_hash.fetch_and_hash(thumbnail_url)
            if candidate_hash:
                match = self.avatar_blocklist.find_matching_hash(avatar_hash.hash_to_str(candidate_hash))
                if match:
                    _key, entry, distance = match
                    label = entry.get("note") or "blocklisted avatar image"
                    return Decision(
                        action="block",
                        reason=f"not friend, avatar image matches '{label}' (distance {distance})",
                        trust_rank=trust_rank,
                    )

        if trust_rank != "Visitor":
            return Decision(action="skip", reason=f"trusted ({trust_rank})", trust_rank=trust_rank)

        return Decision(action="block", reason="not friend, trust=Visitor", trust_rank=trust_rank)

    def evaluate_avatar_name(self, user_id: str, name: str, avatar_name: str) -> Optional[Decision]:
        """Called whenever the log reports someone switching to a new avatar
        (not just on join, since a user already in the instance can switch
        into a blocklisted avatar mid-visit). Returns None for the common
        case of an unremarkable avatar switch, to avoid logging noise for
        every single avatar change."""
        if self.client.current_user and user_id == self.client.current_user.id:
            return None

        cached = self.cache.get(user_id)
        if cached and cached["action"] == "blocked":
            return None

        if user_id in self.friend_ids:
            return None

        if not self.avatar_name_blocklist.contains(avatar_name):
            return None

        return Decision(
            action="block",
            reason=f"not friend, avatar name matches blocklisted '{avatar_name}'",
        )

    def execute(self, decision: Decision, user_id: str, name: str) -> str:
        """Carries out `decision` and returns a human-readable log line."""
        if decision.action == "skip":
            if not self.cache.get(user_id):
                self.cache.set(user_id, "skipped", decision.reason)
            return f"SKIP {name} ({user_id}) - {decision.reason}"

        if not self.enabled:
            self.cache.set(user_id, "skipped-disabled", decision.reason)
            return f"WOULD BLOCK {name} ({user_id}) - {decision.reason} (auto-block disabled)"

        self.client.block_user(user_id)
        self.cache.set(user_id, "blocked", decision.reason)
        return f"BLOCKED {name} ({user_id}) - {decision.reason}"
