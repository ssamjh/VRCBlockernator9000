"""Incremental tailing of the local VRChat game log.

VRChat's API exposes no instance-roster endpoint, so join/leave detection
has to come from the client's own log file. This reads only the bytes
appended since the last poll() call, instead of re-parsing the whole file
every tick.
"""
import glob
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Union

INSTANCE_START_RE = re.compile(r"\[Behaviour\] Joining or Creating Room: (.+)")
JOIN_RE = re.compile(r"\[Behaviour\] OnPlayerJoined (.+) \(usr_([a-f0-9-]+)\)")
LEAVE_RE = re.compile(r"\[Behaviour\] OnPlayerLeft (.+?)(?: \(usr_([a-f0-9-]+)\))?$")
# Fires for every avatar switch your client renders - local and remote players
# alike - independent of the API entirely, so it's unaffected by any privacy
# setting that hides a user's avatar ID/image via get_user().
SWITCH_AVATAR_RE = re.compile(r"\[Behaviour\] Switching (.+?) to avatar (.+)$")


@dataclass
class RoomChanged:
    room: str


@dataclass
class PlayerJoined:
    name: str
    user_id: str


@dataclass
class PlayerLeft:
    name: str
    user_id: Optional[str]


@dataclass
class AvatarChanged:
    name: str
    avatar_name: str


LogEvent = Union[RoomChanged, PlayerJoined, PlayerLeft, AvatarChanged]


def find_latest_log_file() -> Optional[str]:
    if os.name == "nt":
        log_dir = os.path.expandvars(r"%USERPROFILE%\AppData\LocalLow\VRChat\VRChat")
    else:
        log_dir = os.path.expanduser("~/.config/unity3d/VRChat/VRChat")

    try:
        log_files = glob.glob(os.path.join(log_dir, "output_log_*.txt"))
        if not log_files:
            return None
        return max(log_files, key=os.path.getmtime)
    except Exception:
        return None


class LogTailer:
    def __init__(self):
        self._path = None
        self._offset = 0

    def poll(self) -> List[LogEvent]:
        latest = find_latest_log_file()
        if not latest:
            return []

        if latest != self._path:
            # New/rotated log file: start tailing it from its current end so we
            # don't replay a whole prior session's join/leave history.
            self._path = latest
            self._offset = os.path.getsize(latest)
            return []

        try:
            size = os.path.getsize(self._path)
            if size < self._offset:
                # File was truncated/replaced under the same name.
                self._offset = 0
            if size == self._offset:
                return []

            with open(self._path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                new_text = f.read()
                self._offset = f.tell()
        except Exception:
            return []

        events: List[LogEvent] = []
        for line in new_text.splitlines():
            room_match = INSTANCE_START_RE.search(line)
            if room_match:
                events.append(RoomChanged(room_match.group(1)))
                continue

            join_match = JOIN_RE.search(line)
            if join_match:
                events.append(
                    PlayerJoined(join_match.group(1).strip(), "usr_" + join_match.group(2))
                )
                continue

            leave_match = LEAVE_RE.search(line)
            if leave_match:
                user_id = "usr_" + leave_match.group(2) if leave_match.group(2) else None
                events.append(PlayerLeft(leave_match.group(1).strip(), user_id))
                continue

            switch_match = SWITCH_AVATAR_RE.search(line)
            if switch_match:
                events.append(
                    AvatarChanged(switch_match.group(1).strip(), switch_match.group(2).strip())
                )

        return events
