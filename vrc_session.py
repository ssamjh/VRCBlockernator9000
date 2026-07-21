"""Session persistence for VRChat login.

Stores only the two auth cookies vrchatapi actually uses for session
restoration (`auth`, `twoFactorAuth`) - no passwords, no pickled cookiejars.

Note: vrchatapi's `configuration.api_key['authCookie']` mechanism is NOT
sufficient to restore a session - it's only applied to requests whose
generated method declares `auth_settings=[...]`, and `get_current_user()`
(used to verify a restored session) declares none. The cookie header is
actually built per-request from `api_client.rest_client.cookie_jar`, a real
`http.cookiejar.CookieJar`, so restoring a session means injecting Cookie
objects into that jar directly, not setting api_key.
"""
import json
import os
import time
from dataclasses import dataclass
from http.cookiejar import Cookie
from typing import Optional

import vrchatapi

SESSION_FILE = "vrc_session.json"
COOKIE_DOMAIN = "api.vrchat.cloud"


@dataclass
class SessionData:
    username: str
    auth_cookie: str
    tfa_cookie: Optional[str] = None


class SessionStore:
    def __init__(self, path: str = SESSION_FILE):
        self.path = path

    def save(self, session: SessionData):
        with open(self.path, "w") as f:
            json.dump(
                {
                    "username": session.username,
                    "auth_cookie": session.auth_cookie,
                    "tfa_cookie": session.tfa_cookie,
                },
                f,
            )

    def load(self) -> Optional[SessionData]:
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            if not data.get("username") or not data.get("auth_cookie"):
                return None
            return SessionData(
                username=data["username"],
                auth_cookie=data["auth_cookie"],
                tfa_cookie=data.get("tfa_cookie"),
            )
        except Exception:
            return None

    def clear(self):
        if os.path.exists(self.path):
            os.remove(self.path)


def build_configuration(session: SessionData) -> vrchatapi.Configuration:
    return vrchatapi.Configuration(username=session.username)


def _make_cookie(name: str, value: str) -> Cookie:
    # A far-future expiry here only bounds how long the *local* cookiejar
    # holds onto it in memory for this run; VRChat's own server-side auth
    # cookie lifetime is what actually governs when it stops working.
    far_future = int(time.time()) + 10 * 365 * 24 * 60 * 60
    return Cookie(
        0, name, value, None, False, COOKIE_DOMAIN, True, False, "/", False,
        True, far_future, False, None, None, {},
    )


def apply_session_cookies(api_client, session: SessionData):
    """Inject the saved auth/twoFactorAuth cookies directly into the
    ApiClient's real cookiejar, since that's what actually gets sent
    per-request (see module docstring)."""
    jar = api_client.rest_client.cookie_jar
    jar.set_cookie(_make_cookie("auth", session.auth_cookie))
    if session.tfa_cookie:
        jar.set_cookie(_make_cookie("twoFactorAuth", session.tfa_cookie))


def extract_cookies_from_client(api_client, username: str) -> Optional[SessionData]:
    """Pull the auth/twoFactorAuth cookie values out of an authenticated ApiClient."""
    try:
        cookie_jar = api_client.rest_client.cookie_jar._cookies.get(
            "api.vrchat.cloud", {}
        ).get("/", {})
        auth_cookie = cookie_jar.get("auth")
        tfa_cookie = cookie_jar.get("twoFactorAuth")

        if not auth_cookie:
            return None

        return SessionData(
            username=username,
            auth_cookie=auth_cookie.value,
            tfa_cookie=tfa_cookie.value if tfa_cookie else None,
        )
    except Exception:
        return None
