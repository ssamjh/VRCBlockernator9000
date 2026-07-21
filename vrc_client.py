"""Thin wrapper around vrchatapi - every network call the app makes lives here."""
import re
from enum import Enum, auto

import vrchatapi
from vrchatapi.api import authentication_api, friends_api, playermoderation_api, users_api
from vrchatapi.exceptions import ApiException, UnauthorizedException
from vrchatapi.models.two_factor_auth_code import TwoFactorAuthCode
from vrchatapi.models.two_factor_email_code import TwoFactorEmailCode
from vrchatapi.models.moderate_user_request import ModerateUserRequest
from vrchatapi.models.player_moderation_type import PlayerModerationType

from vrc_session import SessionData, apply_session_cookies, build_configuration, extract_cookies_from_client

USER_AGENT = "VRCBlockernator9000/2.0.0 (github.com/ssamjh/VRCBlockernator9000)"


class LoginResult(Enum):
    OK = auto()
    NEEDS_EMAIL_2FA = auto()
    NEEDS_TOTP_2FA = auto()


class VrcApiError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code

    @property
    def is_unauthorized(self):
        return self.status_code == 401

    @property
    def is_rate_limited(self):
        return self.status_code == 429


def _wrap(e: Exception) -> VrcApiError:
    status = getattr(e, "status", None)
    reason = getattr(e, "reason", None) or str(e)
    return VrcApiError(reason, status_code=status)


class VrcClient:
    def __init__(self):
        self.api_client = None
        self.username = None
        self.current_user = None
        self._pending_configuration = None

    # -- auth -----------------------------------------------------------

    def login(self, username: str, password: str) -> LoginResult:
        configuration = vrchatapi.Configuration(username=username, password=password)
        self._pending_configuration = configuration
        self.username = username
        self.api_client = vrchatapi.ApiClient(configuration)
        self.api_client.user_agent = USER_AGENT

        auth_api = authentication_api.AuthenticationApi(self.api_client)
        try:
            self.current_user = auth_api.get_current_user()
            return LoginResult.OK
        except UnauthorizedException as e:
            if e.status == 200 and "Email 2 Factor Authentication" in (e.reason or ""):
                return LoginResult.NEEDS_EMAIL_2FA
            if e.status == 200 and "2 Factor Authentication" in (e.reason or ""):
                return LoginResult.NEEDS_TOTP_2FA
            raise _wrap(e)
        except Exception as e:
            raise _wrap(e)

    def submit_2fa(self, code: str, kind: LoginResult):
        auth_api = authentication_api.AuthenticationApi(self.api_client)
        try:
            if kind == LoginResult.NEEDS_EMAIL_2FA:
                auth_api.verify2_fa_email_code(two_factor_email_code=TwoFactorEmailCode(code))
            else:
                auth_api.verify2_fa(two_factor_auth_code=TwoFactorAuthCode(code))
            self.current_user = auth_api.get_current_user()
        except Exception as e:
            raise _wrap(e)

    def restore_session(self, session: SessionData) -> bool:
        configuration = build_configuration(session)
        self.username = session.username
        self.api_client = vrchatapi.ApiClient(configuration)
        self.api_client.user_agent = USER_AGENT
        apply_session_cookies(self.api_client, session)

        auth_api = authentication_api.AuthenticationApi(self.api_client)
        try:
            self.current_user = auth_api.get_current_user()
            return True
        except Exception:
            self.api_client = None
            self.current_user = None
            return False

    def extract_session(self) -> SessionData:
        return extract_cookies_from_client(self.api_client, self.username)

    def logout(self):
        if self.api_client:
            try:
                authentication_api.AuthenticationApi(self.api_client).logout()
            except Exception:
                pass
        self.api_client = None
        self.current_user = None

    # -- data -------------------------------------------------------------

    def get_self_location(self) -> str:
        try:
            user = users_api.UsersApi(self.api_client).get_user(self.current_user.id)
            return user.location
        except Exception as e:
            raise _wrap(e)

    def get_friend_ids(self) -> set:
        try:
            api = friends_api.FriendsApi(self.api_client)
            ids = set()
            offset = 0
            page_size = 100
            while True:
                page = api.get_friends(offset=offset, n=page_size)
                if not page:
                    break
                ids.update(u.id for u in page)
                if len(page) < page_size:
                    break
                offset += page_size
            return ids
        except Exception as e:
            raise _wrap(e)

    def get_user(self, user_id: str):
        try:
            return users_api.UsersApi(self.api_client).get_user(user_id)
        except Exception as e:
            raise _wrap(e)

    def get_world_name(self, world_id: str):
        try:
            from vrchatapi.api import worlds_api
            world = worlds_api.WorldsApi(self.api_client).get_world(world_id)
            return world.name
        except Exception:
            return None

    @staticmethod
    def resolve_trust_rank(user) -> str:
        """VRChat encodes trust rank as a system_trust_* tag. A brand-new
        "Visitor" account has none of these tags at all, so its absence
        (not an "Unknown" tag) is what identifies a Visitor."""
        if user.tags:
            for tag in user.tags:
                if tag.startswith("system_trust_"):
                    return tag.replace("system_trust_", "").title()
        return "Visitor"

    @staticmethod
    def extract_avatar_id(user) -> str:
        """Pulls the avatar file ID (id_<uuid>) out of a user's current avatar
        image URL. Returns None if the user has no avatar image set/visible."""
        url = getattr(user, "current_avatar_image_url", None)
        if not url:
            return None
        match = re.search(r"file_([a-f0-9-]+)", url)
        return f"id_{match.group(1)}" if match else None

    def get_existing_block_ids(self) -> set:
        try:
            api = playermoderation_api.PlayerModerationApi(self.api_client)
            moderations = api.get_player_moderations(type=PlayerModerationType.BLOCK)
            return {m.target_user_id for m in moderations}
        except Exception as e:
            raise _wrap(e)

    def block_user(self, user_id: str):
        try:
            api = playermoderation_api.PlayerModerationApi(self.api_client)
            api.moderate_user(
                ModerateUserRequest(moderated=user_id, type=PlayerModerationType.BLOCK)
            )
        except Exception as e:
            raise _wrap(e)

    def unblock_user(self, user_id: str):
        try:
            api = playermoderation_api.PlayerModerationApi(self.api_client)
            api.unmoderate_user(
                ModerateUserRequest(moderated=user_id, type=PlayerModerationType.BLOCK)
            )
        except Exception as e:
            raise _wrap(e)
