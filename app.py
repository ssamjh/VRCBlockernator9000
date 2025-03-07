import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import json
import base64
import threading
import time
import pickle
import vrchatapi
from vrchatapi.api import authentication_api, worlds_api, users_api
from vrchatapi.exceptions import UnauthorizedException
from vrchatapi.models.two_factor_auth_code import TwoFactorAuthCode
from vrchatapi.models.two_factor_email_code import TwoFactorEmailCode
import re
import glob


class ToolTip:
    """Create a tooltip for a given widget"""

    def __init__(self, widget, text=""):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<Motion>", self.motion)

    def enter(self, event=None):
        """Display the tooltip when mouse enters widget"""
        self.schedule()

    def leave(self, event=None):
        """Hide the tooltip when mouse leaves widget"""
        self.unschedule()
        self.hidetip()

    def motion(self, event=None):
        """Update position when mouse moves"""
        self.x, self.y = event.x, event.y
        if self.tipwindow:
            self.hidetip()
            self.schedule()

    def schedule(self):
        """Schedule showing the tooltip"""
        self.unschedule()
        self.id = self.widget.after(500, self.showtip)

    def unschedule(self):
        """Unschedule showing the tooltip"""
        if self.id:
            self.widget.after_cancel(self.id)
            self.id = None

    def showtip(self):
        """Display text in tooltip window"""
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + self.x + 20
        y = self.widget.winfo_rooty() + self.y + 10
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#ffffe0",
            relief=tk.SOLID,
            borderwidth=1,
            wraplength=250,
        )
        label.pack(ipadx=1)

    def hidetip(self):
        """Hide the tooltip"""
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()


class VRChatTrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VRChat Instance Tracker")
        self.root.geometry("600x500")
        self.root.resizable(True, True)

        self.api_client = None
        self.current_user = None
        self.tracking = False
        self.tracking_thread = None
        self.credentials_file = "vrc_credentials.json"
        self.cookies_file = "vrc_cookies.pkl"
        self.auth_token_file = "vrc_auth_token.json"  # New file for auth tokens

        # Auth token storage
        self.auth_token = None
        self.auth_token_expiry = None

        self.setup_ui()
        self.load_credentials()
        # First try to restore from auth token, then fall back to cookies
        if not self.try_restore_from_token():
            self.try_restore_session()

        self.tooltips = []
        self.setup_tooltips()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="10")
        login_frame.pack(fill=tk.X, pady=5)

        ttk.Label(login_frame, text="Username:").grid(
            row=0, column=0, sticky=tk.W, pady=2
        )
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var, width=30).grid(
            row=0, column=1, sticky=tk.W, pady=2
        )

        ttk.Label(login_frame, text="Password:").grid(
            row=1, column=0, sticky=tk.W, pady=2
        )
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=30).grid(
            row=1, column=1, sticky=tk.W, pady=2
        )

        self.remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            login_frame, text="Remember credentials", variable=self.remember_var
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)

        buttons_frame = ttk.Frame(login_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Button(buttons_frame, text="Login", command=self.login).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(buttons_frame, text="Logout", command=self.logout).pack(
            side=tk.LEFT, padx=5
        )

        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)

        self.status_var = tk.StringVar(value="Not logged in")
        ttk.Label(status_frame, textvariable=self.status_var).pack(anchor=tk.W)

        # Tracking frame
        tracking_frame = ttk.LabelFrame(
            main_frame, text="Instance Tracking", padding="10"
        )
        tracking_frame.pack(fill=tk.X, pady=5)

        self.track_button = ttk.Button(
            tracking_frame, text="Start Tracking", command=self.toggle_tracking
        )
        self.track_button.pack(fill=tk.X, pady=5)
        self.track_button["state"] = "disabled"

        # Current instance frame
        instance_frame = ttk.LabelFrame(
            main_frame, text="Current Instance", padding="10"
        )
        instance_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.instance_var = tk.StringVar(value="Not tracking")
        ttk.Label(instance_frame, textvariable=self.instance_var).pack(anchor=tk.W)

        # Members list
        ttk.Label(instance_frame, text="Users in Instance:").pack(
            anchor=tk.W, pady=(10, 5)
        )

        # Create a frame with scrollbar for the members list
        members_frame = ttk.Frame(instance_frame)
        members_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(members_frame, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.members_list = tk.Listbox(
            members_frame, height=10, yscrollcommand=scrollbar.set
        )
        self.members_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=self.members_list.yview)

        # Add a debug button to test log parsing (add near the bottom of setup_ui)
        debug_button = ttk.Button(
            instance_frame, text="Debug: Test Log Parsing", command=self.test_parse_log
        )
        debug_button.pack(pady=5)

    def encode_password(self, password):
        return base64.b64encode(password.encode()).decode()

    def decode_password(self, encoded):
        return base64.b64decode(encoded.encode()).decode()

    def save_credentials(self):
        if (
            self.remember_var.get()
            and self.username_var.get()
            and self.password_var.get()
        ):
            data = {
                "username": self.username_var.get(),
                "password": self.encode_password(self.password_var.get()),
            }
            with open(self.credentials_file, "w") as f:
                json.dump(data, f)
        else:
            # Remove the credentials file if it exists
            if os.path.exists(self.credentials_file):
                os.remove(self.credentials_file)

    def load_credentials(self):
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, "r") as f:
                    data = json.load(f)
                self.username_var.set(data.get("username", ""))
                self.password_var.set(self.decode_password(data.get("password", "")))
                self.remember_var.set(True)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load credentials: {str(e)}")

    def extract_auth_cookies(self):
        """Extract auth cookies from the API client"""
        if (
            self.api_client
            and hasattr(self.api_client, "rest_client")
            and hasattr(self.api_client.rest_client, "cookie_jar")
        ):
            try:
                cookie_jar = self.api_client.rest_client.cookie_jar._cookies.get(
                    "api.vrchat.cloud", {}
                ).get("/", {})
                auth_cookie = cookie_jar.get("auth")
                tfa_cookie = cookie_jar.get("twoFactorAuth")

                if auth_cookie:
                    return {
                        "auth": auth_cookie.value,
                        "twoFactorAuth": tfa_cookie.value if tfa_cookie else None,
                    }
            except Exception as e:
                print(f"Error extracting auth cookies: {str(e)}")
        return None

    def save_auth_cookies(self):
        """Save the authentication cookies for long-term use"""
        if not self.remember_var.get():
            return

        cookies = self.extract_auth_cookies()
        if cookies:
            try:
                # Set expiry to 30 days from now
                expiry = time.time() + (30 * 24 * 60 * 60)

                data = {
                    "auth": cookies["auth"],
                    "twoFactorAuth": cookies["twoFactorAuth"],
                    "username": self.username_var.get(),
                    "expiry": expiry,
                    "timestamp": time.time(),
                }

                with open(self.auth_token_file, "w") as f:
                    json.dump(data, f)

                print("Auth cookies saved successfully")
            except Exception as e:
                print(f"Error saving auth cookies: {str(e)}")

    def try_restore_from_token(self):
        """Try to restore session from saved auth cookies"""
        if not os.path.exists(self.auth_token_file):
            return False

        try:
            with open(self.auth_token_file, "r") as f:
                data = json.load(f)

            auth = data.get("auth")
            tfa = data.get("twoFactorAuth")
            username = data.get("username")
            expiry = data.get("expiry", 0)

            # Check if token is expired
            if expiry < time.time():
                print("Auth token expired")
                os.remove(self.auth_token_file)
                return False

            # Check if username matches
            if username != self.username_var.get():
                print("Username does not match saved token")
                return False

            # Create configuration
            configuration = vrchatapi.Configuration(username=self.username_var.get())

            # Create API client
            self.api_client = vrchatapi.ApiClient(configuration)
            self.api_client.user_agent = "VRChatInstanceTracker/1.0.0"

            # Set auth cookies properly
            from http.cookiejar import Cookie

            def make_cookie(name, value):
                return Cookie(
                    0,
                    name,
                    value,
                    None,
                    False,
                    "api.vrchat.cloud",
                    True,
                    False,
                    "/",
                    False,
                    False,
                    int(expiry),
                    False,
                    None,
                    None,
                    {},
                )

            self.api_client.rest_client.cookie_jar.set_cookie(make_cookie("auth", auth))
            if tfa:
                self.api_client.rest_client.cookie_jar.set_cookie(
                    make_cookie("twoFactorAuth", tfa)
                )

            self.status_var.set("Restoring session from token...")
            self.root.update()

            # Verify in separate thread
            threading.Thread(target=self._verify_restored_session, daemon=True).start()

            return True
        except Exception as e:
            print(f"Error restoring from token: {str(e)}")
            if os.path.exists(self.auth_token_file):
                os.remove(self.auth_token_file)
            return False

    def save_cookies(self):
        """Save the API client cookies to a file"""
        if (
            self.api_client
            and hasattr(self.api_client, "cookie")
            and self.remember_var.get()
        ):
            try:
                # Save auth token first (preferred method)
                self.save_auth_token()

                # Also save full cookies as backup
                with open(self.cookies_file, "wb") as f:
                    # Save both the cookies and username, add a timestamp
                    cookie_data = {
                        "cookies": self.api_client.cookie,
                        "username": self.username_var.get(),
                        "timestamp": time.time(),
                        # Store up to 90 days
                        "expiry": time.time() + (90 * 24 * 60 * 60),
                    }
                    pickle.dump(cookie_data, f)
            except Exception as e:
                print(f"Error saving cookies: {str(e)}")

    def try_restore_session(self):
        """Try to restore a previous session using saved cookies"""
        if os.path.exists(self.cookies_file):
            try:
                with open(self.cookies_file, "rb") as f:
                    cookie_data = pickle.load(f)

                # Check if cookie is not too old (90 days max)
                current_time = time.time()
                saved_time = cookie_data.get("timestamp", 0)
                expiry = cookie_data.get("expiry", saved_time + (90 * 24 * 60 * 60))

                if current_time > expiry:
                    # Delete the expired cookie file
                    os.remove(self.cookies_file)
                    print("Cookies expired, deleted old file")
                    return False

                # Check if username matches
                if cookie_data.get("username") == self.username_var.get():
                    # Create a configuration with username and password for fallback auth
                    configuration = vrchatapi.Configuration(
                        username=self.username_var.get(),
                    )
                    if self.password_var.get():
                        configuration.password = self.password_var.get()

                    # Create API client and set the cookies
                    self.api_client = vrchatapi.ApiClient(configuration)
                    self.api_client.user_agent = "VRChatInstanceTracker/1.0.0"
                    self.api_client.cookie = cookie_data.get("cookies")

                    # Try to get current user with the restored session
                    self.status_var.set("Restoring session...")
                    self.root.update()

                    # Try to verify the session in a separate thread
                    threading.Thread(
                        target=self._verify_restored_session, daemon=True
                    ).start()
                    return True
            except Exception as e:
                print(f"Error restoring session: {str(e)}")
                # Delete the corrupted cookie file
                if os.path.exists(self.cookies_file):
                    os.remove(self.cookies_file)

        return False

    def _verify_restored_session(self):
        """Verify if the restored session is valid"""
        try:
            auth_api = authentication_api.AuthenticationApi(self.api_client)
            self.current_user = auth_api.get_current_user()
            self.root.after(0, self._login_success)
            # Update cookies after successful verification
            self.save_auth_cookies()
            return True
        except Exception as e:
            print(f"Session restoration failed: {str(e)}")

            # Try to login again with stored password if available
            if self.password_var.get():
                self.root.after(
                    0,
                    lambda: self.status_var.set(
                        "Session expired, trying to login with saved credentials..."
                    ),
                )
                configuration = vrchatapi.Configuration(
                    username=self.username_var.get(),
                    password=self.password_var.get(),
                )
                # Try to log in again
                self.root.after(0, lambda: self._login(configuration))
            else:
                self.root.after(
                    0,
                    lambda: self.status_var.set("Session expired, please login again"),
                )
                self.api_client = None

            # Delete the invalid files
            if os.path.exists(self.cookies_file):
                os.remove(self.cookies_file)
            if os.path.exists(self.auth_token_file):
                os.remove(self.auth_token_file)

            return False

    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return

        # Save credentials if remember is checked
        if self.remember_var.get():
            self.save_credentials()

        # Create configuration
        configuration = vrchatapi.Configuration(
            username=username,
            password=password,
        )

        self.status_var.set("Logging in...")
        self.root.update()

        # Login in a separate thread to avoid freezing the UI
        threading.Thread(target=self._login, args=(configuration,), daemon=True).start()

    def logout(self):
        """Logout and clear session data"""
        if self.tracking:
            self.stop_tracking()

        if self.api_client:
            try:
                auth_api = authentication_api.AuthenticationApi(self.api_client)
                auth_api.logout()
            except Exception:
                pass  # Ignore errors on logout

        self.api_client = None
        self.current_user = None
        self.status_var.set("Not logged in")
        self.track_button["state"] = "disabled"

        # Delete session files
        if os.path.exists(self.cookies_file):
            os.remove(self.cookies_file)
        if os.path.exists(self.auth_token_file):
            os.remove(self.auth_token_file)

        messagebox.showinfo("Logout", "You have been logged out")

    def _login(self, configuration):
        try:
            # Create API client
            self.api_client = vrchatapi.ApiClient(configuration)
            self.api_client.user_agent = "VRChatInstanceTracker/1.0.0"

            # Create API instances
            auth_api = authentication_api.AuthenticationApi(self.api_client)

            try:
                # Try to login
                self.current_user = auth_api.get_current_user()
                # Save cookies after successful login
                self.save_auth_cookies()
                self.root.after(0, self._login_success)
            except UnauthorizedException as e:
                if e.status == 200:
                    if "Email 2 Factor Authentication" in e.reason:
                        # Handle email 2FA
                        self.root.after(0, self._handle_email_2fa, auth_api)
                    elif "2 Factor Authentication" in e.reason:
                        # Handle regular 2FA
                        self.root.after(0, self._handle_2fa, auth_api)
                else:
                    self.root.after(0, self._login_failed, f"Login failed: {e.reason}")
            except Exception as e:
                self.root.after(0, self._login_failed, f"Login failed: {str(e)}")
        except Exception as e:
            self.root.after(0, self._login_failed, f"Login failed: {str(e)}")

    def _handle_email_2fa(self, auth_api):
        code = simpledialog.askstring(
            "2FA Required", "Email 2FA Code:", parent=self.root
        )
        if code:
            try:
                auth_api.verify2_fa_email_code(
                    two_factor_email_code=TwoFactorEmailCode(code)
                )
                self.current_user = auth_api.get_current_user()
                # Save cookies after successful 2FA
                self.save_auth_cookies()
                self._login_success()
            except Exception as e:
                self._login_failed(f"2FA verification failed: {str(e)}")
        else:
            self._login_failed("2FA code required")

    def _handle_2fa(self, auth_api):
        code = simpledialog.askstring("2FA Required", "2FA Code:", parent=self.root)
        if code:
            try:
                auth_api.verify2_fa(two_factor_auth_code=TwoFactorAuthCode(code))
                self.current_user = auth_api.get_current_user()
                # Save cookies after successful 2FA
                self.save_auth_cookies()
                self._login_success()
            except Exception as e:
                self._login_failed(f"2FA verification failed: {str(e)}")
        else:
            self._login_failed("2FA code required")

    def _login_success(self):
        self.status_var.set(f"Logged in as: {self.current_user.display_name}")
        self.track_button["state"] = "normal"
        messagebox.showinfo("Success", f"Logged in as {self.current_user.display_name}")

    def _login_failed(self, message):
        self.status_var.set("Not logged in")
        messagebox.showerror("Login Failed", message)

    def find_vrchat_log_file(self):
        """Find the most recent VRChat log file"""
        # Default log directory paths for different OSes
        if os.name == "nt":  # Windows
            log_dir = os.path.expandvars(
                r"%USERPROFILE%\AppData\LocalLow\VRChat\VRChat"
            )
        elif os.name == "posix":  # macOS/Linux
            log_dir = os.path.expanduser("~/.config/unity3d/VRChat/VRChat")
        else:
            self.debug_log(f"Unsupported OS: {os.name}")
            return None

        self.debug_log(f"Looking for VRChat logs in: {log_dir}")

        # Find the most recent log file
        try:
            log_files = glob.glob(os.path.join(log_dir, "output_log_*.txt"))
            if not log_files:
                self.debug_log("No log files found!")
                return None

            # Sort by modification time (most recent first)
            latest_log = max(log_files, key=os.path.getmtime)
            self.debug_log(f"Found log file: {latest_log}")
            return latest_log
        except Exception as e:
            self.debug_log(f"Error finding VRChat log file: {e}")
            return None

    def parse_users_from_log(self):
        """Parse VRChat log to extract users in the current instance"""
        self.debug_log(f"Parsing logs for current instance")
        log_file = self.find_vrchat_log_file()
        if not log_file:
            self.debug_log("No log file found, can't parse users")
            return []

        users = set()  # Use a set to avoid duplicates
        instance_pattern = re.compile(r"Joining or Creating Room: (.+)")
        user_pattern = re.compile(r"OnPlayerJoined\s+(.+)")
        leave_pattern = re.compile(r"OnPlayerLeft\s+(.+)")

        current_instance = None
        instance_users = {}  # Change to dict to store user_id with name

        try:
            self.debug_log(f"Analyzing log file: {log_file}")

            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

                # Find the last (most recent) instance join
                for line in reversed(lines):
                    instance_match = instance_pattern.search(line)
                    if instance_match:
                        current_instance = instance_match.group(1)
                        self.debug_log(
                            f"Found most recent instance: {current_instance}"
                        )
                        break

                if not current_instance:
                    self.debug_log("No instance found in logs")
                    return []

                # Now parse the log for users in this instance
                in_target_instance = False
                for line in lines:
                    # Check for instance change
                    instance_match = instance_pattern.search(line)
                    if instance_match:
                        found_instance = instance_match.group(1)
                        if found_instance == current_instance:
                            in_target_instance = True
                            # Reset user list when we find our target instance
                            instance_users = {}
                            self.debug_log(
                                f"Parsing users for instance: {current_instance}"
                            )
                        else:
                            # We found a different instance after our target instance
                            if in_target_instance:
                                break

                    # If we're not in the target instance, skip
                    if not in_target_instance:
                        continue

                    # Check for players joining
                    user_match = user_pattern.search(line)
                    if user_match:
                        full_username = user_match.group(1).strip()
                        # Extract user ID if present
                        user_id = None
                        username = full_username
                        id_match = re.search(r"\((usr_[a-f0-9-]+)\)", full_username)
                        if id_match:
                            user_id = id_match.group(1)
                            username = full_username.split("(usr_")[0].strip()

                        instance_users[username] = user_id
                        self.debug_log(
                            f"Found user in instance: {username} with ID: {user_id}"
                        )

                    # Check for players leaving
                    leave_match = leave_pattern.search(line)
                    if leave_match:
                        full_username = leave_match.group(1).strip()
                        # Extract username without ID
                        username = full_username
                        if "(usr_" in full_username:
                            username = full_username.split("(usr_")[0].strip()

                        if username in instance_users:
                            del instance_users[username]
                            self.debug_log(f"User left instance: {username}")

                self.debug_log(f"Found {len(instance_users)} users in current instance")
                # Return list of tuples with (name, id)
                return [(name, user_id) for name, user_id in instance_users.items()]
        except Exception as e:
            self.debug_log(f"Error parsing log file: {e}")
            import traceback

            self.debug_log(traceback.format_exc())
            return []

    def toggle_tracking(self):
        if not self.tracking:
            self.start_tracking()
        else:
            self.stop_tracking()

    def start_tracking(self):
        if not self.api_client or not self.current_user:
            messagebox.showerror("Error", "You must be logged in to track instances")
            return

        self.tracking = True
        self.track_button["text"] = "Stop Tracking"
        self.instance_var.set("Starting tracking...")

        # Start tracking in a separate thread
        self.tracking_thread = threading.Thread(
            target=self._track_instance, daemon=True
        )
        self.tracking_thread.start()

    def stop_tracking(self):
        self.tracking = False
        self.track_button["text"] = "Start Tracking"
        self.instance_var.set("Not tracking")
        self.members_list.delete(0, tk.END)

    def _track_instance(self):
        users_api_instance = users_api.UsersApi(self.api_client)
        refresh_count = 0

        while self.tracking:
            try:
                # Get current user to check current instance
                user = users_api_instance.get_user(self.current_user.id)

                # Periodic token refresh (every 4 hours of tracking)
                refresh_count += 1
                if refresh_count >= 8:  # 8 * 30 minutes = 4 hours
                    # Save the updated cookies/tokens to extend the session
                    self.save_auth_cookies()
                    self.save_auth_token()
                    refresh_count = 0

                # Update instance info
                if user.location:
                    location_parts = user.location.split(":")
                    if len(location_parts) >= 2:
                        world_id = location_parts[0]
                        instance_id = ":".join(location_parts[1:])

                        # Get world info if available
                        world_name = self._get_world_name(world_id)

                        instance_info = f"World: {world_name or world_id}\nInstance: {instance_id}\nLocation: {user.location}"
                        self.root.after(0, self._update_instance_info, instance_info)

                        # Get instance users
                        instance_users = self._get_instance_users(user.location)

                        # Update members list
                        self.root.after(0, self._update_members_list, instance_users)
                    else:
                        self.root.after(
                            0, self._update_instance_info, "Invalid location format"
                        )
                else:
                    self.root.after(
                        0, self._update_instance_info, "Not in any instance"
                    )
                    self.root.after(0, lambda: self.members_list.delete(0, tk.END))
            except Exception as e:
                self.root.after(0, self._update_instance_info, f"Error: {str(e)}")

                # Check if this is an authentication error and try to refresh session
                if "401" in str(e) or "Unauthorized" in str(e):
                    self.root.after(
                        0,
                        lambda: self.status_var.set(
                            "Session expired, attempting to refresh..."
                        ),
                    )

                    # Try different auth methods in sequence:
                    # 1. First try with the auth token if available
                    if self.auth_token:
                        try:
                            configuration = vrchatapi.Configuration(
                                username=self.username_var.get()
                            )
                            self.api_client = vrchatapi.ApiClient(configuration)
                            self.api_client.user_agent = "VRChatInstanceTracker/1.0.0"
                            self.api_client.cookie = f"auth={self.auth_token}"

                            auth_api = authentication_api.AuthenticationApi(
                                self.api_client
                            )
                            self.current_user = auth_api.get_current_user()

                            self.root.after(
                                0,
                                lambda: self.status_var.set(
                                    f"Session restored with token as: {self.current_user.display_name}"
                                ),
                            )
                            continue
                        except Exception:
                            # Token failed, try next method
                            pass

                    # 2. Try with saved password
                    if self.password_var.get():
                        try:
                            configuration = vrchatapi.Configuration(
                                username=self.username_var.get(),
                                password=self.password_var.get(),
                            )

                            self.api_client = vrchatapi.ApiClient(configuration)
                            self.api_client.user_agent = "VRChatInstanceTracker/1.0.0"

                            auth_api = authentication_api.AuthenticationApi(
                                self.api_client
                            )
                            self.current_user = auth_api.get_current_user()

                            # Save new cookies and token
                            self.save_auth_cookies()
                            self.save_auth_token()

                            self.root.after(
                                0,
                                lambda: self.status_var.set(
                                    f"Session refreshed as: {self.current_user.display_name}"
                                ),
                            )
                            continue
                        except Exception as login_err:
                            print(f"Auto re-login failed: {str(login_err)}")

                    # All methods failed
                    self.root.after(0, self.stop_tracking)
                    self.root.after(
                        0,
                        lambda: self.status_var.set(
                            "Session expired, please login again"
                        ),
                    )
                    break

            # Wait before checking again
            time.sleep(30)  # Check every 30 seconds

    def _get_world_name(self, world_id):
        try:
            worlds_api_instance = worlds_api.WorldsApi(self.api_client)
            world = worlds_api_instance.get_world(world_id)
            return world.name
        except Exception:
            return None

    def _get_instance_users(self, location):
        """Get users in the current instance"""
        self.debug_log(f"Getting users for location: {location}")

        # Get users in the same instance using friends API
        friends_api = vrchatapi.api.friends_api.FriendsApi(self.api_client)
        instance_users = []

        try:
            # First add the current user
            self.debug_log(f"Adding self: {self.current_user.display_name}")
            instance_users.append(
                {
                    "display_name": self.current_user.display_name,
                    "user_id": self.current_user.id,
                    "status": "Self",
                    "is_self": True,
                    "is_friend": True,
                }
            )

            # Get online friends
            self.debug_log("Getting online friends...")
            friends = friends_api.get_friends(offline=False)
            self.debug_log(f"Found {len(friends)} online friends")

            # Get friend display names for later comparison
            friend_names = {
                friend.display_name
                for friend in friends
                if friend.location and friend.location == location
            }
            friend_names.add(self.current_user.display_name)  # Add self to friend names
            self.debug_log(f"Friends in this instance: {friend_names}")

            # Check which friends are in the same instance
            friends_in_instance = 0
            for friend in friends:
                if friend.location and friend.location == location:
                    friends_in_instance += 1
                    instance_users.append(
                        {
                            "display_name": friend.display_name,
                            "user_id": friend.id,
                            "status": friend.status,
                            "is_self": False,
                            "is_friend": True,
                        }
                    )
            self.debug_log(f"Added {friends_in_instance} friends from API")

            # Parse log file for additional users
            log_users = self.parse_users_from_log()
            self.debug_log(f"Found {len(log_users)} users in log")

            log_users_added = 0
            for username, user_id in log_users:
                # Skip if already added (self or friend)
                if username in friend_names:
                    self.debug_log(f"Skipping {username} (already in friends list)")
                    continue

                log_users_added += 1
                instance_users.append(
                    {
                        "display_name": username,
                        "user_id": user_id,
                        "status": "In Instance",
                        "is_self": False,
                        "is_friend": False,
                    }
                )
            self.debug_log(f"Added {log_users_added} additional users from logs")
            self.debug_log(f"Total users in instance: {len(instance_users)}")

        except Exception as e:
            self.debug_log(f"Error getting instance users: {str(e)}")
            import traceback

            self.debug_log(traceback.format_exc())

        return instance_users

    def _update_instance_info(self, info):
        self.instance_var.set(info)

    def _update_members_list(self, members):
        self.debug_log(f"Updating members list with {len(members)} users")
        self.members_list.delete(0, tk.END)
        
        # Store members data for tooltips
        self.members_data = members

        # Clear existing tooltips
        if hasattr(self, "tooltips"):
            for tooltip in self.tooltips:
                tooltip.hidetip()
        self.tooltips = []

        if not members:
            self.debug_log("No members to display")
            self.members_list.insert(tk.END, "No users found in this instance")
        else:
            # Sort members: self first, then friends, then others
            sorted_members = sorted(
                members,
                key=lambda x: (
                    0
                    if x.get("is_self", False)
                    else (1 if x.get("is_friend", False) else 2)
                ),
            )

            for member in sorted_members:
                if member.get("is_self"):
                    prefix = "👤 "  # Self
                    self.debug_log(f"Adding self user: {member['display_name']}")
                elif member.get("is_friend", False):
                    prefix = "👥 "  # Friend
                    self.debug_log(f"Adding friend: {member['display_name']}")
                else:
                    prefix = "🧍 "  # Other user from logs
                    self.debug_log(f"Adding other user: {member['display_name']}")

                display_text = f"{prefix}{member['display_name']} ({member['status']})"
                self.members_list.insert(tk.END, display_text)

                # Create tooltip with user ID if available
                if "user_id" in member and member["user_id"]:
                    index = self.members_list.size() - 1
                    tooltip_text = f"User ID: {member['user_id']}"
                    # Create tooltip using itemcget to get the list item
                    self.members_list.itemconfig(
                        index, bg=self.members_list.cget("bg")
                    )  # Ensure background color

                    # Since we can't directly bind to list items, we need to use event detection in the main list
                    # We'll need to track which item is currently hovered
                    self.tooltips.append(ToolTip(self.members_list, tooltip_text))

    def setup_tooltips(self):
        """Set up event handling for list item tooltips"""
        self.list_tooltips = {}  # Map of index -> tooltip
        self.active_tooltip = None
        
        # Bind mouse movement to monitor which list item is under the cursor
        self.members_list.bind("<Motion>", self.update_list_tooltip)
        
    def update_list_tooltip(self, event):
        """Update tooltip based on which list item is under the cursor"""
        if not hasattr(self, 'members_data'):
            return
            
        # Get the item index under the cursor
        index = self.members_list.nearest(event.y)
        if 0 <= index < len(self.members_data):
            member = self.members_data[index]
            if 'user_id' in member and member['user_id']:
                if self.active_tooltip is None:
                    self.active_tooltip = ToolTip(self.members_list, f"User ID: {member['user_id']}")
                else:
                    self.active_tooltip.text = f"User ID: {member['user_id']}"
                    self.active_tooltip.showtip()
        else:
            if self.active_tooltip:
                self.active_tooltip.hidetip()

    def debug_log(self, message):
        """Print debug messages to console with timestamp"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        print(f"[DEBUG {timestamp}] {message}")

    def test_parse_log(self):
        """Test function to manually check log file and parsing"""
        self.debug_log("=== TESTING LOG PARSING ===")
        log_file = self.find_vrchat_log_file()

        if not log_file:
            self.debug_log("No log file found!")
            return

        self.debug_log(f"Analyzing log file: {log_file}")

        # Look for all instances and users mentioned in the log
        instance_pattern = re.compile(r"Joining or Creating Room: (.+)")
        user_pattern = re.compile(r"OnPlayerJoined\s+(.+)")

        instances = []
        users = {}

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                current_instance = None
                for i, line in enumerate(f):
                    if i % 10000 == 0:
                        self.debug_log(f"Processing line {i}...")

                    # Check for instance references
                    instance_match = instance_pattern.search(line)
                    if instance_match:
                        current_instance = instance_match.group(1)
                        instances.append(current_instance)
                        users[current_instance] = set()
                        self.debug_log(f"Found instance: {current_instance}")

                    # Check for user join events
                    if current_instance:
                        user_match = user_pattern.search(line)
                        if user_match:
                            username = user_match.group(1).strip()
                            users[current_instance].add(username)

            self.debug_log(f"Found {len(instances)} instances in log:")
            for idx, instance in enumerate(instances):
                user_count = len(users.get(instance, []))
                self.debug_log(f"{idx+1}. Instance: '{instance}' ({user_count} users)")
                if user_count > 0:
                    self.debug_log(f"   Users: {', '.join(users.get(instance, []))}")

        except Exception as e:
            self.debug_log(f"Error in test parse: {str(e)}")
            import traceback

            self.debug_log(traceback.format_exc())


if __name__ == "__main__":
    root = tk.Tk()
    app = VRChatTrackerApp(root)
    root.mainloop()
