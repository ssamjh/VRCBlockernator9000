import json
import os
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, simpledialog, ttk

import avatar_hash
from auto_block import AutoBlockEngine, AvatarBlockList, AvatarNameBlockList, ProcessedCache
from log_tail import AvatarChanged, LogTailer, PlayerJoined, PlayerLeft, RoomChanged
from vrc_client import LoginResult, VrcApiError, VrcClient
from vrc_session import SessionStore

SETTINGS_FILE = "settings.json"
ACTIVITY_LOG_FILE = "activity_log.txt"

SELF_LOCATION_POLL_SECONDS = 30
FRIEND_REFRESH_SECONDS = 10 * 60
TICK_SECONDS = 1


def load_settings() -> dict:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"auto_block_enabled": False}


def save_settings(settings: dict):
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f)
    except Exception:
        pass


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("VRCBlockernator9000")
        self.root.geometry("640x560")
        self.root.resizable(True, True)

        self.client = VrcClient()
        self.session_store = SessionStore()
        self.cache = ProcessedCache()
        self.avatar_blocklist = AvatarBlockList()
        self.avatar_name_blocklist = AvatarNameBlockList()
        self.engine = AutoBlockEngine(
            self.client, self.cache, self.avatar_blocklist, self.avatar_name_blocklist
        )
        self.log_tailer = LogTailer()

        settings = load_settings()
        self.engine.enabled = bool(settings.get("auto_block_enabled", False))

        self.tracking = False
        self.tracking_thread = None
        self._refresh_friends_now = threading.Event()
        self._pending_2fa_kind = None
        self._members = {}  # user_id -> {"name": str, "is_self": bool}
        self._avatar_names = {}  # user_id -> last-known avatar name (from log)

        self._setup_ui()
        self._try_restore_session()

    # -- UI construction ---------------------------------------------------

    def _setup_ui(self):
        main = ttk.Frame(self.root, padding="10")
        main.pack(fill=tk.BOTH, expand=True)

        login_frame = ttk.LabelFrame(main, text="Login", padding="10")
        login_frame.pack(fill=tk.X, pady=5)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var, width=30).grid(
            row=0, column=1, sticky=tk.W, pady=2
        )

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*", width=30).grid(
            row=1, column=1, sticky=tk.W, pady=2
        )

        buttons = ttk.Frame(login_frame)
        buttons.grid(row=2, column=0, columnspan=2, pady=5)
        ttk.Button(buttons, text="Login", command=self._on_login_click).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons, text="Logout", command=self._on_logout_click).pack(side=tk.LEFT, padx=5)

        status_frame = ttk.LabelFrame(main, text="Status", padding="10")
        status_frame.pack(fill=tk.X, pady=5)
        self.status_var = tk.StringVar(value="Not logged in")
        ttk.Label(status_frame, textvariable=self.status_var).pack(anchor=tk.W)
        self.instance_var = tk.StringVar(value="Not tracking")
        ttk.Label(status_frame, textvariable=self.instance_var).pack(anchor=tk.W)

        control_frame = ttk.LabelFrame(main, text="Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=5)

        self.track_button = ttk.Button(
            control_frame, text="Start Tracking", command=self._toggle_tracking, state="disabled"
        )
        self.track_button.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)

        self.auto_block_var = tk.BooleanVar(value=self.engine.enabled)
        ttk.Checkbutton(
            control_frame,
            text="Auto-Block Enabled (blocks non-friend Visitors automatically)",
            variable=self.auto_block_var,
            command=self._on_auto_block_toggle,
        ).grid(row=0, column=1, padx=15, pady=2, sticky=tk.W)

        ttk.Button(
            control_frame, text="Refresh Friends Now", command=self._on_refresh_friends_click
        ).grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)

        avatar_frame = ttk.LabelFrame(
            main, text="Blocklisted Avatars (auto-blocks non-friends wearing these)", padding="10"
        )
        avatar_frame.pack(fill=tk.X, pady=5)

        avatar_entry_row = ttk.Frame(avatar_frame)
        avatar_entry_row.pack(fill=tk.X)
        self.avatar_id_var = tk.StringVar()
        ttk.Entry(avatar_entry_row, textvariable=self.avatar_id_var, width=45).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        ttk.Button(avatar_entry_row, text="Add", command=self._on_add_avatar_click).pack(side=tk.LEFT)
        ttk.Button(avatar_entry_row, text="Remove Selected", command=self._on_remove_avatar_click).pack(
            side=tk.LEFT, padx=5
        )

        self.avatar_blocklist_widget = tk.Listbox(avatar_frame, height=4)
        self.avatar_blocklist_widget.pack(fill=tk.X, pady=(5, 0))
        self._refresh_avatar_blocklist_widget()

        avatar_name_frame = ttk.LabelFrame(
            main,
            text="Blocklisted Avatar Names (weaker match, but works even when ID/image are hidden)",
            padding="10",
        )
        avatar_name_frame.pack(fill=tk.X, pady=5)

        avatar_name_entry_row = ttk.Frame(avatar_name_frame)
        avatar_name_entry_row.pack(fill=tk.X)
        self.avatar_name_var = tk.StringVar()
        ttk.Entry(avatar_name_entry_row, textvariable=self.avatar_name_var, width=45).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        ttk.Button(avatar_name_entry_row, text="Add", command=self._on_add_avatar_name_click).pack(
            side=tk.LEFT
        )
        ttk.Button(
            avatar_name_entry_row, text="Remove Selected", command=self._on_remove_avatar_name_click
        ).pack(side=tk.LEFT, padx=5)

        self.avatar_name_blocklist_widget = tk.Listbox(avatar_name_frame, height=4)
        self.avatar_name_blocklist_widget.pack(fill=tk.X, pady=(5, 0))
        self._refresh_avatar_name_blocklist_widget()

        activity_frame = ttk.LabelFrame(main, text="Activity Log", padding="10")
        activity_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=14, state="disabled")
        self.activity_text.pack(fill=tk.BOTH, expand=True)

        members_frame = ttk.LabelFrame(main, text="Users in Instance (double-click for details)", padding="10")
        members_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.members_list = tk.Listbox(members_frame, height=6)
        self.members_list.pack(fill=tk.BOTH, expand=True)
        self.members_list.bind("<Double-1>", self._on_member_double_click)

    # -- logging -------------------------------------------------------------

    def log(self, message: str):
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        self.activity_text.configure(state="normal")
        self.activity_text.insert(tk.END, line + "\n")
        self.activity_text.see(tk.END)
        self.activity_text.configure(state="disabled")
        try:
            with open(ACTIVITY_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def _log_threadsafe(self, message: str):
        self.root.after(0, self.log, message)

    # -- auth ----------------------------------------------------------------

    def _try_restore_session(self):
        session = self.session_store.load()
        if not session:
            return
        self.username_var.set(session.username)
        self.status_var.set("Restoring session...")

        def worker():
            ok = self.client.restore_session(session)
            if ok:
                self.root.after(0, self._on_login_success)
            else:
                self.session_store.clear()
                self.root.after(0, lambda: self.status_var.set("Session expired, please log in"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_login_click(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return

        self.status_var.set("Logging in...")
        threading.Thread(target=self._login_worker, args=(username, password), daemon=True).start()

    def _login_worker(self, username, password):
        try:
            result = self.client.login(username, password)
        except VrcApiError as e:
            self.root.after(0, self._on_login_failed, str(e))
            return

        if result == LoginResult.OK:
            self.root.after(0, self._on_login_success)
        else:
            self._pending_2fa_kind = result
            self.root.after(0, self._prompt_2fa)

    def _prompt_2fa(self):
        prompt = "Email 2FA Code:" if self._pending_2fa_kind == LoginResult.NEEDS_EMAIL_2FA else "2FA Code:"
        code = simpledialog.askstring("2FA Required", prompt, parent=self.root)
        if not code:
            self._on_login_failed("2FA code required")
            return
        threading.Thread(target=self._submit_2fa_worker, args=(code,), daemon=True).start()

    def _submit_2fa_worker(self, code):
        try:
            self.client.submit_2fa(code, self._pending_2fa_kind)
            self.root.after(0, self._on_login_success)
        except VrcApiError as e:
            self.root.after(0, self._on_login_failed, f"2FA failed: {e}")

    def _on_login_success(self):
        self.status_var.set(f"Logged in as: {self.client.current_user.display_name}")
        self.track_button["state"] = "normal"

        session = self.client.extract_session()
        if session:
            self.session_store.save(session)

        self.log(f"Logged in as {self.client.current_user.display_name}")
        self._start_background_setup()
        self._start_tracking()

    def _on_login_failed(self, message):
        self.status_var.set("Not logged in")
        messagebox.showerror("Login Failed", message)

    def _on_logout_click(self):
        self._stop_tracking()
        self.client.logout()
        self.session_store.clear()
        self.status_var.set("Not logged in")
        self.track_button["state"] = "disabled"
        messagebox.showinfo("Logout", "You have been logged out")

    def _start_background_setup(self):
        def worker():
            try:
                self.engine.seed_from_existing_moderations()
                self.engine.refresh_friends(force=True)
                self._log_threadsafe(f"Loaded {len(self.engine.friend_ids)} friends")
            except VrcApiError as e:
                self._log_threadsafe(f"Startup sync failed: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # -- auto-block toggle -----------------------------------------------------

    def _on_auto_block_toggle(self):
        self.engine.enabled = self.auto_block_var.get()
        save_settings({"auto_block_enabled": self.engine.enabled})
        self.log(f"Auto-block {'ENABLED' if self.engine.enabled else 'disabled'}")

    def _on_refresh_friends_click(self):
        self._refresh_friends_now.set()

    # -- avatar blocklist -------------------------------------------------------

    def _refresh_avatar_blocklist_widget(self):
        self.avatar_blocklist_widget.delete(0, tk.END)
        for key, info in sorted(self.avatar_blocklist.items().items()):
            note = info.get("note")
            label = f"{key} - {note}" if note else key
            if info.get("phash"):
                label += " [image match]"
            self.avatar_blocklist_widget.insert(tk.END, label)

    def _on_add_avatar_click(self):
        avatar_id = self.avatar_id_var.get().strip()
        if not avatar_id:
            return
        if not avatar_id.startswith("id_"):
            messagebox.showerror(
                "Invalid Avatar ID",
                "Expected an avatar file ID in the form 'id_<uuid>' - this is what gets matched "
                "against a joining user's current avatar. You can grab one from the user detail "
                "popup (double-click a user) via its 'Add Avatar to Block List' button.",
            )
            return
        self.avatar_blocklist.add(avatar_id)
        self.avatar_id_var.set("")
        self._refresh_avatar_blocklist_widget()
        self.log(f"Added {avatar_id} to the avatar blocklist")

    def _on_remove_avatar_click(self):
        selection = self.avatar_blocklist_widget.curselection()
        if not selection:
            return
        label = self.avatar_blocklist_widget.get(selection[0])
        avatar_id = label.split(" - ")[0]
        self.avatar_blocklist.remove(avatar_id)
        self._refresh_avatar_blocklist_widget()
        self.log(f"Removed {avatar_id} from the avatar blocklist")

    # -- avatar name blocklist ---------------------------------------------------

    def _refresh_avatar_name_blocklist_widget(self):
        self.avatar_name_blocklist_widget.delete(0, tk.END)
        for info in sorted(self.avatar_name_blocklist.items().values(), key=lambda e: e["display"]):
            note = info.get("note")
            label = f"{info['display']} - {note}" if note else info["display"]
            self.avatar_name_blocklist_widget.insert(tk.END, label)

    def _on_add_avatar_name_click(self):
        avatar_name = self.avatar_name_var.get().strip()
        if not avatar_name:
            return
        self.avatar_name_blocklist.add(avatar_name)
        self.avatar_name_var.set("")
        self._refresh_avatar_name_blocklist_widget()
        self.log(f"Added avatar name '{avatar_name}' to the blocklist")

    def _on_remove_avatar_name_click(self):
        selection = self.avatar_name_blocklist_widget.curselection()
        if not selection:
            return
        label = self.avatar_name_blocklist_widget.get(selection[0])
        avatar_name = label.split(" - ")[0]
        self.avatar_name_blocklist.remove(avatar_name)
        self._refresh_avatar_name_blocklist_widget()
        self.log(f"Removed avatar name '{avatar_name}' from the blocklist")

    # -- tracking thread -------------------------------------------------------

    def _toggle_tracking(self):
        if self.tracking:
            self._stop_tracking()
        else:
            self._start_tracking()

    def _start_tracking(self):
        if self.tracking or not self.client.api_client:
            return
        self.tracking = True
        self.track_button["text"] = "Stop Tracking"
        self.instance_var.set("Starting tracking...")
        self._last_location_poll = 0.0
        self._last_friend_refresh = 0.0
        self.tracking_thread = threading.Thread(target=self._tracking_loop, daemon=True)
        self.tracking_thread.start()

    def _stop_tracking(self):
        self.tracking = False
        self.track_button["text"] = "Start Tracking"
        self.instance_var.set("Not tracking")

    def _tracking_loop(self):
        while self.tracking:
            try:
                self._tick()
            except VrcApiError as e:
                if e.is_unauthorized:
                    if not self._handle_reauth():
                        break
                else:
                    self._log_threadsafe(f"API error: {e}")
            except Exception as e:
                self._log_threadsafe(f"Tracking error: {e}")

            time.sleep(TICK_SECONDS)

    def _tick(self):
        now = time.time()

        if self._refresh_friends_now.is_set() or now - self._last_friend_refresh >= FRIEND_REFRESH_SECONDS:
            self.engine.refresh_friends(force=self._refresh_friends_now.is_set())
            self._refresh_friends_now.clear()
            self._last_friend_refresh = now

        if now - self._last_location_poll >= SELF_LOCATION_POLL_SECONDS:
            self._poll_self_location()
            self._last_location_poll = now

        for event in self.log_tailer.poll():
            self._handle_log_event(event)

    def _poll_self_location(self):
        location = self.client.get_self_location()
        if not location:
            self.root.after(0, self.instance_var.set, "Not in any instance")
            return
        parts = location.split(":")
        world_id = parts[0]
        world_name = self.client.get_world_name(world_id) or world_id
        self.root.after(0, self.instance_var.set, f"World: {world_name}\nLocation: {location}")

    def _handle_log_event(self, event):
        if isinstance(event, RoomChanged):
            self._members.clear()
            self.root.after(0, self._refresh_members_widget)
            self._log_threadsafe(f"Joined instance: {event.room}")
            return

        if isinstance(event, PlayerLeft):
            self._members.pop(event.user_id, None)
            self.root.after(0, self._refresh_members_widget)
            return

        if isinstance(event, PlayerJoined):
            is_self = self.client.current_user and event.name == self.client.current_user.display_name
            self._members[event.user_id] = {"name": event.name, "is_self": is_self}
            self.root.after(0, self._refresh_members_widget)

            if is_self:
                return

            decision = self.engine.evaluate(event.user_id, event.name)
            line = self.engine.execute(decision, event.user_id, event.name)
            self._log_threadsafe(line)
            return

        if isinstance(event, AvatarChanged):
            user_id = self._find_user_id_by_name(event.name)
            if not user_id:
                return
            self._avatar_names[user_id] = event.avatar_name

            decision = self.engine.evaluate_avatar_name(user_id, event.name, event.avatar_name)
            if decision:
                line = self.engine.execute(decision, user_id, event.name)
                self._log_threadsafe(line)

    def _find_user_id_by_name(self, name: str):
        for user_id, info in self._members.items():
            if info["name"] == name:
                return user_id
        return None

    def _refresh_members_widget(self):
        self.members_list.delete(0, tk.END)
        self._listbox_ids = []
        sorted_members = sorted(
            self._members.items(),
            key=lambda kv: (0 if kv[1]["is_self"] else 1, kv[1]["name"]),
        )
        for user_id, info in sorted_members:
            prefix = "\U0001F464 " if info["is_self"] else "\U0001F9CD "
            self.members_list.insert(tk.END, f"{prefix}{info['name']} - {user_id}")
            self._listbox_ids.append(user_id)

    def _handle_reauth(self) -> bool:
        session = self.session_store.load()
        if session and self.client.restore_session(session):
            self._log_threadsafe("Session refreshed")
            return True

        self._log_threadsafe("Session expired, please log in again")
        self.root.after(0, self._on_session_expired)
        return False

    def _on_session_expired(self):
        self._stop_tracking()
        self.status_var.set("Session expired, please log in again")
        self.track_button["state"] = "disabled"

    # -- member detail popup -----------------------------------------------

    def _on_member_double_click(self, _event):
        selection = self.members_list.curselection()
        if not selection:
            return
        index = selection[0]
        if index >= len(getattr(self, "_listbox_ids", [])):
            return
        user_id = self._listbox_ids[index]
        threading.Thread(target=self._show_user_details_worker, args=(user_id,), daemon=True).start()

    def _show_user_details_worker(self, user_id):
        try:
            user = self.client.get_user(user_id)
            trust_rank = VrcClient.resolve_trust_rank(user)
            avatar_id = VrcClient.extract_avatar_id(user)
        except VrcApiError as e:
            self.root.after(0, messagebox.showerror, "Error", f"Failed to get user details: {e}")
            return
        thumbnail_url = getattr(user, "current_avatar_thumbnail_image_url", None)
        avatar_name = self._avatar_names.get(user_id)
        self.root.after(
            0, self._show_user_details_popup, user, trust_rank, avatar_id, thumbnail_url, avatar_name
        )

    def _show_user_details_popup(self, user, trust_rank, avatar_id, thumbnail_url, avatar_name):
        popup = tk.Toplevel(self.root)
        popup.title(f"User Details: {user.display_name}")
        popup.geometry("380x320")
        popup.transient(self.root)
        popup.grab_set()

        frame = ttk.Frame(popup, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="User Information", font=("TkDefaultFont", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(frame, text=f"Display Name: {user.display_name}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"User ID: {user.id}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Trust Rank: {trust_rank}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Status: {user.status}").pack(anchor=tk.W)
        is_friend = user.id in self.engine.friend_ids
        ttk.Label(frame, text=f"Friend: {'Yes' if is_friend else 'No'}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Current Avatar ID: {avatar_id or 'Unknown'}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Current Avatar Name (from log): {avatar_name or 'Not seen yet'}").pack(
            anchor=tk.W
        )

        ttk.Separator(frame).pack(fill=tk.X, pady=10)

        cached = self.cache.get(user.id)
        is_blocked = bool(cached and cached.get("action") == "blocked")
        block_btn = ttk.Button(frame, text="")
        block_btn.config(
            text="Unblock" if is_blocked else "Block",
            command=lambda: self._toggle_block(user.id, user.display_name, block_btn),
        )
        block_btn.pack(pady=5)

        avatar_btn = ttk.Button(frame, text="")
        if avatar_id:
            self._configure_avatar_button(avatar_btn, avatar_id, thumbnail_url, user.display_name)
        elif thumbnail_url:
            avatar_btn.config(
                text="Add Avatar to Block List (by image)",
                command=lambda: self._add_avatar_by_image(thumbnail_url, user.display_name, avatar_btn),
            )
        else:
            avatar_btn.config(text="No Avatar Info Available", state="disabled")
        avatar_btn.pack(pady=5)

        name_btn = ttk.Button(frame, text="")
        if avatar_name:
            self._configure_avatar_name_button(name_btn, avatar_name)
        else:
            name_btn.config(text="No Avatar Name Seen Yet", state="disabled")
        name_btn.pack(pady=5)

        ttk.Button(frame, text="Close", command=popup.destroy).pack(pady=5)

    def _configure_avatar_name_button(self, button, avatar_name):
        in_blocklist = self.avatar_name_blocklist.contains(avatar_name)
        button.config(
            text="Remove Avatar Name from Block List" if in_blocklist else "Block This Avatar Name",
            command=lambda: self._toggle_avatar_name_blocklist(avatar_name, button),
        )

    def _toggle_avatar_name_blocklist(self, avatar_name, button):
        if self.avatar_name_blocklist.contains(avatar_name):
            self.avatar_name_blocklist.remove(avatar_name)
            self.log(f"Removed avatar name '{avatar_name}' from the blocklist")
        else:
            self.avatar_name_blocklist.add(avatar_name)
            self.log(f"Added avatar name '{avatar_name}' to the blocklist")
        self._configure_avatar_name_button(button, avatar_name)
        self._refresh_avatar_name_blocklist_widget()

    def _configure_avatar_button(self, button, avatar_id, thumbnail_url, display_name):
        in_blocklist = self.avatar_blocklist.contains(avatar_id)
        button.config(
            text="Remove Avatar from Block List" if in_blocklist else "Add Avatar to Block List",
            command=lambda: self._toggle_avatar_blocklist(avatar_id, thumbnail_url, display_name, button),
        )

    def _toggle_avatar_blocklist(self, avatar_id, thumbnail_url, display_name, button):
        if self.avatar_blocklist.contains(avatar_id):
            self.avatar_blocklist.remove(avatar_id)
            self.log(f"Removed {avatar_id} from the avatar blocklist")
            self._configure_avatar_button(button, avatar_id, thumbnail_url, display_name)
            self._refresh_avatar_blocklist_widget()
            return

        # Adding: also grab a perceptual hash of the thumbnail in the background so
        # this entry still matches if the avatar gets re-uploaded under a new ID.
        button.config(state="disabled", text="Adding...")

        def worker():
            image_hash = avatar_hash.fetch_and_hash(thumbnail_url) if thumbnail_url else None
            phash = avatar_hash.hash_to_str(image_hash) if image_hash else None
            self.avatar_blocklist.add(avatar_id=avatar_id, note=display_name, phash=phash)
            self._log_threadsafe(f"Added {avatar_id} to the avatar blocklist")
            self.root.after(0, lambda: self._configure_avatar_button(button, avatar_id, thumbnail_url, display_name))
            self.root.after(0, self._refresh_avatar_blocklist_widget)

        threading.Thread(target=worker, daemon=True).start()

    def _add_avatar_by_image(self, thumbnail_url, display_name, button):
        button.config(state="disabled", text="Hashing image...")

        def worker():
            image_hash = avatar_hash.fetch_and_hash(thumbnail_url)
            if not image_hash:
                self.root.after(
                    0, messagebox.showerror, "Error", "Could not fetch/hash this avatar's thumbnail image."
                )
                self.root.after(0, lambda: button.config(state="normal", text="Add Avatar to Block List (by image)"))
                return
            self.avatar_blocklist.add(phash=avatar_hash.hash_to_str(image_hash), note=display_name)
            self._log_threadsafe(f"Added {display_name}'s avatar image to the blocklist (no ID available)")
            self.root.after(0, lambda: button.config(text="Added (by image)"))
            self.root.after(0, self._refresh_avatar_blocklist_widget)

        threading.Thread(target=worker, daemon=True).start()

    def _toggle_block(self, user_id, name, button):
        cached = self.cache.get(user_id)
        is_blocked = bool(cached and cached.get("action") == "blocked")
        try:
            if is_blocked:
                self.client.unblock_user(user_id)
                self.cache.set(user_id, "skipped", "manually unblocked")
                button.config(text="Block")
                self.log(f"Manually unblocked {name} ({user_id})")
            else:
                self.client.block_user(user_id)
                self.cache.set(user_id, "blocked", "manually blocked")
                button.config(text="Unblock")
                self.log(f"Manually blocked {name} ({user_id})")
        except VrcApiError as e:
            messagebox.showerror("Error", f"Action failed: {e}")
