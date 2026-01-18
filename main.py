import flet as ft
import asyncio
import threading
import json
import os
import warnings
from pynput import keyboard
from utils import (
    epoch_to_datetime, datetime_to_epoch, format_json, 
    minify_json, base64_encode, base64_decode, get_timezone_time, get_available_timezones,
    milliseconds_to_duration, jwt_decode, cron_next_runs, yaml_to_json, json_to_yaml,
    generate_ids, calculate_hashes, calculate_cidr_advanced, test_regex, decode_cert,
    check_port, calculate_wildcard, calculate_mss, calculate_ttl, lookup_mac_vendor,
    get_ip_ownership, audit_ssl_site
)

import sys
import subprocess

from pathlib import Path

# Config Logic
APP_NAME = "OpsNexus"
CONFIG_DIR = Path.home() / f".{APP_NAME.lower()}"
CONFIG_FILE = CONFIG_DIR / "config.json"

def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        # PyInstaller: _MEIPASS for onefile, executable dir for onedir
        if hasattr(sys, '_MEIPASS'):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(sys.executable)
    else:
        # Development mode
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "timezones": ["UTC", "Asia/Kolkata", "US/Eastern", "Europe/London"],
        "tabs": {
            "epoch": True,
            "json": True,
            "secret": True,
            "jwt": True,
            "cron": True,
            "yaml": True,
            "uuid": True,
            "cidr": True,
            "regex": True,
            "cert": True,
            "sslaudit": True,
            "mac": True
        },
        "pinned_tabs": [],
        "tab_usage": {},
        "regex_samples": {
            "Kafka Log": ["\\[(\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2},\\d{3})\\]\\s(\\w+)\\s(.*)", "[2024-03-21 10:15:30,123] ERROR [ReplicaFetcher] Error"],
            "Nginx Access": ["(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\s-\\s-\\s\\[(.*?)\\]\\s\"(.*?)\"\\s(\\d{3})", "127.0.0.1 - - [21/Mar/2024:10:15:30 +0000] \"GET /api\" 200"],
            "JVM Stack": ["at\\s+([\\w\\.]+)\\(([\\w\\.]+):(\\d+)\\)", "at com.example.service.Engine.start(Engine.java:150)"],
            "AWS ARN": ["arn:(aws|aws-cn|aws-us-gov):(\\w+):([\\w-]*):(\\d{12}):(.+)", "arn:aws:iam::123456789012:user/jdoe"],
            "IPv4 Address": ["\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "IPs: 192.168.1.1, 10.0.0.50"],
            "ISO Time": ["\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z?", "2024-03-21T15:30:00Z"]
        }
    }

def save_config(config):
    try:
        if not CONFIG_DIR.exists():
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
    except Exception:
        pass

def restart_app():
    """Restarts the current python process."""
    try:
        if getattr(sys, 'frozen', False):
            # If running as a frozen executable
            executable = sys.executable
            args = sys.argv
        else:
            # If running as a script
            executable = sys.executable
            args = [executable] + sys.argv

        subprocess.Popen(args)
        os._exit(0)
    except Exception as e:
        print(f"Error restarting: {e}")

class AddRegexSampleDialog(ft.AlertDialog):
    def __init__(self, on_save):
        super().__init__()
        self.on_save = on_save
        self.name_input = ft.TextField(label="Sample Name", autofocus=True)
        self.title = ft.Text("Add to Samples")
        self.content = ft.Column([
            ft.Text("Enter a name for this regex pattern:", size=12),
            self.name_input
        ], tight=True)
        self.actions = [
            ft.TextButton("Cancel", on_click=lambda _: self.close_dlg()),
            ft.Button("Save", on_click=self.save_click)
        ]

    def close_dlg(self, e=None):
        self.open = False
        self.page.update()

    def save_click(self, e):
        if self.name_input.value:
            self.on_save(self.name_input.value)
            self.close_dlg()

class TZPicker(ft.AlertDialog):
    def __init__(self, on_select):
        super().__init__()
        self.on_select = on_select
        self.all_tz = get_available_timezones()
        self.search_field = ft.TextField(
            label="Search Timezone",
            on_change=self.filter_tz,
            autofocus=True,
            label_style=ft.TextStyle(size=12)
        )
        self.tz_list = ft.ListView(expand=True, spacing=2, height=300)
        self.title = ft.Text("Select Timezone")
        self.content = ft.Column([
            self.search_field,
            self.tz_list
        ], width=300, height=400)
        
    def did_mount(self):
        self.load_tz("")

    def load_tz(self, filter_text):
        self.tz_list.controls.clear()
        count = 0
        for tz in self.all_tz:
            if filter_text.lower() in tz.lower():
                self.tz_list.controls.append(
                    ft.ListTile(
                        title=ft.Text(tz, size=13),
                        on_click=lambda e, t=tz: self.select_tz(t),
                        dense=True
                    )
                )
                count += 1
            if count > 50: # Limit result display for performance
                break
        self.update()

    def filter_tz(self, e):
        self.load_tz(e.control.value)
    def select_tz(self, tz):
        self.on_select(tz)
        self.open = False
        self.page.update()

class TimezoneClock(ft.Container):
    def __init__(self, initial_tz, open_picker, on_tz_change):
        super().__init__()
        self.tz = initial_tz
        self.open_picker = open_picker
        self.on_tz_change = on_tz_change
        self.time_display = ft.Text(size=16, weight="bold", color=ft.Colors.CYAN_300)
        self.tz_display = ft.Text(value=self.tz, size=10, color=ft.Colors.GREY_400)
        
        self.padding = 10
        self.border = ft.Border.all(1, ft.Colors.GREY_800)
        self.border_radius = 8
        self.width = 130
        self.bgcolor = ft.Colors.GREY_900
        self.content = ft.Column(
            [
                self.time_display,
                ft.GestureDetector(
                    content=self.tz_display,
                    on_tap=lambda _: self.open_picker(self)
                )
            ],
            spacing=0,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

    def change_tz(self, new_tz):
        self.tz = new_tz
        self.tz_display.value = self.tz
        self.update()
        if self.on_tz_change:
            self.on_tz_change()

    def update_time(self):
        self.time_display.value = get_timezone_time(self.tz)

class SettingsDialog(ft.AlertDialog):
    def __init__(self, config, on_save):
        super().__init__()
        self.config = config
        self.on_save = on_save
        self.title = ft.Text("Settings - Apps & Pinning")
        
        self.toggles = {}
        self.pins = {}
        controls = []
        
        labels = {
            "epoch": "Epoch Converter", "json": "JSON Tools", "secret": "Secret Decoder",
            "jwt": "JWT Inspector", "cron": "Cron Visualizer", "yaml": "YAML <-> JSON",
            "uuid": "UUID & Hash", "cidr": "CIDR Calculator", "regex": "Regex Tester",
            "cert": "Certificate Decoder", "network": "Network Tools", "sslaudit": "SSL Site Auditor",
            "mac": "MAC Lookup"
        }
        
        # Ensure config sets
        if "tabs" not in self.config: self.config["tabs"] = {k: True for k in labels.keys()}
        if "pinned_tabs" not in self.config: self.config["pinned_tabs"] = []

        controls.append(ft.Row([
            ft.Text("App Name", weight="bold", expand=True),
            ft.Text("Show", weight="bold", width=60, text_align=ft.TextAlign.CENTER),
            ft.Text("Pin", weight="bold", width=60, text_align=ft.TextAlign.CENTER),
        ]))
        
        for key, label in labels.items():
            is_enabled = self.config["tabs"].get(key, True)
            is_pinned = key in self.config["pinned_tabs"]
            
            sw = ft.Checkbox(value=is_enabled, visual_density=ft.VisualDensity.COMPACT)
            pin = ft.Checkbox(value=is_pinned, visual_density=ft.VisualDensity.COMPACT)
            
            self.toggles[key] = sw
            self.pins[key] = pin
            
            controls.append(ft.Row([
                ft.Text(label, expand=True),
                ft.Container(sw, width=60, alignment=ft.Alignment(0, 0)),
                ft.Container(pin, width=60, alignment=ft.Alignment(0, 0))
            ]))
            
        self.content = ft.Column(controls, height=450, width=350, scroll=ft.ScrollMode.AUTO)
        self.actions = [
            ft.TextButton("Save & Restart", on_click=self.save_click),
            ft.TextButton("Cancel", on_click=self.cancel_click)
        ]

    async def save_click(self, e):
        self.config["tabs"] = {k: v.value for k, v in self.toggles.items()}
        self.config["pinned_tabs"] = [k for k, v in self.pins.items() if v.value]
        if asyncio.iscoroutinefunction(self.on_save):
            await self.on_save(self.config)
        else:
            self.on_save(self.config)
        self.open = False
        self.page.update()

    def cancel_click(self, e):
        self.open = False
        self.page.update()

async def main(page: ft.Page):
    page.title = "OpsNexus - SRE Swiss Army Knife"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 1000
    page.window_height = 950
    page.scroll = ft.ScrollMode.AUTO
    page.padding = 20
    # Icon Logic with robust path resolution
    icon_path = get_resource_path(os.path.join("assets", "icon.png"))
    if os.path.exists(icon_path):
        page.window.icon = icon_path
        page.icon = icon_path
    else:
        print(f"Warning: Icon not found at {icon_path}")

    # Load config
    config = load_config()

    # Hotkey Logic
    loop = asyncio.get_running_loop()

    def toggle_window():
        print("Hotkey triggered! Toggling window...")
        try:
            # Use page.window object consistently for modern Flet (desktop)
            if page.window.minimized:
                print("Restoring window...")
                page.window.minimized = False
                page.window.focused = True
            else:
                print("Minimizing window...")
                page.window.minimized = True
            page.update()
        except Exception as e:
            # Fallback for older Flet versions if necessary
            try:
                if page.window_minimized:
                    page.window_minimized = False
                else:
                    page.window_minimized = True
                page.update()
            except Exception as e2:
                print(f"Error toggling window: {e} | Fallback Error: {e2}")

    def on_hotkey():
        print("!!! Hotkey signal received")
        loop.call_soon_threadsafe(toggle_window)

    def handle_keyboard(e: ft.KeyboardEvent):
        # Only toggle on plain Escape (no modifiers) to avoid conflict with Ctrl+Esc global hotkey
        if e.key == "Escape" and not (e.ctrl or e.shift or e.alt or e.meta):
            toggle_window()

    page.on_keyboard_event = handle_keyboard

    def on_press(key):
        # Keep debug logging for now to help the user verify keys
        pass

    def start_hotkey():
        print("Starting HotKeys listeners...")
        try:
            # Multi-hotkey support: Alt+H (Win/Linux) and Cmd+Shift+P (Mac)
            hotkeys = {
                '<ctrl>+<esc>': on_hotkey
            }
            
            with keyboard.GlobalHotKeys(hotkeys) as h:
                print(f"Listening for: {list(hotkeys.keys())}")
                h.join()
        except Exception as e:
            print(f"HotKey thread error: {e}")

    threading.Thread(target=start_hotkey, daemon=True).start()

    # Timezone Picker Logic
    current_clock = None
    
    def handle_tz_change():
        new_tzs = [c.tz for c in clocks]
        save_config({"timezones": new_tzs})

    def on_tz_select(tz):
        if current_clock:
            current_clock.change_tz(tz)
    
    picker = TZPicker(on_select=on_tz_select)
    page.overlay.append(picker)

    def open_picker(clock):
        nonlocal current_clock
        current_clock = clock
        picker.open = True
        page.update()

    # --- Top Timezone Bar ---
    clocks = [TimezoneClock(tz, open_picker, handle_tz_change) for tz in config["timezones"]]
    
    timezone_bar = ft.Row(
        controls=[c for c in clocks],
        alignment=ft.MainAxisAlignment.CENTER,
        spacing=10
    )


    # --- Tab 1: Time Keeper ---
    epoch_input = ft.TextField(
        label="Unix Epoch (sec or ms)", 
        expand=True,
        label_style=ft.TextStyle(size=12),
        text_size=14
    )
    dt_output = ft.Text(size=13, selectable=True)
    
    async def convert_epoch(e):
        if not epoch_input.value:
            dt_output.value = ""
            page.update()
            return
        res = epoch_to_datetime(epoch_input.value)
        if "error" in res:
            dt_output.value = f"Error: {res['error']}"
            dt_output.color = ft.Colors.RED_400
        else:
            dt_output.value = f"UTC: {res['utc']}\nLocal: {res['local']}"
            dt_output.color = ft.Colors.GREEN_400
        page.update()

    iso_input = ft.TextField(
        label="Date String", 
        expand=True,
        label_style=ft.TextStyle(size=12),
        text_size=14
    )
    epoch_output = ft.Text(size=13, selectable=True)

    async def convert_date(e):
        if not iso_input.value:
            epoch_output.value = ""
            page.update()
            return
        res = datetime_to_epoch(iso_input.value)
        if "error" in res:
            epoch_output.value = f"Error: {res['error']}"
            epoch_output.color = ft.Colors.RED_400
        else:
            epoch_output.value = f"Sec: {res['seconds']}\nMs: {res['milliseconds']}"
            epoch_output.color = ft.Colors.GREEN_400
        page.update()

    # --- New: Duration Converter ---
    duration_input = ft.TextField(
        label="Value in ms", 
        expand=True,
        label_style=ft.TextStyle(size=12),
        text_size=14
    )
    duration_output = ft.Text(size=13, selectable=True)
    
    async def convert_duration(e):
        if not duration_input.value:
            duration_output.value = ""
            page.update()
            return
        res = milliseconds_to_duration(duration_input.value)
        if "error" in res:
            duration_output.value = f"Error: {res['error']}"
            duration_output.color = ft.Colors.RED_400
        else:
            duration_output.value = f"{res['hours']}\n{res['days']}\n{res['weeks']}"
            duration_output.color = ft.Colors.GREEN_400
        page.update()

    # --- New: TTL Calculator ---
    ttl_input = ft.TextField(
        label="TTL in Seconds", 
        expand=True,
        label_style=ft.TextStyle(size=12),
        text_size=14
    )
    ttl_output = ft.Text(size=13, selectable=True)
    
    async def convert_ttl(e):
        if not ttl_input.value:
            ttl_output.value = ""
            page.update()
            return
        res = calculate_ttl(ttl_input.value)
        if "error" in res:
            ttl_output.value = f"Error: {res['error']}"
            ttl_output.color = ft.Colors.RED_400
        else:
            ttl_output.value = f"Duration: {res['duration']}\nLocal Expiry: {res['expiry_local']}\nUTC Expiry: {res['expiry_utc']}"
            ttl_output.color = ft.Colors.BLUE_400
        page.update()

    tab_time = ft.Container(
        content=ft.Column([
            ft.Row([
                # Col 1: Epoch to Human
                ft.Column([
                    ft.Text("Epoch to Human", size=16, weight="bold", color=ft.Colors.BLUE_200),
                    epoch_input,
                    ft.Text("", size=9), # Placeholder
                    ft.Button("Convert", on_click=convert_epoch, width=120),
                    dt_output,
                ], expand=True, spacing=10),
                
                ft.VerticalDivider(width=1, color=ft.Colors.GREY_800),
                
                # Col 2: Human to Epoch
                ft.Column([
                    ft.Text("Human to Epoch", size=16, weight="bold", color=ft.Colors.GREEN_200),
                    iso_input,
                    ft.Text("Default: Local. Supports 'UTC'", size=9, color=ft.Colors.GREY_500),
                    ft.Button("Convert", on_click=convert_date, width=120),
                    epoch_output,
                ], expand=True, spacing=10),

                ft.VerticalDivider(width=1, color=ft.Colors.GREY_800),

                # Col 3: MS to Duration
                ft.Column([
                    ft.Text("MS to Duration", size=16, weight="bold", color=ft.Colors.ORANGE_200),
                    duration_input,
                    ft.Text("Useful for retention policies", size=9, color=ft.Colors.GREY_500),
                    ft.Button("Convert", on_click=convert_duration, width=120),
                    duration_output,
                ], expand=True, spacing=10),

                ft.VerticalDivider(width=1, color=ft.Colors.GREY_800),

                # Col 4: TTL Calculator
                ft.Column([
                    ft.Text("TTL Calculator", size=16, weight="bold", color=ft.Colors.PURPLE_200),
                    ttl_input,
                    ft.Text("Seconds to duration/expiry", size=9, color=ft.Colors.GREY_500),
                    ft.Button("Calculate", on_click=convert_ttl, width=120),
                    ttl_output,
                ], expand=True, spacing=10),
            ], spacing=20, vertical_alignment=ft.CrossAxisAlignment.START)
        ]),
        padding=15
    )

    # --- Tab 2: JSON Tools ---
    json_input = ft.TextField(
        label="Raw JSON", 
        multiline=True, 
        min_lines=20, 
        text_size=12,
        expand=True,
        text_style=ft.TextStyle(font_family="monospace"),
        label_style=ft.TextStyle(size=12)
    )
    
    async def beautify_click(e):
        json_input.value = format_json(json_input.value)
        page.update()

    async def minify_click(e):
        json_input.value = minify_json(json_input.value)
        page.update()

    async def set_clip(text):
        if not text:
            return False
        
        # Robust fallback using the method that works on this version
        try:
            res = page.clipboard.set(text)
            if asyncio.iscoroutine(res):
                await res
            return True
        except Exception as e:
            try:
                page.set_clipboard(text)
                return True
            except Exception:
                return False

    async def handle_copy_click(e, text):
        if await set_clip(text):
            e.control.icon = ft.Icons.CHECK
            e.control.tooltip = "Copied!"
        else:
            e.control.icon = ft.Icons.ERROR_OUTLINE
            e.control.tooltip = "Empty!"
        page.update()
        await asyncio.sleep(2)
        e.control.icon = ft.Icons.COPY
        e.control.tooltip = "Copy"
        page.update()

    async def copy_click(e):
        if await set_clip(json_input.value):
            e.control.text = "Copied!"
            e.control.icon = ft.Icons.CHECK
        else:
            e.control.text = "Empty!"
            e.control.icon = ft.Icons.ERROR_OUTLINE
            
        page.update()
        await asyncio.sleep(2)
        e.control.text = "Copy"
        e.control.icon = ft.Icons.COPY
        page.update()

    async def clear_click(e):
        json_input.value = ""
        page.update()

    tab_json = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("JSON Formatter", size=20, weight="bold", color=ft.Colors.BLUE_200),
                ft.Row([
                    ft.Button("Beautify", icon=ft.Icons.FORMAT_ALIGN_LEFT, on_click=beautify_click),
                    ft.Button("Minify", icon=ft.Icons.COMPRESS, on_click=minify_click),
                    ft.Button("Copy", icon=ft.Icons.COPY, on_click=copy_click),
                    ft.Button("Clear", icon=ft.Icons.DELETE_OUTLINE, on_click=clear_click),
                ], spacing=10)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            json_input,
        ], spacing=15, expand=True),
        padding=20,
        expand=True
    )

    # --- Tab 3: Secret Decoder ---
    secret_input = ft.TextField(
        label="Input Text", 
        multiline=True, 
        expand=True,
        label_style=ft.TextStyle(size=12)
    )
    secret_output = ft.TextField(
        label="Output", 
        multiline=True, 
        expand=True,
        read_only=True,
        label_style=ft.TextStyle(size=12)
    )
    mode_toggle = ft.Switch(value=True, scale=0.7)
    mode_toggle_container = ft.Row([
        mode_toggle,
        ft.Text("Encode Mode (ON = Encode, OFF = Decode)", size=12, color=ft.Colors.GREY_400),
    ], spacing=10)

    async def process_secret(e):
        if mode_toggle.value:
            secret_output.value = base64_encode(secret_input.value)
        else:
            secret_output.value = base64_decode(secret_input.value)
        page.update()

    async def copy_secret_click(e):
        if await set_clip(secret_output.value):
            e.control.text = "Copied!"
            e.control.icon = ft.Icons.CHECK
        else:
            e.control.text = "Empty!"
            e.control.icon = ft.Icons.ERROR_OUTLINE

        page.update()
        await asyncio.sleep(2)
        e.control.text = "Copy"
        e.control.icon = ft.Icons.COPY
        page.update()

    async def clear_secret_click(e):
        secret_input.value = ""
        secret_output.value = ""
        page.update()

    tab_secret = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("Base64 Tool", size=20, weight="bold", color=ft.Colors.PURPLE_200),
                ft.Row([
                    ft.Button("Process", icon=ft.Icons.PLAY_ARROW, on_click=process_secret),
                    ft.Button("Copy", icon=ft.Icons.COPY, on_click=copy_secret_click),
                    ft.Button("Clear", icon=ft.Icons.DELETE_OUTLINE, on_click=clear_secret_click),
                ], spacing=10)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            mode_toggle_container,
            ft.Row([
                secret_input,
                ft.VerticalDivider(width=1, color=ft.Colors.GREY_800),
                secret_output
            ], expand=True, spacing=10)
        ], spacing=15, expand=True),
        padding=20,
        expand=True
    )

    # --- Tab 4: JWT Inspector ---
    jwt_input = ft.TextField(
        label="JWT Token", 
        multiline=True, 
        max_lines=10, 
        expand=True,
        text_style=ft.TextStyle(font_family="monospace", size=12)
    )
    jwt_header = ft.TextField(label="Header", multiline=True, read_only=True, expand=True, text_size=12)
    jwt_payload = ft.TextField(label="Payload", multiline=True, read_only=True, expand=True, text_size=12)

    async def decode_jwt_click(e):
        if not jwt_input.value:
            return
        res = jwt_decode(jwt_input.value)
        if "error" in res:
            jwt_header.value = f"Error: {res['error']}"
            jwt_payload.value = ""
        else:
            jwt_header.value = json.dumps(res['header'], indent=2)
            jwt_payload.value = json.dumps(res['payload'], indent=2)
        page.update()

    async def clear_jwt_click(e):
        jwt_input.value = jwt_header.value = jwt_payload.value = ""
        page.update()

    tab_jwt = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("JWT Inspector", size=20, weight="bold", color=ft.Colors.YELLOW_200),
                ft.Row([
                     ft.Button("Decode", icon=ft.Icons.LOCK_OPEN, on_click=decode_jwt_click),
                     ft.Button("Clear", icon=ft.Icons.DELETE_OUTLINE, on_click=clear_jwt_click),
                ])
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            jwt_input,
            ft.Row([jwt_header, jwt_payload], expand=True)
        ], spacing=15, expand=True),
        padding=20,
        expand=True
    )

    # --- Tab 5: Cron Visualizer ---
    cron_input = ft.TextField(label="Cron Expression (e.g. */5 * * * *)", expand=True)
    cron_output = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True)

    # Builder Fields
    # Builder Fields
    cron_min = ft.TextField(label="Min", value="*", width=100, text_align=ft.TextAlign.CENTER, border_color=ft.Colors.GREY_400, focused_border_color=ft.Colors.GREY_400, label_style=ft.TextStyle(color=ft.Colors.GREY_400))
    cron_hour = ft.TextField(label="Hour", value="*", width=100, text_align=ft.TextAlign.CENTER, border_color=ft.Colors.GREY_400, focused_border_color=ft.Colors.GREY_400, label_style=ft.TextStyle(color=ft.Colors.GREY_400))
    cron_day = ft.TextField(label="Day", value="*", width=100, text_align=ft.TextAlign.CENTER, border_color=ft.Colors.GREY_400, focused_border_color=ft.Colors.GREY_400, label_style=ft.TextStyle(color=ft.Colors.GREY_400))
    cron_month = ft.TextField(label="Month", value="*", width=100, text_align=ft.TextAlign.CENTER, border_color=ft.Colors.GREY_400, focused_border_color=ft.Colors.GREY_400, label_style=ft.TextStyle(color=ft.Colors.GREY_400))
    cron_weekday = ft.TextField(label="Weekday", value="*", width=100, text_align=ft.TextAlign.CENTER, border_color=ft.Colors.GREY_400, focused_border_color=ft.Colors.GREY_400, label_style=ft.TextStyle(color=ft.Colors.GREY_400))

    async def generate_cron_click(e):
        # Construct cron string
        c_str = f"{cron_min.value} {cron_hour.value} {cron_day.value} {cron_month.value} {cron_weekday.value}"
        cron_input.value = c_str
        page.update()
        # Auto-explain after generation
        await explain_cron_click(None)

    async def explain_cron_click(e):
        if not cron_input.value:
            return
        runs = cron_next_runs(cron_input.value)
        cron_output.controls.clear()
        cron_output.controls.append(ft.Text("Next Scheduled Runs:", weight="bold", size=14))
        for r in runs:
            cron_output.controls.append(ft.Text(f"• {r}", size=13))
        page.update()

    async def copy_cron_btn_click(e):
        await handle_copy_click(e, cron_input.value)

    tab_cron = ft.Container(
        content=ft.Column([
            ft.Text("Cron Visualizer", size=20, weight="bold", color=ft.Colors.RED_200),
            
            # Section 1: Builder
            ft.Container(
                content=ft.Column([
                    ft.Text("Builder", size=14, weight="bold", color=ft.Colors.GREY_400),
                    ft.Row([
                        cron_min, cron_hour, cron_day, cron_month, cron_weekday,
                        ft.IconButton(ft.Icons.ARROW_DOWNWARD, tooltip="Generate Down", on_click=generate_cron_click)
                    ], spacing=10, alignment=ft.MainAxisAlignment.CENTER)
                ]),
                padding=15,
                border=ft.Border.all(1, ft.Colors.BLACK),
                border_radius=10,
            ),

            # Section 2: Explainer/Input
            ft.Container(
                content=ft.Row([
                    cron_input,
                    ft.Button("Explain", icon=ft.Icons.VIBRATION, on_click=explain_cron_click),
                    ft.IconButton(ft.Icons.COPY, tooltip="Copy", on_click=copy_cron_btn_click)
                ], spacing=10),
                padding=0 
            ),

            # Section 3: Output
            ft.Container(content=cron_output, bgcolor=ft.Colors.BLACK, padding=15, border_radius=10, expand=True)
            
        ], spacing=20, expand=True),
        padding=20,
        expand=True
    )

    # --- Tab 6: YAML <> JSON ---
    async def copy_yaml_click(e):
        await handle_copy_click(e, yaml_input_str.value)

    async def copy_json_click(e):
        await handle_copy_click(e, json_output_str.value)

    yaml_input_str = ft.TextField(
        label="YAML", multiline=True, expand=True, text_size=12, text_style=ft.TextStyle(font_family="monospace"),
        suffix=ft.IconButton(ft.Icons.COPY, tooltip="Copy YAML", on_click=copy_yaml_click)
    )
    json_output_str = ft.TextField(
        label="JSON", multiline=True, expand=True, text_size=12, text_style=ft.TextStyle(font_family="monospace"),
        suffix=ft.IconButton(ft.Icons.COPY, tooltip="Copy JSON", on_click=copy_json_click)
    )

    async def to_json_click(e):
        json_output_str.value = yaml_to_json(yaml_input_str.value)
        page.update()

    async def to_yaml_click(e):
        yaml_input_str.value = json_to_yaml(json_output_str.value)
        page.update()
        
    async def clear_yaml_click(e):
        yaml_input_str.value = ""
        json_output_str.value = ""
        page.update()

    tab_yaml = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("YAML <-> JSON", size=20, weight="bold", color=ft.Colors.INDIGO_200),
                ft.Row([
                     ft.Button("To JSON >", on_click=to_json_click),
                     ft.Button("< To YAML", on_click=to_yaml_click),
                     ft.Button("Clear", icon=ft.Icons.DELETE_OUTLINE, on_click=clear_yaml_click),
                ])
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Row([yaml_input_str, json_output_str], expand=True)
        ], spacing=15, expand=True),
        padding=20,
        expand=True
    )

    # --- Tab 7: UUID & Hash ---
    def create_copy_field(label):
        f = ft.TextField(label=label, read_only=True, expand=True, text_size=12, text_style=ft.TextStyle(font_family="monospace"), height=40)
        async def copy_click(e):
            await handle_copy_click(e, f.value)
        f.suffix = ft.IconButton(ft.Icons.COPY, tooltip="Copy", on_click=copy_click)
        return f

    uuid_v4 = create_copy_field("UUIDv4")
    uuid_ulid = create_copy_field("ULID")
    uuid_hex = create_copy_field("Hex")
    
    hash_input = ft.TextField(label="Input Text for Hashing", expand=True)
    hash_md5 = create_copy_field("MD5")
    hash_sha1 = create_copy_field("SHA1")
    hash_sha256 = create_copy_field("SHA256")

    async def gen_uuid_click(e):
        from utils import generate_ids
        ids = generate_ids()
        uuid_v4.value = ids['uuid']
        uuid_ulid.value = ids['ulid']
        uuid_hex.value = ids['hex']
        page.update()

    async def calc_hash_click(e):
        from utils import calculate_hashes
        if not hash_input.value: return
        res = calculate_hashes(hash_input.value)
        hash_md5.value = res['md5']
        hash_sha1.value = res['sha1']
        hash_sha256.value = res['sha256']
        page.update()

    tab_uuid = ft.Container(
        content=ft.Column([
            ft.Text("UUID & Hash Generator", size=20, weight="bold", color=ft.Colors.TEAL_200),
            
            ft.Divider(),
            ft.Row([
                ft.Text("Generated IDs:", weight="bold", size=16),
                ft.Button("Generate IDs", icon=ft.Icons.REFRESH, on_click=gen_uuid_click),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            uuid_v4, uuid_ulid, uuid_hex,
            
            ft.Divider(),
            ft.Text("Hash Calculator:", weight="bold", size=16),
            ft.Row([
                hash_input,
                ft.Button("Calculate", icon=ft.Icons.CALCULATE, on_click=calc_hash_click),
            ]),
            hash_md5, hash_sha1, hash_sha256
        ], spacing=10, expand=True, scroll=ft.ScrollMode.AUTO),
        padding=20, expand=True
    )

    # --- Tab 8: CIDR Calculator ---
    # --- TAB: Advanced IP Subnet Calculator ---
    import ipaddress
    
    mask_options = []
    for i in range(32, 0, -1):
        # Generate dotted decimal for prefix
        net = ipaddress.ip_network(f"0.0.0.0/{i}")
        mask_options.append(ft.dropdown.Option(key=f"/{i}", text=f"{net.netmask} /{i}"))

    cidr_ip_in = ft.TextField(label="IP Address", value="49.206.128.42", expand=True)
    cidr_mask_in = ft.Dropdown(
        label="Subnet Mask",
        value="/30",
        options=mask_options,
        width=240
    )
    
    cidr_metadata_grid = ft.Column(spacing=5, visible=False)
    cidr_sibling_table = ft.ListView(expand=True, spacing=2, visible=False)
    
    async def calc_cidr_click(e):
        from utils import calculate_cidr_advanced, get_ip_ownership
        if not cidr_ip_in.value: return
        res = calculate_cidr_advanced(cidr_ip_in.value, cidr_mask_in.value)
        if "error" in res:
            page.snack_bar = ft.SnackBar(ft.Text(f"Error: {res['error']}"))
            page.snack_bar.open = True
            page.update()
            return

        # Build Metadata Table
        rows = [
            ("IP Address:", res["ip"]),
            ("Network Address:", res["network"]),
            ("Usable Range:", res["range"]),
            ("Broadcast:", res["broadcast"]),
            ("Total Hosts:", str(res["hosts_total"])),
            ("Usable Hosts:", str(res["hosts_usable"])),
            ("Subnet Mask:", res["netmask"]),
            ("Wildcard Mask:", res["wildcard"]),
            ("Binary Mask:", res["mask_bin"]),
            ("IP Class:", res["ip_class"]),
            ("IP Type:", res["ip_type"]),
        ]

        # Ownership Lookup for Public IPs
        ownership = get_ip_ownership(res["ip"])
        if ownership["status"] == "public":
            rows.append(("Owner / ISP:", ownership["isp"]))
            rows.append(("Organization:", ownership["org"]))
            rows.append(("Location:", ownership["location"]))
        elif ownership["status"] == "private":
            rows.append(("Ownership:", "N/A (Private IP)"))

        rows.extend([
            ("CIDR:", res["cidr"]),
            ("Hex ID:", res["hex_id"]),
            ("Binary ID:", res["binary_id"]),
            ("Reverse DNS:", res["reverse_dns"]),
            ("mapped IPv6:", res["ipv4_mapped"]),
            ("6to4 Prefix:", res["prefix_6to4"]),
        ])
        
        cidr_metadata_grid.controls = [
            ft.Row([
                ft.Container(ft.Text(label, weight="bold", size=13), width=150),
                ft.Text(val, size=13, selectable=True)
            ]) for label, val in rows
        ]
        cidr_metadata_grid.visible = True

        # Build Sibling Table
        cidr_sibling_table.controls = [
            ft.Text(f"All Possible {res['cidr']} Networks for {res['ip'].rsplit('.', 1)[0]}.*", weight="bold", size=14, color=ft.Colors.CYAN_200),
            ft.Container(
                content=ft.Row([
                    ft.Container(ft.Text("Network", weight="bold"), width=120),
                    ft.Container(ft.Text("Usable Range", weight="bold"), expand=True),
                    ft.Container(ft.Text("Broadcast", weight="bold"), width=120),
                ]),
                bgcolor=ft.Colors.GREY_900,
                padding=5
            )
        ]
        
        for sib in res.get("siblings", []):
            is_current = sib["net"] == res["network"]
            cidr_sibling_table.controls.append(
                ft.Container(
                    content=ft.Row([
                        ft.Container(ft.Text(sib["net"], size=12, color=ft.Colors.BLUE_200 if is_current else None), width=120),
                        ft.Container(ft.Text(sib["range"], size=12), expand=True),
                        ft.Container(ft.Text(sib["broadcast"], size=12), width=120),
                    ]),
                    padding=2
                )
            )
        
        cidr_sibling_table.visible = True
        page.update()

    tab_cidr = ft.Container(
        content=ft.Column([
            ft.Text("Advanced IP Subnet Calculator", size=20, weight="bold", color=ft.Colors.CYAN_200),
            ft.Row([
                cidr_ip_in, 
                cidr_mask_in,
                ft.Button("Calculate", icon=ft.Icons.CALCULATE, on_click=calc_cidr_click),
            ]),
            ft.Row([
                ft.Container(
                    content=ft.Column([
                        ft.Text("Network Metadata", weight="bold", color=ft.Colors.BLUE_200),
                        ft.Divider(height=1),
                        cidr_metadata_grid,
                    ], scroll=ft.ScrollMode.AUTO, alignment=ft.MainAxisAlignment.START),
                    expand=1, padding=10, border=ft.Border.all(1, ft.Colors.GREY_800), border_radius=5
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("Subnet Explorer", weight="bold", color=ft.Colors.BLUE_200),
                        ft.Divider(height=1),
                        cidr_sibling_table,
                    ], alignment=ft.MainAxisAlignment.START),
                    expand=1, padding=10, border=ft.Border.all(1, ft.Colors.GREY_800), border_radius=5
                )
            ], expand=True, vertical_alignment=ft.CrossAxisAlignment.START)
        ], spacing=15, expand=True),
        padding=20, expand=True
    )

    # --- Tab 9: Regex Tester ---
    # --- Tab 9: Regex Tester (Clean Rewrite) ---
    # --- TAB: REGEX (FINAL REWRITE) ---
    rx_p = ft.TextField(label="Regex Pattern", expand=True, text_style=ft.TextStyle(font_family="monospace"))
    rx_t = ft.TextField(label="Test String", multiline=True, expand=True, min_lines=8)
    rx_f = ft.TextField(label="Path to Load", expand=True, text_size=12, height=40)
    rx_res = ft.ListView(expand=True, spacing=5)

    rx_data = config.get("regex_samples", {})
    # Safety merge for exhaustive default samples if missing
    exhaustive_defaults = {
        "Kafka Log": [r"\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\]\s(\w+)\s(.*)", "[2024-03-21 10:15:30,123] ERROR [ReplicaFetcher] Error while fetching data from broker 1"],
        "Nginx Access": [r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s-\s-\s\[(.*?)\]\s"(.*?)"\s(\d{3})\s(\d+)', '127.0.0.1 - - [21/Mar/2024:10:15:30 +0000] "GET /api/v1/health HTTP/1.1" 200 1234'],
        "JVM Stack": [r"at\s+([\w\.]+)\(([\w\.]+):(\d+)\)", "at com.example.service.Engine.start(Engine.java:150)\nat com.example.App.main(App.java:10)"],
        "AWS ARN": [r"arn:(aws|aws-cn|aws-us-gov):(\w+):([\w-]*):(\d{12}):(.+)", "arn:aws:iam::123456789012:user/jdoe\narn:aws:s3:::my-bucket/logs/2024/03/21"],
        "Postgres Log": [r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\w+)\s\\[(\d+)\\]:(.*)", "2024-03-21 10:15:30 UTC [1234]: LOG: started streaming WAL from primary"],
        "UUID v4": [r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", "550e8400-e29b-41d4-a716-446655440000"],
        "MAC Address": [r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", "eth0 00:0c:29:44:a3:21"],
        "IPv4 Address": [r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IPs: 192.168.1.1, 10.0.0.50"],
        "ISO Time": [r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?", "2024-03-21T15:30:00Z"],
        "Docker Image": [r"^([a-z0-9]+(?:[._-][a-z0-9]+)*)(?:/([a-z0-9]+(?:[._-][a-z0-9]+)*))?(?::([\w][\w.-]{0,127}))?$", "nginx:latest, myreg.io/myapp:v1.2.3"],
        "K8s Pod": [r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", "my-app-v1-6f8d9b7c"],
        "Python Trace": [r'File\s+"(.*?)",\s+line\s+(\d+),\s+in\s+(.*)', 'File "app.py", line 42, in process_data']
    }
    for k, v in exhaustive_defaults.items():
        if k not in rx_data:
            rx_data[k] = v

    def rx_load_sample(e):
        val = rx_dd.value
        if val in rx_data:
            sample = rx_data[val]
            rx_p.value = sample[0]
            rx_t.value = sample[1]
            rx_p.update()
            rx_t.update()
        page.update()

    def rx_add_to_samples(e):
        if not rx_p.value or not rx_t.value:
            page.snack_bar = ft.SnackBar(ft.Text("Define pattern and text first!"))
            page.snack_bar.open = True
            page.update()
            return

        def save_new(name):
            rx_data[name] = [rx_p.value, rx_t.value]
            config["regex_samples"] = rx_data
            save_config(config)
            
            # Refresh UI
            rx_dd.options = [ft.dropdown.Option(k) for k in rx_data.keys()]
            rx_dd.value = name
            rx_dd.update()
            page.snack_bar = ft.SnackBar(ft.Text(f"Sample '{name}' saved!"))
            page.snack_bar.open = True
            page.update()

        dlg = AddRegexSampleDialog(save_new)
        page.overlay.append(dlg)
        dlg.open = True
        page.update()

    async def rx_run_test(e):
        from utils import test_regex
        if not rx_p.value or not rx_t.value: return
        res = test_regex(rx_p.value, rx_t.value)
        rx_res.controls.clear()
        if "error" in res:
            rx_res.controls.append(ft.Text(f"Error: {res['error']}", color="red"))
        else:
            rx_res.controls.append(ft.Text(f"Matches ({res['count']}):", weight="bold"))
            for m in res['matches']:
                rx_res.controls.append(ft.Container(
                    content=ft.Text(f"'{m['match']}'", color="green"),
                    padding=5, bgcolor="#111111", border_radius=5
                ))
        page.update()

    async def rx_clear(e):
        rx_p.value = ""
        rx_t.value = ""
        rx_dd.value = None
        rx_res.controls.clear()
        page.update()

    async def rx_load_path(e):
        if not rx_f.value: return
        try:
            with open(rx_f.value, "r") as f:
                rx_t.value = f.read()
            page.update()
        except Exception as ex:
            rx_res.controls.clear()
            rx_res.controls.append(ft.Text(f"Error: {ex}", color="red"))
            page.update()

    rx_dd = ft.Dropdown(
        label="Samples",
        options=[ft.dropdown.Option(k) for k in rx_data.keys()],
        width=200,
        text_size=12
    )
    rx_dd.on_change = rx_load_sample

    tab_regex = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("Regex Tester", size=20, weight="bold", color="pink"),
                ft.Row([
                    rx_dd,
                    ft.IconButton(ft.Icons.DOWNLOAD, on_click=rx_load_sample, tooltip="Load Sample"),
                    ft.IconButton(ft.Icons.ADD_CIRCLE_OUTLINE, on_click=rx_add_to_samples, tooltip="Save current as sample"),
                ], spacing=0)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            rx_p,
            rx_t,
            ft.Row([rx_f, ft.Button("Load Path", on_click=rx_load_path)]),
            ft.Row([
                ft.Button("Run Test", icon=ft.Icons.PLAY_ARROW, on_click=rx_run_test),
                ft.Button("Clear", icon=ft.Icons.DELETE, on_click=rx_clear),
            ]),
            ft.Container(content=rx_res, expand=True, padding=10, border=ft.Border.all(1, "#333333"))
        ], spacing=10, expand=True),
        padding=20, expand=True
    )

    # --- Tab 10: Cert Decoder ---
    cert_input = ft.TextField(label="PEM Certificate", multiline=True, expand=True, text_style=ft.TextStyle(font_family="monospace", size=10))
    cert_output = ft.Text("Certificate Details...", size=13, selectable=True, font_family="monospace")

    async def decode_cert_click(e):
        from utils import decode_cert
        if not cert_input.value: return
        res = decode_cert(cert_input.value)
        if "error" in res:
            cert_output.value = f"Error: {res['error']}"
            cert_output.color = ft.Colors.RED_400
        else:
            cert_output.value = (
                f"Subject: {res['subject']}\n"
                f"Issuer:  {res['issuer']}\n"
                f"Serial:  {res['serial']}\n"
                f"Valid From: {res['not_valid_before']}\n"
                f"Valid To:   {res['not_valid_after']}\n"
                f"Version:    {res['version']}"
            )
            cert_output.color = ft.Colors.AMBER_200
        page.update()

    async def clear_cert_click(e):
        cert_input.value = ""
        cert_output.value = "Certificate Details..."
        cert_output.color = None
        page.update()

    tab_cert = ft.Container(
        content=ft.Column([
            ft.Text("Certificate Decoder", size=20, weight="bold", color=ft.Colors.AMBER_200),
            cert_input,
            ft.Row([
                ft.Button("Decode", icon=ft.Icons.LOCK_OPEN, on_click=decode_cert_click),
                ft.Button("Clear", icon=ft.Icons.DELETE_OUTLINE, on_click=clear_cert_click),
            ]),
            ft.Container(content=ft.Column([cert_output], scroll=ft.ScrollMode.AUTO), padding=10, border=ft.Border.all(1, ft.Colors.GREY_800), border_radius=5, expand=True)
        ], spacing=10, expand=True),
        padding=20, expand=True
    )

    # --- Main Layout with Dynamic Tabs ---
    # --- Tab 11: Network Tools ---
    nw_host = ft.TextField(label="Hostname/IP", value="google.com", expand=True)
    nw_port = ft.TextField(label="Port", value="443", width=100)
    nw_port_res = ft.Text("", size=16, weight="bold")
    
    nw_mask_in = ft.TextField(label="Mask/CIDR", value="255.255.255.0", expand=True)
    nw_mask_res = ft.Text("", size=14, selectable=True)
    
    nw_mtu_in = ft.TextField(label="MTU", value="1500", width=100)
    nw_tunnel_dd = ft.Dropdown(
        label="Tunnel Type",
        options=[
            ft.dropdown.Option("Standard (No Tunnel)"),
            ft.dropdown.Option("IPsec Transport"),
            ft.dropdown.Option("IPsec Tunnel"),
            ft.dropdown.Option("GRE"),
            ft.dropdown.Option("VXLAN"),
            ft.dropdown.Option("Wireguard"),
        ],
        value="Standard (No Tunnel)",
        expand=True
    )
    nw_mss_res = ft.Text("", size=14, selectable=True)

    async def nw_check_port_click(e):
        from utils import check_port
        nw_port_res.value = "Checking..."
        nw_port_res.color = ft.Colors.GREY_400
        page.update()
        is_open = check_port(nw_host.value, nw_port.value)
        if is_open:
            nw_port_res.value = "OPEN"
            nw_port_res.color = ft.Colors.GREEN_400
        else:
            nw_port_res.value = "CLOSED / TIMEOUT"
            nw_port_res.color = ft.Colors.RED_400
        page.update()

    async def nw_calc_mask_click(e):
        from utils import calculate_wildcard
        res = calculate_wildcard(nw_mask_in.value)
        if "error" in res:
            nw_mask_res.value = f"Error: {res['error']}"
            nw_mask_res.color = ft.Colors.RED_400
        else:
            nw_mask_res.value = f"Mask: {res['mask']}\nWildcard: {res['wildcard']}"
            nw_mask_res.color = ft.Colors.CYAN_300
        page.update()

    async def nw_calc_mss_click(e):
        from utils import calculate_mss
        res = calculate_mss(nw_mtu_in.value, nw_tunnel_dd.value)
        if "error" in res:
            nw_mss_res.value = f"Error: {res['error']}"
            nw_mss_res.color = ft.Colors.RED_400
        else:
            nw_mss_res.value = f"MSS: {res['mss']} bytes\nOverhead: {res['overhead']} bytes\n{res['description']}"
            nw_mss_res.color = ft.Colors.AMBER_300
        page.update()

    tab_network = ft.Container(
        content=ft.Column([
            ft.Text("Network Operations Hub", size=20, weight="bold", color=ft.Colors.BLUE_200),
            ft.Text("TCP Port Checker", size=16, weight="bold"),
            ft.Row([nw_host, nw_port, ft.Button("Check", icon=ft.Icons.NETWORK_CHECK, on_click=nw_check_port_click)]),
            nw_port_res,
            ft.Divider(),
            ft.Text("Wildcard Mask Helper", size=16, weight="bold"),
            ft.Row([nw_mask_in, ft.Button("Convert", icon=ft.Icons.SWAP_HORIZ, on_click=nw_calc_mask_click)]),
            nw_mask_res,
            ft.Divider(),
            ft.Text("SD-WAN / Tunnel MSS Calculator", size=16, weight="bold"),
            ft.Row([nw_mtu_in, nw_tunnel_dd, ft.Button("Calculate", icon=ft.Icons.CALCULATE, on_click=nw_calc_mss_click)]),
            nw_mss_res,
        ], spacing=15, scroll=ft.ScrollMode.AUTO, expand=True),
        padding=20, expand=True
    )

    # --- Tab: MAC Lookup ---
    mac_input = ft.TextField(
        label="MAC Address (e.g. 00:00:0C:00:00:01)",
        hint_text="Supports any format (00:00:0C, 00-00-0C, 0000.0C00, etc.)",
        expand=True
    )
    mac_res = ft.Text(size=14, selectable=True)

    async def mac_lookup_click(e):
        if not mac_input.value:
            mac_res.value = ""
            page.update()
            return
        
        mac_res.value = "Searching..."
        mac_res.color = ft.Colors.AMBER_300
        page.update()
        
        res = lookup_mac_vendor(mac_input.value)
        if "error" in res:
            mac_res.value = f"Error: {res['error']}"
            mac_res.color = ft.Colors.RED_400
        else:
            mac_res.value = f"Vendor: {res['vendor']}\nPrefix (OUI): {res['oui']}\nSource: {res['source'].upper()}"
            mac_res.color = ft.Colors.GREEN_400
        page.update()

    tab_mac = ft.Container(
        content=ft.Column([
            ft.Text("MAC Address Vendor Lookup", size=20, weight="bold", color=ft.Colors.BLUE_200),
            ft.Text("Identify device manufacturers by MAC address or OUI.", size=12, color=ft.Colors.GREY_500),
            ft.Row([mac_input, ft.Button("Lookup", icon=ft.Icons.SEARCH, on_click=mac_lookup_click)]),
            ft.Divider(),
            mac_res
        ], spacing=15),
        padding=20, expand=True
    )

    # --- Tab 10: SSL Site Auditor ---
    ssl_host_in = ft.TextField(label="Hostname / URL", hint_text="e.g. google.com", expand=True)
    ssl_port_in = ft.TextField(label="Port", value="443", width=80)
    ssl_res_grid = ft.Column(visible=False, spacing=10)
    
    async def audit_click(e):
        from utils import audit_ssl_site
        if not ssl_host_in.value: return
        
        # Extract hostname if they pasted a URL
        host = ssl_host_in.value.split("://")[-1].split("/")[0].split(":")[0]
        
        res = audit_ssl_site(host, ssl_port_in.value)
        if res["status"] == "error":
            page.snack_bar = ft.SnackBar(ft.Text(f"Audit Error: {res['message']}"))
            page.snack_bar.open = True
            page.update()
            return
            
        # Build Results
        rows = [
            ("Status:", "Valid ✅" if res["is_valid"] else "Invalid/Expired ❌"),
            ("Days Until Expiry:", f"{res['days_left']} days"),
            ("Protocol Supported:", res["protocol"]),
            ("Subject:", res["subject"]),
            ("Issuer:", res["issuer"]),
            ("Valid From:", res["valid_from"]),
            ("Valid To:", res["valid_to"]),
            ("SANs (Alternative):", res["sans"]),
            ("Serial Number:", res["serial"]),
            ("Fingerprint:", res["fingerprint"]),
        ]
        
        ssl_res_grid.controls = [
            ft.Row([
                ft.Container(ft.Text(label, weight="bold", size=13), width=150),
                ft.Text(val, size=13, selectable=True)
            ]) for label, val in rows
        ]
        ssl_res_grid.visible = True
        page.update()

    tab_ssl_auditor = ft.Container(
        content=ft.Column([
            ft.Text("SSL/TLS Site Auditor", size=20, weight="bold", color=ft.Colors.CYAN_200),
            ft.Row([
                ssl_host_in,
                ssl_port_in,
                ft.Button("Audit Site", icon=ft.Icons.SECURITY, on_click=audit_click),
            ]),
            ft.Divider(height=1),
            ft.Container(
                content=ft.Column([
                    ft.Text("Audit Results", weight="bold", color=ft.Colors.BLUE_200),
                    ft.Divider(height=1),
                    ssl_res_grid
                ], scroll=ft.ScrollMode.AUTO),
                padding=10, border=ft.Border.all(1, ft.Colors.GREY_800), border_radius=5, expand=True
            )
        ], spacing=15, expand=True),
        padding=20, expand=True
    )

    available_tabs = [
        ("epoch", "Epoch Converter", ft.Icons.ACCESS_TIME, tab_time),
        ("json", "JSON Tools", ft.Icons.DATA_OBJECT, tab_json),
        ("secret", "Secret Decoder", ft.Icons.LOCK, tab_secret),
        ("jwt", "JWT Inspector", ft.Icons.TOKEN, tab_jwt),
        ("cron", "Cron Visualizer", ft.Icons.SCHEDULE, tab_cron),
        ("yaml", "YAML <-> JSON", ft.Icons.SWAP_HORIZ, tab_yaml),
        ("uuid", "UUID & Hash", ft.Icons.FINGERPRINT, tab_uuid),
        ("cidr", "CIDR Calculator", ft.Icons.NETWORK_CHECK, tab_cidr),
        ("sslaudit", "SSL Site Auditor", ft.Icons.LOCK, tab_ssl_auditor),
        ("regex", "Regex Tester", ft.Icons.BUG_REPORT, tab_regex),
        ("cert", "Cert Decoder", ft.Icons.VERIFIED_USER, tab_cert),
        ("network", "Network Tools", ft.Icons.ROUTER, tab_network),
        ("mac", "MAC Lookup", ft.Icons.SEARCH, tab_mac),
    ]

    active_tabs = []
    active_controls = []
    
    # Check config and build lists
    user_tabs = config.get("tabs", {})
    for key, label, icon, content in available_tabs:
        if user_tabs.get(key, True):
            active_tabs.append(ft.Tab(label=label, icon=icon))
            active_controls.append(content)

    quick_access_bar = ft.Row(spacing=2)

    def update_quick_access():
        quick_access_bar.controls.clear()
        # Ensure unique pins and only those that are currently enabled in settings
        enabled_tabs_keys = [t[0] for t in available_tabs if config.get("tabs", {}).get(t[0], True)]
        
        raw_pinned = config.get("pinned_tabs", [])
        # Unique pins that are actually enabled
        pinned = []
        for p in raw_pinned:
            if p in enabled_tabs_keys and p not in pinned:
                pinned.append(p)
        
        usage = config.get("tab_usage", {})
        # Sort usage keys by frequency, but exclude what's already in pinned
        sorted_usage_keys = sorted(usage.keys(), key=lambda k: usage[k], reverse=True)
        most_used = [k for k in sorted_usage_keys if k in enabled_tabs_keys and k not in pinned]
        
        # Combine pinned + most used, limit to 5
        shortcuts_keys = (pinned + most_used)[:5]
        
        # Build icons
        for key in shortcuts_keys:
            # Find icon for this key
            icon_data = next((t for t in available_tabs if t[0] == key), None)
            if icon_data:
                _, label, icon, _ = icon_data
                
                def jump_to_tab(e, k=key):
                    # Find index of this key in active_tabs (filter by enabled state)
                    try:
                        active_keys = [t[0] for t in available_tabs if config.get("tabs", {}).get(t[0], True)]
                        idx = active_keys.index(k)
                        tabs_control.selected_index = idx
                        page.update()
                        handle_tab_change(None) 
                    except ValueError:
                        pass

                quick_access_bar.controls.append(
                    ft.IconButton(
                        icon=icon,
                        icon_size=28,
                        tooltip=label,
                        on_click=jump_to_tab,
                        visual_density=ft.VisualDensity.COMPACT
                    )
                )
        page.update()

    def handle_tab_change(e):
        # Tracking logic
        current_idx = tabs_control.selected_index
        # Get the key of the active tab
        active_keys = [t[0] for t in available_tabs if config.get("tabs", {}).get(t[0], True)]
        if current_idx < len(active_keys):
            active_key = active_keys[current_idx]
            usage = config.get("tab_usage", {})
            usage[active_key] = usage.get(active_key, 0) + 1
            config["tab_usage"] = usage
            save_config(config)
            update_quick_access()

    tabs_control = ft.Tabs(
        length=len(active_tabs),
        animation_duration=300,
        on_change=handle_tab_change,
        content=ft.Column([
            ft.TabBar(tabs=active_tabs, scrollable=True),
            ft.TabBarView(controls=active_controls, expand=True)
        ], expand=True),
        expand=True
    )
    
    # Initial build of quick access
    update_quick_access()

    def open_settings(e):
        async def save_settings(new_config):
            save_config(new_config)
            page.snack_bar = ft.SnackBar(ft.Text("Settings saved! Restarting app..."))
            page.snack_bar.open = True
            page.update()
            
            # Close the window before restarting to avoid ghosts
            await page.window.close()
            restart_app()

        dlg = SettingsDialog(config, save_settings)
        page.overlay.append(dlg)
        dlg.open = True
        page.update()

    page.add(
        ft.Column([
            ft.Row([
                # Left Column: Logo & Title
                ft.Row([
                    ft.Icon(ft.Icons.HUB, color=ft.Colors.CYAN_400, size=30),
                    ft.Text("OpsNexus", size=20, weight="bold", color=ft.Colors.BLUE_400),
                ], spacing=10, expand=True, alignment=ft.MainAxisAlignment.START),
                
                # Center Column: Shortcuts
                ft.Row([quick_access_bar], alignment=ft.MainAxisAlignment.CENTER, expand=True),
                
                # Right Column: Settings & Version
                ft.Row([
                    ft.IconButton(ft.Icons.SETTINGS, tooltip="Settings", on_click=open_settings),
                    ft.Text("v1.1", size=10, color=ft.Colors.GREY_500)
                ], spacing=5, expand=True, alignment=ft.MainAxisAlignment.END)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            timezone_bar,
            ft.Divider(height=1),
            tabs_control
        ], expand=True, spacing=10)
    )

    async def tick():
        while True:
            try:
                for clock in clocks:
                    clock.update_time()
                page.update()
                await asyncio.sleep(1)
            except Exception:
                break

    # Start clock task
    asyncio.create_task(tick())

# Suppress the Flet clipboard deprecation warning for now 
# since the suggested replacement (ft.Clipboard) is not recognized by the client.
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*clipboard is deprecated.*")

ft.run(main, assets_dir="assets")
