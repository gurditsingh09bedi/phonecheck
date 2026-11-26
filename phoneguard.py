#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhoneGuard - Android privacy scanner + live camera / mic / location monitor
===========================================================================

What it does (over USB debugging / ADB, no app installed on the phone):
  1. FULL SCAN  -> lists every 3rd-party app, where it was installed from,
                   every permission it has (camera, mic, location, SMS, ...),
                   special access (accessibility, device admin, notification
                   reading, draw-over-apps, usage access, install apps),
                   hidden apps (no icon), when each app LAST used camera/mic/
                   location/clipboard and whether it was in the BACKGROUND,
                   plus phone-level security checks. Produces an HTML report.
  2. LIVE MONITOR -> watches in real time and alerts you the moment any app
                   starts using the camera, microphone or GPS - and shouts
                   loudly if that app is NOT on your screen (background use).

Requirements: Python 3.8+ and Android "platform-tools" (adb). No pip installs.
Works on Windows, macOS and Linux. Android 8+ (best on Android 10+).

Usage:
    python phoneguard.py              # simple menu
    python phoneguard.py scan         # full scan + HTML report
    python phoneguard.py monitor      # live camera/mic/GPS monitor
    python phoneguard.py scan --include-system
    python phoneguard.py monitor --interval 2 --minutes 60

This tool only READS information. It never changes, uninstalls or uploads
anything. All reports stay on your computer.
"""

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import webbrowser

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Console helpers
# --------------------------------------------------------------------------
if os.name == "nt":
    os.system("")  # enables ANSI colours on Windows 10+
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

_C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m",
      "m": "\033[95m", "c": "\033[96m", "d": "\033[2m", "B": "\033[1m",
      "x": "\033[0m"}
if not sys.stdout.isatty():
    _C = {k: "" for k in _C}


def c(text, *styles):
    return "".join(_C[s] for s in styles) + str(text) + _C["x"]


def info(msg):
    print(c("[*] ", "c") + msg)


def ok(msg):
    print(c("[+] ", "g") + msg)


def warn(msg):
    print(c("[!] ", "y") + msg)


def bad(msg):
    print(c("[X] ", "r", "B") + msg)


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------
# permission -> (friendly label, category, risk weight)
RUNTIME_PERMS = {
    "android.permission.CAMERA": ("Camera", "camera", 3),
    "android.permission.RECORD_AUDIO": ("Microphone", "mic", 3),
    "android.permission.ACCESS_FINE_LOCATION": ("Precise location", "location", 2),
    "android.permission.ACCESS_COARSE_LOCATION": ("Approx. location", "location", 1),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Location ALL the time (background)", "location", 3),
    "android.permission.READ_SMS": ("Read SMS", "sms", 3),
    "android.permission.RECEIVE_SMS": ("Receive SMS / OTP", "sms", 2),
    "android.permission.SEND_SMS": ("Send SMS", "sms", 3),
    "android.permission.RECEIVE_MMS": ("Receive MMS", "sms", 1),
    "android.permission.READ_CONTACTS": ("Read contacts", "contacts", 1),
    "android.permission.WRITE_CONTACTS": ("Edit contacts", "contacts", 1),
    "android.permission.GET_ACCOUNTS": ("See accounts on phone", "contacts", 1),
    "android.permission.READ_CALL_LOG": ("Read call history", "calls", 2),
    "android.permission.WRITE_CALL_LOG": ("Edit call history", "calls", 2),
    "android.permission.PROCESS_OUTGOING_CALLS": ("See outgoing calls", "calls", 2),
    "android.permission.CALL_PHONE": ("Make phone calls", "calls", 1),
    "android.permission.ANSWER_PHONE_CALLS": ("Answer calls", "calls", 1),
    "android.permission.READ_PHONE_STATE": ("Phone status & IDs", "phone", 1),
    "android.permission.READ_PHONE_NUMBERS": ("Read your phone number", "phone", 1),
    "android.permission.BODY_SENSORS": ("Body sensors", "sensors", 1),
    "android.permission.BODY_SENSORS_BACKGROUND": ("Body sensors (background)", "sensors", 2),
    "android.permission.ACTIVITY_RECOGNITION": ("Physical activity", "sensors", 0),
    "android.permission.READ_CALENDAR": ("Read calendar", "calendar", 1),
    "android.permission.WRITE_CALENDAR": ("Edit calendar", "calendar", 0),
    "android.permission.READ_EXTERNAL_STORAGE": ("Files & media", "storage", 1),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Write files", "storage", 1),
    "android.permission.READ_MEDIA_IMAGES": ("Photos", "storage", 1),
    "android.permission.READ_MEDIA_VIDEO": ("Videos", "storage", 1),
    "android.permission.READ_MEDIA_AUDIO": ("Music & audio files", "storage", 0),
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED": ("Selected photos only", "storage", 0),
    "android.permission.ACCESS_MEDIA_LOCATION": ("Location inside photos", "storage", 1),
    "android.permission.BLUETOOTH_SCAN": ("Scan nearby Bluetooth", "nearby", 0),
    "android.permission.BLUETOOTH_CONNECT": ("Connect Bluetooth", "nearby", 0),
    "android.permission.NEARBY_WIFI_DEVICES": ("Nearby Wi-Fi devices", "nearby", 0),
    "android.permission.UWB_RANGING": ("Ultra-wideband", "nearby", 0),
}

# install-time permissions worth showing
INSTALL_PERMS = {
    "android.permission.QUERY_ALL_PACKAGES": ("Sees list of all your apps", 1),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Starts automatically at boot", 0),
    "android.permission.FOREGROUND_SERVICE_CAMERA": ("Camera in a background service", 1),
    "android.permission.FOREGROUND_SERVICE_MICROPHONE": ("Mic in a background service", 1),
    "android.permission.FOREGROUND_SERVICE_LOCATION": ("Location in a background service", 1),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("Avoids battery limits (keeps running)", 0),
    "android.permission.READ_LOGS": ("Read system logs", 3),
    "android.permission.CHANGE_WIFI_STATE": ("Change Wi-Fi", 0),
}

# special app-ops that the user grants on a separate settings screen
SPECIAL_OPS = {
    "SYSTEM_ALERT_WINDOW": ("Draw over other apps", 2),
    "GET_USAGE_STATS": ("Usage access (sees which apps you use)", 3),
    "REQUEST_INSTALL_PACKAGES": ("Can install other apps", 3),
    "MANAGE_EXTERNAL_STORAGE": ("All-files access", 2),
    "WRITE_SETTINGS": ("Modify system settings", 1),
    "PICTURE_IN_PICTURE": None,  # ignore
}

# usage-history ops tracked for every app
USAGE_OPS = {
    "CAMERA": "Camera",
    "RECORD_AUDIO": "Microphone",
    "FINE_LOCATION": "Precise location",
    "COARSE_LOCATION": "Approx. location",
    "READ_CLIPBOARD": "Read clipboard",
}

STORES = {
    "com.android.vending": "Google Play Store",
    "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
    "com.amazon.venezia": "Amazon Appstore",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.xiaomi.market": "Xiaomi GetApps",
    "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.heytap.market": "OPPO / Realme App Market",
    "com.oppo.market": "OPPO App Market",
    "com.bbk.appstore": "vivo App Store",
    "com.oneplus.store": "OnePlus Store",
    "com.google.android.feedback": "Google Play (legacy)",
    "com.android.managedprovisioning": "Work profile / company (MDM)",
    "com.google.android.apps.work.clouddpc": "Company device policy (MDM)",
}
APK_INSTALLERS = {
    "com.google.android.packageinstaller", "com.android.packageinstaller",
    "com.samsung.android.packageinstaller", "com.miui.packageinstaller",
    "com.android.shell", "adb",
}

# system packages that legitimately hold accessibility / admin etc.
TRUSTED_PREFIXES = ("com.google.android.", "com.android.", "android",
                    "com.samsung.", "com.sec.", "com.miui.", "com.xiaomi.",
                    "com.oneplus.", "com.oplus.", "com.coloros.", "com.vivo.",
                    "com.huawei.", "com.motorola.", "com.realme.")

SEP = "__PG_SEP__"
PKG_RE = r"[A-Za-z][\w]*(?:\.[\w]+)+"


# --------------------------------------------------------------------------
# ADB wrapper
# --------------------------------------------------------------------------
def find_adb():
    here = os.path.dirname(os.path.abspath(__file__))
    exe = "adb.exe" if os.name == "nt" else "adb"
    cands = [os.path.join(here, "platform-tools", exe), os.path.join(here, exe)]
    p = shutil.which("adb")
    if p:
        cands.append(p)
    home = os.path.expanduser("~")
    cands += [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", exe),
        os.path.join(home, "Library", "Android", "sdk", "platform-tools", exe),
        os.path.join(home, "Android", "Sdk", "platform-tools", exe),
        os.path.join(home, "platform-tools", exe),
        os.path.join(home, "Downloads", "platform-tools", exe),
        "C:\\platform-tools\\adb.exe",
    ]
    for cand in cands:
        if cand and os.path.isfile(cand):
            return cand
    return None


class ADB:
    def __init__(self, adb_path, serial=None):
        self.adb = adb_path
        self.serial = serial

    def run(self, args, timeout=90):
        cmd = [self.adb] + (["-s", self.serial] if self.serial else []) + args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
            return (r.stdout or "") + ("" if r.returncode == 0 else (r.stderr or ""))
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""

    def sh(self, command, timeout=90):
        return self.run(["shell", command], timeout=timeout)

    def multi(self, commands, timeout=90):
        """Run several shell commands in one round-trip; returns list of outputs."""
        joined = ("; echo " + SEP + "; ").join(commands)
        out = self.sh(joined, timeout=timeout)
        parts = out.split(SEP)
        parts += [""] * (len(commands) - len(parts))
        return [p.strip("\r\n") for p in parts[:len(commands)]]


def connect(serial=None):
    adb_path = find_adb()
    if not adb_path:
        bad("adb nahi mila (adb not found).")
        print("   Download 'SDK Platform-Tools': https://developer.android.com/tools/releases/platform-tools")
        print("   Zip ko extract karke 'platform-tools' folder ko is script ke saath wale folder me rakh do.")
        sys.exit(1)
    a = ADB(adb_path)
    a.run(["start-server"], timeout=30)
    out = a.run(["devices"], timeout=30)
    devs = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devs.append((parts[0], parts[1]))
    if serial:
        devs = [d for d in devs if d[0] == serial]
    if not devs:
        bad("Koi phone connect nahi hai (no device found).")
        print("   1) Phone par Developer options -> USB debugging ON karo")
        print("   2) USB cable se computer se jodo (charging-only cable nahi chalegi)")
        print("   3) Phone par 'Allow USB debugging?' aaye to ALLOW dabao")
        sys.exit(1)
    unauth = [d for d in devs if d[1] == "unauthorized"]
    good = [d for d in devs if d[1] == "device"]
    if not good:
        if unauth:
            bad("Phone ne permission nahi di (unauthorized).")
            print("   Phone unlock karo aur 'Allow USB debugging' popup par ALLOW dabao, phir dobara chalao.")
        else:
            bad("Device state: " + ", ".join(d[1] for d in devs))
        sys.exit(1)
    if len(good) > 1 and not serial:
        warn("Ek se zyada phone mile, pehla use kar raha hoon: %s  (use --serial to choose)" % good[0][0])
    a.serial = good[0][0]
    return a


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------
def parse_duration(s):
    """'-1d2h3m4s5ms' / '+3h ago' -> seconds (float)."""
    if not s:
        return None
    total = 0.0
    found = False
    for num, unit in re.findall(r"(\d+)(ms|d|h|m|s)", s):
        found = True
        n = int(num)
        total += {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit] * n
    return total if found else None


def ago(seconds):
    if seconds is None:
        return "-"
    s = int(seconds)
    if s < 60:
        return "%ds ago" % s
    if s < 3600:
        return "%dm ago" % (s // 60)
    if s < 86400:
        return "%dh %dm ago" % (s // 3600, (s % 3600) // 60)
    return "%dd %dh ago" % (s // 86400, (s % 86400) // 3600)


def parse_appops(text, default_pkg=None):
    """
    Parses output of `appops get <pkg>` or `dumpsys appops [--op X]` (all
    Android versions, best effort).
    Returns {pkg: {OP: {"mode", "last_s", "last_abs", "states", "rejects",
                        "reject_last_s", "running", "count"}}}
    """
    result = {}
    pkg = default_pkg
    op = None
    op_re = re.compile(r"^\s*(?:Uid mode:\s*)?([A-Z][A-Z0-9_]+)(?:\s*\((\w+)\))?:\s*(?:mode=)?(\w+)?(.*)$")
    for raw in text.splitlines():
        line = raw.rstrip()
        m = re.match(r"^\s*Package (" + PKG_RE + r"):\s*$", line)
        if m:
            pkg = m.group(1)
            op = None
            continue
        if re.match(r"^\s*Uid \S+:\s*$", line):
            pkg = default_pkg
            op = None
            continue
        m = op_re.match(line)
        if m and pkg:
            name = m.group(1)
            mode = m.group(2) or m.group(3)
            rest = m.group(4) or ""
            if mode and mode.lower() not in ("allow", "ignore", "deny", "default",
                                             "foreground", "errored", "ask"):
                mode = None
            d = result.setdefault(pkg, {}).setdefault(name, {
                "mode": None, "last_s": None, "last_abs": None, "states": set(),
                "rejects": 0, "reject_last_s": None, "running": False, "count": 0})
            if mode and not d["mode"]:
                d["mode"] = mode.lower()
            op = name
            # old inline format: CAMERA: allow; time=+1h2m ago; duration=+3s; rejectTime=+5m ago
            t = re.search(r"\btime=\+?([0-9dhms]+) ago", rest)
            if t:
                _update_last(d, parse_duration(t.group(1)), None, None)
            rt = re.search(r"rejectTime=\+?([0-9dhms]+) ago", rest)
            if rt:
                d["rejects"] += 1
                _update_reject(d, parse_duration(rt.group(1)))
            if "running" in rest.lower():
                d["running"] = True
            continue
        if op and pkg and pkg in result and op in result[pkg]:
            d = result[pkg][op]
            low = line.lower()
            if "access:" in low:
                rel = re.search(r"\(-([0-9dhms]+)\)", line)
                ab = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
                st = re.search(r"\[([a-z\-]+)\]", line)
                _update_last(d, parse_duration(rel.group(1)) if rel else None,
                             ab.group(1) if ab else None,
                             st.group(1) if st else None)
            elif "reject:" in low:
                d["rejects"] += 1
                rel = re.search(r"\(-([0-9dhms]+)\)", line)
                _update_reject(d, parse_duration(rel.group(1)) if rel else None)
            if "running" in low and "=false" not in low:
                d["running"] = True
    return result


def _update_last(d, secs, abs_t, state):
    d["count"] += 1
    if state:
        d["states"].add(state.replace("-s", "").replace("-", ""))
    if secs is not None and (d["last_s"] is None or secs < d["last_s"]):
        d["last_s"] = secs
        d["last_abs"] = abs_t


def _update_reject(d, secs):
    if secs is not None and (d["reject_last_s"] is None or secs < d["reject_last_s"]):
        d["reject_last_s"] = secs


def parse_package_dump(text):
    """Parses `dumpsys package <pkg>`."""
    info_ = {"version": None, "target_sdk": None, "first_install": None,
             "last_update": None, "requested": [], "install_granted": [],
             "runtime_granted": [], "runtime_denied": [], "system": False,
             "enabled": True}
    m = re.search(r"versionName=(\S+)", text)
    info_["version"] = m.group(1) if m else None
    m = re.search(r"targetSdk=(\d+)", text)
    info_["target_sdk"] = int(m.group(1)) if m else None
    m = re.search(r"firstInstallTime=([\d\- :]+)", text)
    info_["first_install"] = m.group(1).strip() if m else None
    m = re.search(r"lastUpdateTime=([\d\- :]+)", text)
    info_["last_update"] = m.group(1).strip() if m else None
    if re.search(r"pkgFlags=\[[^\]]*\bSYSTEM\b", text):
        info_["system"] = True
    m = re.search(r"\benabled=(\d)", text)
    if m and m.group(1) in ("2", "3", "4"):
        info_["enabled"] = False

    section = None
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith("requested permissions:"):
            section = "req"
            continue
        if low.startswith("install permissions:"):
            section = "install"
            continue
        if low.startswith("runtime permissions:"):
            section = "runtime"
            continue
        if low.endswith(":") and "." not in line:
            section = None if section == "req" else section
        g = re.match(r"^(" + PKG_RE + r"): granted=(true|false)", line)
        if g:
            perm, granted = g.group(1), g.group(2) == "true"
            if section == "install":
                if granted:
                    info_["install_granted"].append(perm)
            else:
                (info_["runtime_granted"] if granted else info_["runtime_denied"]).append(perm)
            continue
        if section == "req":
            r = re.match(r"^(" + PKG_RE + r")(?:[:,].*)?$", line)
            if r:
                info_["requested"].append(r.group(1))
            else:
                section = None
    for k in ("requested", "install_granted", "runtime_granted", "runtime_denied"):
        info_[k] = sorted(set(info_[k]))
    # some permissions are "granted=true" in runtime of one user only; fine.
    return info_


def components_to_pkgs(value):
    pkgs = []
    if not value or value.strip() in ("null", ""):
        return pkgs
    for part in re.split(r"[:,]", value.strip()):
        part = part.strip()
        if "/" in part:
            pkgs.append(part.split("/")[0])
        elif re.match(PKG_RE + "$", part):
            pkgs.append(part)
    return sorted(set(pkgs))


def installer_label(inst):
    if not inst or inst == "null":
        return "Unknown / APK sideload", True
    if inst in STORES:
        return STORES[inst], False
    if inst in APK_INSTALLERS:
        return "Installed from APK file", True
    return "Installed by app: " + inst, True


# --------------------------------------------------------------------------
# FULL SCAN
# --------------------------------------------------------------------------
def scan(a, include_system=False, out_dir=None, open_report=True):
    t0 = time.time()
    print()
    print(c("=" * 64, "c"))
    print(c("  PhoneGuard %s  -  FULL PRIVACY SCAN" % VERSION, "B", "c"))
    print(c("=" * 64, "c"))

    # ---- device info -----------------------------------------------------
    info("Phone ki details le raha hoon...")
    props = a.multi([
        "getprop ro.product.manufacturer", "getprop ro.product.model",
        "getprop ro.build.version.release", "getprop ro.build.version.sdk",
        "getprop ro.build.version.security_patch", "getprop ro.build.display.id",
        "getprop ro.crypto.state", "getprop ro.boot.verifiedbootstate",
        "getprop ro.boot.flash.locked", "getprop ro.debuggable",
        "which su; ls /system/xbin/su /system/bin/su /sbin/su 2>/dev/null",
        "settings get global development_settings_enabled",
        "settings get global http_proxy", "settings get secure always_on_vpn_app",
        "ls /sys/class/net 2>/dev/null",
        "settings get secure install_non_market_apps",
        "settings get global package_verifier_user_consent",
        "pm list packages -s | wc -l",
    ])
    (manu, model, rel, sdk, patch, build, crypto, vboot, flashlock, debuggable,
     su, devopts, proxy, aovpn, netifs, nonmarket, verifier, nsys) = props
    try:
        sdk_i = int(sdk.strip())
    except ValueError:
        sdk_i = 0
    device = {
        "manufacturer": manu.strip(), "model": model.strip(),
        "android": rel.strip(), "sdk": sdk_i, "security_patch": patch.strip(),
        "build": build.strip(), "serial": a.serial,
        "scanned_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    ok("%s %s  |  Android %s (SDK %s)  |  Security patch %s" % (
        device["manufacturer"], device["model"], device["android"], sdk_i, device["security_patch"]))

    # ---- phone-level security checks ------------------------------------
    sec = []  # (level, title, detail)
    try:
        pd = dt.datetime.strptime(device["security_patch"], "%Y-%m-%d")
        age = (dt.datetime.now() - pd).days
        if age > 365:
            sec.append(("high", "Security update bahut purana hai",
                        "Last patch %s (%d days old). Settings > Software update check karo." % (device["security_patch"], age)))
        elif age > 180:
            sec.append(("medium", "Security update purana hai",
                        "Last patch %s (%d days old)." % (device["security_patch"], age)))
        else:
            sec.append(("ok", "Security patch recent hai", device["security_patch"]))
    except ValueError:
        pass
    if su.strip() and "not found" not in su.lower() and "/su" in su:
        sec.append(("high", "Phone ROOTED lagta hai",
                    "'su' binary mila: %s. Rooted phone par koi bhi app sab kuch dekh sakta hai." % su.strip().splitlines()[0]))
    if vboot.strip() in ("orange", "yellow", "red"):
        sec.append(("high", "Bootloader unlocked / verified boot = %s" % vboot.strip(),
                    "Phone ka software modify ho sakta hai. Agar aapne khud unlock nahi kiya to serious hai."))
    if flashlock.strip() == "0":
        sec.append(("medium", "Bootloader unlocked (flash.locked=0)", ""))
    if debuggable.strip() == "1":
        sec.append(("medium", "ro.debuggable=1 (debug build)", "Normal phones par 0 hota hai."))
    if crypto.strip() and crypto.strip() not in ("encrypted",):
        sec.append(("medium", "Storage encryption: %s" % crypto.strip(), ""))
    p = proxy.strip()
    if p and p not in ("null", ":0", ""):
        sec.append(("high", "Wi-Fi / global PROXY set hai: %s" % p,
                    "Proxy se aapka internet traffic kisi aur server se ho kar ja sakta hai. Agar aapne set nahi kiya to hatao."))
    v = aovpn.strip()
    if v and v != "null":
        sec.append(("medium", "Always-on VPN app: %s" % v, "Saara traffic is app se guzarta hai."))
    if re.search(r"\b(tun\d+|ppp\d+)\b", netifs):
        sec.append(("info", "Abhi koi VPN chal raha hai", "Interface: " + ", ".join(re.findall(r"\b(?:tun|ppp)\d+\b", netifs))))
    if nonmarket.strip() == "1":
        sec.append(("medium", "Unknown sources ON (old setting)", "Bahar se APK install ho sakte hain."))
    sec.append(("info", "USB debugging ON hai", "Scan ke baad Settings > Developer options me USB debugging OFF kar dena."))

    # ---- apps list -------------------------------------------------------
    info("Apps ki list nikal raha hoon...")
    third_raw = a.sh("pm list packages -3 -i")
    third = {}
    for line in third_raw.splitlines():
        m = re.match(r"package:(\S+)(?:\s+installer=(\S+))?", line.strip())
        if m:
            third[m.group(1)] = m.group(2)
    if not third:
        # fallback without installer flag
        for line in a.sh("pm list packages -3").splitlines():
            if line.startswith("package:"):
                third[line[8:].strip()] = None
    all_pkgs = set()
    for line in a.sh("pm list packages").splitlines():
        if line.startswith("package:"):
            all_pkgs.add(line[8:].strip())
    ok("%d third-party apps, %d total apps" % (len(third), len(all_pkgs)))

    # launcher (visible icon) apps
    lr = a.sh("cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER")
    launcher = set(re.findall(r"^\s*(" + PKG_RE + r")/", lr, re.M)) | set(re.findall(r"packageName=(" + PKG_RE + r")", lr))
    if not launcher:
        lr = a.sh("cmd package query-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER")
        launcher = set(re.findall(r"packageName=(" + PKG_RE + r")", lr))
    launcher_ok = len(launcher) > 3

    # ---- special access --------------------------------------------------
    info("Special access check (accessibility, device admin, notifications, keyboard)...")
    sp = a.multi([
        "settings get secure enabled_accessibility_services",
        "settings get secure enabled_notification_listeners",
        "settings get secure default_input_method",
        "settings get secure enabled_input_methods",
        "dumpsys device_policy",
        "cmd role get-role-holders android.app.role.SMS",
        "cmd role get-role-holders android.app.role.DIALER",
        "cmd role get-role-holders android.app.role.ASSISTANT",
        "cmd role get-role-holders android.app.role.HOME",
        "settings get secure sms_default_application",
        "settings get secure voice_interaction_service",
    ])
    access_pkgs = components_to_pkgs(sp[0])
    notif_pkgs = components_to_pkgs(sp[1])
    ime_default = components_to_pkgs(sp[2])
    ime_enabled = components_to_pkgs(sp[3])
    admin_pkgs = set()
    dp = sp[4]
    for m in re.finditer(r"ComponentInfo\{(" + PKG_RE + r")/", dp):
        admin_pkgs.add(m.group(1))
    in_admin = False
    for line in dp.splitlines():
        if "Enabled Device Admins" in line or "Active admin" in line.lower():
            in_admin = True
            continue
        if in_admin:
            m = re.match(r"^\s+(" + PKG_RE + r")/[\w.$]+:?\s*$", line)
            if m:
                admin_pkgs.add(m.group(1))
            elif line.strip() and not line.startswith("    ") and not line.startswith("\t"):
                in_admin = False
    device_owner = re.findall(r"Device Owner:.*?package=(" + PKG_RE + r")", dp, re.S)
    profile_owner = re.findall(r"Profile Owner.*?package=(" + PKG_RE + r")", dp, re.S)

    def role(txt):
        r = [x.strip() for x in txt.splitlines() if re.match(PKG_RE + "$", x.strip())]
        return r
    roles = {
        "SMS app": role(sp[5]) or components_to_pkgs(sp[9]),
        "Phone/Dialer app": role(sp[6]),
        "Assistant": role(sp[7]) or components_to_pkgs(sp[10]),
        "Home launcher": role(sp[8]),
    }
    special = {
        "accessibility": access_pkgs, "notification_listeners": notif_pkgs,
        "keyboard_default": ime_default, "keyboards_enabled": ime_enabled,
        "device_admins": sorted(admin_pkgs), "device_owner": sorted(set(device_owner)),
        "profile_owner": sorted(set(profile_owner)), "roles": roles,
    }
    if device_owner:
        sec.append(("high", "Phone kisi company/app ke control me hai (Device Owner)",
                    ", ".join(set(device_owner)) + " - agar ye aapki company ka phone nahi hai to bahut serious hai."))

    # ---- usage history for ALL apps (camera / mic / location / clipboard) -
    info("Camera / Mic / Location / Clipboard ka usage history padh raha hoon...")
    ops_out = a.multi(["dumpsys appops --op %s" % op for op in USAGE_OPS], timeout=120)
    usage = {}  # pkg -> op -> data
    for op, txt in zip(USAGE_OPS, ops_out):
        parsed = parse_appops(txt)
        for pkg, opsd in parsed.items():
            if op in opsd:
                usage.setdefault(pkg, {})[op] = opsd[op]

    # ---- per-app details -------------------------------------------------
    targets = sorted(third)
    if include_system:
        targets += sorted(all_pkgs - set(third))
    apps = []
    n = len(targets)
    info("Har app ki permissions check kar raha hoon (%d apps, thoda time lagega)..." % n)
    for i, pkg in enumerate(targets, 1):
        _progress(i, n, pkg)
        dump, ops_txt = a.multi(["dumpsys package %s" % pkg, "appops get %s" % pkg], timeout=60)
        pinfo = parse_package_dump(dump)
        per_ops = parse_appops(ops_txt, default_pkg=pkg).get(pkg, {})
        is_third = pkg in third
        inst = third.get(pkg) if is_third else "system"
        ilabel, risky_src = installer_label(inst) if is_third else ("Pre-installed (system)", False)
        app = {
            "package": pkg, "third_party": is_third, "installer": inst,
            "installer_label": ilabel, "risky_source": risky_src,
            "has_icon": (pkg in launcher) if launcher_ok else None,
            **pinfo,
            "special_ops": {}, "usage": {}, "flags": [], "score": 0,
        }
        for op, meta in SPECIAL_OPS.items():
            if meta and op in per_ops and per_ops[op]["mode"] == "allow":
                app["special_ops"][op] = meta[0]
        u = dict(usage.get(pkg, {}))
        for op in USAGE_OPS:
            if op not in u and op in per_ops and (per_ops[op]["last_s"] is not None or per_ops[op]["rejects"]):
                u[op] = per_ops[op]
        app["usage"] = {op: _usage_json(d) for op, d in u.items()}
        _score(app, special)
        apps.append(app)
    print()

    # system apps that used camera / mic recently (even if not included)
    sys_usage = []
    for pkg, opsd in usage.items():
        if pkg in third or include_system:
            continue
        for op in ("CAMERA", "RECORD_AUDIO"):
            d = opsd.get(op)
            if d and d["last_s"] is not None and d["last_s"] < 7 * 86400:
                sys_usage.append({"package": pkg, "op": USAGE_OPS[op],
                                  **_usage_json(d)})
    sys_usage.sort(key=lambda x: x["last_s"] if x["last_s"] is not None else 1e12)

    apps.sort(key=lambda x: (-x["score"], x["package"]))

    # ---- summary ---------------------------------------------------------
    report = {"tool": "PhoneGuard", "version": VERSION, "device": device,
              "security": [{"level": l, "title": t, "detail": d} for l, t, d in sec],
              "special_access": special, "apps": apps,
              "system_recent_cam_mic": sys_usage,
              "scan_seconds": round(time.time() - t0, 1)}
    _print_summary(report)

    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = "PhoneGuard_%s_%s" % (re.sub(r"\W+", "_", device["model"] or "phone"), stamp)
    jpath = os.path.join(out_dir, base + ".json")
    hpath = os.path.join(out_dir, base + ".html")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=list)
    with open(hpath, "w", encoding="utf-8") as f:
        f.write(render_html(report))
    print()
    ok("Report ready: " + c(hpath, "B"))
    ok("Raw data   : " + jpath)
    if open_report:
        try:
            webbrowser.open("file://" + os.path.abspath(hpath))
        except Exception:
            pass
    return report


def _progress(i, n, pkg):
    w = 30
    done = int(w * i / max(n, 1))
    sys.stdout.write("\r   [%s%s] %d/%d %-45s" % ("#" * done, "." * (w - done), i, n, pkg[:45]))
    sys.stdout.flush()


def _usage_json(d):
    return {"mode": d["mode"], "last_s": d["last_s"], "last_ago": ago(d["last_s"]),
            "last_abs": d["last_abs"], "states": sorted(d["states"]),
            "background": any(s.startswith(("bg", "cch", "cached")) for s in d["states"]),
            "fg_service": any(s.startswith("fgsvc") for s in d["states"]),
            "rejects": d["rejects"], "reject_ago": ago(d["reject_last_s"]) if d["reject_last_s"] is not None else None,
            "running": d["running"]}


def _score(app, special):
    flags = []  # (weight, level, text)
    pkg = app["package"]
    trusted = pkg.startswith(TRUSTED_PREFIXES) and not app["third_party"]
    for perm in app["runtime_granted"]:
        if perm in RUNTIME_PERMS:
            label, cat, w = RUNTIME_PERMS[perm]
            if w:
                flags.append((w, "perm", "Permission: " + label))
    for perm in app["install_granted"]:
        if perm in INSTALL_PERMS and INSTALL_PERMS[perm][1]:
            flags.append((INSTALL_PERMS[perm][1], "perm", INSTALL_PERMS[perm][0]))
    for op, label in app["special_ops"].items():
        flags.append((SPECIAL_OPS[op][1], "special", "Special access: " + label))
    if pkg in special["accessibility"]:
        flags.append((5, "danger", "ACCESSIBILITY ON - screen padh sakta hai, aapki jagah tap/type kar sakta hai"))
    if pkg in special["device_admins"]:
        flags.append((4, "danger", "DEVICE ADMIN - phone lock/wipe kar sakta hai, uninstall rok sakta hai"))
    if pkg in special["notification_listeners"]:
        flags.append((3, "danger", "Saari NOTIFICATIONS padh sakta hai (OTP, WhatsApp messages)"))
    if pkg in special["keyboards_enabled"] and app["third_party"]:
        flags.append((3, "danger", "Keyboard app - jo bhi type karte ho dekh sakta hai"))
    if pkg in special.get("device_owner", []):
        flags.append((6, "danger", "DEVICE OWNER - poore phone ko control karta hai"))
    if app["risky_source"]:
        flags.append((3, "source", "Play Store se nahi aaya: " + app["installer_label"]))
    if app["has_icon"] is False and app["third_party"]:
        flags.append((4, "danger", "HIDDEN APP - home screen par icon nahi hai"))
    for op, u in app["usage"].items():
        label = USAGE_OPS.get(op, op)
        if u["running"]:
            flags.append((3, "usage", "%s ABHI use ho raha hai (scan ke time)" % label))
        if u["background"] and op in ("CAMERA", "RECORD_AUDIO"):
            flags.append((4, "danger", "%s BACKGROUND me use kiya (%s)" % (label, u["last_ago"])))
        elif u["background"] and op in ("FINE_LOCATION",):
            flags.append((1, "usage", "Location background me li (%s)" % u["last_ago"]))
        if u["rejects"] and op in ("CAMERA", "RECORD_AUDIO"):
            flags.append((2, "usage", "%s use karne ki koshish ki par block hua (%s)" % (label, u["reject_ago"] or "")))
        if op == "READ_CLIPBOARD" and u["last_s"] is not None and u["background"]:
            flags.append((2, "usage", "Clipboard background me padha (%s)" % u["last_ago"]))
    has = set(app["runtime_granted"])
    if {"android.permission.CAMERA", "android.permission.RECORD_AUDIO"} <= has and \
            ("android.permission.ACCESS_BACKGROUND_LOCATION" in has or "android.permission.READ_SMS" in has):
        flags.append((2, "combo", "Combo: camera + mic + (SMS/always-location) - spy apps jaisa pattern"))
    score = sum(f[0] for f in flags)
    if trusted:
        score = score // 2
    app["flags"] = [{"weight": w, "kind": k, "text": t} for w, k, t in sorted(flags, key=lambda x: -x[0])]
    app["score"] = score
    dangers = sum(1 for f in flags if f[1] == "danger")
    if dangers >= 2 or (score >= 16 and (dangers >= 1 or app["risky_source"])):
        app["level"] = "HIGH"
    elif score >= 8 or dangers == 1:
        app["level"] = "MEDIUM"
    else:
        app["level"] = "LOW"


def _print_summary(r):
    apps = r["apps"]
    print()
    print(c("-" * 64, "c"))
    print(c("  RESULT SUMMARY", "B"))
    print(c("-" * 64, "c"))
    for s in r["security"]:
        if s["level"] == "high":
            bad(s["title"])
        elif s["level"] == "medium":
            warn(s["title"])
    tp = [a for a in apps if a["third_party"]]
    cam = [a for a in tp if "android.permission.CAMERA" in a["runtime_granted"]]
    mic = [a for a in tp if "android.permission.RECORD_AUDIO" in a["runtime_granted"]]
    print("   Third-party apps            : %d" % len(tp))
    print("   Apps with CAMERA permission : %d" % len(cam))
    print("   Apps with MIC permission    : %d" % len(mic))
    print("   Not from Play Store         : %d" % sum(1 for a in tp if a["risky_source"]))
    print("   Hidden apps (no icon)       : %d" % sum(1 for a in tp if a["has_icon"] is False))
    sa = r["special_access"]
    print("   Accessibility ON            : %s" % (", ".join(sa["accessibility"]) or "none"))
    print("   Reads notifications         : %s" % (", ".join(sa["notification_listeners"]) or "none"))
    print("   Device admins               : %s" % (", ".join(sa["device_admins"]) or "none"))
    print()
    recent = []
    for a in apps:
        for op in ("CAMERA", "RECORD_AUDIO"):
            u = a["usage"].get(op)
            if u and u["last_s"] is not None and u["last_s"] < 86400:
                recent.append((u["last_s"], a["package"], USAGE_OPS[op], u["background"]))
    for x in r["system_recent_cam_mic"]:
        if x["last_s"] is not None and x["last_s"] < 86400:
            recent.append((x["last_s"], x["package"] + " (system)", x["op"], x["background"]))
    if recent:
        print(c("   Last 24 hours camera / mic use:", "B"))
        for s, p, op, bg in sorted(recent)[:15]:
            line = "     %-12s %-11s %s" % (ago(s), op, p)
            print(c(line + "   <-- BACKGROUND!", "r") if bg else line)
        print()
    hi = [a for a in apps if a["level"] == "HIGH"]
    if hi:
        print(c("   HIGH RISK apps (pehle inko check karo):", "r", "B"))
        for a in hi[:15]:
            print(c("     %-45s score %d" % (a["package"], a["score"]), "r"))
            for f in a["flags"][:3]:
                print(c("        - " + f["text"], "d"))
    else:
        ok("Koi HIGH risk app nahi mila.")


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------
def render_html(r):
    e = lambda s: html.escape(str(s if s is not None else ""))
    d = r["device"]
    apps = r["apps"]
    tp = [a for a in apps if a["third_party"]]

    def count(pred):
        return sum(1 for a in tp if pred(a))
    stats = [
        ("Third-party apps", len(tp), ""),
        ("HIGH risk", count(lambda a: a["level"] == "HIGH"), "red"),
        ("MEDIUM risk", count(lambda a: a["level"] == "MEDIUM"), "amber"),
        ("Camera permission", count(lambda a: "android.permission.CAMERA" in a["runtime_granted"]), ""),
        ("Mic permission", count(lambda a: "android.permission.RECORD_AUDIO" in a["runtime_granted"]), ""),
        ("Not from Play Store", count(lambda a: a["risky_source"]), "amber"),
        ("Hidden (no icon)", count(lambda a: a["has_icon"] is False), "red"),
    ]
    stat_html = "".join('<div class="stat %s"><b>%d</b><span>%s</span></div>' % (cl, n, e(t)) for t, n, cl in stats)

    sec_html = ""
    for s in r["security"]:
        sec_html += '<li class="lv-%s"><b>%s</b> %s</li>' % (e(s["level"]), e(s["title"]),
                                                          ("<br><small>%s</small>" % e(s["detail"])) if s["detail"] else "")

    sa = r["special_access"]

    def plist(pk):
        return ", ".join('<code>%s</code>' % e(p) for p in pk) if pk else '<span class="muted">none</span>'
    spec_rows = [
        ("Accessibility services (can read screen & control phone)", sa["accessibility"]),
        ("Notification access (reads all notifications / OTPs)", sa["notification_listeners"]),
        ("Device administrators", sa["device_admins"]),
        ("Device owner (full control)", sa["device_owner"]),
        ("Work profile owner", sa["profile_owner"]),
        ("Default keyboard", sa["keyboard_default"]),
        ("Enabled keyboards", sa["keyboards_enabled"]),
    ] + [(k, v) for k, v in sa["roles"].items()]
    spec_html = "".join("<tr><td>%s</td><td>%s</td></tr>" % (e(t), plist(v)) for t, v in spec_rows)

    # recent camera / mic table
    rec = []
    for a in apps:
        for op in ("CAMERA", "RECORD_AUDIO", "FINE_LOCATION", "READ_CLIPBOARD"):
            u = a["usage"].get(op)
            if u and (u["last_s"] is not None or u["rejects"]):
                rec.append((u["last_s"] if u["last_s"] is not None else 1e12, a["package"],
                            "3rd-party" if a["third_party"] else "system", USAGE_OPS[op], u))
    for x in r["system_recent_cam_mic"]:
        rec.append((x["last_s"], x["package"], "system", x["op"], x))
    rec.sort(key=lambda t: t[0])
    rec_html = ""
    for s, p, kind, op, u in rec[:150]:
        state = ", ".join(u["states"]) or "-"
        tag = ""
        if u["running"]:
            tag += '<span class="tag red">RUNNING NOW</span>'
        if u["background"]:
            tag += '<span class="tag red">BACKGROUND</span>'
        elif u.get("fg_service"):
            tag += '<span class="tag amber">background service</span>'
        if u["rejects"]:
            tag += '<span class="tag amber">blocked %dx</span>' % u["rejects"]
        rec_html += "<tr><td>%s</td><td><code>%s</code> <small class='muted'>%s</small></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            e(op), e(p), e(kind), e(u["last_ago"]), e(u.get("last_abs") or ""), e(state), tag)

    # per-app rows
    rows = ""
    for a in apps:
        chips = ""
        for perm in a["runtime_granted"]:
            if perm in RUNTIME_PERMS:
                label, cat, w = RUNTIME_PERMS[perm]
                chips += '<span class="chip c-%s w%d">%s</span>' % (cat, min(w, 3), e(label))
        for op, label in a["special_ops"].items():
            chips += '<span class="chip c-special w3">%s</span>' % e(label)
        others = [p for p in a["runtime_granted"] if p not in RUNTIME_PERMS]
        flags = "".join('<li class="k-%s">%s</li>' % (e(f["kind"]), e(f["text"])) for f in a["flags"] if f["kind"] != "perm")
        usage = ""
        for op in ("CAMERA", "RECORD_AUDIO", "FINE_LOCATION", "READ_CLIPBOARD"):
            u = a["usage"].get(op)
            if u and u["last_s"] is not None:
                usage += "<div>%s: <b>%s</b>%s</div>" % (e(USAGE_OPS[op]), e(u["last_ago"]),
                                                        ' <span class="tag red">bg</span>' if u["background"] else "")
        icon = {True: "yes", False: '<span class="tag red">HIDDEN</span>', None: "?"}[a["has_icon"]]
        search = " ".join([a["package"], a["installer_label"], a["level"]] +
                          [RUNTIME_PERMS[p][0] for p in a["runtime_granted"] if p in RUNTIME_PERMS])
        rows += """
<tr class="app lvl-{lvl}" data-s="{search}" data-third="{third}">
 <td><span class="badge {lvl}">{lvl}</span><div class="score">score {score}</div></td>
 <td><code>{pkg}</code><div class="muted small">v{ver} &middot; installed {fi}</div>
     <div class="small"><a href="https://play.google.com/store/apps/details?id={pkg}" target="_blank">Play Store</a> &middot;
     <a href="https://www.google.com/search?q={pkg}" target="_blank">Google it</a></div></td>
 <td class="{srccls}">{src}<div class="small">icon: {icon}</div></td>
 <td>{chips}{other}</td>
 <td class="small">{usage}</td>
 <td><ul class="flags">{flags}</ul></td>
</tr>""".format(lvl=e(a["level"]), search=e(search.lower()), third="1" if a["third_party"] else "0",
                score=a["score"], pkg=e(a["package"]), ver=e(a["version"] or "?"),
                fi=e((a["first_install"] or "?")[:10]),
                srccls="srcbad" if a["risky_source"] else "", src=e(a["installer_label"]), icon=icon,
                chips=chips or '<span class="muted">no sensitive permissions</span>',
                other=('<div class="muted small">+%d other</div>' % len(others)) if others else "",
                usage=usage or '<span class="muted">-</span>', flags=flags)

    return HTML_TEMPLATE.format(
        title=e("%s %s" % (d["manufacturer"], d["model"])), ver=e(VERSION),
        model=e("%s %s" % (d["manufacturer"], d["model"])), android=e(d["android"]),
        sdk=e(d["sdk"]), patch=e(d["security_patch"]), build=e(d["build"]),
        when=e(d["scanned_at"]), secs=e(r["scan_seconds"]), stats=stat_html, sec=sec_html,
        spec=spec_html, rec=rec_html or '<tr><td colspan="6" class="muted">No usage history found</td></tr>',
        rows=rows)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhoneGuard report - {title}</title>
<style>
:root{{--bg:#0f1218;--card:#171b23;--line:#262c38;--txt:#e6e9ef;--mut:#8b93a3;--red:#ff5c5c;--amber:#ffb547;--green:#3ddc84;--blue:#5aa9ff}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt)}}
header{{padding:28px 32px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#141a26,#0f1218)}}
h1{{margin:0 0 4px;font-size:24px}}h2{{font-size:17px;margin:32px 0 12px}}
main{{padding:0 32px 60px;max-width:1500px;margin:auto}}
.muted{{color:var(--mut)}}.small{{font-size:12px}}code{{font:12px ui-monospace,Consolas,monospace;color:#cfe3ff;word-break:break-all}}
a{{color:var(--blue)}}
.stats{{display:flex;flex-wrap:wrap;gap:12px;margin-top:20px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:140px}}
.stat b{{display:block;font-size:26px}}.stat span{{color:var(--mut);font-size:12px}}
.stat.red b{{color:var(--red)}}.stat.amber b{{color:var(--amber)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 20px}}
ul.sec{{list-style:none;padding:0;margin:0}}ul.sec li{{padding:8px 0 8px 14px;border-left:4px solid var(--line);margin:6px 0}}
.lv-high{{border-color:var(--red)!important}}.lv-medium{{border-color:var(--amber)!important}}.lv-ok{{border-color:var(--green)!important}}.lv-info{{border-color:var(--blue)!important}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{background:#1d2230;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);position:sticky;top:0}}
.badge{{font-weight:700;font-size:11px;padding:3px 8px;border-radius:20px}}
.badge.HIGH{{background:#4a1616;color:var(--red)}}.badge.MEDIUM{{background:#4a3410;color:var(--amber)}}.badge.LOW{{background:#123522;color:var(--green)}}
.score{{font-size:11px;color:var(--mut);margin-top:4px}}
.chip{{display:inline-block;font-size:11px;padding:2px 8px;border-radius:12px;margin:2px;background:#232a38;border:1px solid #2f3747}}
.chip.w3{{border-color:var(--red);color:#ffb3b3}}.chip.w2{{border-color:var(--amber);color:#ffe0a8}}
.tag{{font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;margin-left:4px}}
.tag.red{{background:var(--red);color:#000}}.tag.amber{{background:var(--amber);color:#000}}
ul.flags{{margin:0;padding-left:16px;font-size:12px}}ul.flags li.k-danger{{color:var(--red);font-weight:600}}ul.flags li.k-source{{color:var(--amber)}}
.srcbad{{color:var(--amber)}}
.tools{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}}
input,select{{background:var(--card);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:14px}}
input{{flex:1;min-width:240px}}
.help{{font-size:13px;color:var(--mut)}}.help b{{color:var(--txt)}}
footer{{text-align:center;color:var(--mut);font-size:12px;padding:30px}}
@media print{{body{{background:#fff;color:#000}}th{{position:static}}}}
</style></head><body>
<header>
 <h1>PhoneGuard privacy report</h1>
 <div class="muted">{model} &middot; Android {android} (SDK {sdk}) &middot; Security patch {patch} &middot; Build {build}</div>
 <div class="muted small">Scanned {when} in {secs}s &middot; PhoneGuard v{ver}</div>
 <div class="stats">{stats}</div>
</header>
<main>
<h2>1. Phone security checks</h2>
<div class="card"><ul class="sec">{sec}</ul></div>

<h2>2. Special / powerful access (spy apps usually need these)</h2>
<table><tr><th style="width:40%">Access type</th><th>Apps that have it</th></tr>{spec}</table>
<p class="help">Agar yahan koi aisa app dikhe jo aapne install nahi kiya ya pehchante nahi ho, wo sabse bada red flag hai.
Settings &gt; Accessibility, Settings &gt; Security &gt; Device admin apps, Settings &gt; Notifications &gt; Notification access se hatao.</p>

<h2>3. Who used Camera / Mic / Location / Clipboard - and when</h2>
<table><tr><th>What</th><th>App</th><th>Last used</th><th>Exact time</th><th>App state</th><th>Notes</th></tr>{rec}</table>
<p class="help"><b>App state</b>: <b>top</b> = app screen par tha (normal) &middot; <b>fgsvc</b> = background service (notification dikhti hai) &middot;
<b>bg / cch</b> = app background me tha - camera/mic ke liye ye suspicious hai. History phone ke andar se aati hai, aam taur par kuch ghante se kuch din tak ki hoti hai.</p>

<h2>4. All apps &amp; their permissions</h2>
<div class="tools">
 <input id="q" placeholder="Search: package, 'camera', 'microphone', 'APK', 'HIGH'..." oninput="f()">
 <select id="lv" onchange="f()"><option value="">All risk levels</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
 <select id="ty" onchange="f()"><option value="">All apps</option><option value="1">Third-party only</option><option value="0">System only</option></select>
</div>
<table id="apps"><tr><th>Risk</th><th>App</th><th>Installed from</th><th>Granted permissions</th><th>Last use</th><th>Why flagged</th></tr>{rows}</table>

<h2>5. What should I do?</h2>
<div class="card help">
<p><b>1.</b> HIGH risk apps ko pehle dekho. Jo app pehchante nahi ho ya use nahi karte - uninstall karo (Settings &gt; Apps).</p>
<p><b>2.</b> Kisi app ko camera/mic ki zaroorat nahi hai (jaise torch, calculator, game) to: Settings &gt; Apps &gt; [app] &gt; Permissions &gt; Camera/Microphone &gt; <b>Don't allow</b>.</p>
<p><b>3.</b> Android 12+ par: Settings &gt; Security &amp; privacy &gt; <b>Privacy dashboard</b> - last 24h/7 days kis app ne kya use kiya. Quick settings me <b>Camera access</b> aur <b>Microphone access</b> toggles se poora block kar sakte ho.</p>
<p><b>4.</b> Screen ke top-right me <span style="color:var(--green)">green dot</span> = camera/mic use ho raha hai. Us par tap karke app ka naam dekho.</p>
<p><b>5.</b> Real-time pakadne ke liye: <code>python phoneguard.py monitor</code> chalao aur phone side me rakh do.</p>
<p><b>6.</b> Scan ke baad USB debugging OFF kar do. Agar Device admin/Accessibility me unknown app hai aur hat nahi raha, phone ko Safe mode me boot karke uninstall karo, ya backup lekar factory reset.</p>
<p class="small">Note: 'Google it' link se package name search karke pata karo app kis company ka hai. Pre-installed (system) apps ki zyada permissions normal hain.</p>
</div>
</main>
<footer>Generated locally by PhoneGuard. Nothing was uploaded anywhere. This is a best-effort tool, not a guarantee.</footer>
<script>
function f(){{var q=document.getElementById('q').value.toLowerCase().trim(),lv=document.getElementById('lv').value,ty=document.getElementById('ty').value;
document.querySelectorAll('#apps tr.app').forEach(function(r){{var s=r.getAttribute('data-s');
var ok=(!q||q.split(/\\s+/).every(function(w){{return s.indexOf(w)>=0}}))&&(!lv||r.classList.contains('lvl-'+lv))&&(!ty||r.getAttribute('data-third')===ty);
r.style.display=ok?'':'none';}});}}
</script>
</body></html>"""


# --------------------------------------------------------------------------
# LIVE MONITOR
# --------------------------------------------------------------------------
LIVE_OPS = [("CAMERA", "CAMERA"), ("RECORD_AUDIO", "MIC"), ("FINE_LOCATION", "GPS")]


def _foreground(txt):
    for line in txt.splitlines():
        if "ResumedActivity" in line or "mCurrentFocus" in line or "mFocusedApp" in line:
            m = re.search(r"\s(" + PKG_RE + r")/", line)
            if m:
                return m.group(1)
    return None


def _camera_clients(txt):
    pk = set()
    for m in re.finditer(r"(?:Client package|Package(?: Name)?)\s*:\s*(" + PKG_RE + r")", txt, re.I):
        pk.add(m.group(1))
    return pk


def _running(txt, op):
    res = set()
    for pkg, opsd in parse_appops(txt).items():
        d = opsd.get(op)
        if d and d["running"]:
            res.add(pkg)
    return res


def monitor(a, interval=2.0, minutes=0, out_dir=None, beep=True, gps=True):
    print()
    print(c("=" * 64, "m"))
    print(c("  PhoneGuard LIVE MONITOR  -  camera / mic%s" % (" / GPS" if gps else ""), "B", "m"))
    print(c("=" * 64, "m"))
    third = set()
    for line in a.sh("pm list packages -3").splitlines():
        if line.startswith("package:"):
            third.add(line[8:].strip())
    model = a.sh("getprop ro.product.model").strip()
    ok("Phone: %s  |  %d third-party apps" % (model, len(third)))
    info("Har %.1f second me check kar raha hoon. Band karne ke liye Ctrl+C dabao." % interval)
    info("Tip: phone ko unlock/lock dono haalat me rakh ke dekho. Screen band ho aur camera/mic chale = sabse bada red flag.")
    print()

    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(out_dir, "PhoneGuard_live_%s.csv" % stamp)
    fcsv = open(csv_path, "w", newline="", encoding="utf-8")
    w = csv.writer(fcsv)
    w.writerow(["time", "event", "sensor", "package", "app_type", "foreground_app",
                "screen", "background_use", "duration_seconds"])

    ops = [o for o in LIVE_OPS if gps or o[1] != "GPS"]
    cmds = ["dumpsys appops --op %s" % op for op, _ in ops] + [
        "dumpsys media.camera | grep -iE 'package'",
        "dumpsys activity activities | grep -E 'ResumedActivity'",
        "dumpsys power | grep -E 'mWakefulness=|Display Power: state='",
    ]
    active = {}   # (sensor, pkg) -> (start_time, bg_flag)
    events = []
    end_at = time.time() + minutes * 60 if minutes else None
    polls = 0
    last_hb = 0
    try:
        while True:
            t_start = time.time()
            outs = a.multi(cmds, timeout=30)
            polls += 1
            now_set = {}
            for (op, label), txt in zip(ops, outs):
                for pkg in _running(txt, op):
                    now_set[(label, pkg)] = True
            for pkg in _camera_clients(outs[len(ops)]):
                now_set[("CAMERA", pkg)] = True
            fg = _foreground(outs[len(ops) + 1])
            pw = outs[len(ops) + 2]
            screen = "off" if re.search(r"mWakefulness=(Asleep|Dozing)|state=OFF", pw) else "on"
            ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for key in now_set:
                if key in active:
                    continue
                sensor, pkg = key
                bg = (pkg != fg) or screen == "off"
                active[key] = (time.time(), bg)
                kind = "3rd-party" if pkg in third else "system"
                msg = "%s  %-6s STARTED  %s  [%s]" % (ts[11:], sensor, pkg, kind)
                if bg and sensor in ("CAMERA", "MIC"):
                    print(c("\n" + "!" * 64, "r", "B"))
                    print(c("  ALERT: %s chalu kiya BACKGROUND me (screen %s, on-screen app: %s)" % (sensor, screen, fg or "?"), "r", "B"))
                    print(c("  " + msg, "r", "B"))
                    print(c("!" * 64, "r", "B"))
                    if beep:
                        sys.stdout.write("\a\a\a")
                        sys.stdout.flush()
                elif bg:
                    print(c(msg + "   (background)", "y"))
                else:
                    print(c(msg + "   (app on screen - normal)", "g"))
                w.writerow([ts, "start", sensor, pkg, kind, fg or "", screen, "yes" if bg else "no", ""])
                fcsv.flush()
                events.append({"time": ts, "event": "start", "sensor": sensor, "package": pkg,
                               "type": kind, "foreground": fg, "screen": screen, "background": bg})

            for key in list(active):
                if key not in now_set:
                    sensor, pkg = key
                    st, bg = active.pop(key)
                    dur = time.time() - st
                    kind = "3rd-party" if pkg in third else "system"
                    print(c("%s  %-6s stopped  %s  (%.0fs)" % (ts[11:], sensor, pkg, dur), "d"))
                    w.writerow([ts, "stop", sensor, pkg, kind, fg or "", screen, "yes" if bg else "no", round(dur, 1)])
                    fcsv.flush()
                    events.append({"time": ts, "event": "stop", "sensor": sensor, "package": pkg,
                                   "type": kind, "duration": round(dur, 1), "background": bg})

            if time.time() - last_hb > 60:
                last_hb = time.time()
                sys.stdout.write(c("   ...watching (%s, screen %s, on-screen: %s, %d checks)\n" % (ts[11:], screen, fg or "?", polls), "d"))
                sys.stdout.flush()
            if end_at and time.time() > end_at:
                break
            time.sleep(max(0.2, interval - (time.time() - t_start)))
    except KeyboardInterrupt:
        pass
    finally:
        fcsv.close()

    print()
    starts = [e for e in events if e["event"] == "start"]
    bgs = [e for e in starts if e["background"] and e["sensor"] in ("CAMERA", "MIC")]
    ok("Monitoring band. %d events, %d background camera/mic alerts." % (len(starts), len(bgs)))
    if bgs:
        bad("Background camera/mic use karne wale apps:")
        for p in sorted(set(e["package"] + " (" + e["sensor"] + ")" for e in bgs)):
            print(c("     " + p, "r"))
    hpath = csv_path[:-4] + ".html"
    with open(hpath, "w", encoding="utf-8") as f:
        f.write(_monitor_html(model, events, polls, interval))
    ok("Live log : " + csv_path)
    ok("Live report: " + hpath)
    return events


def _monitor_html(model, events, polls, interval):
    e = lambda s: html.escape(str(s if s is not None else ""))
    rows = ""
    for ev in events:
        cls = "bad" if ev["event"] == "start" and ev.get("background") and ev["sensor"] in ("CAMERA", "MIC") else ""
        rows += "<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            cls, e(ev["time"]), e(ev["event"]), e(ev["sensor"]), e(ev["package"]), e(ev["type"]),
            e(ev.get("foreground", "")), e(ev.get("screen", "")),
            e(ev.get("duration", "")) if ev["event"] == "stop" else ("BACKGROUND" if ev.get("background") else "on screen"))
    return """<!DOCTYPE html><html><head><meta charset="utf-8"><title>PhoneGuard live log</title>
<style>body{font:14px system-ui,Segoe UI,sans-serif;background:#0f1218;color:#e6e9ef;padding:24px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #262c38;padding:8px;text-align:left}
th{color:#8b93a3;font-size:12px;text-transform:uppercase}tr.bad td{background:#3a1414;color:#ff9c9c;font-weight:600}
code{color:#cfe3ff}</style></head><body><h1>PhoneGuard live monitor - """ + e(model) + """</h1>
<p>""" + "%d checks every %.1fs. Red rows = camera/mic started while that app was not on screen or screen was off." % (polls, interval) + """</p>
<table><tr><th>Time</th><th>Event</th><th>Sensor</th><th>App</th><th>Type</th><th>On-screen app</th><th>Screen</th><th>Info</th></tr>""" + (
        rows or "<tr><td colspan=8>No camera/mic/GPS use detected during monitoring.</td></tr>") + "</table></body></html>"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="PhoneGuard - Android privacy scanner & live camera/mic monitor")
    ap.add_argument("mode", nargs="?", choices=["scan", "monitor", "both"], help="what to run (default: menu)")
    ap.add_argument("--serial", help="device serial if more than one phone connected")
    ap.add_argument("--include-system", action="store_true", help="also list all pre-installed system apps in the report")
    ap.add_argument("--interval", type=float, default=2.0, help="monitor check interval in seconds (default 2)")
    ap.add_argument("--minutes", type=float, default=0, help="stop monitor after N minutes (default: until Ctrl+C)")
    ap.add_argument("--no-gps", action="store_true", help="monitor only camera + mic")
    ap.add_argument("--no-beep", action="store_true", help="no sound on alerts")
    ap.add_argument("--no-open", action="store_true", help="do not open the report in the browser")
    ap.add_argument("--out", help="folder for reports (default: ./reports)")
    args = ap.parse_args()

    mode = args.mode
    if not mode:
        print(c("\n  PhoneGuard %s - Android privacy checker" % VERSION, "B", "c"))
        print("  1) Full scan + report      (sab apps, permissions, history)")
        print("  2) Live monitor            (real time camera / mic / GPS alert)")
        print("  3) Both                    (pehle scan, phir live monitor)")
        print("  4) Full scan incl. system apps")
        choice = input("\n  Choose 1-4: ").strip()
        mode = {"1": "scan", "2": "monitor", "3": "both", "4": "scan"}.get(choice, "scan")
        if choice == "4":
            args.include_system = True

    a = connect(args.serial)
    if mode in ("scan", "both"):
        scan(a, include_system=args.include_system, out_dir=args.out, open_report=not args.no_open)
    if mode in ("monitor", "both"):
        monitor(a, interval=args.interval, minutes=args.minutes, out_dir=args.out,
                beep=not args.no_beep, gps=not args.no_gps)
    if os.name == "nt" and not args.mode:
        input("\nPress Enter to close...")


if __name__ == "__main__":
    main()
