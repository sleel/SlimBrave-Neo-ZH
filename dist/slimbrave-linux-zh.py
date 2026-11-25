#!/usr/bin/env python3
"""SlimBrave Neo - Linux TUI for debloating and hardening Brave Browser.

Sets Chromium enterprise policies via JSON files at
/etc/brave/policies/managed/slimbrave.json. Requires root.

Multi-channel handling on Linux:
  brave-core hardcodes the managed-policy directory to /etc/brave/policies
  for every Brave channel (Stable / Beta / Nightly / Dev) and for Brave
  Origin, so a single policy file applies to all of them. Channel info is
  still used to scrub leaked Shields exceptions from each channel's
  user-data directory and to detect which Brave processes are currently
  running. Brave Origin is detected as its own "origin" channel (Arch
  brave-origin-bin, the brave-origin deb/rpm, or a brave-origin launcher
  on PATH); the rows for features Origin compiles out are no-ops there.

Supports interactive curses TUI and non-interactive CLI usage:
  sudo python3 slimbrave.py                        # TUI
  sudo python3 slimbrave.py --import preset.json   # CLI import
  sudo python3 slimbrave.py --export out.json      # CLI export
  sudo python3 slimbrave.py --reset                # CLI reset
"""

import argparse
import curses
import json
import locale
import math
import os
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import unicodedata
import tempfile

POLICY_DIR = "/etc/brave/policies/managed"
POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")

# Where a `--policy-file` argument may point. The flag runs with root, so an
# unvalidated path combined with `--reset` would let a permissive sudoers
# rule delete arbitrary files (e.g. `--policy-file /etc/shadow --reset`).
# Two rules, both on the resolved path: the file sits directly in one of
# these directories, never in a subdirectory, and its name is
# slimbrave*.json, so a policy file another tool put there is out of reach.
# Chromium reads a managed directory without descending into it, so neither
# rule hides a file Brave would read. Brave reads Linux policies only from
# /etc/brave/policies; it never reads Chromium's /etc/chromium/policies,
# which this list still accepts.
ALLOWED_POLICY_DIRS = (
    "/etc/brave/policies/managed",
    "/etc/chromium/policies/managed",
)

# Brave channel definitions on Linux. Each channel has its own user-data
# directory under ~/.config/BraveSoftware/<dir>/ and (for some channels) a
# distinct binary name on PATH. Policy targets are shared across channels.
LINUX_CHANNELS = [
    {"id": "stable", "label": "Stable",
     "user_data_dir": "Brave-Browser", "process_name": "brave"},
    {"id": "beta", "label": "Beta",
     "user_data_dir": "Brave-Browser-Beta", "process_name": "brave-browser-beta"},
    {"id": "nightly", "label": "Nightly",
     "user_data_dir": "Brave-Browser-Nightly", "process_name": "brave-browser-nightly"},
    {"id": "dev", "label": "Dev",
     "user_data_dir": "Brave-Browser-Dev", "process_name": "brave-browser-dev"},
    # Brave Origin is a separate build rather than a channel of this one,
    # but on Linux it walks the same paths: brave-core's chrome_paths_linux.cc
    # names its profile BraveSoftware/Brave-Origin with the same -Beta and
    # -Nightly suffixes, and its launcher is brave-origin[-beta|-nightly] on
    # every packaging (the AUR wrapper, the deb/rpm script). The launcher's
    # bash process stays alive around the browser, and its comm is the name
    # it was started by: brave-origin from the AUR wrapper, brave-origin-st
    # (comm's 15-char cap) from the deb/rpm desktop file's
    # /usr/bin/brave-origin-stable - the SingletonLock check covers that
    # case, as it does the long beta and nightly names. Beta and nightly ship
    # as brave-origin-beta / brave-origin-nightly (apt, rpm and AUR *-bin);
    # brave-core also names a dev channel, but no such package is published,
    # so it gets no row.
    {"id": "origin", "label": "Origin",
     "user_data_dir": "Brave-Origin", "process_name": "brave-origin"},
    {"id": "origin-beta", "label": "Origin Beta",
     "user_data_dir": "Brave-Origin-Beta", "process_name": "brave-origin-beta"},
    {"id": "origin-nightly", "label": "Origin Nightly",
     "user_data_dir": "Brave-Origin-Nightly", "process_name": "brave-origin-nightly"},
]

CHANNEL_IDS = [c["id"] for c in LINUX_CHANNELS]


# Policy keys whose handler Brave Origin compiles out. Each one's entry in
# brave-core's browser/policy/brave_simple_policy_map.h sits under a
# BUILDFLAG whose .gni definition carries `&& !is_brave_origin_branded`
# (v1.94.121; the receipts, including a check on the shipped binary, are in
# AUDIT.md, Brave Origin). On a machine whose only Brave is Origin these rows
# are shown inert: the feature is not in the binary, so there is nothing
# for a policy to switch. P3A and the stats ping are not listed - their
# entries are unguarded, Origin merely defaults them off, and a managed
# value pins them.
ORIGIN_BUILTIN_KEYS = frozenset((
    "BraveRewardsDisabled", "BraveWalletDisabled", "BraveVPNDisabled",
    "BraveAIChatEnabled", "BraveLocalAIEnabled", "BraveNewsDisabled",
    "BraveTalkDisabled", "BravePlaylistEnabled", "BraveWebDiscoveryEnabled",
    "BraveSpeedreaderEnabled", "BraveWaybackMachineEnabled", "TorDisabled",
    "EmailAliasesEnabled",
))

# The suffix an inert row carries in the list.
INERT_SUFFIX = "(built into Origin)"

# The launch notes: one status line each at 80 columns, which is 76 chars.
ORIGIN_NOTE_ONLY = "Brave Origin found: policies apply; rows for features it removes are inert."
ORIGIN_NOTE_BESIDE = "Origin beside Brave: one policy file serves both; every row stays live."


def is_origin_only(installations):
    """True when every detected Brave is a Brave Origin build.

    The one shared policy file is read by every Brave on the machine, so a
    row goes inert only when no regular Brave could be reading it: an old
    Brave-Browser profile beside Origin keeps every row live, as does the
    --policy-file override and any macOS channel. A record detect_brave()
    made carries the whole machine's answer in "origin_only", so a list
    narrowed by --channels cannot turn a mixed machine into an Origin-only
    one; a record built by hand answers for its channel.
    """
    return bool(installations) and all(
        i.get("origin_only", str(i.get("channel", "")).startswith("origin"))
        for i in installations)


def _invoking_user():
    """Return (name, uid, gid, home) of the user who ran this, or None.

    The one answer to "who is the user here": the prefs scrub, Export and
    the macOS profile hand-off all act for this account. The name is
    SUDO_USER, else USER, which a plain `su` to root leaves as the caller's.
    None when neither is set, the name is root, pwd does not know it (or
    there is no pwd, as on Windows), or it maps to uid 0, so nothing is ever
    done as root, or in root's home, on its behalf.
    """
    name = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not name or name == "root":
        return None
    try:
        import pwd
        info = pwd.getpwnam(name)
    except (ImportError, KeyError):
        return None
    if info.pw_uid == 0:
        return None
    return (name, info.pw_uid, info.pw_gid, info.pw_dir)


def _user_home_for_brave():
    """Return the invoking user's home directory (see _invoking_user).

    Brave's profile lives under the invoking user's home, not root's.
    """
    identity = _invoking_user()
    return identity[3] if identity else None


def _channel_prefs_path(user_data_dir):
    """Return the Default profile Preferences path for a channel."""
    home = _user_home_for_brave()
    if not home:
        return None
    return os.path.join(
        home, ".config", "BraveSoftware", user_data_dir, "Default", "Preferences",
    )


def _flatpak_prefs_path():
    """Return the Flatpak Brave's Default profile Preferences path.

    Flatpak keeps the profile under ~/.var/app/com.brave.Browser/config
    instead of ~/.config, so the native channel paths never see it. The
    Flathub manifest grants --filesystem=host-etc specifically to load
    policies from /etc/brave/policies, so the shared POLICY_FILE works;
    only prefs repair needs this extra location.
    """
    home = _user_home_for_brave()
    if not home:
        return None
    return os.path.join(
        home, ".var", "app", "com.brave.Browser", "config",
        "BraveSoftware", "Brave-Browser", "Default", "Preferences",
    )


def _profile_prefs_paths(default_prefs_path):
    """Expand a channel's Default-profile Preferences path to all profiles.

    Chromium keeps one directory per profile (Default, Profile 1, ...)
    under the same user-data dir, and the Shields-exception leak lands in
    every profile that was used while the policy was active — not just
    Default.
    """
    if not default_prefs_path:
        return []
    user_data = os.path.dirname(os.path.dirname(default_prefs_path))
    try:
        entries = sorted(os.listdir(user_data))
    except OSError:
        return [default_prefs_path]
    paths = []
    for name in entries:
        if name != "Default" and not name.startswith("Profile "):
            continue
        prefs = os.path.join(user_data, name, "Preferences")
        if os.path.isfile(prefs):
            paths.append(prefs)
    return paths or [default_prefs_path]


def _is_allowed_policy_file(path):
    """True if `path` is a slimbrave*.json directly in an allowed policy dir.

    Both rules run on the realpath, so a symlinked directory or file cannot
    lead out of ALLOWED_POLICY_DIRS, and neither a subdirectory nor the
    directory itself qualifies.
    """
    real = os.path.realpath(path)
    parent, name = os.path.split(real)
    allowed = {os.path.realpath(d) if os.path.exists(d) else d
               for d in ALLOWED_POLICY_DIRS}
    if parent not in allowed:
        return False
    return name.startswith("slimbrave") and name.endswith(".json")


def _atomic_write(path, data, *, binary=False, mode=0o644):
    """Write `data` to `path` atomically via a same-directory tempfile.

    `tempfile.mkstemp` uses O_CREAT|O_EXCL so it cannot be tricked into
    writing through a symlink, and `os.replace` atomically replaces the
    target directory entry without following a symlink that happened to
    exist there. Fixes two classes of root footgun at once: symlink
    races and partial-state writes if the process is killed mid-write.

    The data is fsynced before the rename, as Chromium's ImportantFileWriter
    does, so a crash or power cut leaves the old file or the new one, never
    an empty one: ext4's rename heuristic misses a freshly created file and
    XFS has none. The directory is fsynced afterwards where POSIX allows it,
    on a best-effort basis.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".slimbrave.", suffix=".tmp", dir=directory)
    try:
        # Pin the text encoding: readers use utf-8 explicitly, so inheriting
        # the locale's would round-trip non-ASCII through the wrong codec.
        with os.fdopen(fd, "wb" if binary else "w",
                       encoding=None if binary else "utf-8") as f:
            f.write(data)
            # fchmod on the descriptor, not chmod on the path — the temp
            # file can sit in a directory the unprivileged user owns, so a
            # second path lookup here is redirectable. (Windows only grew
            # os.fchmod in 3.13; fall back there.)
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), mode)
            else:
                os.chmod(tmp, mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # BaseException, so a Ctrl+C mid-write leaves no temp file either.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if os.name == "posix":
        # Makes the rename itself durable. Outside the cleanup above: the
        # file is already in place, so a directory that cannot be opened or
        # synced fails nothing.
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

# ---------------------------------------------------------------------------
# Brave browser detection
# ---------------------------------------------------------------------------


def _make_installation(channel_def, *, app_path="", plist_path="", prefs_path=None):
    """Build an installation record from a channel definition."""
    return {
        "channel": channel_def["id"],
        "label": channel_def["label"],
        "app_path": app_path,
        "bundle_id": "",
        "plist_path": plist_path,
        "prefs_path": prefs_path,
        "process_name": channel_def["process_name"],
        "user_data_dir": channel_def["user_data_dir"],
    }


def detect_brave():
    """Detect Brave browser installation(s) and packaging method.

    Returns a dict with keys:
        found, method, path, warnings, installations.
    On Linux every detected channel shares POLICY_FILE (no per-channel
    plist), so installations is informational + drives prefs repair and
    process-running checks.
    """
    method = None
    primary_path = ""
    warnings = []
    found_any = False
    home = _user_home_for_brave()

    # Arch (brave-bin AUR package)
    if os.path.isfile("/opt/brave-bin/brave"):
        method, primary_path, found_any = "arch", "/opt/brave-bin/brave", True
    # Deb / RPM (official brave-browser package)
    elif os.path.isfile("/opt/brave.com/brave/brave-browser"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave-browser", True
    elif os.path.isfile("/opt/brave.com/brave/brave"):
        method, primary_path, found_any = "deb/rpm", "/opt/brave.com/brave/brave", True
    # Whether a regular Brave is on the machine at all, started or not. The
    # inert-row decision hangs on it: it must never fire beside one.
    regular_found = found_any

    # Brave Origin is a separate package that can sit beside regular Brave,
    # so it is probed on its own rather than as one more arm of the chain
    # above. Arch: the brave-origin-bin AUR package (PKGBUILD maintained by
    # Brave, mirrored in the CachyOS repo) unpacks the upstream zip under
    # /opt/brave-origin-bin. Deb / RPM: brave-core's installer config sets
    # INSTALLDIR=/opt/brave.com/brave-origin and keeps PROGNAME=brave, so the
    # launcher is brave-origin and the binary is brave, mirroring the regular
    # /opt/brave.com/brave layout. Origin reads /etc/brave/policies like
    # regular Brave: brave_main_delegate.cc overrides DIR_POLICY_FILES for
    # every POSIX build with no branding guard (AUDIT.md, Brave Origin).
    origin_method, origin_path = "", ""
    if os.path.isfile("/opt/brave-origin-bin/brave"):
        origin_method, origin_path = "arch", "/opt/brave-origin-bin/brave"
    elif os.path.isfile("/opt/brave.com/brave-origin/brave-origin"):
        origin_method, origin_path = "deb/rpm", "/opt/brave.com/brave-origin/brave-origin"
    elif os.path.isfile("/opt/brave.com/brave-origin/brave"):
        origin_method, origin_path = "deb/rpm", "/opt/brave.com/brave-origin/brave"
    if origin_path and not found_any:
        method, primary_path, found_any = f"{origin_method} (Brave Origin)", origin_path, True

    # Flatpak and Snap are probed unconditionally, not as the `else` of the
    # native chain: a mixed install has both, and the Snap warning applies
    # whenever a Snap Brave exists. Flatpak is checked on the filesystem
    # rather than via `flatpak info`, which under sudo runs with HOME=/root
    # and so never sees the user's --user installation.
    if os.path.isdir("/var/lib/flatpak/app/com.brave.Browser") or (
            home and os.path.isdir(os.path.join(
                home, ".local", "share", "flatpak", "app", "com.brave.Browser"))):
        regular_found = True
        if not found_any:
            method, primary_path, found_any = "flatpak", "com.brave.Browser", True

    snap_path = "/snap/brave/current/opt/brave.com/brave/brave"
    if os.path.isfile(snap_path) or os.path.isdir("/snap/brave/current"):
        regular_found = True
        if not found_any:
            method, primary_path, found_any = "snap", snap_path, True
        warnings.append(
            "Snap confinement may prevent policies from taking effect. "
            "Native packages are recommended."
        )

    # Probed whenever no regular Brave has turned up yet, not only when
    # nothing has, so a launcher on PATH still counts beside a native Origin.
    if not regular_found:
        for name in ("brave-browser-stable", "brave-browser", "brave"):
            found = shutil.which(name)
            if found:
                regular_found = True
                if not found_any:
                    method, primary_path, found_any = "unknown", found, True
                break

    # Origin's launcher names, for a hand-unpacked zip: the deb ships the
    # /usr/bin/brave-origin-stable symlink and its postinst registers the
    # bare brave-origin alternative, the same way regular Brave gets
    # brave-browser-stable; the beta and nightly debs ship their launcher
    # symlink directly. There is no official Flatpak or Snap of Origin
    # (Flathub carries only com.brave.Browser, the Snap store only brave;
    # unofficial Origin Flatpaks are not probed, though one of them,
    # io.github.shyvortex.BraveOrigin, reads host policy).
    if not found_any:
        for name in ("brave-origin-stable", "brave-origin",
                     "brave-origin-beta", "brave-origin-nightly"):
            found = shutil.which(name)
            if found:
                method, primary_path, found_any = "unknown (Brave Origin)", found, True
                if name in ("brave-origin-stable", "brave-origin"):
                    origin_path = found
                break

    if not found_any:
        method = "not found"
        warnings.append(
            "Brave browser not found. Policies will be written but may have no effect."
        )

    # Detect installed Linux channels by user-data dir presence (best effort).
    installations = []
    detected_labels = []
    for ch in LINUX_CHANNELS:
        ch_dir = (
            os.path.join(home, ".config", "BraveSoftware", ch["user_data_dir"])
            if home else None
        )
        installed = (
            (ch_dir is not None and os.path.isdir(ch_dir))
            or shutil.which(ch["process_name"]) is not None
            # A native stable Origin whose launcher is off PATH and that has
            # never been started still needs its record, or the stable
            # fallback below would stand in for it. Beta and nightly Origin
            # are found the way Brave's own beta and nightly are: by profile
            # directory or launcher on PATH.
            or (ch["id"] == "origin" and bool(origin_path))
        )
        if installed:
            if ch["id"] == "stable":
                app_path = "" if primary_path == origin_path else primary_path
            elif ch["id"] == "origin":
                app_path = origin_path
            else:
                app_path = ""
            installations.append(_make_installation(
                ch,
                app_path=app_path,
                plist_path=POLICY_FILE,
                prefs_path=_channel_prefs_path(ch["user_data_dir"]),
            ))
            detected_labels.append(ch["label"])

    # Flatpak keeps its profile under ~/.var/app, so the loop above cannot
    # see it. Add a synthetic stable-channel record pointing at the Flatpak
    # prefs so leak repair covers that profile too. Channel id stays
    # "stable" so --channels filtering keeps working.
    flatpak_prefs = _flatpak_prefs_path()
    if flatpak_prefs and os.path.isdir(
            os.path.dirname(os.path.dirname(flatpak_prefs))):
        installations.append(_make_installation(
            {"id": "stable", "label": "Stable (Flatpak)",
             "user_data_dir": "Brave-Browser", "process_name": "brave"},
            app_path="com.brave.Browser" if method == "flatpak" else "",
            plist_path=POLICY_FILE,
            prefs_path=flatpak_prefs,
        ))
        detected_labels.append("Flatpak")

    # A regular Brave found by package, Flatpak, Snap or launcher but never
    # started has no profile, so the loop above made it no record. Alone on
    # a machine, the fallback below stands in for it, as it always has;
    # beside Origin it would let the machine pass for Origin-only, so it
    # gets its record here, ahead of Origin's.
    if (regular_found
            and not any(i["channel"] == "stable" for i in installations)
            and any(i["channel"].startswith("origin") for i in installations)):
        stable = LINUX_CHANNELS[0]
        installations.insert(0, _make_installation(
            stable,
            app_path="" if primary_path == origin_path else primary_path,
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(stable["user_data_dir"]),
        ))
        detected_labels.insert(0, stable["label"])

    if not installations:
        stable = LINUX_CHANNELS[0]
        installations.append(_make_installation(
            stable,
            app_path=primary_path,
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(stable["user_data_dir"]),
        ))

    if found_any and len(detected_labels) > 1:
        method = f"{method}: " + ", ".join(detected_labels)

    # Not a warning: nothing is wrong, and the status line paints warnings
    # in the error color. Origin honors the shared policy file - verified
    # end to end on 1.94.121, where a managed ExtensionInstallForcelist put
    # its extensions into the Brave-Origin profile - so every row works
    # there except the ones whose feature Origin compiles out.
    # Stamp the whole machine's answer on every record, so a list narrowed
    # by --channels still knows whether a regular Brave shares the file.
    origin_only = is_origin_only(installations)
    for inst in installations:
        inst["origin_only"] = origin_only
    notes = []
    if origin_only:
        notes.append(ORIGIN_NOTE_ONLY)
    elif any(i["channel"].startswith("origin") for i in installations):
        notes.append(ORIGIN_NOTE_BESIDE)

    return {
        "found": found_any,
        "method": method,
        "path": primary_path,
        "warnings": warnings,
        "notes": notes,
        "installations": installations,
    }


# ---------------------------------------------------------------------------
# Feature definitions - mirrors the Windows SlimBrave Neo PS1 categories
# ---------------------------------------------------------------------------

# Features with a `group` key are mutually exclusive within that group:
# checking one silently unchecks the others. Used for policies where two
# rows set conflicting values for the same key (IncognitoModeAvailability,
# HardwareAccelerationModeEnabled, DefaultBraveReferrersSetting,
# ChromeVariations, SafeBrowsingProtectionLevel), for the Shields URL
# lists, and for the two spellcheck rows — upstream states the enhanced
# spell check policy has no effect once SpellcheckEnabled is false.

# Content settings Chromium models as an enum rather than a boolean carry a
# `choices` list: an ordered list of (label, value) pairs where value None
# means "not managed" (write nothing). The first entry is always
# ("Not managed", None) and is the default selection, so an untouched row
# behaves exactly like the unticked checkbox it replaced. A feature without
# `choices` stays a plain checkbox.
#
# The enum is NOT uniform. Allow=1 is a legal member of the notifications,
# geolocation and sensors settings only; for the guard settings (WebUSB,
# Serial, WebHID) and for local fonts / window management / clipboard,
# value 1 is not a schema member. Chromium does not reject one: it drops it
# for the guard settings and applies it as a managed Allow for the other
# three, so those rows never offer "Allow".
# Notifications offers no Ask either: a managed Ask lets no notification
# through (AUDIT.md, DefaultNotificationsSetting row).
# Each row keeps the `value` it wrote as a checkbox: that is what a legacy
# array-format config resolves to on import, and what the SlimBrave.ps1
# feature table is compared against.
CHOICES_ALLOW_ASK_BLOCK = [("Not managed", None), ("Allow", 1), ("Ask", 3), ("Block", 2)]
CHOICES_ALLOW_BLOCK = [("Not managed", None), ("Allow", 1), ("Block", 2)]
CHOICES_ASK_BLOCK = [("Not managed", None), ("Ask", 3), ("Block", 2)]

CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False, "desc": "Stops Brave from uploading crash reports: locks 'Automatically send diagnostic reports' off, hides the prompt after a crash and blocks Send now on brave://crashes. Beta and Nightly turn it on by default; on Release the welcome page pre-ticks it. P3A and the usage ping have their own rows."},

            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False, "desc": "Locks 'Make searches and browsing better' (URL-keyed anonymized data collection) off. Brave already ships it off; its only switch, the hidden Privacy Guide at brave://settings/privacy/guide, goes away once any policy is set. This also overrides an opt-in made there earlier."},

            {"name": "Disable Google Image Descriptions", "key": "AccessibilityImageLabelsEnabled", "value": False, "desc": "Brave already keeps Google's image descriptions off and no longer offers the opt-in. A profile that accepted it in an older version still sends unlabeled images to Google whenever a screen reader runs; this turns that off and locks it."},

            {"name": "Disable P3A Analytics", "key": "BraveP3AEnabled", "value": False, "desc": "Disables P3A (Privacy-Preserving Product Analytics), Brave's anonymized product usage telemetry."},

            {"name": "Disable Stats Ping", "key": "BraveStatsPingEnabled", "value": False, "desc": "Stops the daily usage ping that counts this install in Brave's active-user statistics, plus the search-engine usage counts it carries and the referral-code check. P3A Analytics sends its own copy of the search counts until it is disabled too."},

            {"name": "Limit Variations to Critical Fixes", "key": "ChromeVariations", "value": 1, "group": "variations", "desc": "Restricts Brave's remote seed (Griffin) to critical studies, so what Brave enables only that way stays off: WebGL/WebGPU fingerprint masking, image metadata stripping (brave://flags restores both), a Google sign-in fix. Takes effect after a restart. Mutually exclusive with Disable Variations."},

            {"name": "Disable Variations / Griffin Experiments", "key": "ChromeVariations", "value": 2, "group": "variations", "desc": "Refuses every Griffin study, critical ones too, so what Brave enables only through its remote seed stays off: WebGL/WebGPU fingerprint masking, image metadata stripping, a Google sign-in fix. The seed still downloads. Takes effect after a restart. Mutually exclusive with Limit Variations."},

            {"name": "Disable Enhanced Spell Check", "key": "SpellCheckServiceEnabled", "value": False, "group": "spellcheck", "desc": "Locks off enhanced spell check, which sends what you type in web forms to Google. Brave already ships it off with no setting to turn it on; offline spell checking keeps working. Mutually exclusive with Disable Spellcheck, which turns spell checking off altogether and makes this row do nothing."},

        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing (security downgrade)", "key": "SafeBrowsingProtectionLevel", "value": 0, "group": "safebrowsing", "desc": "Turns Safe Browsing fully off. Brave routes these lookups through its own servers, so Google never learns who made them; turning it off buys almost no privacy and costs you the phishing and malware warning pages. Excluded from every preset. Mutually exclusive with Lock Safe Browsing On."},

            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False, "desc": "Stops Brave from saving and auto-filling addresses and other contact details in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet."},

            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False, "desc": "Stops Brave from saving and auto-filling credit card numbers in web forms. Chromium has deprecated this policy, so brave://policy lists it as Deprecated, but Brave still applies it; its replacement (AutofillSettings) does not work in Brave yet."},

            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False, "desc": "Stops the built-in password manager from offering to save or generate passwords. Passwords already saved still autofill. Recommended if you use a dedicated password manager."},

            {"name": "Disable Password Leak Detection", "key": "PasswordLeakDetectionEnabled", "value": False, "desc": "Locks off the online check of your credentials against known breach lists, which runs after you sign in to a site and when you edit a saved login. Brave already ships it off; this keeps it off."},

            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0, "desc": "Brave has no Google browser sign-in; this locks 'Allow Google login for extensions' (brave://settings/extensions) off, as Brave already ships it. Extensions can still open Google's sign-in popup via chrome.identity. Brave Account is not affected. Takes effect after a restart."},

            {"name": "Enable Global Privacy Control", "key": "BraveGlobalPrivacyControlEnabled", "value": True, "desc": "Brave already sends the Global Privacy Control signal (asking sites not to sell or share your data) on every request and has no setting for it; this keeps it on if Adblock-Only mode (English UI only) is turned on. Works even where Shields are down."},

            {"name": "Enable De-AMP", "key": "BraveDeAmpEnabled", "value": True, "desc": "Keeps De-AMP on: Google AMP pages are skipped for the publisher's original page. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off."},

            {"name": "Enable Debouncing", "key": "BraveDebouncingEnabled", "value": True, "desc": "Keeps debouncing on: known tracking redirects are skipped and you go straight to the final URL. Brave already does this by default; this locks the Settings toggle and stops Adblock-Only mode from turning it off."},

            {"name": "Strip Tracking URL Parameters", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True, "desc": "Brave already strips known tracking parameters (fbclid, gclid, mc_eid, ...) from URLs and has no setting for it; this keeps stripping on if Adblock-Only mode (English UI only) is turned on. Needs Shields up."},

            {"name": "Reduce Language Fingerprinting", "key": "BraveReduceLanguageEnabled", "value": True, "desc": "Brave already does this by default; this locks its Settings toggle on. Sites get only your first language in the Accept-Language header and, on Windows, macOS and a few Linux distros, only a standard font list. Needs Shields up and fingerprinting protection on."},

            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp", "desc": "Restricts WebRTC to proxied connections so video/voice calls can't expose your real IP address behind a VPN or proxy."},

            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False, "desc": "Disables QUIC (HTTP/3) for web requests so they use TCP (HTTP/2 or HTTP/1.1). Useful when a firewall or filter can't inspect QUIC; may slightly slow some Google sites. WebRTC calls and WebTransport still use UDP."},

            {"name": "Disable Network Prediction (Prefetch)", "key": "NetworkPredictionOptions", "value": 2, "desc": "Stops Brave from fetching pages ahead of your click when a site's speculation rules or prerender hints ask for it, and from pre-connecting to your search engine. Brave already defaults to this; the policy locks it against Sync and extensions."},

            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True, "desc": "Brave already blocks third-party cookies by default; this locks that, so the global 'Allow all cookies' choice in Shields settings, extensions, Sync and Adblock-Only mode can't turn it off. Per-site Shields exceptions still work, e.g. for an embedded login that breaks."},

            {"name": "Block Payment Method Probing", "key": "PaymentMethodQueryEnabled", "value": False, "desc": "Stops sites from learning whether you have payment methods saved: canMakePayment() always answers yes and hasEnrolledInstrument() always answers no, so neither reveals anything."},

            {"name": "Block Remote Debugging", "key": "RemoteDebuggingAllowed", "value": False, "desc": "Blocks the remote debugging port and pipe, the interface automation tools use to drive the browser and read your cookies and logged-in sessions. Disable Developer Tools does not cover this. Breaks Puppeteer, Playwright and the brave://inspect remote-debugging toggle. No restart needed."},

            {"name": "Require HTTPS for Basic Auth", "key": "BasicAuthOverHttpEnabled", "value": False, "desc": "Refuses HTTP Basic authentication over plain HTTP so your username and password are never sent in the clear. Breaks logins on legacy routers, printers and other appliances that only serve HTTP, and plain-HTTP proxies that use Basic authentication."},

            {"name": "Block Local Network Access", "key": "LocalNetworkAccessBlockedForUrls", "value": ["*"], "desc": "Stops public websites from reaching devices on your local network (router, NAS, printers, smart-home hubs) or apps on this computer, with no prompt or per-site exception; Brave otherwise asks. Pages opened from a local address still work. Breaks web apps that pair with local devices or helper apps."},

            {"name": "Disable XSLT", "key": "XSLTEnabled", "value": False, "desc": "Turns off XSLT, the legacy XML transform engine behind XSLTProcessor and xml-stylesheet pages, an attack surface Chromium is removing; this keeps it off, even for sites that opt back in. XML styled with it (some RSS feeds and sitemaps) shows unstyled. Takes full effect after a restart."},

            {"name": "Disable JavaScript Optimization (hardening)", "key": "DefaultJavaScriptOptimizerSetting", "value": 2, "desc": "Turns off V8's optimizing compilers (TurboFan, Maglev) on websites; Brave says this makes it more resistant to attacks. Sites keep working, WebAssembly included, but script-heavy pages and web apps run slower, with no per-site exception. Applies to tabs opened after the change."},

            {"name": "Remove 'Always Allow' from App-Launch Prompts", "key": "ExternalProtocolDialogShowAlwaysOpenCheckbox", "value": False, "desc": "Removes the 'Always allow' checkbox from the prompt Brave shows before a site opens an external app, so every launch (mailto:, Zoom, Teams, Steam, ms-* links) needs a click. Apps you already set to always open from a site still open without asking."},

            {"name": "Force Site Isolation for Every Site", "key": "SitePerProcess", "value": True, "desc": "Keeps every site in its own process, as Brave already does on desktop, and stops brave://flags#site-isolation-trial-opt-out or --disable-site-isolation-trials from turning it off. Takes effect after a restart."},

            {"name": "Isolate Subdomains in Separate Processes", "key": "OriginKeyedProcessesEnabled", "value": True, "desc": "Puts each origin (for example mail.example.com and docs.example.com) in its own process rather than one per site, for stronger protection against Spectre-style leaks between subdomains. Uses more processes and memory. Takes effect after a restart. A brave://flags setting overrides it."},

            # DynamicCodeSettings is chrome.win only: SlimBrave.ps1 alone offers it.
        ],
    },
    {
        # Content-setting defaults sites are granted: each is a selector
        # (Not managed / Ask / Block, plus Allow where Chromium has one).
        # The microphone and camera rows at the end are checkboxes: their
        # policies are booleans whose true equals unset.
        "name": "Site Permissions",
        "features": [
            {"name": "Web Notifications", "key": "DefaultNotificationsSetting", "value": 2, "choices": CHOICES_ALLOW_BLOCK, "desc": "Sets the default for desktop notifications. Block stops every site from asking or showing them; Allow lets every site show them. Either overrides your per-site settings. Not managed keeps Brave's normal prompt (a managed Ask would let no notification through)."},

            {"name": "Location Access", "key": "DefaultGeolocationSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK, "desc": "Sets the default for reading your physical location. Block removes the prompt entirely, so maps and delivery sites will need the location typed manually; Ask prompts every time a site asks and remembers no answer. Any choice overrides your per-site settings."},

            {"name": "Motion Sensors", "key": "DefaultSensorsSetting", "value": 2, "choices": CHOICES_ALLOW_ASK_BLOCK, "desc": "Motion and orientation sensors are a fingerprinting vector, and Brave already blocks them by default. Block locks that: neither the settings page nor a per-site exception, even one made earlier, can allow them. Ask and Allow loosen Brave's default."},

            {"name": "WebUSB Access", "key": "DefaultWebUsbGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites talking to USB devices. Block removes the prompt and breaks web-based hardware wallets (Ledger, Trezor) and in-browser firmware flashers; Ask keeps the prompt. Chromium has no Allow state for this key."},

            {"name": "Web Serial Access", "key": "DefaultSerialGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites opening serial ports. Block removes the prompt and breaks in-browser microcontroller and device programming tools; Ask keeps the prompt. Chromium has no Allow state for this key."},

            {"name": "WebHID Access", "key": "DefaultWebHidGuardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites talking to human interface devices. Block removes the prompt, cuts Brave Wallet's own Ledger hardware-wallet connection, and may break security keys and gamepad configurators that use WebHID rather than WebAuthn. Chromium has no Allow state for this key."},

            {"name": "Local Font Enumeration", "key": "DefaultLocalFontsSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites asking which fonts are installed on your machine - a strong fingerprinting signal that Shields' font protections don't cover. Blocking rarely breaks anything outside web design tools. Chromium has no Allow state for this key."},

            {"name": "Multi-Screen Access", "key": "DefaultWindowManagementSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites reading your monitor layout and placing windows on a chosen screen. Blocking breaks the full-screen presentation mode in some web apps. Chromium has no Allow state for this key."},

            {"name": "Clipboard Read Access", "key": "DefaultClipboardSetting", "value": 2, "choices": CHOICES_ASK_BLOCK, "desc": "Sets the default for sites reading your clipboard without you pasting. Block removes the prompt and breaks Paste buttons inside web apps; Ask keeps the prompt. Either one overrides sites you allowed before. Ctrl+V and copy buttons still work. Chromium has no Allow state for this key."},

            {"name": "Block Microphone Access", "key": "AudioCaptureAllowed", "value": False, "desc": "Stops every site and extension from using the microphone or any other audio input, with no prompt; per-site Allow exceptions stop working too. Breaks web calls and meetings (Meet, Zoom or Teams on the web, Discord, Brave Talk), voice messages and dictation on websites."},

            {"name": "Block Camera Access", "key": "VideoCaptureAllowed", "value": False, "desc": "Stops every site and extension from using the camera or any other video input, with no prompt; per-site Allow exceptions stop working too. Breaks web video calls (Meet, Zoom or Teams on the web, Discord, Brave Talk), webcam ID checks and in-browser QR scanners."},

        ],
    },
    {
        # Lockdowns and the escape hatches (guest, incognito, extensions)
        # that would otherwise bypass the rest of the policy set.
        "name": "Access Controls",
        "features": [
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True, "desc": "Forces SafeSearch on for all Google searches. Mainly useful for parental controls."},

            {"name": "Force YouTube Restricted Mode (Strict)", "key": "ForceYouTubeRestrict", "value": 2, "desc": "Forces YouTube's Strict Restricted Mode on youtube.com and its country domains, including videos other sites embed from them; the user cannot turn it off. Many videos become unavailable and comments are hidden. Videos embedded from youtube-nocookie.com are not restricted."},

            {"name": "Lock Safe Browsing On (Standard)", "key": "SafeBrowsingProtectionLevel", "value": 1, "group": "safebrowsing", "desc": "Locks Safe Browsing at Standard protection so it cannot be switched to No protection in brave://settings/security. Lookups go through Brave's proxy, as they do by default. Mutually exclusive with Disable Safe Browsing."},

            {"name": "Block Bypassing Safe Browsing Warnings", "key": "DisableSafeBrowsingProceedAnyway", "value": True, "desc": "Removes the option to continue past Safe Browsing's malware and phishing warnings, so a flagged site cannot be opened, even one flagged by mistake. Does not cover certificate or download warnings. Does nothing while Safe Browsing is off; Lock Safe Browsing On keeps it on."},

            {"name": "Block Bypassing Certificate Warnings", "key": "SSLErrorOverrideAllowed", "value": False, "desc": "Removes the Proceed link, and the typed bypass, from certificate-error pages, so a site whose certificate is invalid, expired or self-signed cannot be opened at all. Breaks router, NAS and printer admin pages and local dev servers that use self-signed certificates."},

            {"name": "Disable Guest Mode", "key": "BrowserGuestModeEnabled", "value": False, "desc": "Removes guest browsing sessions: off-the-record windows that keep no history and run without your profile's extensions. Disable Incognito Mode does not remove them. These policies still apply inside guest windows."},

            {"name": "Prevent Deleting History", "key": "AllowDeletingBrowserHistory", "value": False, "desc": "Stops anyone deleting browsing and download history in History, Downloads or Clear browsing data; Brave's clear-on-exit keeps them too. Brave's Local history retention setting (brave://settings/privacy) can still expire history after as little as a day, and SlimBrave cannot lock it."},

            {"name": "Block All Extensions", "key": "ExtensionInstallBlocklist", "value": ["*"], "desc": "Blocks installation of every extension and disables ones already installed. For lockdown/parental setups - a proxy or VPN extension would bypass DNS filtering."},

            {"name": "Block Sideloaded (External) Extensions", "key": "BlockExternalExtensions", "value": True, "desc": "Blocks extensions other programs install through the Windows registry or a drop-in file (how bundleware gets in) and removes any added that way at the next launch, even ones you approved. Extensions you install yourself keep working."},

            {"name": "Block Command-Line Extensions (--load-extension)", "key": "ExtensionInstallTypeBlocklist", "value": ["command_line"], "desc": "Ignores extensions passed with --load-extension, which malware adds to Brave's shortcuts to slip one in. Google Chrome ignores that switch; Brave honours it unless this is set. --disable-extensions-except can still load one. Breaks shortcuts and test tools that use the switch. Restart needed."},

            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito", "desc": "Removes private browsing entirely - no incognito windows can be opened. Mutually exclusive with Force Incognito Mode."},

            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito", "desc": "Every window opens in incognito: no history, and logins and most extensions stop persisting. Tor windows go too, and so do Leo and Brave Rewards, plus Brave Wallet unless it is allowed in private windows. Mutually exclusive with Disable Incognito Mode."},

        ],
    },
    {
        "name": "Brave Features",
        "features": [
            {"name": "Disable Brave Rewards", "key": "BraveRewardsDisabled", "value": True, "desc": "Removes Brave Rewards and keeps Brave's ads service off, so no sponsored New Tab Page images or notification ads. Brave Search's own result ads are not affected, and an anonymous background fetch of the ads encryption key still runs unless Limit or Disable Variations is also set."},

            {"name": "Disable Brave Wallet", "key": "BraveWalletDisabled", "value": True, "desc": "Disables the built-in cryptocurrency wallet and hides its UI."},

            {"name": "Disable Brave VPN (no effect on Linux builds)", "key": "BraveVPNDisabled", "value": True, "desc": "Removes the Brave VPN feature and its upsell prompts. Linux builds have no VPN, so this key changes nothing there."},

            {"name": "Disable Brave AI Chat", "key": "BraveAIChatEnabled", "value": False, "desc": "Disables Leo, Brave's built-in AI assistant, and removes it from the sidebar and address bar. Brave still downloads Leo's WebMCP tool-scripts component, though nothing uses it while Leo is off."},

            {"name": "Disable Local AI (On-Device Models, Brave 1.94+, off by default on Release)", "key": "BraveLocalAIEnabled", "value": False, "desc": "Stops Brave from downloading and running on-device AI models and from building an AI index of your browsing history; disabling Leo does not cover this. Off by default on Release (on in Nightly and Beta); this keeps it off if Brave or you turn it on. Takes effect after a restart."},

            {"name": "Disable Brave Shields", "key": "BraveShieldsDisabledForUrls", "value": ["https://*", "http://*"], "group": "shields", "desc": "Kiosk/testing only. Shields OFF for every site: no ad or tracker blocking; Shields & Content Protection rows, Strip Tracking URL Parameters and Reduce Language Fingerprinting do nothing. De-AMP, Debouncing, GPC and third-party cookie blocking still work. Mutually exclusive with Force Shields On."},

            {"name": "Force Shields On (All Sites)", "key": "BraveShieldsEnabledForUrls", "value": ["https://*", "http://*"], "group": "shields", "desc": "Locks Shields ON for every site: the per-site toggle can no longer drop ad, tracker or fingerprinting protection, but switching it off still unblocks third-party cookies and storage for that site. Mutually exclusive with Disable Brave Shields."},

            {"name": "Disable Brave News", "key": "BraveNewsDisabled", "value": True, "desc": "Removes the Brave News feed from the new tab page. A profile Brave opted into News on first run can still show a News button in the sidebar, which opens an empty panel."},

            {"name": "Disable Brave Talk", "key": "BraveTalkDisabled", "value": True, "desc": "Hides Brave Talk (private video calls) from the new tab page, sidebar and menus. The talk.brave.com website itself still works."},

            {"name": "Disable Brave Playlist (off by default on Release)", "key": "BravePlaylistEnabled", "value": False, "desc": "Disables the Playlist feature for saving and playing media in the sidebar. Playlist is off by default on Release and Beta (on in Nightly); this keeps it off if Brave or you turn it on."},

            {"name": "Disable Web Discovery", "key": "BraveWebDiscoveryEnabled", "value": False, "desc": "Stops Brave from anonymously contributing pages you visit to the Brave Search index (Web Discovery Project)."},

            {"name": "Disable Speedreader", "key": "BraveSpeedreaderEnabled", "value": False, "desc": "Disables Speedreader, the distraction-free article reading mode."},

            {"name": "Disable Tor", "key": "TorDisabled", "value": True, "desc": "Removes the 'New private window with Tor' option."},

            {"name": "Disable Sync", "key": "SyncDisabled", "value": True, "desc": "Disables Brave Sync, which shares bookmarks, history, and settings across devices via a sync chain. Applying it also removes this device from its chain, so once the policy is lifted it has to rejoin with a sync code from another device."},

            {"name": "Disable Email Aliases", "key": "EmailAliasesEnabled", "value": False, "desc": "Disables the Email Aliases feature for generating throwaway email addresses, which current Brave releases turn on."},

        ],
    },
    {
        # Brave 1.86+ content-protection enforcers (fingerprinting
        # protection also works on 1.85). These pin Brave's own privacy
        # defaults as managed policy so neither the user nor a malicious
        # page/extension can quietly weaken them.
        "name": "Shields & Content Protection",
        "features": [
            {"name": "Enforce Ad Blocking", "key": "DefaultBraveAdblockSetting", "value": 2, "desc": "Pins Brave's network ad and tracker blocking on as managed policy, so it can't be lowered in settings or per site. Cosmetic filtering (element hiding, scriptlets) is not locked, and sites with Shields off are not covered."},

            {"name": "Enforce Fingerprinting Protection", "key": "DefaultBraveFingerprintingV2Setting", "value": 3, "desc": "Pins Shields fingerprinting protection on as managed policy, so it can't be turned off per site. Per-API exceptions (Brave's compatibility list or your own Shields toggles) still apply, and sites with Shields off are not covered."},

            {"name": "Force HTTPS Upgrades (Strict; not enforced on Brave's HTTPS-First rollout)", "key": "DefaultBraveHttpsUpgradeSetting", "value": 2, "desc": "Always upgrades connections to HTTPS; sites that can't serve it show a warning instead of falling back to HTTP. Not enforced where Brave moved to Chromium's HTTPS-First mode (Beta, Nightly, part of Release), which it only presets once; Limit or Disable Variations keeps it enforced."},

            {"name": "Cap Referrers (Strict Origin)", "key": "DefaultBraveReferrersSetting", "value": 2, "group": "referrers", "desc": "Caps the Referer header at the origin for cross-origin requests, as Brave already does by default, and locks it: per-site exceptions stop applying, including any Brave's compatibility list adds to fix sites. Mutually exclusive with Allow Permissive Referrers."},

            {"name": "Allow Permissive Referrers (unsafe-url)", "key": "DefaultBraveReferrersSetting", "value": 1, "group": "referrers", "desc": "Sends your full referring URL cross-origin when a site requests it. Compatibility escape hatch only - this weakens privacy and is excluded from every preset. Mutually exclusive with Cap Referrers."},

            {"name": "Forget First-Party Storage on Close", "key": "DefaultBraveRemember1PStorageSetting", "value": 2, "desc": "Clears a site's cookies and storage when you close its last tab - sites forget you (and your logins) between visits."},

        ],
    },
    {
        "name": "Performance & Bloat",
        "features": [
            {"name": "Disable Background Mode", "key": "BackgroundModeEnabled", "value": False, "desc": "Stops Brave from staying open in the background after its last window closes, which it does only while an installed extension asks to run in the background. Without one, the policy only locks off 'Continue running background apps when Brave is closed' (brave://settings/system)."},

            {"name": "Enable Memory Saver", "key": "HighEfficiencyModeEnabled", "value": True, "desc": "Forces Memory Saver on: inactive tabs are discarded to free RAM and reload when you return to them."},

            {"name": "Force Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": True, "group": "hwaccel", "desc": "Brave already has 'Use graphics acceleration when available' on; this locks it on, so it can't be turned off in Settings to work around GPU glitches. The GPU blocklist or repeated GPU crashes can still force software rendering. Takes effect after a browser restart."},

            {"name": "Disable Hardware Acceleration", "key": "HardwareAccelerationModeEnabled", "value": False, "group": "hwaccel", "desc": "Forces GPU acceleration off, unlike Brave's default, costing rendering speed and battery. Use it only when the GPU path is the problem: flicker or artifacts from a faulty driver, a VM or RDP session with no usable GPU, or corruption while screen sharing. Takes effect after a browser restart."},

            {"name": "Disable Media Router (Cast)", "key": "EnableMediaRouter", "value": False, "desc": "Disables Google Cast and its background device discovery on the local network. Takes effect after a browser restart. A profile first opened under this policy keeps Cast off after it is lifted, until the Media Router toggle in brave://settings/extensions is back on and Brave restarted."},

            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True, "desc": "Downloads PDF files instead of showing them in Brave's built-in viewer; nothing opens them until you do. Sites can tell the viewer is off, and fingerprinting protection does not hide it, which makes you easier to fingerprint."},

            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False, "desc": "Disables the built-in page translation feature and its popup prompts."},

            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False, "group": "spellcheck", "desc": "Turns off spell checking in text fields entirely. Mutually exclusive with Disable Enhanced Spell Check, which keeps offline checking and only removes the Google lookup."},

            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False, "desc": "Stops sending what you type in the address bar to your search engine for live suggestions."},

            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False, "desc": "Disables printing from the browser entirely (including Ctrl+P and Save as PDF). Brave features built on print preview break too: Leo reading Google Docs and scanned PDFs, and the Screenshot tool's Full page on PDFs and Google Docs."},

            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False, "desc": "Stops Brave from asking to become your default browser, and brave://settings loses its Make default button. Brave's first-run welcome page still offers Set as default, and clicking it with this policy on crashes Brave: choose Skip there."},

            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2, "desc": "Blocks DevTools (F12), extension debugging and the View page source shortcut and menu, and turns extension Developer mode off (no Load unpacked). Brave's Screenshot Full page then never finishes and greys out Screenshot in that window until it is closed. Not for web developers."},

            {"name": "Disable Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False, "desc": "Stops Brave from offering an archive.org snapshot when a page is missing or fails (404, 408, 410, 451 and some 5xx errors), including the offer Brave can pop up on its own."},

        ],
    },
]

# "unmanaged" (the default) writes no DNS policy at all, leaving Brave's
# DNS settings user-controlled. The other four are managed-policy values —
# including "off", which actively force-disables DoH as policy.
DNS_MODES = ["unmanaged", "automatic", "off", "secure", "custom"]

# ---------------------------------------------------------------------------
# Build a flat list of rows for the TUI (headers + toggleable items + DNS)
# ---------------------------------------------------------------------------

ROW_HEADER = 0
ROW_FEATURE = 1
ROW_DNS = 2
ROW_DNS_TEMPLATE = 3
ROW_CHOICE = 4


def build_rows(installations=None):
    """Return a list of dicts describing each visual row.

    On Linux every channel shares POLICY_FILE so a per-channel selector
    cannot meaningfully scope the policy write. `installations` has one
    effect on the layout: when every detected Brave is Brave Origin, the
    rows whose feature Origin compiles out are marked inert
    (ORIGIN_BUILTIN_KEYS).
    """
    rows = []
    for cat in CATEGORIES:
        # `collapsed` lives only on headers, and import/reset/sync all
        # mutate rows in place without touching one, so a fold survives.
        rows.append({"type": ROW_HEADER, "text": cat["name"],
                     "collapsed": False})
        for feat in cat["features"]:
            if "choices" in feat:
                rows.append({
                    "type": ROW_CHOICE,
                    "text": feat["name"],
                    "key": feat["key"],
                    "value": feat["value"],   # what the old checkbox wrote
                    "choices": feat["choices"],
                    "desc": feat.get("desc", ""),
                    "selected": 0,            # index into choices; 0 = unmanaged
                })
                continue
            rows.append({
                "type": ROW_FEATURE,
                "text": feat["name"],
                "key": feat["key"],
                "value": feat["value"],
                "group": feat.get("group"),
                "desc": feat.get("desc", ""),
                "checked": False,
            })
    # On a machine whose only Brave is Origin, the rows for the features
    # Origin compiles out are shown but inert (see ORIGIN_BUILTIN_KEYS).
    if is_origin_only(installations):
        for row in rows:
            if row["type"] == ROW_FEATURE and row["key"] in ORIGIN_BUILTIN_KEYS:
                row["inert"] = True
    # DNS mode selector at the end
    rows.append({"type": ROW_HEADER, "text": "DNS Over HTTPS",
                 "collapsed": False})
    rows.append({
        "type": ROW_DNS,
        "text": "DNS Mode",
        "options": DNS_MODES,
        "selected": 0,  # index into DNS_MODES
    })
    rows.append({
        "type": ROW_DNS_TEMPLATE,
        "text": "DoH Template",
        "value": "",        # the URL string
        "cursor": 0,        # cursor position within the text
        "scroll": 0,        # horizontal scroll offset for long URLs
    })
    return rows


def get_dns_mode(rows):
    """Return the currently selected DNS mode string."""
    for row in rows:
        if row["type"] == ROW_DNS:
            return row["options"][row["selected"]]
    return "unmanaged"


def get_dns_template(rows):
    """Return the current DoH template URL string."""
    for row in rows:
        if row["type"] == ROW_DNS_TEMPLATE:
            return row["value"]
    return ""


def toggle_feature_row(rows, target):
    """Flip `target`'s checked state. If it belongs to a group, uncheck the
    other group members first so at most one is active (e.g. Disable vs
    Force Incognito, which set conflicting values for the same policy).
    An inert row (built into Brave Origin) never changes."""
    if target.get("inert"):
        return
    new_state = not target["checked"]
    target["checked"] = new_state
    group = target.get("group")
    if new_state and group:
        for row in rows:
            if row is target:
                continue
            if row.get("type") == ROW_FEATURE and row.get("group") == group:
                row["checked"] = False


def _choice_value(row):
    """Return the policy value a choice row is set to, or None if unmanaged."""
    return row["choices"][row["selected"]][1]


def _choice_index_for_value(row, value):
    """Return the index of the choice carrying `value`, or None if illegal.

    Type-strict, because `True == 1` in Python: a JSON `true` would
    otherwise select "Allow" on the three settings that have one, and no
    bool is a legal member of any of these enums.
    """
    for idx, choice in enumerate(row["choices"]):
        choice_value = choice[1]
        if choice_value is None:
            continue
        if type(choice_value) is type(value) and choice_value == value:
            return idx
    return None


def cycle_choice_row(row, step=1):
    """Advance a choice row's selection, wrapping at both ends.

    Same idiom as the DNS selector: Left/Right/Space/Enter all walk the
    same ordered list.
    """
    row["selected"] = (row["selected"] + step) % len(row["choices"])


def activate_row(rows, row):
    """Space/Enter action for a list row: header fold, feature toggle,
    choice/DNS advance. Returns True when the row type has one, so the
    caller clears the status line; False otherwise (e.g. NO_ROW)."""
    if row["type"] == ROW_HEADER:
        row["collapsed"] = not row.get("collapsed", False)
    elif row["type"] == ROW_FEATURE:
        if row.get("inert"):
            return False
        toggle_feature_row(rows, row)
    elif row["type"] == ROW_CHOICE:
        cycle_choice_row(row, 1)
    elif row["type"] == ROW_DNS:
        row["selected"] = (row["selected"] + 1) % len(row["options"])
    else:
        return False
    return True


def _is_json_int(value):
    """True for a JSON integer as Windows PowerShell 5.1 reads one: an [int]
    or a [long]. A larger one is a [decimal] or a [double] there, so it is
    no integer to any of the three scripts."""
    return type(value) is int and -2 ** 63 <= value < 2 ** 63


def _value_fits_row(row, value):
    """True when `value` has the JSON type of the policy a checkbox row writes.

    Import and policy-sync take a value only in that type, the rule
    SlimBrave.ps1's import applies too: an integer policy only a JSON
    integer within 64 bits, a boolean policy true/false or such an
    integer, a list policy an array, the string policy a string.
    """
    want = row["value"]
    if isinstance(want, bool):
        return type(value) is bool or _is_json_int(value)  # Windows exports write 0/1
    if isinstance(want, int):
        return _is_json_int(value)  # True == 1 must not pick an enum member
    if isinstance(want, list):
        return isinstance(value, list)
    return isinstance(value, str)


def _value_matches_row(row, value):
    """True when `value` is exactly what a checkbox row writes."""
    if not _value_fits_row(row, value):
        return False
    if isinstance(row["value"], list):
        # Order means nothing to Chromium, as in SlimBrave.ps1's Compare-Object.
        # Only JSON strings are entries, as there. Checked first, so no
        # nested entry is ever compared or printed: str() of one recursed
        # as deep as the file nests it.
        return (all(type(v) is str for v in value)
                and sorted(value) == sorted(row["value"]))
    return value == row["value"]


def _enforce_groups(rows):
    """Collapse every group down to at most one checked row.

    Import and policy-sync set `checked` per row with no group awareness,
    so a config naming both BraveShieldsDisabledForUrls and
    BraveShieldsEnabledForUrls ticks both and _build_policy would emit
    force-off and force-on for the same wildcards. The later row in table
    order wins, whatever order the file or policy lists the keys in. Where
    the members sit on different keys that is what Brave enforces when both
    are set: BraveShieldsEnabledForUrls is applied after the Disabled list,
    so it wins for the same patterns, and SpellCheckServiceEnabled does
    nothing once SpellcheckEnabled is false. SlimBrave.ps1's
    Enforce-ExclusionGroups applies the same rule.

    Returns the keys of the rows it unchecked, for the import message.
    """
    # Choice rows never reach the bodies below: every test here is gated on
    # ROW_FEATURE, and a choice row carries neither "checked" nor a group.
    dropped = []
    groups = dict.fromkeys(r["group"] for r in rows
                           if r["type"] == ROW_FEATURE and r.get("group"))
    for group in groups:
        members = [r for r in rows
                   if r["type"] == ROW_FEATURE
                   and r.get("group") == group and r["checked"]]
        for r in members[:-1]:
            r["checked"] = False
            dropped.append(r["key"])
    return dropped

# ---------------------------------------------------------------------------
# BOM-aware JSON reader (handles PowerShell UTF-16 exports)
# ---------------------------------------------------------------------------


# Import reads the file you name as root, so it reads no more than a config
# could ever need. A pipe such as /dev/stdin still works: nothing asks for a
# regular file, the read just stops one byte past the cap.
MAX_IMPORT_BYTES = 1024 * 1024


def _fold_case(key):
    """`key` with each character in its simple upper case: c.upper() where
    that is one character, c itself where it is more (the sharp s, a
    ligature) or lies beyond U+FFFF. Close to .NET Framework's
    OrdinalIgnoreCase, by which Windows PowerShell 5.1 compares the names of
    a JSON object one UTF-16 unit at a time: U+00C9 and U+00E9 are one name
    there and here, and a letter beyond U+FFFF folds in neither."""
    return "".join(_fold_char(c) for c in key)


def _fold_char(c):
    """One character of _fold_case: its simple upper case. str.upper() is
    the full mapping, two characters for the 27 Greek letters with
    ypogegrammeni (U+1F80), whose simple upper case is the one-character
    title case .NET folds them to (U+1F88), so that is taken instead."""
    if ord(c) > 0xFFFF:
        return c
    up = c.upper()
    if len(up) == 1:
        return up
    title = c.title()
    return title if len(title) == 1 else c


class _KeysDifferInCase(ValueError):
    """Two keys of one JSON object differ only in letter case."""

    def __init__(self, first, second):
        super().__init__("keys differ only in letter case")
        self.keys = (first, second)


class _EmptyKey(ValueError):
    """A key of a JSON object is the empty string."""

    def __init__(self):
        super().__init__("a key is empty")


def _refuse_unreadable_keys(pairs):
    """read_json_file's object_pairs_hook: the object, unless one of its
    keys is empty or two of them differ only in letter case.

    Windows PowerShell 5.1's ConvertFrom-Json cannot read either, at any
    depth: a property with an empty name is refused, and two names that
    differ only in case are DuplicateKeysInJsonString. SlimBrave.ps1 so
    refuses such a file, and the Python scripts refuse it too, so one file
    never imports here and fails there. Case is folded by _fold_case, as
    near as Python comes to .NET's rule. A key written twice in the same
    case is left to json: the last one wins.
    """
    first_seen = {}
    for key, _ in pairs:
        if not key:
            raise _EmptyKey()
        first = first_seen.setdefault(_fold_case(key), key)
        if first != key:
            raise _KeysDifferInCase(first, key)
    return dict(pairs)


def _json_int(text):
    """read_json_file's parse_int: an integer within 64 bits as an int, a
    larger one as a float (_json_float), as Windows PowerShell 5.1 reads it
    as a [decimal] or a [double], neither of which _is_json_int takes.
    float() reads any length in linear time, so a million digits cannot
    stall a Python without the 4300-digit limit (3.9.6, macOS's own)."""
    if len(text) <= 20:
        value = int(text)
        if -2 ** 63 <= value < 2 ** 63:
            return value
    return _json_float(text)


def _json_float(text):
    """read_json_file's parse_float: a number past the double range is
    refused (ValueError), as Windows PowerShell 5.1's reader refuses it."""
    value = float(text)
    if math.isinf(value):
        raise ValueError("a number is out of range")
    return value


def read_json_file(path):
    """Read a JSON file, handling BOM and encoding from PS1 exports.

    Raises OSError for a file over MAX_IMPORT_BYTES, which import_settings
    reports as a read error; and, both ValueErrors, _EmptyKey for an object
    with an empty key and _KeysDifferInCase for one with two keys that
    differ only in letter case.
    """
    with open(path, "rb") as f:
        data = f.read(MAX_IMPORT_BYTES + 1)
    if len(data) > MAX_IMPORT_BYTES:
        raise OSError("file is larger than 1 MiB")

    # Detect BOM and decode accordingly
    if data[:2] == b"\xff\xfe":
        text = data[2:].decode("utf-16-le", errors="replace")
    elif data[:2] == b"\xfe\xff":
        text = data[2:].decode("utf-16-be", errors="replace")
    elif data[:3] == b"\xef\xbb\xbf":
        text = data[3:].decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = data.decode("utf-16-le", errors="replace")

    # Strip null bytes (UTF-16 artifacts in malformed files)
    text = text.replace("\x00", "")
    return json.loads(text, object_pairs_hook=_refuse_unreadable_keys,
                      parse_int=_json_int, parse_float=_json_float)

# ---------------------------------------------------------------------------
# Profile-prefs repair
#
# Some profiles carry braveShields exceptions for exactly the patterns the
# "Disable Brave Shields" row writes (`http://*,*` and `https://*,*`), left
# behind after that policy was applied and removed; while there they keep
# Shields off after the row is unchecked. Brave does not write the managed
# policy into Preferences (policy content settings stay in memory), and no
# writer of these entries has been identified, so this scrub is a guard for
# profiles that carry them, not a fix for a known cause.
# ---------------------------------------------------------------------------


def _pid_is_alive(pid):
    """True if `pid` names a live process.

    /proc is the cheap check; signal 0 is the fallback for kernels without
    it. Never reached off POSIX — os.kill there terminates rather than
    probes.
    """
    if os.path.isdir(f"/proc/{pid}"):
        return True
    if os.name != "posix":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # it exists, we just can't signal it
    return True


def _singleton_lock_pid(prefs_path):
    """Return (host, pid) from a profile's Chromium SingletonLock, or None.

    Chromium symlinks <user-data-dir>/SingletonLock to "<hostname>-<pid>"
    for as long as the profile is open. This is the only running-check that
    covers every channel: `pgrep -x` matches /proc/<pid>/comm, capped at 15
    characters, so "brave-browser-beta" and friends can never match.
    """
    if not prefs_path:
        return None
    user_data = os.path.dirname(os.path.dirname(prefs_path))
    try:
        target = os.readlink(os.path.join(user_data, "SingletonLock"))
    except OSError:
        return None
    host, sep, pid_part = target.rpartition("-")
    if not sep or not pid_part.isdigit():
        return None
    return host, int(pid_part)


def _lock_holder_is_running(host, pid):
    """True if a SingletonLock's holder still counts as a running Brave.

    A lock taken on another host counts: the profile is in use there (a
    shared home), and Chromium treats it the same way. On this host the
    pid has to be alive, and on Linux it also has to be a Brave binary,
    Chromium's own IsChromeProcess test: a lock a crash left behind can
    name a pid some other program has since been given. Every Brave build
    on Linux, Origin included, runs a binary named brave. macOS has no
    procfs, so there a live pid is enough.
    """
    if host != socket.gethostname():
        return True
    if not _pid_is_alive(pid):
        return False
    if not os.path.isdir("/proc/self"):
        return True
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    if exe.endswith(" (deleted)"):
        exe = exe[:-len(" (deleted)")]
    return os.path.basename(exe) == "brave"


# pgrep by absolute path, never through PATH: sudo can pass the caller's
# PATH through, and a script-only sudoers grant must not let it pick the
# program root runs. macOS and procps install it in /usr/bin; /bin covers
# Linux distributions that have not merged /usr.
PGREP_PATHS = ("/usr/bin/pgrep", "/bin/pgrep")


def _pgrep(name, uid=None):
    """Return the exit status of `pgrep [-u uid] -x name`, or None with no pgrep."""
    args = ["-x", name] if uid is None else ["-u", str(uid), "-x", name]
    for exe in PGREP_PATHS:
        try:
            return subprocess.run(
                [exe, *args],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode
        except FileNotFoundError:
            continue
    return None


def _is_brave_running(installations=None):
    """True if any of the listed Brave installations have a live process.

    The process search is limited to the invoking user's processes
    (_invoking_user): theirs is the profile the scrub rewrites, and another
    account's Brave cannot overwrite it.
    """
    if installations is None:
        names = ["brave"]
    else:
        for inst in installations:
            holder = _singleton_lock_pid(inst.get("prefs_path"))
            if holder is not None and _lock_holder_is_running(*holder):
                return True
        names = [i["process_name"] for i in installations if i.get("process_name")]
        if not names:
            names = ["brave"]

    identity = _sudo_user_identity()
    uid = identity[1] if identity else None
    for name in names:
        # A name longer than comm's 15-char cap can only ever be a false
        # negative, so don't spend a process asking.
        if len(name) > 15:
            continue
        rc = _pgrep(name, uid)
        if rc is None:
            return False
        if rc == 0:
            return True
    return False


def _sudo_user_identity():
    """Return (name, uid, gid) of the invoking user, or None (_invoking_user)."""
    identity = _invoking_user()
    return identity[:3] if identity else None


def _run_as_invoking_user(fn, *args, default):
    """Call fn(*args) with the invoking user's rights; return its result.

    As root with an invoking user to drop to, fn runs in a forked child
    that takes on that user's groups, gid and uid first, so it can read,
    create and replace only what the user could; its JSON-encoded result
    comes back over a pipe. A failed fork or drop, an exception in fn, or
    a reply that does not decode gives `default`, never a second try as
    root. Without root, without an invoking user or without fork (Windows),
    fn runs inline.
    """
    identity = _sudo_user_identity()
    if identity is None or not hasattr(os, "fork") or os.geteuid() != 0:
        return fn(*args)

    name, uid, gid = identity
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return default

    if pid == 0:
        try:
            os.close(read_fd)
            try:
                os.initgroups(name, gid)
            except (AttributeError, OSError):
                # Never keep root's supplementary groups: fall back to the
                # primary group alone, and if even that fails the drop
                # fails and fn never runs.
                os.setgroups([gid])
            os.setgid(gid)
            os.setuid(uid)
            data = json.dumps(fn(*args)).encode("utf-8")
            while data:
                data = data[os.write(write_fd, data):]
        except BaseException:
            pass  # nothing more is sent; a cut-off reply fails to decode
        finally:
            os._exit(0)

    os.close(write_fd)
    chunks = []
    try:
        # Read to EOF before waiting: a reply larger than the pipe buffer
        # would otherwise block the child, and the wait with it.
        while True:
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        chunks = []
    finally:
        os.close(read_fd)
    os.waitpid(pid, 0)
    try:
        return json.loads(b"".join(chunks))
    except ValueError:
        return default


def _scrub_as_invoking_user(scrub, path, default):
    """Run a prefs scrub as the invoking user; `default` when there is none.

    As root with nobody to drop to (a root login, `su -`), nothing is
    scrubbed: rewriting a home directory as root is what the drop avoids.
    """
    if getattr(os, "geteuid", lambda: -1)() == 0 and _sudo_user_identity() is None:
        return default
    return _run_as_invoking_user(scrub, path, default=default)


def _repair_one_prefs(pref_path):
    """Scrub a single prefs file, dropping root first where we can.

    Every path component under the user's home is theirs to replace, so
    doing the read-modify-write as root would follow a symlinked
    `Default`/`Profile *` into a file root owns and then hand it over.
    Fork and drop to the invoking user's uid/gid instead — the child can
    only reach what that user could already reach. Returns what
    _scrub_one_prefs does (0 when the drop fails, so a broken drop repairs
    nothing rather than repairing as root).
    """
    return _scrub_as_invoking_user(_scrub_one_prefs, pref_path, 0)


def _repair_user_data_dir(default_prefs_path):
    """Scrub every profile of one user-data dir in a single drop.

    The child lists the profiles as well, so root never reads a directory
    inside the user's home. Returns [removed, failed] (_scrub_user_data_dir).
    """
    return _scrub_as_invoking_user(_scrub_user_data_dir, default_prefs_path, [0, 0])


def _scrub_user_data_dir(default_prefs_path):
    """List a user-data dir's profiles and scrub each, as the caller.

    Returns [removed, failed]: the entries removed, and the number of
    profiles whose Preferences could not be read or rewritten. A list, so
    the reply from the dropped child decodes to the same value.
    """
    removed = failed = 0
    for path in _profile_prefs_paths(default_prefs_path):
        count = _scrub_one_prefs(path)
        if count < 0:
            failed += 1
        else:
            removed += count
    return [removed, failed]


def _scrub_one_prefs(pref_path):
    """Remove SlimBrave's Shields-disabled exceptions from one prefs file.

    Returns the number of exception entries removed: 0 if the file is
    missing, is not JSON (or not UTF-8), or holds none of them; -1 if it
    exists but cannot be read, or holds them and cannot be rewritten.
    """
    if not pref_path or not os.path.isfile(pref_path):
        return 0

    try:
        with open(pref_path, "r", encoding="utf-8") as f:
            prefs = json.load(f)
    except ValueError:
        # JSONDecodeError and UnicodeDecodeError: not a file Brave could
        # load either, so there is nothing of ours to remove.
        return 0
    except OSError:
        return -1

    # Walk with type checks: valid JSON can still hold a null or a list
    # where Brave keeps an object.
    node = prefs
    for key in ("profile", "content_settings", "exceptions"):
        node = node.get(key) if isinstance(node, dict) else None
    bs = node.get("braveShields") if isinstance(node, dict) else None
    if not isinstance(bs, dict) or not bs:
        return 0

    removed = 0
    for pattern in ("http://*,*", "https://*,*"):
        if pattern in bs:
            del bs[pattern]
            removed += 1

    if removed == 0:
        return 0

    try:
        original_mode = os.stat(pref_path).st_mode & 0o777
        _atomic_write(
            pref_path,
            json.dumps(prefs, separators=(",", ":")),
            mode=original_mode,
        )
    except OSError:
        return -1

    return removed


def repair_brave_prefs(installations=None):
    """Remove the leaked Shields exceptions across all given channels.

    Returns (removed_count, failed, brave_was_running), where `failed` maps
    each user-data dir to the number of its profiles that could not be
    cleaned (_scrub_failure_note words it).
    """
    if installations is None:
        installations = [{"prefs_path": _channel_prefs_path(LINUX_CHANNELS[0]["user_data_dir"])}]

    running = _is_brave_running(installations)
    total = 0
    failed = {}
    seen = set()
    for inst in installations:
        prefs_path = inst.get("prefs_path")
        if not prefs_path:
            continue
        # One drop per user-data dir, which holds every profile's folder.
        user_data = os.path.dirname(os.path.dirname(prefs_path))
        if user_data in seen:
            continue
        seen.add(user_data)
        removed, not_cleaned = _repair_user_data_dir(prefs_path)
        total += removed
        if not_cleaned:
            failed[user_data] = not_cleaned
    return (total, failed, running)


def _scrub_failure_note(failed):
    """The sentence naming profiles the scrub could not clean, or ''."""
    if not failed:
        return ""
    n = sum(failed.values())
    return (f"Failed to clean {n} profile{'s' if n != 1 else ''}; "
            f"check ownership of {', '.join(failed)}.")


# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------


def _read_one_policy(plist_path):
    """Read a single JSON policy file.

    Anything that is not a readable dict reads as empty.
    """
    try:
        with open(plist_path, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, PermissionError):
        return {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def load_existing_policy(installations=None):
    """Read the current on-disk policy and return its dict.

    On Linux every channel shares POLICY_FILE, so de-duped reads still hit
    just one file. Falls back to POLICY_FILE when no installations are
    supplied.
    """
    if installations is None:
        return _read_one_policy(POLICY_FILE)
    seen = set()
    for inst in installations:
        p = inst.get("plist_path") or POLICY_FILE
        if p in seen:
            continue
        seen.add(p)
        data = _read_one_policy(p)
        if data:
            return data
    return {}


def _build_policy(rows):
    """Translate row state into a {key: value} policy dict.

    Returns (policy, error_msg). On validation failure policy is None.
    """
    policy = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"] and not row.get("inert"):
            policy[row["key"]] = row["value"]
        elif row["type"] == ROW_CHOICE:
            choice_value = _choice_value(row)
            if choice_value is not None:
                policy[row["key"]] = choice_value
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # "secure" with no template is a working configuration that resolves
    # nothing: Chromium applies the mode, blanks the templates pref, and
    # the system-resolver fallback is gated off for kSecure. The user can't
    # undo it in settings either, because the policy is machine-managed.
    # "automatic" is exempt — an empty template is valid and documented.
    if dns_mode in ("custom", "secure") and not dns_template:
        return None, "Secure/custom DNS requires a DoH template URL."

    # "unmanaged" writes no DNS keys at all; since Apply fully overwrites
    # the policy file, any previously-managed DNS policy is removed.
    if dns_mode and dns_mode != "unmanaged":
        if dns_mode == "custom":
            policy["DnsOverHttpsMode"] = "secure"
            policy["DnsOverHttpsTemplates"] = dns_template
        else:
            policy["DnsOverHttpsMode"] = dns_mode
            # Chromium honours a template in "automatic" mode too (it just
            # keeps the plaintext fallback), so don't discard one.
            if dns_mode in ("automatic", "secure") and dns_template:
                policy["DnsOverHttpsTemplates"] = dns_template
    return policy, ""


def _write_one_policy(plist_path, policy):
    """Write a single JSON policy file and return (ok, error_msg).

    The file is SlimBrave's own and is rewritten whole. Any directory
    created on the way is 0755 whatever the caller's umask: under sudo's
    union with a strict one (027) a 0750 root directory would hide every
    policy from Brave, which runs as the user.
    """
    try:
        old_umask = os.umask(0o022)
        try:
            os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        finally:
            os.umask(old_umask)
        _atomic_write(plist_path, json.dumps(policy, indent=4))
    except PermissionError:
        return False, "Permission denied. Run as root."
    except OSError as e:
        return False, f"Failed to write policy: {e}"
    return True, ""


def _unreadable_policy_dir(directory, stop="/etc"):
    """Return (dir, mode) of a policy directory Brave cannot read, or None.

    Brave reads its policy directory as the user, so on Linux every
    directory below `stop` down to `directory` needs o+x, and `directory`
    itself o+r to be listed. A version older than the umask fix, run under
    a strict umask (027), created them 0750 as root. Returns the topmost
    offender; None off POSIX, or for a directory not under `stop`.
    """
    if os.name != "posix":
        return None
    stop = os.path.abspath(stop)
    d = os.path.abspath(directory)
    chain = []
    while d != stop:
        parent = os.path.dirname(d)
        if parent == d:
            return None
        chain.append(d)
        d = parent
    leaf = os.path.abspath(directory)
    for d in reversed(chain):
        try:
            mode = stat.S_IMODE(os.stat(d).st_mode)
        except OSError:
            continue
        need = stat.S_IXOTH | (stat.S_IROTH if d == leaf else 0)
        if mode & need != need:
            return d, mode
    return None


def _unreadable_dir_note(plist_path):
    """The Apply-message sentence for _unreadable_policy_dir, or ''."""
    found = _unreadable_policy_dir(os.path.dirname(plist_path))
    if found is None:
        return ""
    d, mode = found
    return f"Brave cannot read {d} (mode {mode:o}); run 'sudo chmod 755 {d}'"


def _dedupe_plist_targets(installations):
    """Return distinct (plist_path, label) pairs.

    On Linux every channel maps to the same POLICY_FILE; the labels are
    joined into a single string so status messages still surface what was
    written for whom. Insertion order is preserved by the dict
    (Python 3.7+).
    """
    grouped = {}
    for inst in installations:
        path = inst.get("plist_path") or POLICY_FILE
        grouped.setdefault(path, []).append(inst["label"])
    return [(path, ", ".join(labels)) for path, labels in grouped.items()]


def apply_policy(rows, installations=None):
    """Write the policy to every selected channel's plist file."""
    policy, err = _build_policy(rows)
    if policy is None:
        return False, err

    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(installations)

    if not targets:
        return False, "No Brave channel selected."

    written_labels = []
    unreadable = ""
    for plist_path, label in targets:
        ok, err = _write_one_policy(plist_path, policy)
        if not ok:
            scope = f" ({label})" if label else ""
            return False, f"{err}{scope}"
        if label:
            written_labels.append(label)
        if not unreadable:
            unreadable = _unreadable_dir_note(plist_path)

    msg = _post_apply_message(
        *repair_brave_prefs(installations if installations else None),
        labels=written_labels,
    )
    # First, so the TUI's one status line shows it.
    return True, f"{unreadable}. {msg}" if unreadable else msg


def _post_apply_message(repaired, failed, brave_running, labels=None):
    """Build the status message after a successful Apply or Reset."""
    scope = f" to {', '.join(labels)}" if labels else ""
    base = f"Settings applied{scope}. Restart Brave to see changes."
    # Only claim a repair count that can survive: Chromium serves prefs
    # from an in-memory PrefService and flushes on shutdown, so a running
    # Brave writes back over whatever we just cleaned.
    if repaired > 0 and not brave_running:
        base = (
            f"Applied{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if failed:
        base += " " + _scrub_failure_note(failed)
    if brave_running:
        base += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Apply again to make it stick."
        )
    return base


def reset_policy(rows, installations=None):
    """Delete the policy file(s) and uncheck everything."""
    if installations is None:
        targets = [(POLICY_FILE, "")]
    else:
        targets = _dedupe_plist_targets(installations)

    if not targets:
        return False, "No Brave channel selected."

    cleared_labels = []
    try:
        for plist_path, label in targets:
            if os.path.exists(plist_path):
                os.remove(plist_path)
            if label:
                cleared_labels.append(label)
        for row in rows:
            if row["type"] == ROW_FEATURE:
                row["checked"] = False
            elif row["type"] == ROW_CHOICE:
                row["selected"] = 0
            elif row["type"] == ROW_DNS:
                row["selected"] = 0
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = ""
                row["cursor"] = 0
                row["scroll"] = 0
    except OSError as e:
        return False, f"Failed to reset: {e}"

    repaired, failed, running = repair_brave_prefs(installations if installations else None)
    scope = f" for {', '.join(cleared_labels)}" if cleared_labels else ""
    msg = f"All settings reset{scope}. Restart Brave to see changes."
    if repaired > 0 and not running:
        msg = (
            f"Reset{scope}; cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''}. Restart Brave."
        )
    if failed:
        msg += " " + _scrub_failure_note(failed)
    if running:
        msg += (
            " Brave is running: any leaked profile prefs cleaned now will be "
            "overwritten when Brave next saves. Fully close Brave and run "
            "Reset again to make it stick."
        )
    return True, msg


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    # A template that is not a string (a hand-edited file) reads as none
    # instead of crashing the TUI at launch.
    dns_tmpl = policy.get("DnsOverHttpsTemplates", "")
    if not isinstance(dns_tmpl, str):
        dns_tmpl = ""
    for row in rows:
        if row["type"] == ROW_FEATURE:
            # An inert row stays unticked whatever the file says, so the
            # next Apply drops the dead key rather than carrying it.
            if row.get("inert"):
                continue
            # The value must be in its policy's JSON type, as on import, so
            # a true on disk does not tick an integer row.
            if row["key"] in policy and _value_matches_row(row, policy[row["key"]]):
                row["checked"] = True
        elif row["type"] == ROW_CHOICE:
            # A value that is not a legal member of this key's enum leaves
            # the row unmanaged, the same way a non-matching feature value
            # leaves a checkbox unticked.
            if row["key"] in policy:
                idx = _choice_index_for_value(row, policy[row["key"]])
                if idx is not None:
                    row["selected"] = idx
        elif row["type"] == ROW_DNS:
            dns_val = policy.get("DnsOverHttpsMode")
            if dns_val == "secure" and dns_tmpl:
                if "custom" in row["options"]:
                    row["selected"] = row["options"].index("custom")
            elif dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)
        elif row["type"] == ROW_DNS_TEMPLATE:
            if dns_tmpl:
                row["value"] = dns_tmpl
                row["cursor"] = len(dns_tmpl)
                row["scroll"] = 0
    _enforce_groups(rows)

# ---------------------------------------------------------------------------
# Import / Export (PS1-compatible JSON format)
# ---------------------------------------------------------------------------


def export_settings(rows, path):
    """Export current TUI selections to a SlimBrave Neo JSON config file."""
    features = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"] and not row.get("inert"):
            features[row["key"]] = row["value"]
        elif row["type"] == ROW_CHOICE:
            # "Not managed" omits the key entirely, so the exported file has
            # the same shape it had when these rows were checkboxes.
            choice_value = _choice_value(row)
            if choice_value is not None:
                features[row["key"]] = choice_value
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # DnsMode is omitted when DNS is unmanaged, so importing the file
    # (on any platform) lands back on "unmanaged" instead of forcing a
    # managed DNS policy. The template set mirrors _build_policy exactly —
    # "automatic" honours one too, and dropping it here would silently
    # hand DNS back to the default resolver on the next import.
    settings = {"Features": features}
    if dns_mode and dns_mode != "unmanaged":
        settings["DnsMode"] = dns_mode
        if dns_template and dns_mode in ("custom", "secure", "automatic"):
            settings["DnsTemplates"] = dns_template

    # Written as the invoking user, not as root: the file and any folders
    # it needs are theirs from the start, and a path they could not write
    # themselves fails instead of being created with root's rights.
    text = json.dumps(settings, indent=4)
    ok, msg = _run_as_invoking_user(
        _write_export, path, text,
        default=[False, "Export failed: could not write as the invoking user"])
    return ok, msg


def _write_export(path, text):
    """Create the export file and its folders; returns [ok, message]."""
    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        _atomic_write(path, text)
    except PermissionError as e:
        home = _user_home_for_brave()
        if hasattr(os, "geteuid") and os.geteuid() != 0 and home:
            # The hint spells the home out in full, so it works the same
            # pasted into a shell as typed at the TUI prompt.
            import pwd
            try:
                who = pwd.getpwuid(os.getuid()).pw_name
            except KeyError:
                who = f"uid {os.getuid()}"
            suggestion = os.path.join(home, "SlimBraveNeoSettings.json")
            return [False, f"Export failed: {who} cannot write {path}; try {suggestion}"]
        return [False, f"Export failed: {e}"]
    except OSError as e:
        return [False, f"Export failed: {e}"]
    return [True, f"Exported to {path}"]


# What Import takes is decided by the rows alone: a key one of them writes,
# in its exact letter case (Chromium matches policy names that way), with a
# value a row writes. Nothing else is ever written - issue #33's
# pass-through is declined, since a shared file must not set any machine
# policy it likes - and everything else the file holds, but for a
# platform-limited key, is named in the result message, in the words
# SlimBrave.ps1 and slimbrave-mac.py use.

# The fields of a config file.
CONFIG_FIELDS = ("Features", "DnsMode", "DnsTemplates")

# Policies Chromium has on some platforms only: BackgroundModeEnabled on
# Windows and Linux, DynamicCodeSettings on Windows. Where no row writes one
# here, Import skips it without a note: Chromium's schema on this platform
# has no such policy, so nothing is lost, and naming it would put a note on
# four of the six presets on macOS.
PLATFORM_LIMITED_KEYS = frozenset(("BackgroundModeEnabled", "DynamicCodeSettings"))

# Keys earlier versions wrote and this one no longer offers: the names in
# SlimBrave.ps1's $script:retiredPolicies and slimbrave-mac.py's
# RETIRED_POLICIES, held equal by a test.
RETIRED_KEYS = frozenset((
    "AlternateErrorPagesEnabled", "DNSInterceptionChecksEnabled",
    "EnableDoNotTrack", "FeedbackSurveysEnabled", "IPFSEnabled",
    "MediaRecommendationsEnabled", "PromotionsEnabled",
    "SafeBrowsingExtendedReportingEnabled", "SafeSitesFilterBehavior",
    "ShoppingListEnabled",
))

# Where a DNS name inside Features belongs: the policy file's two DNS
# names come from DnsMode and DnsTemplates, which are top-level fields.
FEATURES_NAME_HINTS = {
    "DnsOverHttpsMode": "use DnsMode",
    "DnsOverHttpsTemplates": "use DnsTemplates",
    "DnsMode": "a top-level field",
    "DnsTemplates": "a top-level field",
}

# The clauses of the result message, in this order: (kind, verb, reason).
# The Brave Origin count and then the exclusion groups follow them.
IMPORT_NOTES = (
    ("case", "left unmanaged", "names are case-sensitive"),
    ("type", "left unmanaged", "the value is not one this policy accepts"),
    ("value", "left unmanaged", "no row sets that value"),
    ("retired", "left unmanaged", "SlimBrave Neo no longer offers it"),
    ("unknown", "left unmanaged", "SlimBrave Neo does not offer it"),
    ("field", "ignored", "it is not a SlimBrave Neo setting"),
)
EXCLUSIVE_REASON = "it is mutually exclusive with another imported row"

# The names and values the message copies from the file are shown in
# printable ASCII and cut to SHOWN_MAX characters, since --import prints
# them as root and curses refuses a NUL; a clause lists MAX_SHOWN_ITEMS.
SHOWN_MAX = 64
MAX_SHOWN_ITEMS = 5
_PLAIN_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz0123456789_.-")

# What a DoH template from a file may not hold: the C0 and C1 controls,
# DEL, the line and paragraph separators, and the twelve bidi controls
# (Unicode's Bidi_Control), which would reorder the row here and the text
# box on Windows. Import refuses a template with one rather than strip it,
# and the template field draws one as '?' (_field_text).
_CONTROL_CHARS = frozenset(chr(c) for c in (*range(0x20), *range(0x7F, 0xA0),
                                            0x2028, 0x2029))
_BIDI_CONTROLS = frozenset(chr(c) for c in (0x061C, 0x200E, 0x200F,
                                            *range(0x202A, 0x202F),
                                            *range(0x2066, 0x206A)))


def _escaped(ch):
    """`ch` as it is in printable ASCII (0x20-0x7E), \\uXXXX otherwise:
    UTF-16 code units in uppercase hex, two for a character past U+FFFF."""
    code = ord(ch)
    if 0x20 <= code <= 0x7E:
        return ch
    if code > 0xFFFF:
        code -= 0x10000
        return "\\u%04X\\u%04X" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF))
    return "\\u%04X" % code


# Besides _CONTROL_CHARS and _BIDI_CONTROLS, the zero-width format
# characters, which hide text, are kept out of a file name Import echoes; so
# is a lone surrogate (an undecodable byte of a Linux file name). Any other
# character, a Cyrillic, CJK or emoji name's included, is shown as it is.
_NAME_FORMAT_CHARS = frozenset("\u200b\u200c\u200d\u2060\ufeff")


def _shown_path(path):
    """A file name or path as Import echoes it: a control, bidi or zero-width
    character, or a lone surrogate, as _escaped writes it, with no quotes and
    no cut; any other character as it is, as SlimBrave.ps1 shows it. The CLI
    writes it through _say, so a terminal that cannot show a character still
    cannot make print() fail."""
    return "".join(
        _escaped(ch) if (ch in _CONTROL_CHARS or ch in _BIDI_CONTROLS
                         or ch in _NAME_FORMAT_CHARS or "\ud800" <= ch <= "\udfff")
        else ch
        for ch in path)


def _say(text, stream=None):
    """print() for the CLI that cannot fail on a terminal whose encoding
    lacks a character of `text` (an ASCII or Latin-1 locale): such a
    character is written as _escaped writes it."""
    stream = sys.stdout if stream is None else stream
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        shown = []
        for ch in text:
            try:
                ch.encode(encoding)
                shown.append(ch)
            except UnicodeEncodeError:
                shown.append(_escaped(ch))
        text = "".join(shown)
    except LookupError:
        pass
    print(text, file=stream)


def _quoted(text):
    """`text` as a double-quoted string of printable ASCII.

    Each character outside 0x20-0x7E becomes \\uXXXX (UTF-16 code units,
    uppercase hex), and `"` and `\\` take a backslash. A body longer than
    SHOWN_MAX is cut to SHOWN_MAX - 3 characters and ends in '...'.
    Hand-written rather than json.dumps: SlimBrave.ps1 has to print the
    same text, and its ConvertTo-Json escapes <, >, & and ' as well.
    """
    parts = []
    size = 0
    for ch in text:
        part = "\\" + ch if ch == '"' or ch == "\\" else _escaped(ch)
        parts.append(part)
        size += len(part)
        if size > SHOWN_MAX:
            break  # the cut falls before this point
    body = "".join(parts)
    if len(body) > SHOWN_MAX:
        body = body[:SHOWN_MAX - 3] + "..."
    return '"' + body + '"'


def _shown_name(name):
    """A name from an imported file as the result message shows it.

    As it is when it is 1 to SHOWN_MAX of A-Z a-z 0-9 _ . - (every policy
    name is), quoted by _quoted otherwise, so an odd name can pass neither
    for two names nor for a terminal escape sequence.
    """
    if 0 < len(name) <= SHOWN_MAX and all(c in _PLAIN_NAME_CHARS for c in name):
        return name
    return _quoted(name)


def _shown_value(value):
    """A value from an imported file as the result message shows it.

    true or false, null, an integer within 64 bits (_is_json_int) in
    decimal, a string quoted by _quoted. None for any other number, a list
    or an object, which are not shown: Python and PowerShell print them
    differently, and the scripts have to say the same thing.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if _is_json_int(value):
        return str(value)  # 20 characters at most
    if isinstance(value, str):
        return _quoted(value)
    return None


def _shown_item(key, value):
    """`Key=<value>`, or the key alone for a value that is not shown."""
    name = _shown_name(key)
    shown = _shown_value(value)
    return name if shown is None else f"{name}={shown}"


def _note_clause(verb, reason, items):
    """`; <verb> because <reason>: <items>`, at most MAX_SHOWN_ITEMS of
    them and then ' and N more'."""
    text = ", ".join(items[:MAX_SHOWN_ITEMS])
    if len(items) > MAX_SHOWN_ITEMS:
        text += f" and {len(items) - MAX_SHOWN_ITEMS} more"
    return f"; {verb} because {reason}: {text}"


def _parse_imported_features(features_obj):
    """Normalize the Features field from a config file."""
    if isinstance(features_obj, dict):
        return dict(features_obj), False
    if isinstance(features_obj, list):
        # Drop non-string entries: a nested object would be unhashable and
        # blow up the dict comprehension.
        return {k: None for k in features_obj if isinstance(k, str)}, True
    return {}, False


def import_settings(rows, path):
    """Import a SlimBrave Neo JSON config and update TUI row states.

    Every refusal returns before any row is touched, or puts the rows back
    (a value nested too deep), so a failed import leaves the selections as
    they were. The order matches SlimBrave.ps1's Import: the file, a JSON
    object, a Features block, the DNS fields, each value against its
    policy's type, then the exclusion groups. Returns (ok, message); the
    message names everything in the file that no row took, under the
    reasons in IMPORT_NOTES.
    """
    ok, msg, _ = _import_config(rows, path)
    return ok, msg


def _import_config(rows, path):
    """import_settings, returning (ok, message, outcome).

    `outcome` (None on a refusal) is what --import decides on: "entries",
    how many entries the Features block names; "taken", how many keys a row
    took; "dns", whether the import set a managed DNS mode.
    """
    try:
        config = read_json_file(path)
    except FileNotFoundError:
        return False, f"File not found: {_shown_path(path)}", None
    except _EmptyKey:
        return False, "Invalid config: a key is empty", None
    except _KeysDifferInCase as e:
        return False, ("Invalid config: keys differ only in letter case: "
                       + ", ".join(_shown_name(k) for k in e.keys)), None
    except (ValueError, RecursionError) as e:
        # JSONDecodeError, UnicodeDecodeError and the 4300-digit integer
        # limit are all ValueErrors; a deeply nested file is RecursionError.
        return False, f"Invalid JSON: {e}", None
    except OSError as e:
        return False, f"Read error: {_shown_path(str(e))}", None  # it holds the path

    # Nothing in _take_config walks a value's depth, but a value nested
    # past the stack must not end the TUI or print a traceback: on a
    # RecursionError the rows go back to what they were, as on any refusal.
    saved = [dict(row) for row in rows]
    try:
        return _take_config(rows, config, path)
    except RecursionError:
        for row, before in zip(rows, saved):
            row.clear()
            row.update(before)
        return False, "Invalid config: nesting too deep", None


def _take_config(rows, config, path):
    """_import_config once the file is read: `config` checked, taken into
    `rows` and described, with the same (ok, message, outcome)."""
    # `[1,2]`, `null`, `"x"` and `3` are all valid JSON that would die at
    # the first .get() — in the TUI that traceback escapes curses.wrapper.
    if not isinstance(config, dict):
        return False, (
            f"Invalid config: expected a JSON object, got {type(config).__name__}"
        ), None

    # A file without a Features object or array (the policy file, a
    # Bookmarks dump, a DNS-only file, a lowercase `features`) is not a
    # SlimBrave config. Taking it used to clear every row and report
    # success, and --import then wrote an empty policy. A block spelled in
    # another letter case is pointed at, not taken.
    features = config.get("Features")
    if not isinstance(features, (dict, list)):
        msg = "Invalid config: no Features block (not a SlimBrave Neo config)"
        found = next((k for k in config if k != "Features" and k.isascii()
                      and k.lower() == "features"), None)
        if found is not None:
            msg += f" (found {_shown_name(found)}; names are case-sensitive)"
        return False, msg, None
    features_map, is_legacy = _parse_imported_features(features)

    # A list of strings is joined with spaces, as SlimBrave.ps1 joins an
    # array. A missing, null or empty value is no template, as there, and
    # any other non-string (false, 0, {}) is refused, as there. No strip:
    # SlimBrave.ps1 does not trim either.
    raw_tmpl = config.get("DnsTemplates")
    if isinstance(raw_tmpl, list) and all(isinstance(t, str) for t in raw_tmpl):
        raw_tmpl = " ".join(raw_tmpl)
    if raw_tmpl is None or raw_tmpl == "":
        dns_template = ""
    elif isinstance(raw_tmpl, str):
        dns_template = raw_tmpl
    else:
        return False, "Invalid config: DnsTemplates must be a string", None
    # A control character makes a template corrupt, not one to clean up:
    # stripping it would write a resolver the file never named.
    if not (_CONTROL_CHARS.isdisjoint(dns_template)
            and _BIDI_CONTROLS.isdisjoint(dns_template)):
        return False, "Invalid config: DnsTemplates contains a control character", None
    # No DnsMode in the file (none, null or "") means DNS is unmanaged (a
    # bare DnsTemplates is treated as custom for legacy exports). The mode
    # is SlimBrave's own word, matched in any ASCII letter case as
    # SlimBrave.ps1 matches it; any other value, false or 0 as much as an
    # unknown word, leaves DNS unmanaged and is named.
    raw_mode = config.get("DnsMode")
    bad_mode = None
    if raw_mode is None or raw_mode == "":
        dns_mode = "custom" if dns_template else "unmanaged"
    elif (isinstance(raw_mode, str) and raw_mode.isascii()
          and raw_mode.lower() in DNS_MODES):
        dns_mode = raw_mode.lower()
    else:
        dns_mode = "unmanaged"
        bad_mode = _shown_item("DnsMode", raw_mode)

    # What the rows make of the file, for the message: the keys a row has
    # (inert ones included), the inert ones, the keys a row took, and the
    # keys whose value has the JSON type their rows write (every row of a
    # key writes the same type). A value outside that type is one Brave
    # would ignore or misapply (a 1 on local fonts, window management or
    # clipboard becomes a managed Allow); one inside it that no row writes
    # may be legal, so the two are named apart.
    row_keys = set()
    inert_keys = set()
    taken = set()
    fits = set()
    # Legacy array format can't distinguish value-1 vs value-2 for keys
    # with multiple rows (IncognitoModeAvailability). To avoid silently
    # picking the later entry — which historically force-incognitoed users
    # who imported the Parental Controls preset — only the first matching
    # row per key is checked in legacy mode.
    legacy_handled = set()

    for row in rows:
        if row["type"] == ROW_FEATURE:
            key = row["key"]
            row_keys.add(key)
            if row.get("inert"):
                inert_keys.add(key)
                row["checked"] = False
                continue
            if key not in features_map:
                row["checked"] = False
                continue
            expected = features_map[key]
            if is_legacy:
                if key in legacy_handled:
                    row["checked"] = False
                else:
                    row["checked"] = True
                    legacy_handled.add(key)
            elif _value_fits_row(row, expected):
                fits.add(key)
                row["checked"] = _value_matches_row(row, expected)
            else:
                row["checked"] = False
            if row["checked"]:
                taken.add(key)
        elif row["type"] == ROW_CHOICE:
            key = row["key"]
            row_keys.add(key)
            # Import is authoritative: a key the config does not name goes
            # back to "Not managed", matching the old unticked checkbox.
            row["selected"] = 0
            if key in features_map:
                # The array format carries no values; naming the key used
                # to tick a checkbox that wrote row["value"].
                want = row["value"] if is_legacy else features_map[key]
                idx = _choice_index_for_value(row, want)
                if idx is not None:
                    row["selected"] = idx
                    taken.add(key)
                if _is_json_int(want):
                    fits.add(key)
        elif row["type"] == ROW_DNS:
            # Always set, so the TUI never keeps its pre-import mode.
            row["selected"] = row["options"].index(dns_mode)
        elif row["type"] == ROW_DNS_TEMPLATE:
            row["value"] = dns_template
            row["cursor"] = len(dns_template)
            row["scroll"] = 0

    dropped = set(_enforce_groups(rows))

    # Name what no row took. Every clause lists the Features entries first,
    # in file order, then the DnsMode, then the other top-level names in
    # file order: the order SlimBrave.ps1 builds its lists in (the Features
    # walk, the DnsMode after it, then the top-level names Read-ImportFields
    # kept). A name that matches in all but ASCII letter case is given the
    # spelling that would have: a Features key one of the row keys or the
    # platform-limited ones (a retired or DNS name in the wrong case is
    # simply one SlimBrave Neo does not offer), a top-level field one of
    # CONFIG_FIELDS. A name with any other character matches nothing:
    # Python's and .NET's case rules part outside ASCII (the Kelvin sign,
    # the long s), and SlimBrave.ps1 has to suggest the same spellings.
    notes = {kind: [] for kind, _, _ in IMPORT_NOTES}
    noted = set()
    builtin = set()
    exclusive = []
    key_spellings = {k.lower(): k for k in row_keys | PLATFORM_LIMITED_KEYS}
    field_spellings = {k.lower(): k for k in CONFIG_FIELDS}

    def note(kind, ident, item):
        if (kind, ident) not in noted:  # a legacy array can repeat itself
            noted.add((kind, ident))
            notes[kind].append(item)

    def note_name(name, spellings, kind, hint=None):
        shown = _shown_name(name)
        canonical = spellings.get(name.lower()) if name.isascii() else None
        if canonical is not None:
            note("case", name, f"{shown} (use {canonical})")
        else:
            note(kind, name, f"{shown} ({hint})" if hint else shown)

    for field in ("Features", "DnsMode",
                  *(f for f in config if f not in CONFIG_FIELDS)):
        if field == "DnsMode":
            if bad_mode is not None:
                note("type", field, bad_mode)
        elif field != "Features":
            note_name(field, field_spellings, "field")
        else:
            # The object's keys or the legacy array's entries, in file order.
            for key in features:
                if not isinstance(key, str):
                    # A legacy entry that is no name, shown as a value (a
                    # float, list or object has no rendering to show).
                    shown = _shown_value(key)
                    if shown is not None:
                        note("unknown", (shown,), shown)
                elif key in dropped:
                    if key not in exclusive:
                        exclusive.append(key)
                elif key in taken:
                    pass
                elif key in inert_keys:
                    builtin.add(key)
                elif key in row_keys:
                    if is_legacy:
                        note("value", key, key)
                    elif key in fits:
                        note("value", key, _shown_item(key, features_map[key]))
                    else:
                        note("type", key, _shown_item(key, features_map[key]))
                elif key in PLATFORM_LIMITED_KEYS:
                    pass  # no row here, by design
                elif key in RETIRED_KEYS:
                    note("retired", key, key)
                else:
                    note_name(key, key_spellings, "unknown",
                              FEATURES_NAME_HINTS.get(key))

    msg = f"Imported from {_shown_path(os.path.basename(path))}"
    for kind, verb, reason in IMPORT_NOTES:
        if notes[kind]:
            msg += _note_clause(verb, reason, notes[kind])
    if builtin:
        n = len(builtin)
        msg += (f"; {n} key{'s' if n != 1 else ''} built into Brave Origin "
                "left unmanaged")
    if exclusive:
        # Sorted in any letter case and in full, as SlimBrave.ps1 lists
        # them (Sort-Object -Unique): row keys only, never a name to escape.
        msg += (f"; left unmanaged because {EXCLUSIVE_REASON}: "
                + ", ".join(sorted(exclusive, key=str.lower)))
    outcome = {"entries": len(features), "taken": len(taken),
               "dns": dns_mode != "unmanaged"}
    return True, msg, outcome

# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

# Color pair IDs
CP_NORMAL = 1
CP_HEADER = 2
CP_CHECKED = 3
CP_CURSOR = 4
CP_BUTTON = 5
CP_BUTTON_ACTIVE = 6
CP_STATUS_OK = 7
CP_STATUS_ERR = 8
CP_TITLE = 9
CP_DIM = 10

BUTTONS = ["Import", "Export", "Apply", "Reset", "Quit"]

FOCUS_LIST = 0
FOCUS_BUTTONS = 1
FOCUS_PROMPT = 2

# Every row type the cursor may land on. Headers joined the list when
# Space/Enter started folding them.
SELECTABLE_TYPES = (ROW_HEADER, ROW_FEATURE, ROW_CHOICE, ROW_DNS,
                    ROW_DNS_TEMPLATE)

# Stand-in for "the cursor is on nothing", which a filter matching zero
# rows produces. Its type matches no key branch, so they all fall through.
NO_ROW = {"type": None}


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_HEADER, curses.COLOR_RED, -1)
    curses.init_pair(CP_CHECKED, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_CURSOR, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(CP_BUTTON, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_BUTTON_ACTIVE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_STATUS_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_STATUS_ERR, curses.COLOR_RED, -1)
    curses.init_pair(CP_TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(CP_DIM, curses.COLOR_WHITE, -1)


# Disclosure markers for collapsible headers, resolved once per process.
DISCLOSURE_UNICODE = ("\u25be", "\u25b8")   # small down / right triangles
DISCLOSURE_ASCII = ("v", ">")
_disclosure_glyphs = None


def disclosure_glyphs():
    """Return the (expanded, collapsed) markers this terminal can encode.

    curses encodes everything handed to addnstr with the codeset LC_CTYPE
    gave the interpreter, and neither script sets a locale: on a plain
    VT100 that is ANSI_X3.4-1968, where the triangles raise
    UnicodeEncodeError — which the `except curses.error` guard wrapped
    around every write here does not catch. Ask the codec first.
    """
    global _disclosure_glyphs
    if _disclosure_glyphs is None:
        try:
            enc = locale.getpreferredencoding(False) or "ascii"
            for glyph in DISCLOSURE_UNICODE:
                glyph.encode(enc)
            _disclosure_glyphs = DISCLOSURE_UNICODE
        except (LookupError, UnicodeEncodeError, ValueError):
            _disclosure_glyphs = DISCLOSURE_ASCII
    return _disclosure_glyphs


BOX_UNICODE = ("\u2500", "\u2502", "\u250c", "\u2510", "\u2514", "\u2518", "\u2026")
BOX_ASCII = ("-", "|", "+", "+", "+", "+", "...")
_box_glyphs = None


def box_glyphs():
    """Return (h, v, tl, tr, bl, br, ellipsis) as this terminal can encode them.

    The same rule as disclosure_glyphs(): ask the codec before drawing.
    """
    global _box_glyphs
    if _box_glyphs is None:
        try:
            enc = locale.getpreferredencoding(False) or "ascii"
            for glyph in BOX_UNICODE:
                glyph.encode(enc)
            _box_glyphs = BOX_UNICODE
        except (LookupError, UnicodeEncodeError, ValueError):
            _box_glyphs = BOX_ASCII
    return _box_glyphs


# Rows the list keeps before the description pane gives way to it.
DESC_PANE_MIN_LIST = 4


DESC_PANE_MAX_LINES = 4
_desc_pane_lines = {}


def desc_pane_lines(max_x):
    """Text lines the pane needs at this width.

    What the longest description wraps to at this width, up to
    DESC_PANE_MAX_LINES: four lines at 80 columns, where every description
    fits whole; three from about 110. Sized by the content rather than by a
    constant so a wider terminal gives the list its rows back.
    """
    if max_x not in _desc_pane_lines:
        width = max(1, (max_x - 1) - 4)
        texts = [f.get("desc", "") for cat in CATEGORIES for f in cat["features"]]
        texts += list(DNS_DESC.values()) + list(BUTTON_DESC.values())
        need = max((len(textwrap.wrap(t, width, break_on_hyphens=False))
                    for t in texts), default=1)
        _desc_pane_lines[max_x] = max(1, min(DESC_PANE_MAX_LINES, need))
    return _desc_pane_lines[max_x]


def layout(max_y, max_x, show_desc, status_n=1):
    """The row budget for one frame, shared by draw() and viewport_rows().

    Rows 0-1 are the title and the hints. The list sits in a box, the
    description pane (if shown) in a second, the buttons in a third, and
    the status line is the last row. The pane gives way when it would
    leave the list under DESC_PANE_MIN_LIST rows, so a small terminal
    keeps its list; under 9 rows the boxes go too, and the screen is the
    plain stack it was before them - list from row 2, buttons on the
    second-last row, status on the last - because eight rows of chrome
    would leave nothing else.

    A status of `status_n` lines (status_lines()) takes the last rows, up
    to STATUS_MAX_LINES of them and never the list's last row, so the list
    has fewer rows only while a multi-line status shows; the unframed
    stack keeps one status line.
    """
    if max_y < 9:
        list_rows = max(1, max_y - 5)
        return {
            "framed": False,
            "list_top": 2,
            "list_rows": list_rows,
            "list_bottom": 2 + list_rows,
            "pane_top": None,
            "pane_lines": 0,
            "btn_top": max_y - 3,
            "btn_y": max_y - 2,
            "status_y": max_y - 1,
            "status_lines": 1,
        }
    status_n = max(1, min(status_n, STATUS_MAX_LINES, max_y - 8))
    fixed = 2 + 2 + 3 + status_n
    pane = desc_pane_lines(max_x) if show_desc else 0
    if pane and max_y - fixed - (pane + 2) < DESC_PANE_MIN_LIST:
        pane = 0
    list_rows = max(1, max_y - fixed - (pane + 2 if pane else 0))
    list_top = 3
    list_bottom = list_top + list_rows
    pane_top = list_bottom + 1 if pane else None
    btn_top = pane_top + pane + 2 if pane else list_bottom + 1
    return {
        "framed": True,
        "list_top": list_top,
        "list_rows": list_rows,
        "list_bottom": list_bottom,
        "pane_top": pane_top,
        "pane_lines": pane,
        "btn_top": btn_top,
        "btn_y": btn_top + 1,
        "status_y": max_y - status_n,
        "status_lines": status_n,
    }


def template_field_width(max_x):
    """Width of the editable DoH template field inside the list box.

    The row is '    Template: [' + text + ']' plus a margin; draw() and the
    editing keys in main() must agree on this figure, or the cursor and
    the text scroll drift apart.
    """
    # capped so the closing bracket stays inside the box on a narrow terminal
    return max(1, min(max_x - 21, max(10, (max_x - 1) - 4 - 22)))


def _field_text(text):
    """`text` as the DoH template field draws it, one cell per character:
    a control character (_CONTROL_CHARS), a bidi control, any other format
    or combining character, a lone surrogate or an unassigned one, and a
    wide character as '?', so a template read from the policy or a file can
    neither move the cursor, reorder the row nor run past its field (a wide
    character takes two cells, a combining one none, and the field counts
    characters); any other character, an IDN host's included, as it is."""
    return "".join("?" if (c in _CONTROL_CHARS or c in _BIDI_CONTROLS
                           or unicodedata.category(c) in ("Cf", "Mn", "Me", "Cs", "Cn")
                           or unicodedata.east_asian_width(c) in ("W", "F"))
                   else c
                   for c in text)


def wrap_description(text, width, max_lines, ellipsis="..."):
    """Word-wrap `text` to at most `max_lines` rows of `width`.

    A description that does not fit ends in `ellipsis`, so a cut is
    visible rather than silent.
    """
    if width < 1 or max_lines < 1:
        return []
    # break_on_hyphens off: a resolver URL must not split at "dns-query"
    lines = textwrap.wrap(text or "", width, break_on_hyphens=False)
    if len(lines) <= max_lines:
        return lines
    lines = lines[:max_lines]
    room = max(0, width - len(ellipsis))
    lines[-1] = lines[-1][:room].rstrip() + ellipsis
    return lines


# The status line grows to this many lines rather than lose its tail (an
# import that names what it left out runs well past one), as SlimBrave.ps1's
# status bar grows to four.
STATUS_MAX_LINES = 4


def status_lines(text, max_x, max_lines=STATUS_MAX_LINES):
    """The status message as draw() paints it: wrapped to the status width
    (max_x - 4), at most `max_lines` lines, the last ending in '...' when
    the message runs past them."""
    return wrap_description(text, max(1, max_x - 4), max_lines, "...")


BUTTON_DESC = {
    "Import": "Load a settings file - a preset from Presets/ or an earlier "
              "export - into the list. Nothing is written until Apply.",
    "Export": "Save the current selections as JSON that Import, and the "
              "other platforms' scripts, read back. Under sudo the file is "
              "written as you, not root, so pick a folder you can write to.",
    "Apply": "Write the selected policies where Brave reads them at "
             "startup. A running Brave picks them up when it restarts.",
    "Reset": "Remove the policy this tool wrote, so Brave returns to its "
             "own defaults. Asks before it does.",
    "Quit": "Leave without writing anything.",
}

DNS_DESC = {
    "mode": "Secure and custom send every lookup to the template below and "
            "never fall back, so a wrong template resolves nothing. "
            "Automatic uses DNS over HTTPS when the resolver offers it and "
            "plain DNS otherwise. Off never uses it. Not managed leaves "
            "Brave's own setting alone.",
    "template": "The DNS-over-HTTPS resolver, as a template such as "
                "https://dns.example/dns-query. Required by secure and "
                "custom; automatic uses it when set.",
}


def describe_row(rows, cursor_idx, focus, btn_idx):
    """The description pane's text for whatever has focus."""
    if focus == FOCUS_BUTTONS:
        return BUTTON_DESC.get(BUTTONS[btn_idx], "")
    if not (0 <= cursor_idx < len(rows)):
        return ""
    row = rows[cursor_idx]
    kind = row["type"]
    if kind == ROW_HEADER:
        on, total = header_counts(rows, cursor_idx)
        inert = header_inert_count(rows, cursor_idx)
        if total or inert:
            built_in = f", {inert} built into Origin" if inert else ""
            return (f"{row['text']}: {total} settings, {on} on{built_in}. "
                    "Left folds the section, Right unfolds it, Space "
                    "toggles it, c folds or unfolds them all.")
        return f"{row['text']}: the resolver mode and its template."
    if kind == ROW_DNS:
        return DNS_DESC["mode"]
    if kind == ROW_DNS_TEMPLATE:
        return DNS_DESC["template"]
    if row.get("inert"):
        return ("Built into Brave Origin: this feature is not in the binary, "
                "so there is nothing for a policy to switch; the row is "
                "shown for reference only. " + row.get("desc", ""))
    return row.get("desc", "")


def header_span(rows, header_idx):
    """Return the (start, end) row range a header owns, end-exclusive."""
    end = header_idx + 1
    while end < len(rows) and rows[end]["type"] != ROW_HEADER:
        end += 1
    return header_idx + 1, end


def header_counts(rows, header_idx):
    """Return (on, total) over the countable rows a header owns.

    A row is on when its checkbox is ticked or its choice sits off the
    "Not managed" slot. The DNS section holds neither kind, so it reports
    (0, 0) and draw() omits the counter rather than painting "0/0 on".
    """
    start, end = header_span(rows, header_idx)
    on = 0
    total = 0
    for row in rows[start:end]:
        if row["type"] == ROW_FEATURE:
            # Inert rows (built into Brave Origin) count as neither.
            if row.get("inert"):
                continue
            total += 1
            if row["checked"]:
                on += 1
        elif row["type"] == ROW_CHOICE:
            total += 1
            if row["selected"] > 0:
                on += 1
    return on, total


def header_inert_count(rows, header_idx):
    """How many of a header's rows are built into Brave Origin."""
    start, end = header_span(rows, header_idx)
    return sum(1 for row in rows[start:end]
               if row["type"] == ROW_FEATURE and row.get("inert"))


def collapse_state(rows):
    """Snapshot every header's fold state, in row order."""
    return [r.get("collapsed", False) for r in rows if r["type"] == ROW_HEADER]


def restore_collapse_state(rows, state):
    """Put a collapse_state() snapshot back; None restores nothing."""
    if state is None:
        return
    headers = [r for r in rows if r["type"] == ROW_HEADER]
    for header, collapsed in zip(headers, state):
        header["collapsed"] = collapsed


def apply_startup_collapse(rows):
    """Fold the sections that are not managing anything.

    Called once at launch, after the on-disk policy has been synced in. A
    machine with nothing applied opens on a short overview; one that is
    already configured opens with exactly those sections showing, so the
    first screen answers "what is set right now?". Nothing is persisted --
    the state is derived from what was just read off disk, and any later
    fold the user makes is theirs to keep.
    """
    dns_managed = get_dns_mode(rows) != "unmanaged"
    for idx, row in enumerate(rows):
        if row["type"] != ROW_HEADER:
            continue
        on, total = header_counts(rows, idx)
        if total or header_inert_count(rows, idx):
            # A section whose every row is built into Origin manages
            # nothing, so it folds like one with nothing ticked.
            row["collapsed"] = on == 0
        else:
            # The DNS header owns no countable rows, so judge it by
            # whether a mode is actually being enforced.
            row["collapsed"] = not dns_managed


def row_matches_filter(row, needle):
    """True when a feature or choice row's name contains `needle`."""
    if row["type"] not in (ROW_FEATURE, ROW_CHOICE):
        return False
    return needle in row["text"].lower()


def visible_indices(rows, filter_text=""):
    """Return the row indices the list paints, top to bottom.

    Unfiltered, every header shows and the rows it owns follow unless it
    is collapsed. Filtered, only matching feature and choice rows survive
    along with the headers owning them — collapsed headers included,
    because a search that quietly skipped folded sections would be worse
    than no search at all.
    """
    needle = filter_text.strip().lower()
    out = []
    idx = 0
    while idx < len(rows):
        if rows[idx]["type"] != ROW_HEADER:
            out.append(idx)
            idx += 1
            continue
        start, end = header_span(rows, idx)
        if needle:
            matched = [i for i in range(start, end)
                       if row_matches_filter(rows[i], needle)]
            if matched:
                out.append(idx)
                out.extend(matched)
        else:
            out.append(idx)
            if not rows[idx].get("collapsed", False):
                out.extend(range(start, end))
        idx = end
    return out


def resolve_cursor(sel, cursor_idx):
    """Return the (position, row index) of the nearest selectable row.

    Folding a section or narrowing the filter can delete the row the
    cursor was sitting on; land on the closest survivor so the highlight
    never points at something the screen is not painting. With nothing
    selectable at all — a filter matching zero rows — the row index comes
    back as -1.
    """
    if not sel:
        return 0, -1
    if cursor_idx in sel:
        return sel.index(cursor_idx), cursor_idx
    pos = min(range(len(sel)), key=lambda i: (abs(sel[i] - cursor_idx), sel[i]))
    return pos, sel[pos]


def viewport_rows(stdscr, show_desc=False, status_msg=""):
    """Return how many list rows fit inside the list box this frame."""
    max_y, max_x = stdscr.getmaxyx()
    status_n = len(status_lines(status_msg, max_x))
    return layout(max_y, max_x, show_desc, status_n)["list_rows"]


def clamp_scroll(rows, vis, scroll_offset, cursor_vpos, visible_count):
    """Clamp the viewport offset against the VISIBLE row list.

    scroll_offset counts positions in `vis`, not rows[]: collapse and
    filtering change how many rows the list paints on nearly every
    keystroke, so clamping against len(rows) would let a folded list
    scroll off the end of itself.
    """
    if cursor_vpos >= 0:
        if cursor_vpos < scroll_offset:
            scroll_offset = cursor_vpos
        if cursor_vpos >= scroll_offset + visible_count:
            scroll_offset = cursor_vpos - visible_count + 1
        # Keep the owning header on screen when the cursor sits under it.
        if (cursor_vpos > 0
                and rows[vis[cursor_vpos - 1]]["type"] == ROW_HEADER
                and cursor_vpos - 1 < scroll_offset):
            scroll_offset = cursor_vpos - 1
    return max(0, min(scroll_offset, max(0, len(vis) - visible_count)))


def selectable_indices(rows, filter_text=""):
    """Return list of row indices that can receive cursor focus.

    Headers are selectable now that Space/Enter folds them. Rows hidden
    by a collapsed header or by the filter are not, so the cursor cannot
    land on a row the list is not painting.
    """
    return [i for i in visible_indices(rows, filter_text)
            if rows[i]["type"] in SELECTABLE_TYPES]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method="",
         prompt_label="", prompt_buf="", prompt_cur=0, filter_text="",
         show_desc=False, describe_focus=None):
    """Render the full TUI screen.

    Title and key hints on rows 0-1, the list inside a box, the
    description pane (when shown) inside a second box, the buttons inside
    a third, and the status line last. layout() owns the row arithmetic,
    so this and viewport_rows() cannot disagree about the list's height.
    """
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1  # avoid writing to the last column
    hz, vt, tl, tr, bl, br, ellipsis = box_glyphs()
    # The prompt sits on the status line, so the status is not painted then.
    status = status_lines(status_msg, max_x) if focus != FOCUS_PROMPT else []
    lay = layout(max_y, max_x, show_desc, len(status))
    if len(status) > lay["status_lines"]:
        # Fewer rows than the message wants: cut it where the screen ends.
        status = status_lines(status_msg, max_x, lay["status_lines"])
    framed = lay["framed"]
    inner_x = 2 if framed else 0
    inner_w = max(1, usable_w - 4) if framed else usable_w
    edge_attr = curses.color_pair(CP_NORMAL) | curses.A_DIM

    def put(y, x, text, n, attr):
        # ValueError is curses refusing an embedded NUL. Import escapes what
        # it copies from a file; this keeps any other text from ending the TUI.
        try:
            stdscr.addnstr(y, x, text, n, attr)
        except (curses.error, ValueError):
            pass

    def frame(top, bottom, label=""):
        """A box from row `top` to row `bottom`, `label` set in its top edge."""
        edge = hz * max(0, usable_w - 2)
        head = edge
        if label and len(label) + 2 < len(edge):
            head = hz + label + edge[len(label) + 1:]
        put(top, 0, tl + head + tr, usable_w, edge_attr)
        for y in range(top + 1, bottom):
            put(y, 0, vt, 1, edge_attr)
            put(y, usable_w - 1, vt, 1, edge_attr)
        put(bottom, 0, bl + edge + br, usable_w, edge_attr)

    # Title bar
    if install_method:
        title = f" SlimBrave Neo - Brave Browser Debloater [{install_method}] "
    else:
        title = " SlimBrave Neo - Brave Browser Debloater "
    pad = max(0, (usable_w - len(title)) // 2)
    put(0, 0, " " * usable_w, usable_w,
        curses.color_pair(CP_TITLE) | curses.A_BOLD)
    put(0, pad, title, usable_w - pad,
        curses.color_pair(CP_TITLE) | curses.A_BOLD)

    # Key hints below the title, or the live filter and its match count
    vis = visible_indices(rows, filter_text)
    needle = filter_text.strip()
    if needle:
        matches = sum(1 for i in vis if rows[i]["type"] != ROW_HEADER)
        plural = "" if matches == 1 else "es"
        hint = f" Filter: {needle}   {matches} match{plural}   [Esc] Clear "
    else:
        hint = " [Space/Enter] Toggle  [/] Search  [D] Describe  [Q] Quit  [?] Help "
        if len(hint) > usable_w:
            # the shorter hint from before the pane fits down to 55 columns
            hint = " [Space/Enter] Toggle  [/] Search  [Q] Quit  [?] Help "
    put(1, 0, hint.center(usable_w), usable_w,
        curses.color_pair(CP_NORMAL) | curses.A_DIM)

    # The list, in its box
    list_start_y = lay["list_top"]
    visible_count = lay["list_rows"]
    if framed:
        frame(list_start_y - 1, lay["list_bottom"], " Settings ")

    # Current DNS mode (for dimming the template row)
    current_dns_mode = get_dns_mode(rows)

    for vi in range(visible_count):
        vpos = vi + scroll_offset
        if vpos >= len(vis):
            break
        ri = vis[vpos]
        row = rows[ri]
        y = list_start_y + vi

        is_cursor = (focus == FOCUS_LIST and ri == cursor_idx)

        line = ""
        attr = curses.color_pair(CP_NORMAL)

        if row["type"] == ROW_HEADER:
            attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
            open_glyph, shut_glyph = disclosure_glyphs()
            # A filtered section is force-shown whatever its fold state,
            # so draw it open: the marker describes what is on screen.
            folded = row.get("collapsed", False) and not needle
            marker = shut_glyph if folded else open_glyph
            line = f"{marker} {row['text']}"
            on_count, total = header_counts(rows, ri)
            inert = header_inert_count(rows, ri)
            if total:
                counter = f"{on_count}/{total} on"
            elif inert:
                counter = f"{inert} built into Origin"
            else:
                counter = ""
            if counter:
                line = line.ljust(max(len(line) + 2,
                                      inner_w - len(counter) - 1)) + counter
        elif row["type"] == ROW_FEATURE:
            if row.get("inert"):
                # Built into Origin: nothing to tick, drawn the way the
                # unavailable DoH template field is. A long name gives way
                # so the suffix survives an 80-column terminal.
                text = row["text"]
                room = inner_w - len(INERT_SUFFIX) - len("    [-]  ")
                if len(text) > room:
                    text = text[:max(0, room - 3)].rstrip() + "..."
                line = f"    [-] {text} {INERT_SUFFIX}"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM
            else:
                mark = "x" if row["checked"] else " "
                line = f"    [{mark}] {row['text']}"
                if row["checked"]:
                    attr = curses.color_pair(CP_CHECKED)
                else:
                    attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_CHOICE:
            label = row["choices"][row["selected"]][0]
            line = f"    {row['text']}: < {label} >"
            if row["selected"] > 0:
                attr = curses.color_pair(CP_CHECKED)
            else:
                attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS:
            current = row["options"][row["selected"]]
            line = f"    < {current} >"
            attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl_active = current_dns_mode in ("custom", "secure")
            val = row["value"] if row["value"] else ""
            if tmpl_active:
                field_w = template_field_width(max_x)
                # The stored offset was computed against whatever width the
                # terminal had when the user last typed; re-derive it for
                # the current field so a resize can't strand the text.
                scroll = max(0, min(row.get("scroll", 0), len(val)))
                cur_pos = row.get("cursor", 0)
                if cur_pos - scroll >= field_w:
                    scroll = cur_pos - field_w + 1
                elif cur_pos < scroll:
                    scroll = cur_pos
                row["scroll"] = scroll
                visible_text = _field_text(val[scroll:scroll + field_w])
                # padded to the field width, so the closing bracket keeps
                # its place when the cursor sits at the end of the text
                line = f"    Template: [{visible_text.ljust(field_w)}]"
                attr = curses.color_pair(CP_NORMAL)
            else:
                line = "    Template: (select custom/secure DNS)"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM

        if is_cursor:
            attr = curses.color_pair(CP_CURSOR) | curses.A_BOLD

        put(y, inner_x, line.ljust(inner_w), inner_w, attr)

        # Draw text cursor for active template row
        if (is_cursor and row["type"] == ROW_DNS_TEMPLATE
                and current_dns_mode in ("custom", "secure")):
            tmpl_val = row["value"]
            field_start = inner_x + 15  # len("    Template: [")
            field_w = template_field_width(max_x)
            scroll = row.get("scroll", 0)
            cur_pos = row.get("cursor", 0)
            cur_screen_pos = field_start + cur_pos - scroll
            # Stay inside the bracketed field, not just inside the line.
            if field_start <= cur_screen_pos < min(inner_x + inner_w,
                                                   field_start + field_w):
                ch = _field_text(tmpl_val[cur_pos]) if cur_pos < len(tmpl_val) else " "
                put(y, cur_screen_pos, ch, 1,
                    curses.color_pair(CP_BUTTON_ACTIVE))

    # Scroll indicators, set into the box edges
    mark_x = usable_w - 7 if framed else usable_w - 5
    if scroll_offset > 0:
        put(list_start_y - 1, mark_x, " ^^^ ", 5, edge_attr)
    if scroll_offset + visible_count < len(vis):
        put(lay["list_bottom"], mark_x, " vvv ", 5, edge_attr)

    # Description pane: what the cursor is on, or the focused button
    if lay["pane_lines"]:
        top = lay["pane_top"]
        frame(top, top + lay["pane_lines"] + 1, " Description ")
        what = describe_focus if describe_focus is not None else focus
        text = describe_row(rows, cursor_idx, what, btn_idx)
        parts = wrap_description(text, inner_w, lay["pane_lines"], ellipsis)
        for i, part in enumerate(parts):
            put(top + 1 + i, inner_x, part, inner_w,
                curses.color_pair(CP_NORMAL))

    # Bottom buttons, in their box
    if framed:
        frame(lay["btn_top"], lay["btn_top"] + 2)
    btn_y = lay["btn_y"]
    btn_x = inner_x
    for i, label in enumerate(BUTTONS):
        display = f" {label} "
        if focus == FOCUS_BUTTONS and i == btn_idx:
            attr = curses.color_pair(CP_BUTTON_ACTIVE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_BUTTON)
        put(btn_y, btn_x, display, max(0, inner_x + inner_w - btn_x), attr)
        btn_x += len(display) + 3

    # Status / prompt line
    status_y = lay["status_y"]
    if focus == FOCUS_PROMPT:
        prompt_text = f" {prompt_label}: {prompt_buf}"
        put(status_y, 0, prompt_text.ljust(usable_w), usable_w,
            curses.color_pair(CP_TITLE))
        cur_x = len(prompt_label) + 3 + prompt_cur
        if cur_x < usable_w:
            ch = prompt_buf[prompt_cur] if prompt_cur < len(prompt_buf) else " "
            put(status_y, cur_x, ch, 1, curses.color_pair(CP_BUTTON_ACTIVE))
    elif status_msg:
        cp = CP_STATUS_OK if status_ok else CP_STATUS_ERR
        for i, line in enumerate(status):
            put(status_y + i, 2, line, usable_w - 3, curses.color_pair(cp))

    stdscr.refresh()


HELP_LINES = [
    " SlimBrave Neo - keys",
    "",
    "   Up / Down             Move the cursor",
    "   PageUp / PageDown     Move one screenful",
    "   Home / End            Jump to the first / last row",
    "   Space / Enter         Toggle a setting; fold or unfold a section",
    "   Left / Right          Cycle a selector; fold / unfold a section",
    "   c                     Fold every section, or unfold them all",
    "   /                     Filter rows by name",
    "   d                     Show or hide the description pane",
    "   Esc                   Clear the filter, else quit",
    "   ?                     This help",
    "   Tab                   Jump to the button row",
    "   Q                     Quit",
    "",
    "   Press any key to close.",
]


def draw_help(stdscr):
    """Paint the key-binding overlay over the whole screen."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1
    for i, text in enumerate(HELP_LINES):
        if i >= max_y:
            break
        if i == 0:
            attr = curses.color_pair(CP_TITLE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_NORMAL)
        try:
            stdscr.addnstr(i, 0, text.ljust(usable_w), usable_w, attr)
        except curses.error:
            pass
    stdscr.refresh()


def prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                      install_method, label, default="", on_change=None,
                      show_desc=False):
    """Show a status-line text prompt and return (ok, text) on Enter.

    `on_change` is the live-filter hook: it is handed the buffer after
    every edit and returns the (cursor_idx, scroll_offset) to draw the
    list behind the prompt with, so matches narrow as the query is
    typed rather than only once it is submitted. Passing it also feeds
    the buffer to draw() as the active filter.
    """
    buf = list(default)
    cur = len(buf)
    shown = None

    while True:
        text = "".join(buf)
        if on_change is not None and text != shown:
            cursor_idx, scroll_offset = on_change(text)
            shown = text

        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_PROMPT, btn_idx, "", True, install_method,
             prompt_label=label, prompt_buf=text, prompt_cur=cur,
             filter_text="" if on_change is None else text,
             show_desc=show_desc,
             # the filter prompt (on_change) describes the cursor row; the
             # Import and Export path prompts describe their button
             describe_focus=None if on_change is not None else FOCUS_BUTTONS)

        key = stdscr.getch()

        if key == 27:
            return False, ""
        elif key in (curses.KEY_ENTER, 10, 13):
            return True, "".join(buf).strip()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif key == curses.KEY_DC:
            if cur < len(buf):
                buf.pop(cur)
        elif key == curses.KEY_LEFT:
            if cur > 0:
                cur -= 1
        elif key == curses.KEY_RIGHT:
            if cur < len(buf):
                cur += 1
        elif key == curses.KEY_HOME:
            cur = 0
        elif key == curses.KEY_END:
            cur = len(buf)
        elif 32 <= key <= 126:
            buf.insert(cur, chr(key))
            cur += 1


def _expand_prompt_path(path):
    """Expand a leading ~ in a path typed at the TUI's Import/Export prompt.

    `~` and `~/...` mean the invoking user's home (_invoking_user), not
    root's, falling back to os.path.expanduser when there is none;
    `~name/...` goes through os.path.expanduser. Anything else is
    returned unchanged.
    """
    if path == "~" or path.startswith("~/"):
        home = _user_home_for_brave()
        if home is None:
            return os.path.expanduser(path)
        return home if path == "~" else os.path.join(home, path[2:])
    if path.startswith("~"):
        return os.path.expanduser(path)
    return path


def main(stdscr, override_installations=None):
    """Main TUI event loop."""
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    stdscr.timeout(-1)
    # The description pane starts shown wherever layout() finds room for
    # it; `d` toggles it, and layout() drops it on its own below that room.
    max_y, max_x = stdscr.getmaxyx()
    show_desc = layout(max_y, max_x, True)["pane_lines"] > 0

    brave_info = detect_brave()
    if override_installations is not None:
        installations = override_installations
        install_method = "policy-file override"
    else:
        installations = brave_info["installations"]
        install_method = brave_info["method"]

    rows = build_rows(installations)
    sel = selectable_indices(rows)
    if not sel:
        return

    policy = load_existing_policy(installations)
    sync_rows_with_policy(rows, policy)

    # Fold what is not in use, then re-derive the selectable list: the
    # cursor must never start on a row the fold just hid.
    apply_startup_collapse(rows)
    sel = selectable_indices(rows)
    if not sel:
        return

    cursor_pos = 0
    # Land on the first real setting rather than the header above it, so
    # launch looks the way it did before headers became selectable.
    cursor_idx = next((i for i in sel if rows[i]["type"] != ROW_HEADER),
                      sel[0])
    scroll_offset = 0
    focus = FOCUS_LIST
    btn_idx = 0
    # The live filter, and the fold state Esc has to put back.
    filter_text = ""
    saved_collapse = None

    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        # Both warnings (Snap confinement, Brave not found) are problems —
        # neither belongs in the success color.
        status_ok = False
    elif brave_info.get("notes") and override_installations is None:
        # A note (Brave Origin found) is information, so it keeps the
        # success color; a warning outranks it for the one status line.
        # Under --policy-file the rows come from the override record and
        # stay live, so the note would describe a list that is not shown.
        status_msg = brave_info["notes"][0]
        status_ok = True
    else:
        status_msg = ""
        status_ok = True

    while True:
        visible_count = viewport_rows(stdscr, show_desc, status_msg)
        # Recomputed every pass: a fold, a filter keystroke or an import can
        # change what is on screen between one getch() and the next.
        vis = visible_indices(rows, filter_text)
        sel = selectable_indices(rows, filter_text)
        cursor_pos, cursor_idx = resolve_cursor(sel, cursor_idx)
        cursor_vpos = vis.index(cursor_idx) if cursor_idx in vis else -1
        scroll_offset = clamp_scroll(rows, vis, scroll_offset,
                                     cursor_vpos, visible_count)

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method, filter_text=filter_text,
             show_desc=show_desc)

        key = stdscr.getch()
        if key == curses.KEY_RESIZE:
            curses.update_lines_cols()
            continue
        # A filter matching nothing leaves the cursor on no row at all; NO_ROW
        # matches no branch below, so every one of them falls through.
        row = rows[cursor_idx] if 0 <= cursor_idx < len(rows) else NO_ROW

        if (focus == FOCUS_LIST
                and row["type"] == ROW_DNS_TEMPLATE
                and get_dns_mode(rows) in ("custom", "secure")):
            if 32 <= key <= 126:
                val = row["value"]
                cur = row["cursor"]
                row["value"] = val[:cur] + chr(key) + val[cur:]
                row["cursor"] = cur + 1
                _, max_x = stdscr.getmaxyx()
                field_w = template_field_width(max_x)
                if row["cursor"] - row["scroll"] >= field_w:
                    row["scroll"] = row["cursor"] - field_w + 1
                status_msg = ""
                continue
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if row["cursor"] > 0:
                    val = row["value"]
                    cur = row["cursor"]
                    row["value"] = val[:cur - 1] + val[cur:]
                    row["cursor"] = cur - 1
                    if row["scroll"] > 0:
                        row["scroll"] -= 1
                    status_msg = ""
                continue
            elif key == curses.KEY_DC:
                val = row["value"]
                cur = row["cursor"]
                if cur < len(val):
                    row["value"] = val[:cur] + val[cur + 1:]
                    status_msg = ""
                continue
            elif key == curses.KEY_LEFT:
                if row["cursor"] > 0:
                    row["cursor"] -= 1
                    if row["cursor"] < row["scroll"]:
                        row["scroll"] = row["cursor"]
                continue
            elif key == curses.KEY_RIGHT:
                if row["cursor"] < len(row["value"]):
                    row["cursor"] += 1
                    _, max_x = stdscr.getmaxyx()
                    field_w = template_field_width(max_x)
                    if row["cursor"] - row["scroll"] >= field_w:
                        row["scroll"] = row["cursor"] - field_w + 1
                continue
            elif key == curses.KEY_HOME:
                row["cursor"] = 0
                row["scroll"] = 0
                continue
            elif key == curses.KEY_END:
                row["cursor"] = len(row["value"])
                _, max_x = stdscr.getmaxyx()
                field_w = template_field_width(max_x)
                row["scroll"] = max(0, row["cursor"] - field_w + 1)
                continue

        if key == 27:
            # Esc is the filter's cancel first and the quit key second.
            if filter_text:
                filter_text = ""
                restore_collapse_state(rows, saved_collapse)
                saved_collapse = None
                status_msg = ""
                continue
            break

        elif key == ord("q"):
            break

        elif key == curses.KEY_UP:
            if focus == FOCUS_LIST:
                if cursor_pos > 0:
                    cursor_pos -= 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                focus = FOCUS_LIST
                # sel is empty when the filter matches nothing, and
                # sel[-1] would be an IndexError rather than a no-op.
                if sel:
                    cursor_pos = len(sel) - 1
                    cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == curses.KEY_DOWN:
            if focus == FOCUS_LIST:
                if cursor_pos < len(sel) - 1:
                    cursor_pos += 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
                else:
                    focus = FOCUS_BUTTONS
                    btn_idx = 0
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                pass

        elif key in (curses.KEY_PPAGE, curses.KEY_NPAGE):
            if focus == FOCUS_LIST and sel:
                step = visible_count
                if key == curses.KEY_PPAGE:
                    step = -visible_count
                cursor_pos = max(0, min(len(sel) - 1, cursor_pos + step))
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == curses.KEY_HOME:
            if focus == FOCUS_LIST and sel:
                cursor_pos = 0
                cursor_idx = sel[0]
                scroll_offset = 0
                status_msg = ""

        elif key == curses.KEY_END:
            if focus == FOCUS_LIST and sel:
                cursor_pos = len(sel) - 1
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == ord("c"):
            # Fold every section unless every section is already folded.
            headers = [r for r in rows if r["type"] == ROW_HEADER]
            fold = any(not h.get("collapsed", False) for h in headers)
            for header in headers:
                header["collapsed"] = fold
            status_msg = ""

        elif key == ord("d"):
            show_desc = not show_desc
            status_msg = ""
            max_y, max_x = stdscr.getmaxyx()
            if show_desc and layout(max_y, max_x, True)["pane_lines"] == 0:
                status_msg = "Terminal too short for the description pane."
                status_ok = False

        elif key == ord("?"):
            while True:
                draw_help(stdscr)
                if stdscr.getch() != curses.KEY_RESIZE:
                    break
                curses.update_lines_cols()
            status_msg = ""

        elif key == ord("/"):
            focus = FOCUS_LIST
            if not filter_text:
                # Snapshot on the way in only: reopening the prompt over a
                # live filter must not overwrite what Esc has to restore.
                saved_collapse = collapse_state(rows)

            def preview(text):
                """Re-aim the viewport at the shrinking match set."""
                new_vis = visible_indices(rows, text)
                new_sel = selectable_indices(rows, text)
                _, idx = resolve_cursor(new_sel, cursor_idx)
                vpos = new_vis.index(idx) if idx in new_vis else -1
                return idx, clamp_scroll(rows, new_vis, scroll_offset,
                                         vpos, visible_count)

            ok, text = prompt_text_input(
                stdscr, rows, cursor_idx, scroll_offset,
                btn_idx, install_method,
                "Filter (Esc=clear)",
                default=filter_text, on_change=preview,
                show_desc=show_desc)
            if ok:
                filter_text = text
            else:
                filter_text = ""
                restore_collapse_state(rows, saved_collapse)
                saved_collapse = None
            status_msg = ""

        elif key == ord("\t"):
            if focus == FOCUS_LIST:
                focus = FOCUS_BUTTONS
                btn_idx = 0
                status_msg = ""
            else:
                focus = FOCUS_LIST
                status_msg = ""

        elif key == curses.KEY_LEFT:
            if focus == FOCUS_BUTTONS:
                btn_idx = max(0, btn_idx - 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_HEADER:
                    row["collapsed"] = True
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] - 1) % len(row["options"])
                    status_msg = ""
                elif row["type"] == ROW_CHOICE:
                    cycle_choice_row(row, -1)
                    status_msg = ""

        elif key == curses.KEY_RIGHT:
            if focus == FOCUS_BUTTONS:
                btn_idx = min(len(BUTTONS) - 1, btn_idx + 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_HEADER:
                    row["collapsed"] = False
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""
                elif row["type"] == ROW_CHOICE:
                    cycle_choice_row(row, 1)
                    status_msg = ""

        elif key == ord(" "):
            if focus == FOCUS_LIST and activate_row(rows, row):
                status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                btn_label = BUTTONS[btn_idx]

                if btn_label == "Apply":
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode in ("custom", "secure") and not dns_tmpl:
                        status_msg = "Secure/custom DNS requires a DoH template URL."
                        status_ok = False
                    else:
                        status_ok, status_msg = apply_policy(rows, installations)

                elif btn_label == "Reset":
                    status_msg = ("Reset all settings? "
                                  "Press Enter to confirm, any key to cancel.")
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset,
                         focus, btn_idx, status_msg, status_ok,
                         install_method, filter_text=filter_text,
                         show_desc=show_desc)
                    confirm = stdscr.getch()
                    if confirm in (curses.KEY_ENTER, 10, 13):
                        status_ok, status_msg = reset_policy(rows, installations)
                    else:
                        status_msg = "Reset cancelled."
                        status_ok = True

                elif btn_label == "Import":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Import path (Esc=cancel)",
                        default="./Presets/", show_desc=show_desc)
                    if ok and path:
                        status_ok, status_msg = import_settings(
                            rows, _expand_prompt_path(path))
                    else:
                        status_msg = "Import cancelled."
                        status_ok = True

                elif btn_label == "Export":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "Export path (Esc=cancel)",
                        default="./SlimBraveNeoSettings.json", show_desc=show_desc)
                    if ok and path:
                        status_ok, status_msg = export_settings(
                            rows, _expand_prompt_path(path))
                    else:
                        status_msg = "Export cancelled."
                        status_ok = True

                elif btn_label == "Quit":
                    break

            elif focus == FOCUS_LIST:
                if activate_row(rows, row):
                    status_msg = ""

# ---------------------------------------------------------------------------
# CLI (non-interactive)
# ---------------------------------------------------------------------------


def cli_import(path, installations, doh_templates=""):
    """Non-interactive: import config and apply policies."""
    rows = build_rows(installations)
    ok, msg, outcome = _import_config(rows, path)
    if not ok:
        _say(f"Error: {msg}", sys.stderr)
        return 1
    _say(msg)
    # A Features block that names entries but has none taken, with no DNS
    # mode either, would apply an empty policy and so remove SlimBrave's:
    # a file of policies SlimBrave Neo does not offer writes nothing. An
    # empty block still applies an empty policy, as it always has.
    if outcome["entries"] and not outcome["taken"] and not outcome["dns"]:
        _say(f"Error: nothing in {_shown_path(path)} can be applied; "
             "--import wrote nothing.", sys.stderr)
        return 1

    # A template is inert unless the mode asks for one, and most presets
    # carry no DnsMode at all — promote those rather than dropping the flag
    # silently. "automatic" keeps its mode (Chromium honours a template
    # there); "off" is a contradiction only the caller can resolve.
    if doh_templates:
        dns_mode = get_dns_mode(rows)
        if dns_mode == "off":
            _say(
                "Error: --doh-templates conflicts with DnsMode 'off' in "
                f"{_shown_path(path)}. Remove one of them.",
                sys.stderr,
            )
            return 1
        for row in rows:
            if row["type"] == ROW_DNS and dns_mode == "unmanaged":
                row["selected"] = row["options"].index("custom")
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = doh_templates
                row["cursor"] = len(doh_templates)
                row["scroll"] = 0

    ok, msg = apply_policy(rows, installations)
    if not ok:
        _say(f"Error: {msg}", sys.stderr)
        return 1
    _say(msg)
    return 0


def cli_export(path, installations):
    """Non-interactive: export current policy to a config file."""
    policy = load_existing_policy(installations)
    if not policy:
        print("No existing policy found.", file=sys.stderr)
        return 1

    rows = build_rows(installations)
    sync_rows_with_policy(rows, policy)
    # Keys on disk that are built into Brave Origin here never reach the
    # rows, so they never reach the file either; say so rather than let a
    # backup silently shrink.
    left_out = [r["key"] for r in rows
                if r["type"] == ROW_FEATURE and r.get("inert") and r["key"] in policy]
    if left_out:
        n = len(left_out)
        print(f"Note: {n} key{'s' if n != 1 else ''} built into Brave Origin "
              "left out of the export", file=sys.stderr)

    ok, msg = export_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_reset(installations):
    """Non-interactive: delete the policy file(s) and repair leaked prefs."""
    targets = _dedupe_plist_targets(installations)
    if not targets:
        print(f"No policy file found at {POLICY_FILE}")
        return 0
    try:
        for plist_path, label in targets:
            if os.path.exists(plist_path):
                os.remove(plist_path)
                print(
                    f"Removed {plist_path}"
                    + (f" ({label})" if label else "")
                )
            else:
                print(
                    f"No policy file found at {plist_path}"
                    + (f" ({label})" if label else "")
                )
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    repaired, failed, running = repair_brave_prefs(installations)
    if repaired > 0 and not running:
        print(
            f"Cleaned {repaired} leaked profile "
            f"pref{'s' if repaired != 1 else ''} from Brave's user profile."
        )
    if failed:
        print(f"Warning: {_scrub_failure_note(failed)}", file=sys.stderr)
    if running:
        print(
            "Note: Brave is running — any leaked profile prefs cleaned now "
            "will be overwritten when Brave next saves. Fully close Brave "
            "and run --reset again to make it stick."
        )
    return 0


def _filter_installations_by_channels(installations, channel_spec):
    """Apply --channels flag semantics to detected installations.

    On Linux every channel writes to the same POLICY_FILE, so filtering
    only narrows which channels' user-data dirs get prefs repair and
    which process names are checked when reporting "Brave is running".
    """
    if not channel_spec or channel_spec == "auto":
        return installations, ""
    requested = [c.strip().lower() for c in channel_spec.split(",") if c.strip()]
    unknown = [c for c in requested if c not in CHANNEL_IDS]
    if unknown:
        return None, (
            f"Unknown channel(s): {', '.join(unknown)}. "
            f"Valid: {', '.join(CHANNEL_IDS)}"
        )
    filtered = [i for i in installations if i["channel"] in requested]
    if not filtered:
        return None, (
            f"No installed Brave channel matches --channels {channel_spec}. "
            f"Detected: {', '.join(i['channel'] for i in installations) or 'none'}"
        )
    return filtered, ""


def _check_args(args):
    """Return the error for a command line that cannot run, or None.

    Checked before the root check, so a bad command line is refused
    without sudo; __main__ exits 2 on any of them.
    """
    for flag, value in (("--import", args.import_path),
                        ("--export", args.export_path),
                        ("--policy-file", args.policy_file)):
        if value == "":
            return f"Error: {flag} needs a path."
    # --doh-templates is only ever read by cli_import; --reset, --export and
    # the TUI would drop it without a word.
    if args.doh_templates and args.import_path is None:
        return "Error: --doh-templates requires --import"
    # --reset runs first, so an export after it would save nothing; and a
    # failed export would not stop the reset that loses the policy.
    if args.reset and args.export_path is not None:
        return ("Error: --export cannot be combined with --reset. "
                "Run --export first, then --reset.")
    acting = (args.import_path is not None or args.export_path is not None
              or args.reset)
    if args.channels != "auto" and (args.policy_file is not None or not acting):
        return ("Error: --channels applies only to --import, --export or "
                "--reset, and not with --policy-file.")
    return None


def parse_args(argv=None):
    """Parse command-line arguments (sys.argv[1:] when argv is None)."""
    parser = argparse.ArgumentParser(
        prog="slimbrave",
        description="SlimBrave Neo - Brave Browser debloater",
        epilog=("Run without arguments to launch the interactive TUI. "
                "--reset runs before --import; --export runs last."),
    )
    parser.add_argument(
        "--import", dest="import_path", metavar="PATH",
        help="import a SlimBrave Neo JSON config and apply policies",
    )
    parser.add_argument(
        "--export", dest="export_path", metavar="PATH",
        help="export current policy to a SlimBrave Neo JSON config",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="remove the SlimBrave Neo managed policy file",
    )
    parser.add_argument(
        "--policy-file", metavar="PATH",
        help=f"override policy file path (default: {POLICY_FILE})",
    )
    parser.add_argument(
        "--doh-templates", metavar="URL",
        help="set DnsOverHttpsTemplates (used with custom DNS mode)",
    )
    parser.add_argument(
        "--channels", metavar="LIST", default="auto",
        help=(
            "comma-separated channels for prefs-repair / process detection "
            f"({', '.join(CHANNEL_IDS)}). Default 'auto' = all detected. "
            "Linux always writes a single shared policy file."
        ),
    )
    return parser.parse_args(argv)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------



# ===========================================================================
# SLIMBRAVE-NEO-ZH LOCALIZATION & CJK CURSES RUNTIME (zero external deps)
# ===========================================================================
def _sb_zh_install():
    import base64 as _b64
    import json as _json
    import unicodedata as _ud

    _ZH = _json.loads(_b64.b64decode("eyJjYXRlZ29yaWVzIjp7IlRlbGVtZXRyeSAmIFJlcG9ydGluZyI6IumBpea1i+S4juaKpeWRiiIsIlByaXZhY3kgJiBTZWN1cml0eSI6IumakOengeS4juWuieWFqCIsIlNpdGUgUGVybWlzc2lvbnMiOiLnvZHnq5nmnYPpmZAiLCJBY2Nlc3MgQ29udHJvbHMiOiLorr/pl67mjqfliLYiLCJCcmF2ZSBGZWF0dXJlcyI6IkJyYXZlIOWGhee9ruWKn+iDvSIsIlNoaWVsZHMgJiBDb250ZW50IFByb3RlY3Rpb24iOiLnm77niYzkuI7lhoXlrrnkv53miqQiLCJQZXJmb3JtYW5jZSAmIEJsb2F0Ijoi5oCn6IO95LiO57K+566AIn0sImNob2ljZXMiOnsiTm90IG1hbmFnZWQiOiLkuI3nrqHnkIYiLCJBbGxvdyI6IuWFgeiuuCIsIkFzayI6IuivoumXriIsIkJsb2NrIjoi6Zi75q2iIn0sImRuc19tb2RlcyI6eyJ1bm1hbmFnZWQiOiLkuI3nrqHnkIYiLCJhdXRvbWF0aWMiOiLoh6rliqggKGF1dG8pIiwib2ZmIjoi5YWz6ZetIChvZmYpIiwic2VjdXJlIjoi5a6J5YWoIChzZWN1cmUpIiwiY3VzdG9tIjoi6Ieq5a6a5LmJIChjdXN0b20pIn0sInBvbGljaWVzIjp7Ik1ldHJpY3NSZXBvcnRpbmdFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjmjIfmoIfkuI7ltKnmuoPmiqXlkYoiLCJkZXNjIjoi6Zi75q2iIEJyYXZlIOS4iuS8oOW0qea6g+aKpeWRiu+8mumUgeWumuWFs+mXreKAnOiHquWKqOWPkemAgeiviuaWreaKpeWRiuKAne+8jOmakOiXj+W0qea6g+WQjueahOS4iuS8oOaPkOekuu+8jOW5tuWxj+iUvSBicmF2ZTovL2NyYXNoZXMg5LiK55qE4oCc56uL5Y2z5Y+R6YCB4oCd44CCQmV0YSDkuI4gTmlnaHRseSDpu5jorqTlvIDlkK/vvJtSZWxlYXNlIOmmluasoeasoui/jumhteS5n+S8mum7mOiupOWLvumAieOAglAzQSDkuI7kvb/nlKjnu5/orqEgcGluZyDnlLHljZXni6zmnaHnm67mjqfliLbjgIIifSwiVXJsS2V5ZWRBbm9ueW1pemVkRGF0YUNvbGxlY3Rpb25FbmFibGVkIjp7Im5hbWUiOiLnpoHnlKggVVJMIOWMv+WQjeaVsOaNruaUtumbhiIsImRlc2MiOiLplIHlrprlhbPpl63igJzmlLnov5vmkJzntKLlkozmtY/op4jkvZPpqozigJ3vvIjln7rkuo4gVVJMIOeahOWMv+WQjeaVsOaNruaUtumbhu+8ieOAgkJyYXZlIOm7mOiupOW3suWFs+mXreatpOmhue+8m+WFtuWUr+S4gOW8gOWFs+S9jeS6jumakOiXj+eahOmakOengeaMh+WNl++8iGJyYXZlOi8vc2V0dGluZ3MvcHJpdmFjeS9ndWlkZe+8ie+8jOiuvue9ruS7u+aEj+etlueVpeWQjuivpeWFpeWPo+S8mumakOiXj+OAguatpOmhueS5n+S8muimhuebluatpOWJjeWcqOWFtuS4reW8gOWQr+eahOaOiOadg+OAgiJ9LCJBY2Nlc3NpYmlsaXR5SW1hZ2VMYWJlbHNFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKggR29vZ2xlIOWbvuWDj+aPj+i/sCIsImRlc2MiOiJCcmF2ZSDpu5jorqTlt7LlhbPpl60gR29vZ2xlIOWbvuWDj+aPj+i/sOS4lOS4jeWGjeaPkOS+m+W8gOWQr+WFpeWPo+OAguS9huaXp+eJiOmFjee9ruS4reiLpeabvuWQjOaEj+i/h++8jOi/kOihjOWxj+W5lemYheivu+WZqOaXtuS7jeS8muWwhuaXoOagh+etvuWbvueJh+WPkemAgee7mSBHb29nbGXvvJvlkK/nlKjmraTnrZbnlaXlj6/lvbvlupXlhbPpl63lubbplIHlrprjgIIifSwiQnJhdmVQM0FFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKggUDNBIOS6p+WTgeWIhuaekCIsImRlc2MiOiLnpoHnlKggUDNB77yI6ZqQ56eB5L+d5oqk5Lqn5ZOB5YiG5p6Q77yJ77yM5Y2zIEJyYXZlIOeahOWMv+WQjeS6p+WTgeS9v+eUqOmBpea1i+WKn+iDveOAgiJ9LCJCcmF2ZVN0YXRzUGluZ0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOavj+aXpea0u+i3g+e7n+iuoSBQaW5nIiwiZGVzYyI6IuWBnOatoueUqOS6jue7n+iuoSBCcmF2ZSDmtLvot4PnlKjmiLfmlbDnmoTmr4/ml6Xkvb/nlKggUGluZ++8jOS7peWPiuWFtuS4remZhOW4pueahOaQnOe0ouW8leaTjuS9v+eUqOiuoeaVsOWSjOaOqOW5v+eggeajgOafpeOAguiLpeacquWQjOaXtuemgeeUqCBQM0Eg5YiG5p6Q77yMUDNBIOS7jeS8muWNleeLrOWPkemAgeS4gOS7veaQnOe0ouiuoeaVsOOAgiJ9LCJDaHJvbWVWYXJpYXRpb25zOjEiOnsibmFtZSI6IumZkOWItuS6keerr+WunumqjOS7hemZkOWFs+mUruS/ruWkjSIsImRlc2MiOiLlsIYgQnJhdmUg6L+c56iL6YWN572u56eN5a2Q77yIR3JpZmZpbu+8iemZkOWItuS4uuS7heaOpeaUtuWFs+mUruS/ruWkjeWunumqjO+8jOi/meS8muWQjOaXtuWFs+mXreS7hemdoOi/nOeoi+S4i+WPkeWQr+eUqOeahOeJueaAp++8mldlYkdML1dlYkdQVSDmjIfnurnkvKroo4XjgIHlm77niYflhYPmlbDmja7liaXnprvvvIjkuKTogIXlj6/lnKggYnJhdmU6Ly9mbGFncyDmiYvliqjmgaLlpI3vvInku6Xlj4ogR29vZ2xlIOeZu+W9leS/ruWkjeOAgumHjeWQr+WQjueUn+aViOOAguS4juKAnOWujOWFqOemgeeUqOS6keerr+WunumqjOKAneS6kuaWpeOAgiJ9LCJDaHJvbWVWYXJpYXRpb25zOjIiOnsibmFtZSI6IuWujOWFqOemgeeUqOS6keerr+WunumqjCAvIEdyaWZmaW4iLCJkZXNjIjoi5ouS57ud5omA5pyJIEdyaWZmaW4g5LqR56uv5a6e6aqM77yI5ZCr5YWz6ZSu5L+u5aSN77yJ77yM5LuF6Z2g6L+c56iL56eN5a2Q5ZCv55So55qE54m55oCn5bCG5L+d5oyB5YWz6Zet77yaV2ViR0wvV2ViR1BVIOaMh+e6ueS8quijheOAgeWbvueJh+WFg+aVsOaNruWJpeemu+WPiiBHb29nbGUg55m75b2V5L+u5aSN44CC56eN5a2Q5paH5Lu25pys6Lqr5LuN5Lya5LiL6L2944CC6YeN5ZCv5ZCO55Sf5pWI44CC5LiO4oCc6ZmQ5Yi25LqR56uv5a6e6aqM5LuF6ZmQ5YWz6ZSu5L+u5aSN4oCd5LqS5pal44CCIn0sIlNwZWxsQ2hlY2tTZXJ2aWNlRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5aKe5by65Z6L5Zyo57q/5ou85YaZ5qOA5p+lIiwiZGVzYyI6IumUgeWumuWFs+mXreS8muWwhuihqOWNlei+k+WFpeWPkemAgeWIsCBHb29nbGUg55qE5aKe5by65Z6L5ou85YaZ5qOA5p+l44CCQnJhdmUg6buY6K6k5bey5YWz6Zet5LiU5peg55WM6Z2i5byA5YWz77yb5pys5Zyw56a757q/5ou85YaZ5qOA5p+l5LuN5Y+v5q2j5bi45L2/55So44CC5LiO4oCc56aB55So5ou85YaZ5qOA5p+l4oCd5LqS5pal77yI5ZCO6ICF5Lya5a6M5YWo5YWz6Zet5ou85YaZ5qOA5p+l5bm25L2/5pys6aG55peg5pWI77yJ44CCIn0sIlNhZmVCcm93c2luZ1Byb3RlY3Rpb25MZXZlbDowIjp7Im5hbWUiOiLnpoHnlKjlronlhajmtY/op4jvvIjpmY3kvY7lronlhajmgKfvvIkiLCJkZXNjIjoi5a6M5YWo5YWz6Zet5a6J5YWo5rWP6KeI44CCQnJhdmUg5Lya6YCa6L+H6Ieq5pyJ5pyN5Yqh5Zmo5Luj55CG5p+l6K+i77yMR29vZ2xlIOWOn+acrOS5n+aXoOazleW+l+efpeivt+axguadpea6kO+8m+WFs+mXreWug+WHoOS5juS4jeWinuWKoOmakOenge+8jOWNtOS8muWkseWOu+mSk+mxvOS4juaBtuaEj+i9r+S7tuitpuWRiumhtemdouOAguaJgOaciemihOiuvuWdh+S4jeWMheWQq+atpOmhueOAguS4juKAnOmUgeWumuW8gOWQr+WuieWFqOa1j+iniOKAneS6kuaWpeOAgiJ9LCJBdXRvZmlsbEFkZHJlc3NFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjlnLDlnYDoh6rliqjloavlhYUiLCJkZXNjIjoi6Zi75q2iIEJyYXZlIOWcqOe9kemhteihqOWNleS4reS/neWtmOWSjOiHquWKqOWhq+WFheWcsOWdgOWPiuWFtuS7luiBlOezu+S/oeaBr+OAgkNocm9taXVtIOW3suW8g+eUqOatpOetlueVpe+8iGJyYXZlOi8vcG9saWN5IOS8muagh+azqOS4uiBEZXByZWNhdGVk77yJ77yM5L2GIEJyYXZlIOebruWJjeS7jeS8muaJp+ihjO+8m+WFtuabv+S7o+etlueVpSBBdXRvZmlsbFNldHRpbmdzIOWwmuacquWcqCBCcmF2ZSDkuK3nlJ/mlYjjgIIifSwiQXV0b2ZpbGxDcmVkaXRDYXJkRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5L+h55So5Y2h6Ieq5Yqo5aGr5YWFIiwiZGVzYyI6IumYu+atoiBCcmF2ZSDlnKjnvZHpobXooajljZXkuK3kv53lrZjlkozoh6rliqjloavlhYXkv6HnlKjljaHlj7fjgIJDaHJvbWl1bSDlt7LlvIPnlKjmraTnrZbnlaXvvIhicmF2ZTovL3BvbGljeSDkvJrmoIfms6jkuLogRGVwcmVjYXRlZO+8ie+8jOS9hiBCcmF2ZSDnm67liY3ku43kvJrmiafooYzvvJvlhbbmm7/ku6PnrZbnlaUgQXV0b2ZpbGxTZXR0aW5ncyDlsJrmnKrlnKggQnJhdmUg5Lit55Sf5pWI44CCIn0sIlBhc3N3b3JkTWFuYWdlckVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWGhee9ruWvhueggeeuoeeQhuWZqCIsImRlc2MiOiLlgZzmraLlhoXnva7lr4bnoIHnrqHnkIblmajmj5DnpLrkv53lrZjmiJbnlJ/miJDlr4bnoIHjgILmraTliY3lt7Lkv53lrZjnmoTlr4bnoIHku43lj6/oh6rliqjloavlhYXjgILlpoLmnpzkvaDkvb/nlKjni6znq4vnmoTnrKzkuInmlrnlr4bnoIHnrqHnkIblmajvvIzlu7rorq7lvIDlkK/mraTpobnjgIIifSwiUGFzc3dvcmRMZWFrRGV0ZWN0aW9uRW5hYmxlZCI6eyJuYW1lIjoi56aB55So5a+G56CB5rOE6Zyy5qOA5rWLIiwiZGVzYyI6IumUgeWumuWFs+mXreeZu+W9lee9keermeaIlue8lui+keW3suS/neWtmOWvhueggeaXtuinpuWPkeeahOWcqOe6v+azhOmcsuW6k+avlOWvueajgOafpeOAgkJyYXZlIOm7mOiupOW3suWFs+mXre+8jOatpOetlueVpeeUqOS6jumUgeWumuS/neaMgeWFs+mXreOAgiJ9LCJCcm93c2VyU2lnbmluIjp7Im5hbWUiOiLnpoHnlKjmtY/op4jlmaggR29vZ2xlIOeZu+W9lSIsImRlc2MiOiJCcmF2ZSDmnKzouqvkuI3lkKsgR29vZ2xlIOa1j+iniOWZqOi0puWPt+eZu+W9le+8m+atpOetlueVpeeUqOS6jumUgeWumuWFs+mXreKAnOWFgeiuuOaJqeWxleS9v+eUqCBHb29nbGUg55m75b2V4oCd77yIYnJhdmU6Ly9zZXR0aW5ncy9leHRlbnNpb25z77yJ77yM5LiOIEJyYXZlIOm7mOiupOS4gOiHtOOAguaJqeWxleS7jeWPr+mAmui/hyBjaHJvbWUuaWRlbnRpdHkg5omT5byAIEdvb2dsZSDnmbvlvZXlvLnnqpfjgILkuI3lvbHlk40gQnJhdmUg6LSm5Y+344CC6YeN5ZCv5ZCO55Sf5pWI44CCIn0sIkJyYXZlR2xvYmFsUHJpdmFjeUNvbnRyb2xFbmFibGVkIjp7Im5hbWUiOiLlkK/nlKjlhajnkIPpmpDnp4HmjqfliLYgKEdQQykiLCJkZXNjIjoiQnJhdmUg6buY6K6k5Zyo5q+P5qyh6K+35rGC5Lit5Y+R6YCBIEdQQyDkv6Hlj7fvvIjopoHmsYLnvZHnq5nkuI3opoHlh7rllK7miJblhbHkuqvkvaDnmoTmlbDmja7vvInkuJTml6DmiYvliqjlvIDlhbPvvJvmraTnrZbnlaXlj6/noa7kv53ljbPkvb/lnKjigJzku4Xmi6bmiKrlub/lkYrmqKHlvI/igJ3vvIjku4Xoi7HmlofnlYzpnaLmj5DkvpvvvInkuIvku43kv53mjIHlvIDlkK/vvIzkuJTlnKjlhbPpl63nm77niYznmoTnvZHnq5nkuIrkvp3nhLbnlJ/mlYjjgIIifSwiQnJhdmVEZUFtcEVuYWJsZWQiOnsibmFtZSI6IuWQr+eUqCBEZS1BTVDvvIjot7Pov4cgQU1QIOmhtemdou+8iSIsImRlc2MiOiLkv53mjIEgRGUtQU1QIOW8gOWQr++8muiHquWKqOi3s+i/hyBHb29nbGUgQU1QIOS7o+eQhumhteW5tuebtOi+vuWPkeW4g+iAheWOn+e9kemhteOAgkJyYXZlIOm7mOiupOW8gOWQr++8m+atpOetlueVpemUgeWumuiuvue9ruW8gOWFs++8jOW5tumYsuatouKAnOS7heaLpuaIquW5v+WRiuaooeW8j+KAneWwhuWFtuWFs+mXreOAgiJ9LCJCcmF2ZURlYm91bmNpbmdFbmFibGVkIjp7Im5hbWUiOiLlkK/nlKjpmLLot7Ppk77ph43lrprlkJEgKERlYm91bmNpbmcpIiwiZGVzYyI6IuS/neaMgemYsui3s+mTvuW8gOWQr++8muiHquWKqOi3s+i/h+W3suefpeeahOi/vei4quS4rei9rOi3s+i9rO+8jOebtOaOpeiuv+mXruacgOe7iOebruaghyBVUkzjgIJCcmF2ZSDpu5jorqTlvIDlkK/vvJvmraTnrZbnlaXplIHlrprorr7nva7lvIDlhbPvvIzlubbpmLLmraLigJzku4Xmi6bmiKrlub/lkYrmqKHlvI/igJ3lsIblhbblhbPpl63jgIIifSwiQnJhdmVUcmFja2luZ1F1ZXJ5UGFyYW1ldGVyc0ZpbHRlcmluZ0VuYWJsZWQiOnsibmFtZSI6IuWJpeemu+e9keWdgOi/vei4quWPguaVsCIsImRlc2MiOiJCcmF2ZSDpu5jorqToh6rliqjnp7vpmaQgVVJMIOS4reeahOW3suefpei/vei4quWPguaVsO+8iOWmgiBmYmNsaWTjgIFnY2xpZOOAgW1jX2VpZCDnrYnvvInkuJTml6DmiYvliqjlvIDlhbPvvJvmraTnrZbnlaXlj6/noa7kv53ljbPkvb/lvIDlkK/igJzku4Xmi6bmiKrlub/lkYrmqKHlvI/igJ3kuZ/kv53mjIHliaXnprvjgILpnIDkv53mjIHnm77niYzlvIDlkK/jgIIifSwiQnJhdmVSZWR1Y2VMYW5ndWFnZUVuYWJsZWQiOnsibmFtZSI6IuWHj+WwkeivreiogOaMh+e6ueaatOmcsiIsImRlc2MiOiJCcmF2ZSDpu5jorqTlvIDlkK/vvIzmraTnrZbnlaXnlKjkuo7plIHlrprlvIDlhbPjgILku4XlnKggQWNjZXB0LUxhbmd1YWdlIOivt+axguWktOS4reWQkee9keermeWPkemAgeS9oOeahOmmlumAieivreiogO+8jOW5tuWcqCBXaW5kb3dz44CBbWFjT1Mg5Y+K6YOo5YiGIExpbnV4IOWPkeihjOeJiOS4iuS7heaatOmcsuagh+WHhuWtl+S9k+WIl+ihqOOAgumcgOW8gOWQr+ebvueJjOS4juaMh+e6ueS/neaKpOOAgiJ9LCJXZWJSdGNJUEhhbmRsaW5nIjp7Im5hbWUiOiLpmLLmraIgV2ViUlRDIOazhOmcsuecn+WuniBJUCIsImRlc2MiOiLlsIYgV2ViUlRDIOmZkOWItuS4uuS7heS9v+eUqOS7o+eQhui/nuaOpe+8jOmYsuatoumfs+inhumikemAmuivneWcqOW8gOWQryBWUE4g5oiW5Luj55CG5pe25pq06Zyy5L2g55qE55yf5a6eIElQIOWcsOWdgOOAgiJ9LCJRdWljQWxsb3dlZCI6eyJuYW1lIjoi56aB55SoIFFVSUMgKEhUVFAvMykg5Y2P6K6uIiwiZGVzYyI6IuemgeeUqOe9kemhteivt+axgueahCBRVUlD77yISFRUUC8z77yJ77yM5by65Yi25Zue6YCA6IezIFRDUO+8iEhUVFAvMiDmiJYgSFRUUC8xLjHvvInjgILpgILnlKjkuo7ml6Dms5XlrqHorqEgUVVJQyDmtYHph4/nmoTpmLLngavlopnmiJbov4fmu6Tnjq/looPvvJvlj6/og73nlaXlvq7pmY3kvY7pg6jliIYgR29vZ2xlIOermeeCueWKoOi9vemAn+W6puOAgldlYlJUQyDpgJror53lkowgV2ViVHJhbnNwb3J0IOS7jeS9v+eUqCBVRFDjgIIifSwiTmV0d29ya1ByZWRpY3Rpb25PcHRpb25zIjp7Im5hbWUiOiLnpoHnlKjnvZHnu5zpooTliqDovb3vvIjpooTlj5bvvIkiLCJkZXNjIjoi6Zi75q2iIEJyYXZlIOagueaNrue9keermeeahOaOqOa1i+inhOWImeaIlumihOa4suafk+aPkOekuuaPkOWJjeWKoOi9vee9kemhte+8jOW5tuWBnOatoumihOi/nuaOpeaQnOe0ouW8leaTjuOAgkJyYXZlIOm7mOiupOW3sumHh+eUqOatpOihjOS4uu+8m+atpOetlueVpeeUqOS6jumUgeWumu+8jOmYsuatouiiq+WQjOatpeaIluaJqeWxleaUueWbnuOAgiJ9LCJCbG9ja1RoaXJkUGFydHlDb29raWVzIjp7Im5hbWUiOiLpmLvmraLnrKzkuInmlrkgQ29va2llIiwiZGVzYyI6IkJyYXZlIOm7mOiupOmYu+atouesrOS4ieaWuSBDb29raWXvvJvmraTnrZbnlaXlsIblhbbplIHlrprvvIzpmLLmraLlnKjnm77niYzlhajlsYDorr7nva7kuK3liIflm57igJzlhYHorrjmiYDmnIkgQ29va2ll4oCd5oiW6KKr5omp5bGV44CB5ZCM5q2l5Y+K4oCc5LuF5oum5oiq5bm/5ZGK5qih5byP4oCd5YWz6Zet44CC6ZKI5a+55Y2V5Liq572R56uZ55qE55u+54mM5L6L5aSW77yI5aaC5L+u5aSN5bWM5YWl55m75b2V77yJ5L6d54S25pyJ5pWI44CCIn0sIlBheW1lbnRNZXRob2RRdWVyeUVuYWJsZWQiOnsibmFtZSI6IumYu+atoue9keermeaOoua1i+aUr+S7mOaWueW8jyIsImRlc2MiOiLpmLLmraLnvZHnq5nmjqLnn6XkvaDmmK/lkKbkv53lrZjkuobmlK/ku5jmlrnlvI/vvJrkvb8gY2FuTWFrZVBheW1lbnQoKSDmgZLov5Tlm54geWVz44CBaGFzRW5yb2xsZWRJbnN0cnVtZW50KCkg5oGS6L+U5ZueIG5v77yM5LuO6ICM5LiN5rOE6Zyy5Lu75L2V55yf5a6e54q25oCB44CCIn0sIlJlbW90ZURlYnVnZ2luZ0FsbG93ZWQiOnsibmFtZSI6Iuemgeatoui/nOeoi+iwg+ivleaOpeWPoyIsImRlc2MiOiLlsY/olL3ov5znqIvosIPor5Xnq6/lj6PkuI7nrqHpgZPvvIzpmLLmraLoh6rliqjljJblt6Xlhbfmk43mjqfmtY/op4jlmajlubbor7vlj5bkvaDnmoQgQ29va2llIOS4jueZu+W9leS8muivneOAguKAnOemgeeUqOW8gOWPkeiAheW3peWFt+KAneS4jeWMheWQq+atpOmhueOAguS8muWvvOiHtCBQdXBwZXRlZXLjgIFQbGF5d3JpZ2h0IOWPiiBicmF2ZTovL2luc3BlY3Qg6L+c56iL6LCD6K+V5byA5YWz5LiN5Y+v55So44CC5peg6ZyA6YeN5ZCv5Y2z55Sf5pWI44CCIn0sIkJhc2ljQXV0aE92ZXJIdHRwRW5hYmxlZCI6eyJuYW1lIjoi5Z+656GA6K6k6K+BIChCYXNpYyBBdXRoKSDlvLrliLbkvb/nlKggSFRUUFMiLCJkZXNjIjoi5ouS57ud5Zyo5piO5paHIEhUVFAg6L+e5o6l5LiK5L2/55SoIEhUVFAgQmFzaWMg6K6k6K+B77yM56Gu5L+d6LSm5Y+35a+G56CB5LiN5Lya5Lul5piO5paH5Lyg6L6T44CC5Lya5a+86Ie05LuF5pSv5oyBIEhUVFAg55qE6ICB5pen6Lev55Sx5Zmo44CB5omT5Y2w5py65ZCO5Y+w5Y+K5piO5paHIEhUVFAg5Luj55CG6K6k6K+B5peg5rOV55m75b2V44CCIn0sIkxvY2FsTmV0d29ya0FjY2Vzc0Jsb2NrZWRGb3JVcmxzIjp7Im5hbWUiOiLpmLvmraLlhaznvZHorr/pl67mnKzlnLDlsYDln5/nvZEiLCJkZXNjIjoi56aB5q2i5YWs572R572R56uZ6K6/6Zeu5L2g5bGA5Z+f572R5Lit55qE6K6+5aSH77yI6Lev55Sx5Zmo44CBTkFT44CB5omT5Y2w5py644CB5pm66IO95a625bGF5Lit5p6i77yJ5oiW5pys5py65pyN5Yqh77yM5LiU5LiN5by556qX44CB5LiN5YWB6K645Y2V56uZ5L6L5aSW77yI6buY6K6k5oOF5Ya15LiLIEJyYXZlIOS8muivoumXru+8ieOAguebtOaOpeS7juWxgOWfn+e9keWcsOWdgOaJk+W8gOeahOmhtemdouS4jeWPl+W9seWTjeOAguS8muW9seWTjemcgOmFjeWvueacrOWcsOiuvuWkh+aIluWKqeaJi+eoi+W6j+eahOe9kemhteW6lOeUqOOAgiJ9LCJYU0xURW5hYmxlZCI6eyJuYW1lIjoi56aB55SoIFhTTFQg5byV5pOOIiwiZGVzYyI6IuWFs+mXreaXp+eJiCBYTUwg6L2s5o2i5byV5pOOIFhTTFTvvIhYU0xUUHJvY2Vzc29yIOS4jiB4bWwtc3R5bGVzaGVldO+8ie+8jOi/meaYryBDaHJvbWl1bSDmraPlnKjnp7vpmaTnmoTmlLvlh7vpnaLvvJvljbPkvb/nvZHnq5nkuLvliqjnlLPor7flkK/nlKjkuZ/kvJrkv53mjIHlhbPpl63jgILkvp3otZYgWFNMVCDmoLflvI/nmoQgWE1M77yI5aaC6YOo5YiGIFJTUyDmupDlkoznq5nngrnlnLDlm77vvInlsIbmmL7npLrkuLrml6DmoLflvI/jgILph43lkK/lkI7lrozlhajnlJ/mlYjjgIIifSwiRGVmYXVsdEphdmFTY3JpcHRPcHRpbWl6ZXJTZXR0aW5nIjp7Im5hbWUiOiLnpoHnlKggSmF2YVNjcmlwdCBKSVQg5LyY5YyW77yI5a6J5YWo5Yqg5Zu677yJIiwiZGVzYyI6IuWcqOe9kemhteS4iuWFs+mXrSBWOCDkvJjljJbnvJbor5HlmajvvIhUdXJib0ZhbuOAgU1hZ2xldu+8ie+8jEJyYXZlIOihqOekuui/meiDveaYvuiRl+aPkOmrmOaKl+aUu+WHu+iDveWKm+OAgue9keermeS4jiBXZWJBc3NlbWJseSDku43lj6/ov5DooYzvvIzkvYbph43ohJrmnKzpobXpnaLlkowgV2ViIOW6lOeUqOS8muWPmOaFou+8jOS4lOS4jeaUr+aMgeWNleermeS+i+WkluOAguWvueS/ruaUueWQjuaWsOaJk+W8gOeahOagh+etvumhteeUn+aViOOAgiJ9LCJFeHRlcm5hbFByb3RvY29sRGlhbG9nU2hvd0Fsd2F5c09wZW5DaGVja2JveCI6eyJuYW1lIjoi56e76Zmk5aSW6YOo5bqU55So5ZCv5Yqo5o+Q56S655qE4oCc5aeL57uI5YWB6K644oCdIiwiZGVzYyI6IuS7jue9keermeWUpOi1t+WklumDqOW6lOeUqOWJjeeahOehruiupOW8ueeql+S4reenu+mZpOKAnOWni+e7iOWFgeiuuOKAneWkjemAieahhu+8jOS9v+avj+asoei3s+i9rO+8iOWmgiBtYWlsdG8644CBWm9vbeOAgVRlYW1z44CBU3RlYW3jgIFtcy0qIOmTvuaOpe+8iemDvemcgOaJi+WKqOeCueWHu+ehruiupOOAguatpOWJjeW3suiuvuS4uuWni+e7iOaJk+W8gOeahOW6lOeUqOS4jeWPl+W9seWTjeOAgiJ9LCJTaXRlUGVyUHJvY2VzcyI6eyJuYW1lIjoi5by65Yi25Li65q+P5Liq572R56uZ5ZCv55So56uZ54K56ZqU56a7IiwiZGVzYyI6IuehruS/neavj+S4que9keermei/kOihjOWcqOeLrOeri+i/m+eoi+S4re+8iEJyYXZlIOahjOmdoueJiOm7mOiupOWmguatpO+8ie+8jOW5tumYu+atoumAmui/hyBicmF2ZTovL2ZsYWdzI3NpdGUtaXNvbGF0aW9uLXRyaWFsLW9wdC1vdXQg5oiWIC0tZGlzYWJsZS1zaXRlLWlzb2xhdGlvbi10cmlhbHMg5bCG5YW25YWz6Zet44CC6YeN5ZCv5ZCO55Sf5pWI44CCIn0sIk9yaWdpbktleWVkUHJvY2Vzc2VzRW5hYmxlZCI6eyJuYW1lIjoi5Li65LiN5ZCM5a2Q5Z+f5ZCN5ZCv55So54us56uL6L+b56iL6ZqU56a7IiwiZGVzYyI6IuWwhuavj+S4qua6kO+8iOS+i+WmgiBtYWlsLmV4YW1wbGUuY29tIOS4jiBkb2NzLmV4YW1wbGUuY29t77yJ6ZqU56a75Zyo5ZCE6Ieq6L+b56iL5Lit77yM6ICM6Z2e5oyJ5Li75Z+f5ZCN5YWx5Lqr77yM5Lul5pu05by65Yqb5Zyw6Ziy5b6h5a2Q5Z+f5ZCN6Ze055qEIFNwZWN0cmUg57G75L6n5L+h6YGT5rOE6Zyy44CC5Lya5aKe5Yqg6L+b56iL5pWw5LiO5YaF5a2Y5Y2g55So44CC6YeN5ZCv5ZCO55Sf5pWI77yM5L2G5Y+v6KKrIGJyYXZlOi8vZmxhZ3Mg6KaG55uW44CCIn0sIkR5bmFtaWNDb2RlU2V0dGluZ3MiOnsibmFtZSI6IumYu+atoua1j+iniOWZqOS4u+i/m+eoi+eUn+aIkOWKqOaAgeS7o+eggSAoQUNHKSIsImRlc2MiOiLnpoHmraIgQnJhdmUg5Li76L+b56iL5Yib5bu65oiW5L+u5pS55Y+v5omn6KGM5YaF5a2Y77yI5Lu75oSP5Luj56CB6Ziy5oqkIEFDR++8ie+8jOWPr+acieaViOmYu+aWrei/m+eoi+azqOWFpeeahCBTaGVsbGNvZGUg5LiO5Luj56CB5oyC6ZKp44CC6YOo5YiG5ZCR5rWP6KeI5Zmo5rOo5YWlIERMTCDnmoTmnYDmr5Lova/ku7bjgIHmiZPljbDmnLrpqbHliqjmiJbovpPlhaXms5Xlj6/og73lvILluLjmiJblr7zoh7TltKnmuoPvvIzlpoLpgYfpl67popjor7flj5bmtojli77pgInjgIIifSwiRGVmYXVsdE5vdGlmaWNhdGlvbnNTZXR0aW5nIjp7Im5hbWUiOiLnvZHpobXmoYzpnaLpgJrnn6UiLCJkZXNjIjoi6K6+572u572R56uZ5qGM6Z2i6YCa55+l55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya56aB5q2i5omA5pyJ572R56uZ6K+35rGC5oiW5by55Ye66YCa55+l77yb4oCc5YWB6K644oCd5YiZ5YWo6YOo5pS+6KGM77yM5LqM6ICF5Z2H5Lya6KaG55uW5L2g55qE5Y2V56uZ6K6+572u44CC4oCc5LiN566h55CG4oCd5L+d55WZIEJyYXZlIOm7mOiupOivoumXru+8iOaJmOeuoeetlueVpeS4i+eahOKAnOivoumXruKAneS8muWvvOiHtOS7u+S9lemAmuefpemDveaXoOazlemAgei+vu+8ieOAgiJ9LCJEZWZhdWx0R2VvbG9jYXRpb25TZXR0aW5nIjp7Im5hbWUiOiLlnLDnkIbkvY3nva7mnYPpmZAiLCJkZXNjIjoi6K6+572u572R56uZ6K+75Y+W54mp55CG5L2N572u55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya55u05o6l6ZqQ6JeP5o+Q56S677yI5Zyw5Zu+5LiO5aSW5Y2W572R56uZ6ZyA5omL5Yqo6L6T5YWl5Zyw5Z2A77yJ77yb4oCc6K+i6Zeu4oCd5q+P5qyh6YO95Lya5by556qX5LiU5LiN6K6w5L2P6YCJ5oup44CC5Lu75oSP6Z2e4oCc5LiN566h55CG4oCd6YCJ6aG56YO95Lya6KaG55uW5Y2V56uZ6K6+572u44CCIn0sIkRlZmF1bHRTZW5zb3JzU2V0dGluZyI6eyJuYW1lIjoi6L+Q5Yqo5LiO5pa55ZCR5Lyg5oSf5ZmoIiwiZGVzYyI6Iui/kOWKqOS4juaWueWQkeS8oOaEn+WZqOW4uOiiq+eUqOS6juiuvuWkh+aMh+e6uei/vei4qu+8jEJyYXZlIOm7mOiupOW3sumYu+atouOAguKAnOmYu+atouKAneS8mumUgeWumuivpeihjOS4uu+8jOiuvue9rumhteS4juW3suacieWNleermeS+i+WklumDveaXoOazleaUvuihjO+8m+mAieaLqeKAnOivoumXruKAneaIluKAnOWFgeiuuOKAneWImeS8muaUvuWuvem7mOiupOS/neaKpOOAgiJ9LCJEZWZhdWx0V2ViVXNiR3VhcmRTZXR0aW5nIjp7Im5hbWUiOiJXZWJVU0Ig6K6+5aSH6K6/6ZeuIiwiZGVzYyI6Iuiuvue9rue9keermeiuv+mXriBVU0Ig6K6+5aSH55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya56e76Zmk5o+Q56S677yM5a+86Ie0572R6aG154mI56Gs5Lu26ZKx5YyF77yITGVkZ2Vy44CBVHJlem9y77yJ5ZKM5Zyo57q/5Zu65Lu25Yi35YaZ5bel5YW35LiN5Y+v55So77yb4oCc6K+i6Zeu4oCd5L+d55WZ5by556qX44CCQ2hyb21pdW0g5q2k6aG55LiN5o+Q5L6b4oCc5YWB6K644oCd44CCIn0sIkRlZmF1bHRTZXJpYWxHdWFyZFNldHRpbmciOnsibmFtZSI6IldlYiBTZXJpYWwg5Liy5Y+j6K6/6ZeuIiwiZGVzYyI6Iuiuvue9rue9keermeaJk+W8gOS4suWPo+eahOm7mOiupOetlueVpeOAguKAnOmYu+atouKAneS8muenu+mZpOaPkOekuu+8jOWvvOiHtOe9kemhteerr+WNleeJh+acuueDp+W9leS4juehrOS7tuiwg+ivleW3peWFt+S4jeWPr+eUqO+8m+KAnOivoumXruKAneS/neeVmeW8ueeql+OAgkNocm9taXVtIOatpOmhueS4jeaPkOS+m+KAnOWFgeiuuOKAneOAgiJ9LCJEZWZhdWx0V2ViSGlkR3VhcmRTZXR0aW5nIjp7Im5hbWUiOiJXZWJISUQg5Lq65py65o6l5Y+j6K6+5aSH6K6/6ZeuIiwiZGVzYyI6Iuiuvue9rue9keermeiuv+mXriBISUQg6K6+5aSH55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya56e76Zmk5o+Q56S677yM5pat5byAIEJyYXZlIOmSseWMheWvuSBMZWRnZXIg56Gs5Lu26ZKx5YyF55qE6L+e5o6l77yM5bm25Y+v6IO95b2x5ZON5L6d6LWWIFdlYkhJRO+8iOmdniBXZWJBdXRobu+8ieeahOWuieWFqOWvhumSpeS4juaJi+afhOmFjee9ruW3peWFt+OAgkNocm9taXVtIOatpOmhueS4jeaPkOS+m+KAnOWFgeiuuOKAneOAgiJ9LCJEZWZhdWx0TG9jYWxGb250c1NldHRpbmciOnsibmFtZSI6IuacrOWcsOWtl+S9k+aemuS4vuadg+mZkCIsImRlc2MiOiLorr7nva7nvZHnq5nmn6Xor6LmnKzmnLrlt7Llronoo4XlrZfkvZPliJfooajnmoTpu5jorqTnrZbnlaXigJTigJTov5nmmK/nm77niYzlrZfkvZPkv53miqTmnKrog73opobnm5bnmoTlvLrmjIfnurnnibnlvoHjgILpmaTlnKjnur/orr7orqHlt6XlhbflpJbvvIzigJzpmLvmraLigJ3lvojlsJHlvbHlk43mraPluLjmtY/op4jjgIJDaHJvbWl1bSDmraTpobnkuI3mj5DkvpvigJzlhYHorrjigJ3jgIIifSwiRGVmYXVsdFdpbmRvd01hbmFnZW1lbnRTZXR0aW5nIjp7Im5hbWUiOiLlpJrlsY/luZXnqpflj6PnrqHnkIbmnYPpmZAiLCJkZXNjIjoi6K6+572u572R56uZ6K+75Y+W5aSa5pi+56S65Zmo5biD5bGA5Y+K5Zyo5oyH5a6a5bGP5bmV5pS+572u56qX5Y+j55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya5b2x5ZON6YOo5YiG572R6aG15bqU55So55qE5YWo5bGP5ryU56S65qih5byP44CCQ2hyb21pdW0g5q2k6aG55LiN5o+Q5L6b4oCc5YWB6K644oCd44CCIn0sIkRlZmF1bHRDbGlwYm9hcmRTZXR0aW5nIjp7Im5hbWUiOiLliarotLTmnb/or7vlj5bmnYPpmZAiLCJkZXNjIjoi6K6+572u572R56uZ5Zyo5L2g5pyq5omn6KGM57KY6LS05pe25Li75Yqo6K+75Y+W5Ymq6LS05p2/55qE6buY6K6k562W55Wl44CC4oCc6Zi75q2i4oCd5Lya56e76Zmk5o+Q56S65bm25L2/572R6aG15YaF572u4oCc57KY6LS04oCd5oyJ6ZKu5aSx5pWI77yb4oCc6K+i6Zeu4oCd5L+d55WZ5by556qX44CC5LqM6ICF5Z2H6KaG55uW5pei5pyJ5Y2V56uZ5YWB6K6444CCQ3RybCtWIOS4juWkjeWItuaMiemSruS7jeato+W4uOOAgkNocm9taXVtIOatpOmhueS4jeaPkOS+m+KAnOWFgeiuuOKAneOAgiJ9LCJBdWRpb0NhcHR1cmVBbGxvd2VkIjp7Im5hbWUiOiLlhajlsYDnpoHmraLpuqblhYvpo47orr/pl64iLCJkZXNjIjoi56aB5q2i5omA5pyJ572R56uZ5ZKM5omp5bGV5L2/55So6bqm5YWL6aOO5oiW5Lu75L2V6Z+z6aKR6L6T5YWl6K6+5aSH5LiU5LiN5by556qX77yM5bey6K6+572u55qE5Y2V56uZ4oCc5YWB6K644oCd5Lmf5Lya5aSx5pWI44CC5Lya5a+86Ie0572R6aG15Lya6K6u77yITWVldOOAgVpvb23jgIFUZWFtc+OAgURpc2NvcmTjgIFCcmF2ZSBUYWxr77yJ44CB6K+t6Z+z5raI5oGv5ZKM6K+t6Z+z5ZCs5YaZ5LiN5Y+v55So44CCIn0sIlZpZGVvQ2FwdHVyZUFsbG93ZWQiOnsibmFtZSI6IuWFqOWxgOemgeatouaRhOWDj+WktOiuv+mXriIsImRlc2MiOiLnpoHmraLmiYDmnInnvZHnq5nlkozmianlsZXkvb/nlKjmkYTlg4/lpLTmiJbku7vkvZXop4bpopHovpPlhaXorr7lpIfkuJTkuI3lvLnnqpfvvIzlt7Lorr7nva7nmoTljZXnq5nigJzlhYHorrjigJ3kuZ/kvJrlpLHmlYjjgILkvJrlr7zoh7TnvZHpobXop4bpopHpgJror53jgIHmkYTlg4/lpLTkurrohLjmoLjpqozlj4rnvZHpobXkuoznu7TnoIHmiavmj4/kuI3lj6/nlKjjgIIifSwiRm9yY2VHb29nbGVTYWZlU2VhcmNoIjp7Im5hbWUiOiLlvLrliLblvIDlkK8gR29vZ2xlIOWuieWFqOaQnOe0oiIsImRlc2MiOiLkuLrmiYDmnIkgR29vZ2xlIOaQnOe0ouW8uuWItuWQr+eUqOWuieWFqOaQnOe0oui/h+a7pO+8jOS4u+imgeeUqOS6juWutumVv+aOp+WItuWcuuaZr+OAgiJ9LCJGb3JjZVlvdVR1YmVSZXN0cmljdCI6eyJuYW1lIjoi5by65Yi25byA5ZCvIFlvdVR1YmUg5Lil5qC85Y+X6ZmQ5qih5byPIiwiZGVzYyI6IuWcqCB5b3V0dWJlLmNvbSDlj4rlhbblm73lrrbln5/lkI3vvIjlkKvlhbbku5bnvZHnq5nltYzlhaXnmoTop4bpopHvvInkuIrlvLrliLblvIDlkK/kuKXmoLzlj5fpmZDmqKHlvI/vvIznlKjmiLfml6Dms5XlhbPpl63jgILlpKfph4/op4bpopHlsIbkuI3lj6/mkq3mlL7kuJTor4TorrrljLrkvJrooqvpmpDol4/jgILpgJrov4cgeW91dHViZS1ub2Nvb2tpZS5jb20g5bWM5YWl55qE6KeG6aKR5LiN5Y+X6ZmQ5Yi244CCIn0sIlNhZmVCcm93c2luZ1Byb3RlY3Rpb25MZXZlbDoxIjp7Im5hbWUiOiLplIHlrprlvIDlkK/lronlhajmtY/op4jvvIjmoIflh4bkv53miqTvvIkiLCJkZXNjIjoi5bCG5a6J5YWo5rWP6KeI6ZSB5a6a5Li64oCc5qCH5YeG5L+d5oqk4oCd77yM56aB5q2i5ZyoIGJyYXZlOi8vc2V0dGluZ3Mvc2VjdXJpdHkg5Lit5YiH5Li64oCc5peg5L+d5oqk4oCd44CC5p+l6K+i54Wn5bi457uP55SxIEJyYXZlIOS7o+eQhuOAguS4juKAnOemgeeUqOWuieWFqOa1j+iniOKAneS6kuaWpeOAgiJ9LCJEaXNhYmxlU2FmZUJyb3dzaW5nUHJvY2VlZEFueXdheSI6eyJuYW1lIjoi56aB5q2i57uV6L+H5a6J5YWo5rWP6KeI6K2m5ZGKIiwiZGVzYyI6Iuenu+mZpOaBtuaEj+i9r+S7tuS4jumSk+mxvOitpuWRiumhteS4reeahOKAnOS7jeeEtuiuv+mXruKAnemAiemhue+8jOiiq+agh+iusOeahOe9keerme+8iOWQq+ivr+aKpe+8ieWwhuWujOWFqOaXoOazleaJk+W8gOOAguS4jeW9seWTjeivgeS5puitpuWRiuaIluS4i+i9veitpuWRiuOAguiLpeWuieWFqOa1j+iniOW3suWFs+mXreWImeacrOmhueaXoOaViO+8jOWPr+mFjeWQiOKAnOmUgeWumuW8gOWQr+WuieWFqOa1j+iniOKAneS9v+eUqOOAgiJ9LCJTU0xFcnJvck92ZXJyaWRlQWxsb3dlZCI6eyJuYW1lIjoi56aB5q2i57uV6L+HIEhUVFBTIOivgeS5puitpuWRiiIsImRlc2MiOiLku47or4HkuabplJnor6/pobXnp7vpmaTigJznu6fnu63liY3lvoDigJ3pk77mjqXlj4rplK7nm5jmmpfnoIHnu5Xov4fvvIzor4Hkuabml6DmlYjjgIHov4fmnJ/miJboh6rnrb7lkI3nmoTnq5nngrnlsIblrozlhajml6Dms5XmiZPlvIDjgILkvJrlr7zoh7Tkvb/nlKjoh6rnrb7lkI3or4HkuabnmoTot6/nlLHlmajjgIFOQVPjgIHmiZPljbDmnLrlkI7lj7Dlj4rmnKzlnLDlvIDlj5HmnI3liqHlmajml6Dms5Xorr/pl67jgIIifSwiQnJvd3Nlckd1ZXN0TW9kZUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOiuv+WuouaooeW8jyIsImRlc2MiOiLnp7vpmaTkuI3kv53lrZjljoblj7LkuJTkuI3liqDovb3kuKrkurrphY3nva7mianlsZXnmoTorr/lrqLmtY/op4jnqpflj6PjgILigJznpoHnlKjml6Dnl5XmqKHlvI/igJ3kuI3kvJrnp7vpmaTorr/lrqLmqKHlvI/jgILmiZjnrqHnrZbnlaXlnKjorr/lrqLnqpflj6PkuK3lkIzmoLfnlJ/mlYjjgIIifSwiQWxsb3dEZWxldGluZ0Jyb3dzZXJIaXN0b3J5Ijp7Im5hbWUiOiLnpoHmraLliKDpmaTmtY/op4jkuI7kuIvovb3ljoblj7IiLCJkZXNjIjoi6Zi75q2i5Zyo5Y6G5Y+y6K6w5b2V44CB5LiL6L296K6w5b2V5oiW5riF6Zmk5rWP6KeI5pWw5o2u5Lit5Yig6Zmk5Y6G5Y+y77yM6YCA5Ye65pe25riF6Zmk5Yqf6IO95Lmf5Lya5L+d55WZ5Y6G5Y+y44CC5L2GIGJyYXZlOi8vc2V0dGluZ3MvcHJpdmFjeSDkuK3nmoTigJzmnKzlnLDljoblj7Lkv53nlZnmnJ/pmZDigJ3ku43lj6/orr7kuLrmnIDnn63kuIDlpKnoh6rliqjov4fmnJ/vvIxTbGltQnJhdmUg5peg5rOV6ZSB5a6a6K+l6aG544CCIn0sIkV4dGVuc2lvbkluc3RhbGxCbG9ja2xpc3QiOnsibmFtZSI6IuemgeatouWuieijheW5tuWBnOeUqOWFqOmDqOaJqeWxlSIsImRlc2MiOiLnpoHmraLlronoo4Xku7vkvZXmlrDmianlsZXvvIzlubblgZznlKjmiYDmnInlt7Llronoo4XmianlsZXjgILpgILlkIjplIHlrprnu4jnq6/miJblrrbplb/mjqfliLblnLrmma/igJTigJTpmLLmraLpgJrov4fku6PnkIYvVlBOIOaJqeWxlee7lei/hyBETlMg6L+H5ruk44CCIn0sIkJsb2NrRXh0ZXJuYWxFeHRlbnNpb25zIjp7Im5hbWUiOiLpmLvmraLlpJbpg6jpnZnpu5jkvqfovb3mianlsZUiLCJkZXNjIjoi6Zi75q2i5YW25LuW56iL5bqP6YCa6L+HIFdpbmRvd3Mg5rOo5YaM6KGo5oiW5aSW6YOo6JC955uY5paH5Lu26Z2Z6buY5rOo5YWl5omp5bGV77yI5o2G57uR6L2v5Lu25bi455So5omL5q6177yJ77yM5bm25Zyo5LiL5qyh5ZCv5Yqo5pe256e76Zmk5bey6YCa6L+H6K+l6YCU5b6E5re75Yqg55qE5omp5bGV77yI5Y2z5L2/5L2g5pu+5ZCM5oSP77yJ44CC5L2g6Ieq5bex5Li75Yqo5a6J6KOF55qE5omp5bGV5LiN5Y+X5b2x5ZON44CCIn0sIkV4dGVuc2lvbkluc3RhbGxUeXBlQmxvY2tsaXN0Ijp7Im5hbWUiOiLpmLvmraLlkb3ku6TooYzliqDovb3mianlsZUgKC0tbG9hZC1leHRlbnNpb24pIiwiZGVzYyI6IuW/veeVpemAmui/hyAtLWxvYWQtZXh0ZW5zaW9uIOWPguaVsOS8oOWFpeeahOaJqeWxle+8iOaBtuaEj+i9r+S7tuW4uOevoeaUueW/q+aNt+aWueW8j+WAn+atpOakjeWFpeaJqeWxle+8ieOAgkdvb2dsZSBDaHJvbWUg6buY6K6k5b+955Wl6K+l5Y+C5pWw77yM6ICMIEJyYXZlIOm7mOiupOWFgeiuuOmZpOmdnuWQr+eUqOatpOetlueVpeOAgi0tZGlzYWJsZS1leHRlbnNpb25zLWV4Y2VwdCDku43lj6/liqDovb3jgILkvJrlvbHlk43kvp3otZbor6Xlj4LmlbDnmoTlv6vmjbfmlrnlvI/lkozmtYvor5Xlt6XlhbfjgILpnIDph43lkK/nlJ/mlYjjgIIifSwiSW5jb2duaXRvTW9kZUF2YWlsYWJpbGl0eToxIjp7Im5hbWUiOiLnpoHnlKjml6Dnl5XmqKHlvI8iLCJkZXNjIjoi5b275bqV56e76Zmk6ZqQ56eB5rWP6KeI5Yqf6IO977yM5peg5rOV5YaN5omT5byA5peg55eV56qX5Y+j44CC5LiO4oCc5by65Yi25YWo56iL5peg55eV5qih5byP4oCd5LqS5pal44CCIn0sIkluY29nbml0b01vZGVBdmFpbGFiaWxpdHk6MiI6eyJuYW1lIjoi5by65Yi25YWo56iL5peg55eV5qih5byPIiwiZGVzYyI6IuaJgOacieeql+WPo+Wdh+S7peaXoOeXleaooeW8j+aJk+W8gO+8muS4jeS/neWtmOWOhuWPsu+8jOeZu+W9leaAgeWSjOWkmuaVsOaJqeWxleS4jeS8muaMgeS5heWMluOAglRvciDnqpflj6PjgIFMZW8g5LiOIEJyYXZlIFJld2FyZHMg5Lmf5Lya6ZqP5LmL5raI5aSx77yMQnJhdmUg6ZKx5YyF6Zmk6Z2e5YWB6K645Zyo6ZqQ56eB56qX5Y+j6L+Q6KGM5ZCm5YiZ5ZCM5qC35YGc55So44CC5LiO4oCc56aB55So5peg55eV5qih5byP4oCd5LqS5pal44CCIn0sIkJyYXZlUmV3YXJkc0Rpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUgUmV3YXJkc++8iOWlluWKseS4juW5v+WRiu+8iSIsImRlc2MiOiLnp7vpmaQgQnJhdmUgUmV3YXJkcyDlubblhbPpl60gQnJhdmUg5bm/5ZGK5pyN5Yqh77yM5LiN5YaN5pi+56S65paw5qCH562+6aG16LWe5Yqp5aOB57q45oiW6YCa55+l5bm/5ZGK44CCQnJhdmUgU2VhcmNoIOaQnOe0oue7k+aenOW5v+WRiuS4jeWPl+W9seWTje+8m+mZpOmdnuWQjOaXtuWQr+eUqOmZkOWIti/npoHnlKjkupHnq6/lrp7pqozvvIzlkI7lj7Dku43kvJrljL/lkI3mi4nlj5blub/lkYrliqDlr4blr4bpkqXjgIIifSwiQnJhdmVXYWxsZXREaXNhYmxlZCI6eyJuYW1lIjoi56aB55SoIEJyYXZlIOmSseWMhSIsImRlc2MiOiLnpoHnlKjlhoXnva7liqDlr4botKfluIHpkrHljIXlubbpmpDol4/lhbblhajpg6jnlYzpnaLlhaXlj6PjgIIifSwiQnJhdmVWUE5EaXNhYmxlZCI6eyJuYW1lIjoi56aB55SoIEJyYXZlIFZQTu+8iExpbnV4IOeJiOaXoOaViO+8iSIsImRlc2MiOiLnp7vpmaQgQnJhdmUgVlBOIOWKn+iDveWPiuWFtuaOqOW5v+aPkOekuuOAgkxpbnV4IOeJiOacrOi6q+S4jeWMheWQqyBWUE7vvIzlm6DmraTor6XnrZbnlaXlnKggTGludXgg5LiK5peg5pWI5p6c44CCIn0sIkJyYXZlQUlDaGF0RW5hYmxlZCI6eyJuYW1lIjoi56aB55SoIEJyYXZlIEFJIOiBiuWkqSAoTGVvKSIsImRlc2MiOiLnpoHnlKjlhoXnva4gQUkg5Yqp5omLIExlb++8jOW5tuWwhuWFtuS7juS+p+i+ueagj+WSjOWcsOWdgOagj+enu+mZpOOAgkJyYXZlIOS7jeS8muS4i+i9vSBMZW8g55qEIFdlYk1DUCDlt6XlhbfohJrmnKznu4Tku7bvvIzkvYblnKggTGVvIOWFs+mXreacn+mXtOS4jeS8muiiq+iwg+eUqOOAgiJ9LCJCcmF2ZUxvY2FsQUlFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjmnKzlnLAgQUkg5qih5Z6L77yIQnJhdmUgMS45NCvvvIzmraPlvI/niYjpu5jorqTlhbPpl63vvIkiLCJkZXNjIjoi6Zi75q2iIEJyYXZlIOS4i+i9veWSjOi/kOihjOerr+S+pyBBSSDmqKHlnovvvIzlubbnpoHmraLlr7nmtY/op4jljoblj7Llu7rnq4sgQUkg57Si5byV77yb5LuF56aB55SoIExlbyDml6Dms5Xopobnm5bmraTpobnjgIJSZWxlYXNlIOm7mOiupOWFs+mXre+8iE5pZ2h0bHkvQmV0YSDpu5jorqTlvIDlkK/vvInvvIzmraTnrZbnlaXlj6/pmLLmraLmnKrmnaXooqvoh6rliqjmiJbor6/lvIDlkK/jgILph43lkK/lkI7nlJ/mlYjjgIIifSwiQnJhdmVTaGllbGRzRGlzYWJsZWRGb3JVcmxzIjp7Im5hbWUiOiLlhajlsYDnpoHnlKggQnJhdmUg55u+54mM77yI5LuF6ZmQ5rWL6K+VL+S/oeaBr+S6re+8iSIsImRlc2MiOiLku4XpmZDmtYvor5XmiJbkv6Hmga/kuq3lnLrmma/jgILlr7nmiYDmnInnvZHnq5nlhbPpl63nm77niYzvvJrlgZzmraLlub/lkYrkuI7ov73ouKrmi6bmiKrvvIzigJznm77niYzkuI7lhoXlrrnkv53miqTigJ3kuIvnmoTmnaHnm67jgIHliaXnprvov73ouKrlj4LmlbDlkozlh4/lsJHor63oqIDmjIfnurnpg73lsIblpLHmlYjjgIJEZS1BTVDjgIHpmLLot7Ppk77jgIFHUEMg5LiO56ys5LiJ5pa5IENvb2tpZSDpmLvmraLku43mnInmlYjjgILkuI7igJzlvLrliLbmiYDmnInnvZHnq5nlvIDlkK/nm77niYzigJ3kupLmlqXjgIIifSwiQnJhdmVTaGllbGRzRW5hYmxlZEZvclVybHMiOnsibmFtZSI6IuW8uuWItuaJgOaciee9keermeW8gOWQryBCcmF2ZSDnm77niYwiLCJkZXNjIjoi5Li65omA5pyJ572R56uZ6ZSB5a6a5byA5ZCv55u+54mM77ya5Y2V56uZ5byA5YWz5LiN5YaN6IO95YWz6Zet5bm/5ZGK44CB6L+96Liq5Zmo5oiW5oyH57q55L+d5oqk77yM5L2G5bCG5YW25YiH5Li65YWz6Zet5pe25LuN5Lya5pS+6KGM6K+l572R56uZ55qE56ys5LiJ5pa5IENvb2tpZSDlkozlrZjlgqjjgILkuI7igJzlhajlsYDnpoHnlKggQnJhdmUg55u+54mM4oCd5LqS5pal44CCIn0sIkJyYXZlTmV3c0Rpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUg5paw6Ze7IiwiZGVzYyI6IuS7juaWsOagh+etvumhteenu+mZpCBCcmF2ZSDmlrDpl7votYTorq/mtYHjgILoi6XphY3nva7lnKjpppbmrKHov5DooYzml7bmm77lkK/nlKjov4fmlrDpl7vvvIzkvqfovrnmoI/lj6/og73ku43mrovnlZnmlrDpl7vlm77moIfvvIjngrnlh7vlkI7ku4XmmL7npLrnqbrnmb3pnaLmnb/vvInjgIIifSwiQnJhdmVUYWxrRGlzYWJsZWQiOnsibmFtZSI6IuemgeeUqCBCcmF2ZSBUYWxrIOinhumikemAmuivnSIsImRlc2MiOiLku47mlrDmoIfnrb7pobXjgIHkvqfovrnmoI/lkozoj5zljZXkuK3pmpDol48gQnJhdmUgVGFsa++8iOengeWvhuinhumikemAmuivne+8ieWFpeWPo+OAguebtOaOpeiuv+mXriB0YWxrLmJyYXZlLmNvbSDnvZHnq5nku43lj6/kvb/nlKjjgIIifSwiQnJhdmVQbGF5bGlzdEVuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBCcmF2ZSDmkq3mlL7liJfooajvvIjmraPlvI/niYjpu5jorqTlhbPpl63vvIkiLCJkZXNjIjoi56aB55So55So5LqO5Zyo5L6n6L655qCP5L+d5a2Y5ZKM5pKt5pS+6Z+z6KeG6aKR55qE5pKt5pS+5YiX6KGo5Yqf6IO944CCUmVsZWFzZSDlkowgQmV0YSDpu5jorqTlhbPpl63vvIhOaWdodGx5IOm7mOiupOW8gOWQr++8ie+8m+atpOetlueVpeWPr+ehruS/neWFtuaMgee7reS/neaMgeWFs+mXreOAgiJ9LCJCcmF2ZVdlYkRpc2NvdmVyeUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBXZWIg5Y+R546w6aG555uuIChXZWIgRGlzY292ZXJ5KSIsImRlc2MiOiLlgZzmraIgQnJhdmUg5bCG5L2g6K6/6Zeu55qE572R6aG15Yy/5ZCN6LSh54yu57uZIEJyYXZlIFNlYXJjaCDmkJzntKLlvJXmk47ntKLlvJXvvIhXZWIgRGlzY292ZXJ5IFByb2plY3TvvInjgIIifSwiQnJhdmVTcGVlZHJlYWRlckVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOaegemAn+mYheivu+aooeW8jyAoU3BlZWRyZWFkZXIpIiwiZGVzYyI6IuemgeeUqOaXoOW5suaJsOaWh+eroOeyvueugOmYheivu+aooeW8jyBTcGVlZHJlYWRlcuOAgiJ9LCJUb3JEaXNhYmxlZCI6eyJuYW1lIjoi56aB55SoIFRvciDpmpDnp4Hnqpflj6MiLCJkZXNjIjoi56e76Zmk4oCc5paw5bu65L2/55SoIFRvciDnmoTpmpDnp4Hnqpflj6PigJ3lip/og73lhaXlj6PjgIIifSwiU3luY0Rpc2FibGVkIjp7Im5hbWUiOiLnpoHnlKggQnJhdmUg5ZCM5q2lIiwiZGVzYyI6IuemgeeUqOmAmui/h+WQjOatpemTvui3qOiuvuWkh+WQjOatpeS5puetvuOAgeWOhuWPsuWSjOiuvue9rueahCBCcmF2ZSBTeW5j44CC5bqU55So5ZCO5Lmf5Lya5bCG5pys6K6+5aSH56e75Ye65b2T5YmN5ZCM5q2l6ZO+77yM5bCG5p2l6Kej6Zmk562W55Wl5ZCO6ZyA5L2/55So5YW25LuW6K6+5aSH55qE5ZCM5q2l56CB6YeN5paw5Yqg5YWl44CCIn0sIkVtYWlsQWxpYXNlc0VuYWJsZWQiOnsibmFtZSI6IuemgeeUqOmCrueuseWIq+WQjeWKn+iDvSIsImRlc2MiOiLnpoHnlKjlvZPliY0gQnJhdmUg54mI5pys6buY6K6k5byA5ZCv55qE5LiA5qyh5oCn6YKu566x5Yir5ZCN55Sf5oiQ5Yqf6IO944CCIn0sIkRlZmF1bHRCcmF2ZUFkYmxvY2tTZXR0aW5nIjp7Im5hbWUiOiLlvLrliLblkK/nlKjlub/lkYrkuI7ov73ouKrmi6bmiKoiLCJkZXNjIjoi5bCGIEJyYXZlIOe9kee7nOWxguW5v+WRiuS4jui/vei4quWZqOaLpuaIqumUgeWumuS4uuaJmOeuoeetlueVpe+8jOaXoOazleWcqOiuvue9ruS4reaIlumSiOWvueWNleermemZjeS9juetiee6p+OAguWFg+e0oOmakOiXj+S4juiEmuacrOazqOWFpeetieWkluingui/h+a7pOS4jeiiq+mUgeWumu+8jOW3suWFs+mXreebvueJjOeahOe9keermeS4jeWPl+imhuebluOAgiJ9LCJEZWZhdWx0QnJhdmVGaW5nZXJwcmludGluZ1YyU2V0dGluZyI6eyJuYW1lIjoi5by65Yi25ZCv55So5oyH57q56Ziy5oqkIiwiZGVzYyI6IuWwhuebvueJjOaMh+e6uemYsuaKpOmUgeWumuS4uuaJmOeuoeetlueVpe+8jOaXoOazlemSiOWvueWNleS4que9keermeWFs+mXreOAguWNlSBBUEkg5YW85a655oCn5L6L5aSW77yIQnJhdmUg5YW85a655YiX6KGo5oiW6Ieq5a6a5LmJ55u+54mM6aG577yJ5LuN55Sf5pWI77yM5bey5YWz6Zet55u+54mM55qE572R56uZ5LiN5Y+X6KaG55uW44CCIn0sIkRlZmF1bHRCcmF2ZUh0dHBzVXBncmFkZVNldHRpbmciOnsibmFtZSI6IuW8uuWItuS4peagvCBIVFRQUyDljYfnuqciLCJkZXNjIjoi5aeL57uI5bCG6L+e5o6l5Y2H57qn5Li6IEhUVFBT77yb5LiN5pSv5oyBIEhUVFBTIOeahOe9keermeWwhuW8ueWHuuitpuWRiuiAjOS4jeS8muiHquWKqOWbnumAgOiHsyBIVFRQ44CC5ZyoIEJyYXZlIOW3suWIh+aNouS4uiBDaHJvbWl1bSBIVFRQUy1GaXJzdCDmqKHlvI/nmoTmuKDpgZPvvIhCZXRh44CBTmlnaHRseSDlj4rpg6jliIYgUmVsZWFzZe+8ieS4iuS7heS9nOS4gOasoeaAp+mihOiuvuiAjOmdnuW8uuWItu+8m+mFjeWQiOmZkOWItuaIluemgeeUqOS6keerr+WunumqjOWPr+S/neaMgeW8uuWItueUn+aViOOAgiJ9LCJEZWZhdWx0QnJhdmVSZWZlcnJlcnNTZXR0aW5nOjIiOnsibmFtZSI6IumZkOWItuadpea6kOWktOS7heWPkemAgeS4u+a6kCAoU3RyaWN0IE9yaWdpbikiLCJkZXNjIjoi6Leo5rqQ6K+35rGC5pe25bCGIFJlZmVyZXIg5oiq5pat5Li65LuF5YyF5ZCr5Li75rqQ77yIQnJhdmUg6buY6K6k6KGM5Li677yJ5bm26ZSB5a6a77ya5omA5pyJ5Y2V56uZ5L6L5aSW77yI5YyF5ousIEJyYXZlIOS4uuS/ruWkjeermeeCueWGhee9rueahOWFvOWuueS+i+Wklu+8ieWwhuWkseaViOOAguS4juKAnOWFgeiuuOWujOaVtOadpea6kOWktOKAneS6kuaWpeOAgiJ9LCJEZWZhdWx0QnJhdmVSZWZlcnJlcnNTZXR0aW5nOjEiOnsibmFtZSI6IuWFgeiuuOWujOaVtOadpea6kOWktCAodW5zYWZlLXVybCkiLCJkZXNjIjoi5b2T572R56uZ6K+35rGC5pe26Leo5rqQ5Y+R6YCB5a6M5pW055qE5p2l5rqQIFVSTOOAguS7heS9nOS4uuWFvOWuueaAp+W6lOaApeW8gOWFs+KAlOKAlOS8muWJiuW8semakOengeS/neaKpO+8jOaJgOaciemihOiuvuWdh+acquWQr+eUqOOAguS4juKAnOmZkOWItuadpea6kOWktOS7heWPkemAgeS4u+a6kOKAneS6kuaWpeOAgiJ9LCJEZWZhdWx0QnJhdmVSZW1lbWJlcjFQU3RvcmFnZVNldHRpbmciOnsibmFtZSI6IuWFs+mXreagh+etvumhteaXtua4hemZpOesrOS4gOaWueWtmOWCqCIsImRlc2MiOiLlnKjlhbPpl63mn5DkuKrnvZHnq5nnmoTmnIDlkI7kuIDkuKrmoIfnrb7pobXml7bmuIXpmaTlhbYgQ29va2llIOS4juacrOWcsOWtmOWCqOKAlOKAlOS4i+asoeiuv+mXruaXtue9keermeWwhuS4jeWGjeiusOS9j+S9oO+8iOWPiueZu+W9leeKtuaAge+8ieOAgiJ9LCJCYWNrZ3JvdW5kTW9kZUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWFs+mXreWQjuWQjuWPsOi/kOihjCIsImRlc2MiOiLpmLvmraIgQnJhdmUg5Zyo5YWz6Zet5pyA5ZCO5LiA5Liq56qX5Y+j5ZCO57un57ut6am755WZ5ZCO5Y+w77yI6YCa5bi45LuF5b2T5pyJ5omp5bGV55Sz6K+35ZCO5Y+w6L+Q6KGM5pe25omN5Lya5Y+R55Sf77yJ44CC6Iul5peg5q2k57G75omp5bGV77yM5q2k562W55Wl5LuF6ZSB5a6a5YWz6ZetIGJyYXZlOi8vc2V0dGluZ3Mvc3lzdGVtIOS4reeahOKAnOWFs+mXrSBCcmF2ZSDlkI7nu6fnu63ov5DooYzlkI7lj7DlupTnlKjigJ3jgIIifSwiSGlnaEVmZmljaWVuY3lNb2RlRW5hYmxlZCI6eyJuYW1lIjoi5ZCv55So5YaF5a2Y6IqC55yB56iL5bqPIiwiZGVzYyI6IuW8uuWItuW8gOWQr+WGheWtmOiKguecgeeoi+W6j++8muiHquWKqOS8keecoOS4jea0u+i3g+eahOagh+etvumhteS7pemHiuaUvuWGheWtmO+8jOWIh+WbnuaXtumHjeaWsOWKoOi9veOAgiJ9LCJIYXJkd2FyZUFjY2VsZXJhdGlvbk1vZGVFbmFibGVkOjEiOnsibmFtZSI6IuW8uuWItuW8gOWQr+ehrOS7tuWKoOmAnyIsImRlc2MiOiJCcmF2ZSDpu5jorqTlvIDlkK/igJzlnKjlj6/nlKjml7bkvb/nlKjlm77lvaLliqDpgJ/igJ3vvJvmraTnrZbnlaXlsIblhbbplIHlrprvvIzpmLLmraLlnKjorr7nva7kuK3miYvliqjlhbPpl63ku6Xop4Tpgb/mmL7ljaHlvILluLjjgIJHUFUg6buR5ZCN5Y2V5oiW5Y+N5aSN5bSp5rqD5LuN5Y+v6IO96Kem5Y+R6L2v5Lu25riy5p+T5Zue6YCA44CC6YeN5ZCv5rWP6KeI5Zmo5ZCO55Sf5pWI44CCIn0sIkhhcmR3YXJlQWNjZWxlcmF0aW9uTW9kZUVuYWJsZWQ6MCI6eyJuYW1lIjoi56aB55So56Gs5Lu25Yqg6YCfIiwiZGVzYyI6IuW8uuWItuWFs+mXrSBHUFUg56Gs5Lu25Yqg6YCf77yI5LiO6buY6K6k55u45Y+N77yJ77yM5Lya54m654my5riy5p+T6YCf5bqm5LiO57ut6Iiq44CC5LuF5bu66K6u5Zyo5pi+5Y2h6Lev5b6E5a2Y5Zyo5pWF6Zqc5pe25byA5ZCv77ya5L6L5aaC6amx5Yqo6Zeu6aKY5a+86Ie06Zeq54OB6Iqx5bGP44CB6Jma5ouf5py6L+i/nOeoi+ahjOmdouaXoOWPr+eUqCBHUFXvvIzmiJblhbHkuqvlsY/luZXml7bnlLvpnaLmjZ/lnY/jgILph43lkK/mtY/op4jlmajlkI7nlJ/mlYjjgIIifSwiRW5hYmxlTWVkaWFSb3V0ZXIiOnsibmFtZSI6IuemgeeUqOWqkuS9k+aKleWxjyAoR29vZ2xlIENhc3QpIiwiZGVzYyI6IuemgeeUqCBHb29nbGUgQ2FzdCDlj4rlhbblsYDln5/nvZHlkI7lj7Dorr7lpIflj5HnjrDjgILph43lkK/mtY/op4jlmajlkI7nlJ/mlYjjgILpppbmrKHlnKjmraTnrZbnlaXkuIvliJvlu7rnmoTphY3nva7mlofku7bvvIzljbPkvr/ml6XlkI7np7vpmaTnrZbnlaXvvIzmipXlsY/ku43kvJrkv53mjIHlhbPpl63vvIzpnIDlnKggYnJhdmU6Ly9zZXR0aW5ncy9leHRlbnNpb25zIOS4remHjeaWsOW8gOWQr+WqkuS9k+i3r+eUseWZqOW5tumHjeWQr+OAgiJ9LCJBbHdheXNPcGVuUGRmRXh0ZXJuYWxseSI6eyJuYW1lIjoi5aeL57uI5L2/55So5aSW6YOo56iL5bqP5omT5byAIFBERiIsImRlc2MiOiLnm7TmjqXkuIvovb0gUERGIOaWh+S7tuiAjOmdnuS9v+eUqCBCcmF2ZSDlhoXnva4gUERGIOmYheivu+WZqOmihOiniO+8m+S4i+i9veWQjumcgOaJi+WKqOaJk+W8gOOAgue9keermeWPr+S7peajgOa1i+WIsOWGhee9rumYheivu+WZqOiiq+emgeeUqOS4lOaMh+e6ueS/neaKpOS4jeS8mumakOiXj+atpOeJueW+ge+8jOWPr+iDveS8muWinuWKoOiiq+aMh+e6ueivhuWIq+eahOmjjumZqeOAgiJ9LCJUcmFuc2xhdGVFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjlhoXnva7nvZHpobXnv7vor5EiLCJkZXNjIjoi56aB55So5YaF572u572R6aG157+76K+R5Yqf6IO95Y+K5YW25by556qX5o+Q56S644CCIn0sIlNwZWxsY2hlY2tFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjlhajpg6jmi7zlhpnmo4Dmn6UiLCJkZXNjIjoi5b275bqV5YWz6Zet5paH5pys6L6T5YWl5qGG5Lit55qE5ou85YaZ5qOA5p+l44CC5LiO4oCc56aB55So5aKe5by65Z6L5Zyo57q/5ou85YaZ5qOA5p+l4oCd5LqS5pal77yI5ZCO6ICF5L+d55WZ5pys5Zyw56a757q/5qOA5p+l77yM5LuF56e76ZmkIEdvb2dsZSDlnKjnur/mn6Xor6LvvInjgIIifSwiU2VhcmNoU3VnZ2VzdEVuYWJsZWQiOnsibmFtZSI6IuemgeeUqOWcsOWdgOagj+aQnOe0ouW7uuiuriIsImRlc2MiOiLlgZzmraLlsIbkvaDlnKjlnLDlnYDmoI/ovpPlhaXnmoTlrZfnrKblrp7ml7blj5HpgIHnu5nmkJzntKLlvJXmk47ku6Xojrflj5bogZTmg7Plu7rorq7jgIIifSwiUHJpbnRpbmdFbmFibGVkIjp7Im5hbWUiOiLnpoHnlKjmtY/op4jlmajmiZPljbDlip/og70iLCJkZXNjIjoi5a6M5YWo56aB55So5rWP6KeI5Zmo5omT5Y2w77yI5ZCrIEN0cmwrUCDkuI7lj6blrZjkuLogUERG77yJ44CC5L6d6LWW5omT5Y2w6aKE6KeI55qEIEJyYXZlIOWKn+iDveS5n+S8muWQjOaXtuWkseaViO+8muWMheaLrCBMZW8g6K+75Y+WIEdvb2dsZSBEb2NzL+aJq+aPj+eJiCBQREbvvIzku6Xlj4rmiKrlm77lt6XlhbflnKggUERGIOS4jiBHb29nbGUgRG9jcyDkuIrnmoTplb/miKrlm77jgIIifSwiRGVmYXVsdEJyb3dzZXJTZXR0aW5nRW5hYmxlZCI6eyJuYW1lIjoi56aB55So6buY6K6k5rWP6KeI5Zmo5o+Q56S6IiwiZGVzYyI6IuWBnOatoiBCcmF2ZSDor6Lpl67mmK/lkKborr7kuLrpu5jorqTmtY/op4jlmajvvIzlubblnKggYnJhdmU6Ly9zZXR0aW5ncyDkuK3pmpDol4/igJzorr7kuLrpu5jorqTigJ3mjInpkq7jgILms6jmhI/vvJrpppbmrKHov5DooYzmrKLov47pobXku43lj6/og73mmL7npLrigJzorr7kuLrpu5jorqTigJ3vvIzlnKjmraTnrZbnlaXlvIDlkK/ml7bngrnlh7vkvJrlr7zoh7TltKnmuoPvvIzor7flnKjor6XlpITpgInmi6nigJzot7Pov4figJ3jgIIifSwiRGV2ZWxvcGVyVG9vbHNBdmFpbGFiaWxpdHkiOnsibmFtZSI6IuemgeeUqOW8gOWPkeiAheW3peWFtyAoRjEyKSIsImRlc2MiOiLlsY/olL3lvIDlj5HogIXlt6XlhbfvvIhGMTLvvInjgIHmianlsZXosIPor5Xlj4rigJzmn6XnnIvnvZHpobXmupDku6PnoIHigJ3oj5zljZXkuI7lv6vmjbfplK7vvIzlubblhbPpl63mianlsZXlvIDlj5HogIXmqKHlvI/vvIjnpoHmraLliqDovb3lt7Lop6PljovmianlsZXvvInjgILkvJrlr7zoh7TmlbTpobXmiKrlm77ljaHmrbvlubbkvb/lvZPliY3nqpflj6PmiKrlm77mjInpkq7lj5jngbDnm7Toh7PlhbPpl63jgILnvZHpobXlvIDlj5HogIXor7fli7/lkK/nlKjjgIIifSwiQnJhdmVXYXliYWNrTWFjaGluZUVuYWJsZWQiOnsibmFtZSI6IuemgeeUqCBXYXliYWNrIE1hY2hpbmUg572R6aG15b+r54WnIiwiZGVzYyI6IuW9k+e9kemhteWkseaViOaIluaKpemUme+8iDQwNOOAgTQwOOOAgTQxMOOAgTQ1MSDlj4rpg6jliIYgNXh477yJ5pe277yM5YGc5q2iIEJyYXZlIOaPkOekuuiuv+mXriBhcmNoaXZlLm9yZyDlrZjmoaPlv6vnhafvvIjljIXmi6zoh6rliqjlvLnnqpfmj5DnpLrvvInjgIIifX0sInB5X3VpIjp7InRpdGxlIjoiIFNsaW1CcmF2ZSBOZW8gLSBCcmF2ZSDmtY/op4jlmajnsr7nroDkuI7pmpDnp4HlvLrljJblt6XlhbcgIiwidGl0bGVfd2l0aF9tZXRob2QiOiIgU2xpbUJyYXZlIE5lbyAtIEJyYXZlIOa1j+iniOWZqOeyvueugOS4jumakOengeW8uuWMluW3peWFtyBbezB9XSAiLCJoaW50X2RlZmF1bHQiOiIgW+epuuagvC/lm57ovaZdIOWIh+aNoiAgWy9dIOaQnOe0oiAgW0RdIOivtOaYjumdouadvyAgW1FdIOmAgOWHuiAgWz9dIOW4ruWKqSAiLCJoaW50X3Nob3J0IjoiIFvnqbrmoLwv5Zue6L2mXSDliIfmjaIgIFsvXSDmkJzntKIgIFtRXSDpgIDlh7ogIFs/XSDluK7liqkgIiwiaGludF9maWx0ZXIiOiIg562b6YCJ77yaezB9ICAg5Yy56YWNIHsxfSDpobkgICBbRXNjXSDmuIXpmaQgIiwiZnJhbWVfc2V0dGluZ3MiOiIg562W55Wl6K6+572uICIsImZyYW1lX2Rlc2MiOiIg6K+05piOICIsImRuc19zZWN0aW9uX2hlYWRlciI6IkROUyBPdmVyIEhUVFBTIiwiZG5zX3RlbXBsYXRlX2xhYmVsIjoi5qih5p2/IiwiZG5zX3RlbXBsYXRlX2luYWN0aXZlIjoiICAgIOaooeadv++8mu+8iOmAieaLqSBjdXN0b20g5oiWIHNlY3VyZSDmqKHlvI/lkI7lj6/nvJbovpHvvIkiLCJpbmVydF9zdWZmaXgiOiIoT3JpZ2luIOW3suWGhee9ruenu+mZpCkiLCJvcmlnaW5fbm90ZV9vbmx5Ijoi5qOA5rWL5YiwIEJyYXZlIE9yaWdpbu+8muetlueVpeato+W4uOeUn+aViO+8m09yaWdpbiDnvJbor5Hml7blt7Lnp7vpmaTnmoTlip/og73ooYzlsIbnva7ngbDkuI3lj6/nlKjjgIIiLCJvcmlnaW5fbm90ZV9iZXNpZGUiOiLmo4DmtYvliLAgT3JpZ2luIOS4juW4uOinhCBCcmF2ZSDlhbHlrZjvvJrlhbHkuqvlkIzkuIDnrZbnlaXmlofku7bvvIzmiYDmnInnrZbnlaXooYzlnYfkv53mjIHlj6/nlKjjgIIiLCJwcm9maWxlX3N0aWxsX2luc3RhbGxlZCI6IuW3sumHjee9ru+8jOS9humFjee9ruaPj+i/sOaWh+S7tuS7jeW3suWuieijhe+8muivt+WJjeW+gCDns7vnu5/orr7nva4gPiDpgJrnlKggPiDorr7lpIfnrqHnkIYg5Lit5omL5Yqo56e76Zmk44CCIiwicHJvZmlsZV9zdGlsbF9hcHBsaWVzIjoiIFNsaW1CcmF2ZSDphY3nva7mj4/ov7Dmlofku7bku43lt7Llronoo4XlubbmjIHnu63nlJ/mlYjjgIIiLCJoZWFkZXJfY291bnRlciI6InswfS97MX0g5bey5ZCv55SoIiwiaGVhZGVyX29yaWdpbl9vbmx5IjoiezB9IOmhueeUsSBPcmlnaW4g5YaF572u56e76ZmkIiwiaGVhZGVyX2Rlc2NfdHBsIjoiezB977ya5YWxIHsxfSDpobnorr7nva7vvIzlt7LlkK/nlKggezJ9IOmhuXszfeOAguW3puaWueWQkemUruaKmOWPoO+8jOWPs+aWueWQkemUruWxleW8gO+8jOepuuagvOWIh+aNou+8jOaMiSBjIOWFqOmDqOaKmOWPoC/lsZXlvIDjgIIiLCJoZWFkZXJfZGVzY19vcmlnaW5fcGFydCI6Iu+8jHswfSDpobnlt7LnlLEgT3JpZ2luIOWGhee9ruenu+mZpCIsImhlYWRlcl9kZXNjX2RucyI6Inswfe+8mumFjee9riBEb0gg6Kej5p6Q5Zmo5qih5byP5Y+K6Ieq5a6a5LmJ5qih5p2/IFVSTOOAgiIsImluZXJ0X2Rlc2NfcHJlZml4IjoiQnJhdmUgT3JpZ2luIOWGhee9ruenu+mZpO+8muivpeWKn+iDveW3suS7jueoi+W6j+S6jOi/m+WItuS4reWJlOmZpO+8jOetlueVpeaXoOmcgOS5n+aXoOazleWIh+aNou+8jOacrOihjOS7heS+m+WPguiAg+OAgiIsImJ1dHRvbnMiOnsiSW1wb3J0Ijoi5a+85YWlIiwiRXhwb3J0Ijoi5a+85Ye6IiwiQXBwbHkiOiLlupTnlKgiLCJSZXNldCI6IumHjee9riIsIlF1aXQiOiLpgIDlh7oifSwiYnV0dG9uX2Rlc2NfbGludXgiOnsiSW1wb3J0Ijoi5LuOIFByZXNldHMvIOmihOiuvuaIluatpOWJjeWvvOWHuueahCBKU09OIOaWh+S7tuWKoOi9vemAiemhueWIsOWIl+ihqOOAgueCueWHu+KAnOW6lOeUqOKAneWJjeS4jeS8muWGmeWFpeezu+e7n+OAgiIsIkV4cG9ydCI6IuWwhuW9k+WJjeWLvumAieWvvOWHuuS4uiBKU09OIOaWh+S7tu+8jOWPr+i3qCBXaW5kb3dzIC8gTGludXggLyBtYWNPUyDohJrmnKzlr7zlhaXjgIJzdWRvIOS4i+S8muS7peWOn+eUqOaIt+i6q+S7veWGmeWFpeOAgiIsIkFwcGx5Ijoi5bCG6YCJ5Lit55qE562W55Wl5YaZ5YWlIEJyYXZlIOWQr+WKqOaXtuivu+WPlueahOezu+e7n+etlueVpeebruW9leOAgui/kOihjOS4reeahCBCcmF2ZSDph43lkK/lkI7nlJ/mlYjjgIIiLCJSZXNldCI6Iuenu+mZpOacrOW3peWFt+WGmeWFpeeahOetlueVpeaWh+S7tu+8jOS9vyBCcmF2ZSDmgaLlpI3pu5jorqTooYzkuLrvvIjmk43kvZzliY3kvJrlho3mrKHnoa7orqTvvInjgIIiLCJRdWl0Ijoi5LiN5YaZ5YWl5Lu75L2V5pu05pS55bm255u05o6l6YCA5Ye644CCIn0sImJ1dHRvbl9kZXNjX21hYyI6eyJJbXBvcnQiOiLku44gUHJlc2V0cy8g6aKE6K6+5oiW5q2k5YmN5a+85Ye655qEIEpTT04g5paH5Lu25Yqg6L296YCJ6aG55Yiw5YiX6KGo44CC54K55Ye74oCc5bqU55So4oCd5YmN5LiN5Lya5YaZ5YWl57O757uf44CCIiwiRXhwb3J0Ijoi5bCG5b2T5YmN5Yu+6YCJ5a+85Ye65Li6IEpTT04g5paH5Lu277yM5Y+v6LeoIFdpbmRvd3MgLyBMaW51eCAvIG1hY09TIOiEmuacrOWvvOWFpeOAgnN1ZG8g5LiL5Lya5Lul5Y6f55So5oi36Lqr5Lu95YaZ5YWl44CCIiwiQXBwbHkiOiLlhYjnoa7orqTmmK/lkKbmjIHkuYXljJbvvIjku6Xlj4rlpJrmuKDpgZPml7bnmoTnm67moIfmuKDpgZPvvInvvIzpmo/lkI7lhpnlhaUgQnJhdmUg5ZCv5Yqo6K+75Y+W55qE5omY566h562W55Wl44CC5byA5ZCv5oyB5LmF5YyW5bCG5Lqk55Sx4oCc57O757uf6K6+572u4oCd5a6M5oiQ5o+P6L+w5paH5Lu25a6J6KOF44CCIiwiUmVzZXQiOiLnp7vpmaTmnKzlt6XlhbflhpnlhaXnmoTnrZbnlaXvvIzkvb8gQnJhdmUg5oGi5aSN6buY6K6k6KGM5Li677yI5pON5L2c5YmN5Lya5YaN5qyh56Gu6K6k77yJ44CCIiwiUXVpdCI6IuS4jeWGmeWFpeS7u+S9leabtOaUueW5tuebtOaOpemAgOWHuuOAgiJ9LCJkbnNfZGVzYyI6eyJtb2RlIjoic2VjdXJlIOS4jiBjdXN0b20g5Lya5bCG5YWo6YOo5p+l6K+i5Y+R5b6A5LiL5pa55qih5p2/5LiU5LiN5Zue6YCA77yM5qih5p2/6ZSZ6K+v5bCG5a+86Ie05peg5rOV6Kej5p6Q44CCYXV0b21hdGljIOS8mOWFiOS9v+eUqCBEb0jvvIzlkKbliJnlm57pgIDmma7pgJogRE5T44CCb2ZmIOWujOWFqOemgeeUqCBEb0jjgILkuI3nrqHnkIbliJnkv53nlZkgQnJhdmUg6Ieq6Lqr6K6+572u44CCIiwidGVtcGxhdGUiOiJETlMtb3Zlci1IVFRQUyDop6PmnpDlmajmqKHmnb/lnLDlnYDvvIzkvovlpoIgaHR0cHM6Ly9kbnMuZXhhbXBsZS9kbnMtcXVlcnnjgIJzZWN1cmUg5LiOIGN1c3RvbSDmqKHlvI/lv4XloavvvJthdXRvbWF0aWMg5qih5byP5LiL5aGr5YaZ5Lmf5Lya55Sf5pWI44CCIn0sInBlcnNpc3RfZGVzYyI6eyJvZmYiOiLku4XlhpnlhaUgcGxpc3TvvJttYWNPUyAxMysg6YeN5ZCv5ZCO57O757uf5Y+v6IO95Lya5riF6Zmk5pyq5Y+X5o+P6L+w5paH5Lu25L+d5oqk55qE5YC8Iiwib24iOiLlronoo4UgQXBwbGUg6YWN572u5o+P6L+w5paH5Lu277yb6YeN5ZCv5ZCO5oyB5LmF5pyJ5pWI77yI6ZyA5Zyo57O757uf6K6+572u54K55Ye75LiA5qyh5a6J6KOF77yJIn0sImhlbHBfbGluZXMiOlsiIFNsaW1CcmF2ZSBOZW8gLSDlv6vmjbfplK7or7TmmI4iLCIiLCIgICDihpEgLyDihpMgICAgICAgICAgICAgICAgIOenu+WKqOWFieaghyIsIiAgIFBhZ2VVcCAvIFBhZ2VEb3duICAgICDnv7vpobXmu5rliqgiLCIgICBIb21lIC8gRW5kICAgICAgICAgICAg6Lez6L2s5Yiw6aaW6KGMIC8g5pyr6KGMIiwiICAgU3BhY2UgLyBFbnRlciAgICAgICAgIOWIh+aNouW8gOWFs++8m+aKmOWPoOaIluWxleW8gOWIhuexuyIsIiAgIOKGkCAvIOKGkiAgICAgICAgICAgICAgICAg5YiH5o2i5LiL5ouJ6YCJ6aG577yb5oqY5Y+gIC8g5bGV5byA5YiG57G7IiwiICAgYyAgICAgICAgICAgICAgICAgICAgIOS4gOmUruaKmOWPoOaIluWxleW8gOWFqOmDqOWIhuexuyIsIiAgIC8gICAgICAgICAgICAgICAgICAgICDmjInlkI3np7DjgIHoi7Hmlofljp/lkI3miJbnrZbnlaUgS2V5IOWunuaXtuetm+mAiSIsIiAgIGQgICAgICAgICAgICAgICAgICAgICDmmL7npLrmiJbpmpDol4/lupXpg6jor7TmmI7pnaLmnb8iLCIgICBFc2MgICAgICAgICAgICAgICAgICAg5riF6Zmk562b6YCJ77yb5peg562b6YCJ5pe26YCA5Ye6IiwiICAgPyAgICAgICAgICAgICAgICAgICAgIOaYvuekuuacrOW4ruWKqSIsIiAgIFRhYiAgICAgICAgICAgICAgICAgICDlnKjliJfooajkuI7lupXpg6jmjInpkq7moI/kuYvpl7TliIfmjaIiLCIgICBRICAgICAgICAgICAgICAgICAgICAg6YCA5Ye6IiwiIiwiICAg5oyJ5Lu75oSP6ZSu5YWz6Zet5q2k56qX5Y+j44CCIl0sInByb21wdHMiOnsiZmlsdGVyIjoi562b6YCJ77yI5pSv5oyB5Lit6Iux5paHL+etlueVpUtlee+8jEVzYyDmuIXpmaTvvIkiLCJpbXBvcnRfcGF0aCI6IuWvvOWFpei3r+W+hO+8iEVzYyDlj5bmtojvvIkiLCJleHBvcnRfcGF0aCI6IuWvvOWHuui3r+W+hO+8iEVzYyDlj5bmtojvvIkiLCJyZXNldF9jb25maXJtIjoi56Gu6K6k6YeN572u5omA5pyJ55Sx5pys5bel5YW3566h55CG55qE6K6+572u77yf5oyJIEVudGVyIOehruiupO+8jOaMieWFtuS7luS7u+aEj+mUruWPlua2iOOAgiIsImFwcGx5X2NhbmNlbGxlZCI6IuW3suWPlua2iOW6lOeUqOOAgiIsInJlc2V0X2NhbmNlbGxlZCI6IuW3suWPlua2iOmHjee9ruOAgiIsImltcG9ydF9jYW5jZWxsZWQiOiLlt7Llj5bmtojlr7zlhaXjgIIiLCJleHBvcnRfY2FuY2VsbGVkIjoi5bey5Y+W5raI5a+85Ye644CCIiwiZG9oX3JlcXVpcmVkIjoic2VjdXJlIC8gY3VzdG9tIOaooeW8j+W/hemhu+Whq+WGmeacieaViOeahCBEb0gg5qih5p2/IFVSTOOAgiIsInRlcm1fdG9vX3Nob3J0Ijoi57uI56uv56qX5Y+j6auY5bqm5LiN6Laz77yM5peg5rOV5pi+56S66K+05piO6Z2i5p2/44CCIn19LCJ2YXJpYW50IjoibGludXgifQ==").decode("utf-8"))
    _UI = _ZH["py_ui"]
    _CAT_MAP, _CHOICE_MAP = _ZH["categories"], _ZH["choices"]
    _DNS_MAP, _POL_MAP = _ZH["dns_modes"], _ZH["policies"]
    _BTN_LABELS = _UI["buttons"]
    _IS_MAC_VARIANT = (_ZH.get("variant") == "mac")
    g = globals()

    def _norm_val(v):
        if isinstance(v, bool):
            return "1" if v else "0"
        if isinstance(v, (int, float)):
            return str(int(v)) if float(v).is_integer() else str(v)
        return str(v)

    def _ch_w(ch):
        if not ch or ord(ch) < 32 or _ud.category(ch) in ("Mn", "Me", "Cf"):
            return 0
        return 2 if _ud.east_asian_width(ch) in ("W", "F") else 1

    def _wcswidth(text):
        return sum(_ch_w(c) for c in (text or ""))

    def _slice_w(text, max_w):
        if max_w <= 0:
            return ""
        out, w = [], 0
        for ch in (text or ""):
            cw = _ch_w(ch)
            if w + cw > max_w:
                break
            out.append(ch)
            w += cw
        return "".join(out)

    def _truncate_w(text, max_w, ellipsis="..."):
        if max_w <= 0:
            return ""
        if _wcswidth(text) <= max_w:
            return text
        ew = _wcswidth(ellipsis)
        if max_w <= ew:
            return _slice_w(ellipsis, max_w)
        return _slice_w(text, max_w - ew).rstrip() + ellipsis

    def _ljust_w(text, width):
        s = _slice_w(text, width)
        return s + (" " * max(0, width - _wcswidth(s)))

    def _center_w(text, width):
        s = _slice_w(text, width)
        rem = max(0, width - _wcswidth(s))
        return (" " * (rem // 2)) + s + (" " * (rem - rem // 2))

    def _wrap_w(text, width, max_lines, ellipsis="..."):
        if width < 1 or max_lines < 1:
            return []
        text = " ".join((text or "").split())
        if not text:
            return []
        tokens, buf = [], []
        for ch in text:
            if ch == " " or _ch_w(ch) == 2:
                if buf:
                    tokens.append("".join(buf))
                    buf = []
                tokens.append(ch)
            else:
                buf.append(ch)
        if buf:
            tokens.append("".join(buf))

        lines, cur, cur_w = [], "", 0
        for tok in tokens:
            if tok == " ":
                if cur and cur_w + 1 <= width:
                    cur += " "
                    cur_w += 1
                elif cur:
                    lines.append(cur.rstrip())
                    cur, cur_w = "", 0
                continue
            tw = _wcswidth(tok)
            if cur and cur_w + tw > width:
                lines.append(cur.rstrip())
                cur, cur_w = "", 0
            if tw > width:
                part = tok
                while part:
                    chunk = _slice_w(part, width)
                    if not chunk:
                        break
                    lines.append(chunk)
                    part = part[len(chunk):]
                cur, cur_w = "", 0
            else:
                cur += tok
                cur_w += tw
        if cur.strip():
            lines.append(cur.rstrip())
        if len(lines) <= max_lines:
            return lines
        kept = lines[:max_lines]
        kept[-1] = _truncate_w(kept[-1], width, ellipsis)
        return kept

    # 1. Translate CATEGORIES in-place (preserving en_name / key for bilingual search)
    for cat in g.get("CATEGORIES", []):
        cat["en_name"] = cat.get("name", "")
        cat["name"] = _CAT_MAP.get(cat["en_name"], cat["en_name"])
        for feat in cat.get("features", []):
            feat["en_name"] = feat.get("name", "")
            feat["en_desc"] = feat.get("desc", "")
            key, val = feat.get("key", ""), feat.get("value", "")
            tr = _POL_MAP.get(f"{key}:{_norm_val(val)}") or _POL_MAP.get(key)
            if tr:
                feat["name"] = tr.get("name") or feat["name"]
                feat["desc"] = tr.get("desc") or feat["desc"]
            if "choices" in feat:
                feat["choices"] = [(_CHOICE_MAP.get(lbl, lbl), cval) for lbl, cval in feat["choices"]]

    for cname in ("CHOICES_ALLOW_ASK_BLOCK", "CHOICES_ALLOW_BLOCK", "CHOICES_ASK_BLOCK"):
        if cname in g:
            g[cname] = [(_CHOICE_MAP.get(lbl, lbl), cval) for lbl, cval in g[cname]]

    # 2. Translate module-level constants
    for k_mod, k_ui in (
        ("INERT_SUFFIX", "inert_suffix"),
        ("ORIGIN_NOTE_ONLY", "origin_note_only"),
        ("ORIGIN_NOTE_BESIDE", "origin_note_beside"),
        ("PROFILE_STILL_INSTALLED", "profile_still_installed"),
        ("PROFILE_STILL_APPLIES", "profile_still_applies"),
    ):
        if k_mod in g:
            g[k_mod] = _UI[k_ui]
    if "BUTTON_DESC" in g:
        g["BUTTON_DESC"].update(_UI["button_desc_mac"] if _IS_MAC_VARIANT else _UI["button_desc_linux"])
    if "DNS_DESC" in g:
        g["DNS_DESC"].update(_UI["dns_desc"])
    if "PERSIST_DESCRIPTIONS" in g:
        g["PERSIST_DESCRIPTIONS"].update(_UI["persist_desc"])
    if "HELP_LINES" in g:
        g["HELP_LINES"] = list(_UI["help_lines"])

    # 3. Preserve en_name onto rows built by build_rows() & enable bilingual `/` filter
    _orig_build_rows = g["build_rows"]
    def _zh_build_rows(*args, **kwargs):
        rows = _orig_build_rows(*args, **kwargs)
        fmap = {}
        for cat in g.get("CATEGORIES", []):
            for feat in cat.get("features", []):
                fmap[(feat.get("key"), _norm_val(feat.get("value")))] = feat
                fmap[(feat.get("key"), None)] = feat
        for row in rows:
            if row.get("type") in (g["ROW_FEATURE"], g["ROW_CHOICE"]):
                f = fmap.get((row.get("key"), _norm_val(row.get("value")))) or fmap.get((row.get("key"), None))
                if f:
                    row["en_text"] = f.get("en_name", "")
        return rows
    g["build_rows"] = _zh_build_rows

    def _zh_row_matches_filter(row, needle):
        if row["type"] not in (g["ROW_FEATURE"], g["ROW_CHOICE"]):
            return False
        hay = f"{row.get('text', '')} {row.get('en_text', '')} {row.get('key', '')}".lower()
        return needle in hay
    g["row_matches_filter"] = _zh_row_matches_filter

    # 4. CJK-aware wrapping & description pane
    g["wrap_description"] = _wrap_w
    g["_desc_pane_lines"].clear()
    def _zh_desc_pane_lines(max_x):
        cache = g["_desc_pane_lines"]
        if max_x not in cache:
            width = max(1, (max_x - 1) - 4)
            texts = [f.get("desc", "") for cat in g["CATEGORIES"] for f in cat["features"]]
            texts += list(g["DNS_DESC"].values()) + list(g["BUTTON_DESC"].values())
            need = max((len(_wrap_w(t, width, g["DESC_PANE_MAX_LINES"] + 2)) for t in texts), default=1)
            cache[max_x] = max(1, min(g["DESC_PANE_MAX_LINES"], need))
        return cache[max_x]
    g["desc_pane_lines"] = _zh_desc_pane_lines

    def _zh_describe_row(rows, cursor_idx, focus, btn_idx):
        if focus == g["FOCUS_BUTTONS"]:
            return g["BUTTON_DESC"].get(g["BUTTONS"][btn_idx], "")
        if not (0 <= cursor_idx < len(rows)):
            return ""
        row = rows[cursor_idx]
        kind = row["type"]
        if kind == g["ROW_HEADER"]:
            on, total = g["header_counts"](rows, cursor_idx)
            inert = g["header_inert_count"](rows, cursor_idx)
            if total or inert:
                built_in = _UI["header_desc_origin_part"].format(inert) if inert else ""
                return _UI["header_desc_tpl"].format(row["text"], total, on, built_in)
            return _UI["header_desc_dns"].format(row["text"])
        if kind == g["ROW_DNS"]:
            return g["DNS_DESC"]["mode"]
        if kind == g["ROW_DNS_TEMPLATE"]:
            return g["DNS_DESC"]["template"]
        if row.get("inert"):
            return _UI["inert_desc_prefix"] + " " + row.get("desc", "")
        return row.get("desc", "")
    g["describe_row"] = _zh_describe_row

    _STATUS_EXACT = {
        "Apply cancelled.": _UI["prompts"]["apply_cancelled"],
        "Reset cancelled.": _UI["prompts"]["reset_cancelled"],
        "Import cancelled.": _UI["prompts"]["import_cancelled"],
        "Export cancelled.": _UI["prompts"]["export_cancelled"],
        "Secure/custom DNS requires a DoH template URL.": _UI["prompts"]["doh_required"],
        "Terminal too short for the description pane.": _UI["prompts"]["term_too_short"],
        "Reset all settings? Press Enter to confirm, any key to cancel.": _UI["prompts"]["reset_confirm"],
    }
    _PROMPT_EXACT = {
        "Filter (Esc=clear)": _UI["prompts"]["filter"],
        "Import path (Esc=cancel)": _UI["prompts"]["import_path"],
        "Export path (Esc=cancel)": _UI["prompts"]["export_path"],
    }

    def _safe_put(stdscr, y, x, text, max_cols, attr, max_y, usable_w):
        curses = g["curses"]
        if max_cols <= 0 or y < 0 or y >= max_y or x < 0 or x >= usable_w:
            return
        clipped = _slice_w(text, min(max_cols, usable_w - x))
        if not clipped:
            return
        try:
            stdscr.addstr(y, x, clipped, attr)
        except (curses.error, ValueError):
            pass

    # 5. CJK-safe draw(), draw_help(), _draw_prompt_overlay(), and Unicode prompt_text_input()
    def _zh_draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
                 status_msg, status_ok, install_method="",
                 prompt_label="", prompt_buf="", prompt_cur=0, filter_text="",
                 show_desc=False, describe_focus=None):
        curses = g["curses"]
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        hz, vt, tl, tr, bl, br, ellipsis = g["box_glyphs"]()
        status_msg = _STATUS_EXACT.get(status_msg, status_msg)
        prompt_label = _PROMPT_EXACT.get(prompt_label, prompt_label)
        status = g["status_lines"](status_msg, max_x) if focus != g["FOCUS_PROMPT"] else []
        lay = g["layout"](max_y, max_x, show_desc, len(status))
        if len(status) > lay["status_lines"]:
            status = g["status_lines"](status_msg, max_x, lay["status_lines"])
        framed = lay["framed"]
        inner_x = 2 if framed else 0
        inner_w = max(1, usable_w - 4) if framed else usable_w
        edge_attr = curses.color_pair(g["CP_NORMAL"]) | curses.A_DIM

        def put(y, x, text, max_cols, attr):
            _safe_put(stdscr, y, x, text, max_cols, attr, max_y, usable_w)

        def frame(top, bottom, label=""):
            ew = max(0, usable_w - 2)
            lw = _wcswidth(label)
            head = (hz + label + (hz * (ew - lw - 1))) if (label and lw + 2 < ew) else (hz * ew)
            put(top, 0, tl + head + tr, usable_w, edge_attr)
            for yy in range(top + 1, bottom):
                put(yy, 0, vt, 1, edge_attr)
                put(yy, usable_w - 1, vt, 1, edge_attr)
            put(bottom, 0, bl + (hz * ew) + br, usable_w, edge_attr)

        title = _UI["title_with_method"].format(install_method) if install_method else _UI["title"]
        put(0, 0, _center_w(title, usable_w), usable_w, curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD)

        vis = g["visible_indices"](rows, filter_text)
        needle = filter_text.strip()
        if needle:
            matches = sum(1 for i in vis if rows[i]["type"] != g["ROW_HEADER"])
            hint = _UI["hint_filter"].format(needle, matches)
        else:
            hint = _UI["hint_default"] if _wcswidth(_UI["hint_default"]) <= usable_w else _UI["hint_short"]
        put(1, 0, _center_w(hint, usable_w), usable_w, curses.color_pair(g["CP_NORMAL"]) | curses.A_DIM)

        list_start_y, visible_count = lay["list_top"], lay["list_rows"]
        if framed:
            frame(list_start_y - 1, lay["list_bottom"], _UI["frame_settings"])

        current_dns_mode = g["get_dns_mode"](rows)
        for vi in range(visible_count):
            vpos = vi + scroll_offset
            if vpos >= len(vis):
                break
            ri = vis[vpos]
            row = rows[ri]
            y = list_start_y + vi
            is_cursor = (focus == g["FOCUS_LIST"] and ri == cursor_idx)
            line, attr = "", curses.color_pair(g["CP_NORMAL"])

            if row["type"] == g["ROW_HEADER"]:
                attr = curses.color_pair(g["CP_HEADER"]) | curses.A_BOLD
                open_g, shut_g = g["disclosure_glyphs"]()
                marker = shut_g if (row.get("collapsed", False) and not needle) else open_g
                left_t = f"{marker} {row['text']}"
                on_c, tot = g["header_counts"](rows, ri)
                inert = g["header_inert_count"](rows, ri)
                counter = _UI["header_counter"].format(on_c, tot) if tot else (_UI["header_origin_only"].format(inert) if inert else "")
                if counter:
                    gap = max(2, inner_w - _wcswidth(counter) - _wcswidth(left_t) - 1)
                    line = left_t + (" " * gap) + counter
                else:
                    line = left_t
            elif row["type"] == g["ROW_FEATURE"]:
                if row.get("inert"):
                    suf = g["INERT_SUFFIX"]
                    room = max(0, inner_w - _wcswidth(suf) - _wcswidth("    [-]  "))
                    line = f"    [-] {_truncate_w(row['text'], room, ellipsis)} {suf}"
                    attr = curses.color_pair(g["CP_DIM"]) | curses.A_DIM
                else:
                    mark = "x" if row["checked"] else " "
                    line = f"    [{mark}] {row['text']}"
                    attr = curses.color_pair(g["CP_CHECKED"] if row["checked"] else g["CP_NORMAL"])
            elif row["type"] == g["ROW_CHOICE"]:
                line = f"    {row['text']}: < {row['choices'][row['selected']][0]} >"
                attr = curses.color_pair(g["CP_CHECKED"] if row["selected"] > 0 else g["CP_NORMAL"])
            elif row["type"] == g["ROW_DNS"]:
                cur_opt = row["options"][row["selected"]]
                line = f"    < {_DNS_MAP.get(cur_opt, cur_opt)} >"
            elif row["type"] == g["ROW_DNS_TEMPLATE"]:
                val = row["value"] or ""
                if current_dns_mode in ("custom", "secure"):
                    field_w = g["template_field_width"](max_x)
                    scroll = max(0, min(row.get("scroll", 0), len(val)))
                    cur_pos = row.get("cursor", 0)
                    if cur_pos - scroll >= field_w:
                        scroll = cur_pos - field_w + 1
                    elif cur_pos < scroll:
                        scroll = cur_pos
                    row["scroll"] = scroll
                    line = f"    Template: [{g['_field_text'](val[scroll:scroll + field_w]).ljust(field_w)}]"
                else:
                    line = _UI["dns_template_inactive"]
                    attr = curses.color_pair(g["CP_DIM"]) | curses.A_DIM

            if is_cursor:
                attr = curses.color_pair(g["CP_CURSOR"]) | curses.A_BOLD
            put(y, inner_x, _ljust_w(line, inner_w), inner_w, attr)

            if is_cursor and row["type"] == g["ROW_DNS_TEMPLATE"] and current_dns_mode in ("custom", "secure"):
                tmpl_val, field_start = row["value"], inner_x + 15
                field_w = g["template_field_width"](max_x)
                cur_pos = row.get("cursor", 0)
                cx = field_start + cur_pos - row.get("scroll", 0)
                if field_start <= cx < min(inner_x + inner_w, field_start + field_w):
                    ch = g["_field_text"](tmpl_val[cur_pos]) if cur_pos < len(tmpl_val) else " "
                    put(y, cx, ch, 1, curses.color_pair(g["CP_BUTTON_ACTIVE"]))

        mark_x = usable_w - 7 if framed else usable_w - 5
        if scroll_offset > 0:
            put(list_start_y - 1, mark_x, " ^^^ ", 5, edge_attr)
        if scroll_offset + visible_count < len(vis):
            put(lay["list_bottom"], mark_x, " vvv ", 5, edge_attr)

        if lay["pane_lines"]:
            top = lay["pane_top"]
            frame(top, top + lay["pane_lines"] + 1, _UI["frame_desc"])
            what = describe_focus if describe_focus is not None else focus
            parts = g["wrap_description"](g["describe_row"](rows, cursor_idx, what, btn_idx), inner_w, lay["pane_lines"], ellipsis)
            for i, part in enumerate(parts):
                put(top + 1 + i, inner_x, part, inner_w, curses.color_pair(g["CP_NORMAL"]))

        if framed:
            frame(lay["btn_top"], lay["btn_top"] + 2)
        btn_y, btn_x = lay["btn_y"], inner_x
        for i, label in enumerate(g["BUTTONS"]):
            disp = f" {_BTN_LABELS.get(label, label)} "
            attr = (curses.color_pair(g["CP_BUTTON_ACTIVE"]) | curses.A_BOLD) if (focus == g["FOCUS_BUTTONS"] and i == btn_idx) else curses.color_pair(g["CP_BUTTON"])
            put(btn_y, btn_x, disp, max(0, inner_x + inner_w - btn_x), attr)
            btn_x += _wcswidth(disp) + 3

        status_y = lay["status_y"]
        if focus == g["FOCUS_PROMPT"]:
            prefix = f" {prompt_label}: "
            pw = _wcswidth(prefix)
            avail = max(1, usable_w - pw - 1)
            # Horizontal scroll so long CJK/path inputs stay visible around the cursor
            vis_buf = prompt_buf
            vis_cur = prompt_cur
            while vis_cur > 0 and _wcswidth(vis_buf[:vis_cur]) >= avail:
                vis_buf = vis_buf[1:]
                vis_cur -= 1
            put(status_y, 0, _ljust_w(prefix + vis_buf, usable_w), usable_w, curses.color_pair(g["CP_TITLE"]))
            cur_x = pw + _wcswidth(vis_buf[:vis_cur])
            if cur_x < usable_w:
                ch = vis_buf[vis_cur] if vis_cur < len(vis_buf) else " "
                put(status_y, cur_x, ch, max(1, _ch_w(ch)), curses.color_pair(g["CP_BUTTON_ACTIVE"]))
        elif status_msg:
            cp = g["CP_STATUS_OK"] if status_ok else g["CP_STATUS_ERR"]
            for i, sline in enumerate(status):
                put(status_y + i, 2, sline, usable_w - 3, curses.color_pair(cp))
        stdscr.refresh()

    def _zh_draw_help(stdscr):
        curses = g["curses"]
        stdscr.erase()
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        for i, text in enumerate(g["HELP_LINES"]):
            if i >= max_y:
                break
            attr = (curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD) if i == 0 else curses.color_pair(g["CP_NORMAL"])
            _safe_put(stdscr, i, 0, _ljust_w(text, usable_w), usable_w, attr, max_y, usable_w)
        stdscr.refresh()

    def _zh_draw_prompt_overlay(stdscr, desc_line, keys_line):
        curses = g["curses"]
        max_y, max_x = stdscr.getmaxyx()
        usable_w = max_x - 1
        lay = g["layout"](max_y, max_x, False)
        x, w = (2, max(1, usable_w - 4)) if lay["framed"] else (0, usable_w)
        desc_line = (desc_line
                     .replace("Apply to which Brave channels?", "应用到哪些 Brave 渠道？")
                     .replace("Persist across reboots:", "重启后保持持久化："))
        keys_line = (keys_line
                     .replace("move", "移动").replace("select", "选择")
                     .replace("quick-pick", "快捷切换").replace("toggle", "切换")
                     .replace("Enter=confirm", "Enter=确认").replace("Esc=cancel", "Esc=取消"))
        _safe_put(stdscr, lay["btn_y"], x, _ljust_w(desc_line, w), w,
                  curses.color_pair(g["CP_TITLE"]) | curses.A_BOLD, max_y, usable_w)
        _safe_put(stdscr, lay["status_y"], 0, _ljust_w(keys_line, usable_w), usable_w,
                  curses.color_pair(g["CP_STATUS_OK"]), max_y, usable_w)
        stdscr.refresh()

    def _zh_prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                              install_method, label, default="", on_change=None, show_desc=False):
        """Unicode/CJK IME-aware status-line input using curses get_wch()."""
        curses = g["curses"]
        buf, cur, shown = list(default), len(default), None
        while True:
            text = "".join(buf)
            if on_change is not None and text != shown:
                cursor_idx, scroll_offset = on_change(text)
                shown = text
            g["draw"](stdscr, rows, cursor_idx, scroll_offset,
                      g["FOCUS_PROMPT"], btn_idx, "", True, install_method,
                      prompt_label=label, prompt_buf=text, prompt_cur=cur,
                      filter_text="" if on_change is None else text,
                      show_desc=show_desc,
                      describe_focus=None if on_change is not None else g["FOCUS_BUTTONS"])
            try:
                key = stdscr.get_wch() if hasattr(stdscr, "get_wch") else stdscr.getch()
            except curses.error:
                continue
            if key == curses.KEY_RESIZE:
                curses.update_lines_cols()
                continue
            if key in (27, "\x1b"):
                return False, ""
            if key in (curses.KEY_ENTER, 10, 13, "\n", "\r"):
                return True, "".join(buf).strip()
            if key in (curses.KEY_BACKSPACE, 127, 8, "\x7f", "\x08"):
                if cur > 0:
                    buf.pop(cur - 1)
                    cur -= 1
            elif key == curses.KEY_DC:
                if cur < len(buf):
                    buf.pop(cur)
            elif key == curses.KEY_LEFT:
                if cur > 0:
                    cur -= 1
            elif key == curses.KEY_RIGHT:
                if cur < len(buf):
                    cur += 1
            elif key == curses.KEY_HOME:
                cur = 0
            elif key == curses.KEY_END:
                cur = len(buf)
            elif isinstance(key, str) and key.isprintable():
                buf.insert(cur, key)
                cur += 1
            elif isinstance(key, int) and 32 <= key <= 126:
                buf.insert(cur, chr(key))
                cur += 1

    g["draw"] = _zh_draw
    g["draw_help"] = _zh_draw_help
    g["prompt_text_input"] = _zh_prompt_text_input
    if "_draw_prompt_overlay" in g:
        g["_draw_prompt_overlay"] = _zh_draw_prompt_overlay
    g["_zh_wcswidth"] = _wcswidth

_sb_zh_install()


if __name__ == "__main__":
    args = parse_args()

    error = _check_args(args)
    if error:
        print(error, file=sys.stderr)
        sys.exit(2)

    override_installations = None
    if args.policy_file is not None:
        if not _is_allowed_policy_file(args.policy_file):
            print(
                "--policy-file must be a slimbrave*.json file directly inside one of: "
                + ", ".join(ALLOWED_POLICY_DIRS)
            )
            sys.exit(2)
        POLICY_FILE = os.path.realpath(args.policy_file)
        POLICY_DIR = os.path.dirname(POLICY_FILE)
        # Reuse the stable channel's user-data dir / process name for prefs
        # repair and "is Brave running" detection on the override target.
        default_channel = LINUX_CHANNELS[0]
        override_installations = [_make_installation(
            {**default_channel, "id": "override", "label": "Override"},
            plist_path=POLICY_FILE,
            prefs_path=_channel_prefs_path(default_channel["user_data_dir"]),
        )]

    is_cli = (args.import_path is not None or args.export_path is not None
              or args.reset)

    if os.geteuid() != 0:
        print("SlimBrave Neo must be run as root.")
        if is_cli:
            print("Usage: sudo python3 slimbrave.py --import preset.json")
        else:
            print("Usage: sudo python3 slimbrave.py")
        sys.exit(1)

    if is_cli:
        if override_installations is not None:
            installations = override_installations
        else:
            brave_info = detect_brave()
            installations, err = _filter_installations_by_channels(
                brave_info["installations"], args.channels,
            )
            if installations is None:
                print(f"Error: {err}", file=sys.stderr)
                sys.exit(2)
            for w in brave_info["warnings"]:
                print(f"Warning: {w}", file=sys.stderr)
            for n in brave_info.get("notes", []):
                print(f"Note: {n}", file=sys.stderr)

        # Accumulate so a later success cannot mask an earlier failure
        # (e.g. --reset failing followed by a clean --import).
        rc = 0
        if args.reset:
            rc = max(rc, cli_reset(installations))
        if args.import_path is not None:
            rc = max(rc, cli_import(args.import_path, installations,
                                    doh_templates=args.doh_templates or ""))
        if args.export_path is not None:
            rc = max(rc, cli_export(args.export_path, installations))
        sys.exit(rc)

    try:
        curses.wrapper(lambda s: main(s, override_installations))
    except KeyboardInterrupt:
        pass
