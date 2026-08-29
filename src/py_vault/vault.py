#!/usr/bin/env python3
"""
pwnd_spectrum_vault.py — Colorful HIBP password checker, generator, and vault handoff.

Features
--------
- Checks a password against Have I Been Pwned Pwned Passwords using the
  k-anonymity range API. The password and its full SHA-1 hash never leave
  this computer; only the first five SHA-1 hash characters are queried.
- Generates cryptographically random passwords using Python's `secrets`.
- Can derive deterministic site-specific passwords using PBKDF2-HMAC-SHA-256
  with a user-provided master secret and salt.
- On Windows, can copy a generated password to the clipboard, optionally clear
  it after a timer, and attempt to open Apple iCloud Passwords.
- Can create a Bitwarden Login item using the official `bw` CLI.

Security notes
--------------
- Prefer random mode and save generated passwords in a password manager.
- Do not use --password for real passwords: CLI args may appear in process
  lists and shell history.
- Apple Passwords does not provide a documented Windows CLI/API for creating
  an entry. This tool only copies the password and opens the app for a
  manual save.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "pwnd-spectrum-vault/1.0 (local-password-audit)"

DEFAULT_LENGTH = 24
MIN_LENGTH = 12
MAX_LENGTH = 256
PBKDF2_ITERATIONS = 600_000

COLOR_ENABLED = True


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"

    BG_BRIGHT_RED = "\033[101m"
    BG_BRIGHT_GREEN = "\033[102m"
    BG_BRIGHT_YELLOW = "\033[103m"
    BG_BRIGHT_BLUE = "\033[104m"
    BG_BRIGHT_MAGENTA = "\033[105m"
    BG_BRIGHT_CYAN = "\033[106m"


SPECTRUM = (
    C.BRIGHT_RED,
    C.BRIGHT_YELLOW,
    C.BRIGHT_GREEN,
    C.BRIGHT_CYAN,
    C.BRIGHT_BLUE,
    C.BRIGHT_MAGENTA,
)

BANNER = (
    "██████╗ ██╗    ██╗███╗   ██╗██████╗ ",
    "██╔══██╗██║    ██║████╗  ██║██╔══██╗",
    "██████╔╝██║ █╗ ██║██╔██╗ ██║██║  ██║",
    "██╔═══╝ ██║███╗██║██║╚██╗██║██║  ██║",
    "██║     ╚███╔███╔╝██║ ╚████║██████╔╝",
    "╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═════╝ ",
)


@dataclass
class GeneratedPassword:
    password: str
    mode: str
    caution: str


def supports_color(no_color: bool) -> bool:
    """Enable ANSI output only in an interactive terminal."""
    return (
        not no_color
        and sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
    )


def fmt(text: str, *codes: str) -> str:
    """Apply ANSI styling when terminal color is enabled."""
    if not COLOR_ENABLED:
        return text
    return "".join(codes) + text + C.RESET


def rainbow(text: str, offset: int = 0, bold: bool = False) -> str:
    """Render printable characters through a cycling color spectrum."""
    if not COLOR_ENABLED:
        return text

    output: list[str] = []
    index = offset

    for char in text:
        if char.isspace():
            output.append(char)
            continue

        codes = [SPECTRUM[index % len(SPECTRUM)]]
        if bold:
            codes.insert(0, C.BOLD)

        output.append(fmt(char, *codes))
        index += 1

    return "".join(output)


def print_banner() -> None:
    print()

    for offset, line in enumerate(BANNER):
        print("  " + rainbow(line, offset * 2, bold=True))

    print("  " + rainbow("═" * 62, offset=1, bold=True))

    print(
        "  "
        + fmt("◆", C.BOLD, C.BRIGHT_MAGENTA)
        + " "
        + fmt("HIBP CHECK", C.BOLD, C.BRIGHT_CYAN)
        + fmt("  •  ", C.BRIGHT_BLACK)
        + fmt("PASSWORD GENERATOR", C.BOLD, C.BRIGHT_YELLOW)
        + fmt("  •  ", C.BRIGHT_BLACK)
        + fmt("VAULT HANDOFF", C.BOLD, C.BRIGHT_GREEN)
        + " "
        + fmt("◆", C.BOLD, C.BRIGHT_MAGENTA)
    )

    print("  " + rainbow("═" * 62, offset=4, bold=True))

    print(
        "  "
        + fmt("▸", C.BOLD, C.BRIGHT_BLUE)
        + " "
        + fmt("LOCAL HASHING", C.BOLD, C.BRIGHT_BLUE)
        + fmt("  •  ", C.BRIGHT_BLACK)
        + fmt("ANONYMOUS LOOKUP", C.BOLD, C.BRIGHT_MAGENTA)
        + fmt("  •  ", C.BRIGHT_BLACK)
        + fmt("NO PASSWORD UPLOAD", C.BOLD, C.BRIGHT_GREEN)
    )

    print()


def badge(label: str, background: str) -> str:
    return fmt(f" {label} ", C.BOLD, C.BRIGHT_WHITE, background)


def status(label: str, foreground: str, background: str, icon: str, text: str) -> None:
    print(
        "  "
        + fmt(icon, C.BOLD, foreground)
        + " "
        + badge(label, background)
        + " "
        + fmt(text, C.BOLD, foreground)
    )


def print_box(
    title: str,
    border_colors: Iterable[str],
    title_codes: tuple[str, ...],
    rows: list[tuple[str, str]],
) -> None:
    width = 74
    colors = tuple(border_colors)
    counter = 0

    def border(left: str, fill: str, right: str) -> None:
        nonlocal counter

        left_color = colors[counter % len(colors)]
        right_color = colors[(counter + 2) % len(colors)]

        print(
            "  "
            + fmt(left, C.BOLD, left_color)
            + rainbow(fill * width, offset=counter, bold=True)
            + fmt(right, C.BOLD, right_color)
        )
        counter += 1

    border("╔", "═", "╗")

    print(
        "  "
        + fmt("║", C.BOLD, colors[0])
        + fmt(title.center(width), *title_codes)
        + fmt("║", C.BOLD, colors[-1])
    )

    border("╠", "═", "╣")

    for text, text_color in rows:
        visible = text[: width - 2].ljust(width - 2)

        print(
            "  "
            + fmt("║", C.BOLD, colors[counter % len(colors)])
            + " "
            + fmt(visible, text_color)
            + " "
            + fmt("║", C.BOLD, colors[(counter + 1) % len(colors)])
        )

        counter += 1

    border("╚", "═", "╝")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "

    try:
        answer = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    if not answer:
        return default

    return answer in {"y", "yes"}


def ask_text(prompt: str, required: bool = False) -> str:
    while True:
        try:
            value = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return ""

        if value or not required:
            return value

        status(
            "REQUIRED",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "A value is required to continue.",
        )


def sha1_upper(value: str) -> str:
    """Create uppercase SHA-1 digest needed by HIBP's password range API."""
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def query_pwned_passwords(hash_prefix: str, timeout: float) -> str:
    """
    Query only a five-character SHA-1 prefix.

    HIBP returns matching hash suffixes and their breach counts. The full
    SHA-1 hash and plaintext password are never submitted.
    """
    request = Request(
        HIBP_RANGE_URL.format(hash_prefix),
        headers={
            "User-Agent": USER_AGENT,
            "Add-Padding": "true",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")

    except HTTPError as exc:
        raise RuntimeError(
            f"HIBP returned HTTP {exc.code}: {exc.reason}"
        ) from exc

    except URLError as exc:
        raise RuntimeError(
            f"Could not connect to HIBP: {exc.reason}"
        ) from exc


def find_breach_count(api_response: str, expected_suffix: str) -> int:
    """Find the local hash suffix in the HIBP response."""
    for line in api_response.splitlines():
        try:
            suffix, count = line.split(":", 1)
        except ValueError:
            continue

        if suffix.upper() == expected_suffix:
            return int(count)

    return 0


def check_password(password: str, timeout: float) -> int:
    """Return the number of known HIBP breach occurrences for a password."""
    password_hash = sha1_upper(password)
    prefix = password_hash[:5]
    suffix = password_hash[5:]

    response = query_pwned_passwords(prefix, timeout)
    return find_breach_count(response, suffix)


def random_password(length: int) -> GeneratedPassword:
    """
    Generate a cryptographically random password.

    Includes at least one lowercase letter, uppercase letter, digit, and symbol.
    """
    symbols = "!@#$%^&*_-+=?."
    alphabet = string.ascii_letters + string.digits + symbols

    characters = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(symbols),
    ]

    characters.extend(
        secrets.choice(alphabet)
        for _ in range(length - len(characters))
    )

    secrets.SystemRandom().shuffle(characters)

    return GeneratedPassword(
        password="".join(characters),
        mode="Cryptographically random password via Python secrets",
        caution="Save this in a password manager; it cannot be regenerated.",
    )


def derived_password(
    master_secret: str,
    salt: str,
    length: int,
) -> GeneratedPassword:
    """
    Deterministically derive a password from a master secret and a site salt.

    PBKDF2-HMAC-SHA-256 slows offline guessing relative to plain SHA-256.
    Same master secret + same salt + same length produces the same password.
    """
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        master_secret.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
        dklen=64,
    )

    symbols = "!@#$%^&*_-+=?."
    alphabet = string.ascii_letters + string.digits + symbols

    output: list[str] = []
    material = raw
    counter = 0

    while len(output) < length:
        for byte in material:
            output.append(alphabet[byte % len(alphabet)])

            if len(output) >= length:
                break

        counter += 1
        material = hashlib.sha256(
            material + counter.to_bytes(4, "big")
        ).digest()

    # Guarantee basic character-class coverage.
    output[0] = string.ascii_lowercase[raw[0] % len(string.ascii_lowercase)]
    output[1] = string.ascii_uppercase[raw[1] % len(string.ascii_uppercase)]
    output[2] = string.digits[raw[2] % len(string.digits)]
    output[3] = symbols[raw[3] % len(symbols)]

    return GeneratedPassword(
        password="".join(output),
        mode=(
            "Deterministic PBKDF2-HMAC-SHA-256 "
            f"with {PBKDF2_ITERATIONS:,} iterations"
        ),
        caution=(
            "Same master secret + salt + length recreates this password. "
            "Protect the master secret."
        ),
    )


def choose_length(default_length: int) -> int:
    entered = ask_text(
        fmt(f"  Password length [{default_length}]: ", C.BRIGHT_CYAN)
    )

    if not entered:
        return default_length

    try:
        length = int(entered)
    except ValueError:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            f"Invalid length; using {default_length}.",
        )
        return default_length

    if length < MIN_LENGTH:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            f"Minimum length is {MIN_LENGTH}; using {MIN_LENGTH}.",
        )
        return MIN_LENGTH

    if length > MAX_LENGTH:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            f"Maximum length is {MAX_LENGTH}; using {MAX_LENGTH}.",
        )
        return MAX_LENGTH

    return length


def choose_generation_mode(length: int) -> GeneratedPassword | None:
    print()
    print("  " + fmt("Choose generation mode:", C.BOLD, C.BRIGHT_YELLOW))

    print(
        "  "
        + fmt("[1]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_BLUE)
        + " "
        + fmt("Random", C.BOLD, C.BRIGHT_CYAN)
        + fmt(
            " — recommended; creates a new password using OS cryptographic randomness",
            C.BRIGHT_BLACK,
        )
    )

    print(
        "  "
        + fmt("[2]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_MAGENTA)
        + " "
        + fmt("Salted SHA-256", C.BOLD, C.BRIGHT_MAGENTA)
        + fmt(
            " — reproducible from a master secret and site/service salt",
            C.BRIGHT_BLACK,
        )
    )

    selected = ask_text(
        fmt("  Mode [1]: ", C.BOLD, C.BRIGHT_CYAN)
    ) or "1"

    if selected == "1":
        return random_password(length)

    if selected != "2":
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Unknown mode; using random generation.",
        )
        return random_password(length)

    print()
    status(
        "DERIVE",
        C.BRIGHT_MAGENTA,
        C.BG_MAGENTA,
        "◆",
        "PBKDF2-HMAC-SHA-256 deterministic mode selected",
    )

    print(
        fmt(
            "  A salt identifies the site, such as github.com or vault.example.net.",
            C.DIM,
            C.BRIGHT_BLUE,
        )
    )

    try:
        master_secret = getpass.getpass(
            fmt("  Master secret (hidden): ", C.BOLD, C.BRIGHT_YELLOW)
        )
    except (EOFError, KeyboardInterrupt):
        print()
        status(
            "CANCELLED",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "◌",
            "Generation cancelled.",
        )
        return None

    salt = ask_text(
        fmt("  Site/service salt: ", C.BOLD, C.BRIGHT_CYAN),
        required=True,
    )

    if not master_secret or not salt:
        status(
            "ERROR",
            C.BRIGHT_RED,
            C.BG_RED,
            "✖",
            "Master secret and site/service salt are required.",
        )
        return None

    return derived_password(master_secret, salt, length)


def copy_to_windows_clipboard(text: str) -> bool:
    """
    Copy text through PowerShell stdin rather than a command-line argument.

    Passing password text via stdin avoids exposing it in the PowerShell
    command text and normal process argument listings.
    """
    if os.name != "nt":
        return False

    commands = [
        ["powershell.exe", "-NoProfile", "-Command", "Set-Clipboard -Value ([Console]::In.ReadToEnd())"],
        ["pwsh.exe", "-NoProfile", "-Command", "Set-Clipboard -Value ([Console]::In.ReadToEnd())"],
    ]

    for command in commands:
        try:
            result = subprocess.run(
                command,
                input=text,
                text=True,
                capture_output=True,
                check=True,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    return False


def clear_windows_clipboard() -> bool:
    """Clear the current Windows clipboard."""
    if os.name != "nt":
        return False

    commands = [
        ["powershell.exe", "-NoProfile", "-Command", "Set-Clipboard -Value $null"],
        ["pwsh.exe", "-NoProfile", "-Command", "Set-Clipboard -Value $null"],
    ]

    for command in commands:
        try:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=True,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    return False


def clear_clipboard_after(seconds: int) -> None:
    """Wait, then clear the Windows clipboard as an opt-in safety measure."""
    status(
        "TIMER",
        C.BRIGHT_YELLOW,
        C.BG_YELLOW,
        "◷",
        f"Clipboard will clear in {seconds} seconds. Keep this terminal open.",
    )

    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        print()
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Clipboard timer cancelled; clear it manually when finished.",
        )
        return

    if clear_windows_clipboard():
        status(
            "CLEARED",
            C.BRIGHT_GREEN,
            C.BG_GREEN,
            "✓",
            "Windows clipboard cleared.",
        )
    else:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Could not clear the clipboard automatically.",
        )


def open_icloud_passwords() -> bool:
    """
    Best-effort launch of iCloud Passwords on Windows.

    Apple does not provide a documented, stable Windows CLI/API for adding
    a Passwords item, so this intentionally opens the application only.
    """
    if os.name != "nt":
        return False

    candidates = [
        "shell:AppsFolder\\AppleInc.iCloud_8y3tp7n8gdrf8!iCloudPasswords",
        "shell:AppsFolder\\AppleInc.iCloud_8y3tp7n8gdrf8!iCloud",
    ]

    for target in candidates:
        try:
            subprocess.Popen(
                ["explorer.exe", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except OSError:
            continue

    return False


def apple_passwords_handoff(password: str) -> None:
    """
    Copy password to clipboard and try to open Apple iCloud Passwords.

    Saving remains manual because Apple does not expose a supported API for
    creating a password entry from a Windows CLI.
    """
    print()
    status(
        "APPLE",
        C.BRIGHT_CYAN,
        C.BG_CYAN,
        "◆",
        "Preparing iCloud Passwords handoff…",
    )

    copied = copy_to_windows_clipboard(password)

    if copied:
        status(
            "COPIED",
            C.BRIGHT_GREEN,
            C.BG_GREEN,
            "✓",
            "Generated password copied to the Windows clipboard.",
        )
    else:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Clipboard copy failed; copy the password from the result panel.",
        )

    if open_icloud_passwords():
        status(
            "OPENED",
            C.BRIGHT_MAGENTA,
            C.BG_MAGENTA,
            "◆",
            "iCloud Passwords opened. Add a login and paste the password.",
        )
    else:
        status(
            "NOTICE",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Open iCloud Passwords manually, then add a login entry.",
        )

    if copied and ask_yes_no(
        fmt(
            "  Clear clipboard after 60 seconds",
            C.BOLD,
            C.BRIGHT_YELLOW,
        ),
        default=True,
    ):
        clear_clipboard_after(60)


def bitwarden_available() -> bool:
    """Return whether the Bitwarden `bw` executable is available in PATH."""
    return shutil.which("bw") is not None or shutil.which("bw.exe") is not None


def run_bitwarden(
    arguments: list[str],
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Run bw using stdin for JSON payloads.

    Users should authenticate/unlock Bitwarden themselves. This function uses
    an already available BW_SESSION environment variable when one exists.
    """
    executable = shutil.which("bw") or shutil.which("bw.exe")

    if not executable:
        raise RuntimeError(
            "Bitwarden CLI was not found. Install it and ensure `bw` is in PATH."
        )

    return subprocess.run(
        [executable, *arguments],
        input=stdin_text,
        text=True,
        capture_output=True,
        check=False,
    )


def bitwarden_status() -> str:
    """Get Bitwarden CLI status JSON, returning 'unknown' if unreadable."""
    try:
        result = run_bitwarden(["status"])
    except RuntimeError:
        return "unavailable"

    if result.returncode != 0:
        return "unknown"

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return "unknown"

    return str(data.get("status", "unknown"))


def bitwarden_save(password: str) -> bool:
    """
    Create a Bitwarden Login item through the official CLI.

    The user must already have a usable `bw` CLI session. The script never
    asks for or prints a Bitwarden API key, master password, or session token.
    """
    print()

    if not bitwarden_available():
        status(
            "MISSING",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "Bitwarden CLI (`bw`) is not installed or not on PATH.",
        )
        print(
            fmt(
                "  Install Bitwarden CLI, log in, unlock your vault, then retry.",
                C.DIM,
                C.BRIGHT_BLACK,
            )
        )
        return False

    vault_status = bitwarden_status()

    if vault_status != "unlocked":
        status(
            "LOCKED",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            f"Bitwarden status is '{vault_status}'. Unlock your vault first.",
        )
        print(
            fmt(
                "  In another terminal: bw login  →  bw unlock  →  set BW_SESSION",
                C.DIM,
                C.BRIGHT_BLACK,
            )
        )
        return False

    status(
        "BITWARDEN",
        C.BRIGHT_BLUE,
        C.BG_BLUE,
        "◆",
        "Create a Login item in your unlocked vault",
    )

    name = ask_text(
        fmt("  Entry name (example: GitHub): ", C.BOLD, C.BRIGHT_CYAN),
        required=True,
    )

    username = ask_text(
        fmt("  Username/email: ", C.BOLD, C.BRIGHT_YELLOW)
    )

    url = ask_text(
        fmt("  Website URL: ", C.BOLD, C.BRIGHT_MAGENTA)
    )

    notes = ask_text(
        fmt("  Notes (optional): ", C.BOLD, C.BRIGHT_GREEN)
    )

    if not name:
        status(
            "CANCELLED",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "◌",
            "No Bitwarden item was created.",
        )
        return False

    print()
    print_box(
        "BITWARDEN SAVE CONFIRMATION",
        (C.BRIGHT_BLUE, C.BRIGHT_CYAN, C.BRIGHT_MAGENTA),
        (C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_BLUE),
        [
            (f"Name: {name}", C.BRIGHT_CYAN),
            (f"Username: {username or '(none)'}", C.BRIGHT_YELLOW),
            (f"URL: {url or '(none)'}", C.BRIGHT_MAGENTA),
            ("Password: generated password shown above", C.BRIGHT_GREEN),
        ],
    )

    if not ask_yes_no(
        fmt(
            "  Create this Login in Bitwarden",
            C.BOLD,
            C.BRIGHT_GREEN,
        ),
        default=False,
    ):
        status(
            "SKIPPED",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "◌",
            "Bitwarden save skipped.",
        )
        return False

    login: dict[str, object] = {
        "username": username,
        "password": password,
    }

    if url:
        login["uris"] = [{"uri": url}]

    item = {
        "type": 1,
        "name": name,
        "login": login,
        "notes": notes,
    }

    encoded = base64.b64encode(
        json.dumps(item, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    result = run_bitwarden(["create", "item", encoded])

    if result.returncode == 0:
        status(
            "SAVED",
            C.BRIGHT_GREEN,
            C.BG_GREEN,
            "✓",
            f"Saved '{name}' as a Bitwarden Login item.",
        )
        return True

    error_message = result.stderr.strip() or result.stdout.strip() or "Unknown Bitwarden CLI error."

    print_box(
        "BITWARDEN SAVE FAILED",
        (C.BRIGHT_RED, C.BRIGHT_YELLOW, C.BRIGHT_MAGENTA),
        (C.BOLD, C.BRIGHT_WHITE, C.BG_RED),
        [(error_message, C.BRIGHT_RED)],
    )

    return False


def password_manager_handoff(password: str) -> None:
    """Offer safe post-generation save/copy handoff choices."""
    print()
    print("  " + rainbow("─" * 72, offset=2, bold=True))
    status(
        "SAVE",
        C.BRIGHT_GREEN,
        C.BG_GREEN,
        "✦",
        "Choose what to do with the generated password",
    )

    print(
        "  "
        + fmt("[1]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_GREEN)
        + " "
        + fmt("Copy to Windows clipboard", C.BOLD, C.BRIGHT_GREEN)
    )

    print(
        "  "
        + fmt("[2]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_CYAN)
        + " "
        + fmt("Apple Passwords handoff", C.BOLD, C.BRIGHT_CYAN)
        + fmt(" — copy password and open iCloud Passwords", C.BRIGHT_BLACK)
    )

    print(
        "  "
        + fmt("[3]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_BLUE)
        + " "
        + fmt("Save directly to Bitwarden", C.BOLD, C.BRIGHT_BLUE)
        + fmt(" — requires unlocked bw CLI", C.BRIGHT_BLACK)
    )

    print(
        "  "
        + fmt("[4]", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_MAGENTA)
        + " "
        + fmt("Do nothing", C.BOLD, C.BRIGHT_MAGENTA)
    )

    selected = ask_text(
        fmt("  Save option [4]: ", C.BOLD, C.BRIGHT_CYAN)
    ) or "4"

    if selected == "1":
        if copy_to_windows_clipboard(password):
            status(
                "COPIED",
                C.BRIGHT_GREEN,
                C.BG_GREEN,
                "✓",
                "Password copied to the Windows clipboard.",
            )

            if ask_yes_no(
                fmt(
                    "  Clear clipboard after 60 seconds",
                    C.BOLD,
                    C.BRIGHT_YELLOW,
                ),
                default=True,
            ):
                clear_clipboard_after(60)
        else:
            status(
                "NOTICE",
                C.BRIGHT_YELLOW,
                C.BG_YELLOW,
                "!",
                "Clipboard copy failed. Copy it from the result panel.",
            )
        return

    if selected == "2":
        apple_passwords_handoff(password)
        return

    if selected == "3":
        bitwarden_save(password)
        return

    status(
        "SKIPPED",
        C.BRIGHT_MAGENTA,
        C.BG_MAGENTA,
        "◌",
        "Password-manager handoff skipped.",
    )


def generate_after_check(default_length: int, allow_handoff: bool) -> None:
    """Offer password generation after a completed HIBP check."""
    print()
    print("  " + rainbow("─" * 72, offset=3, bold=True))

    status(
        "NEXT",
        C.BRIGHT_MAGENTA,
        C.BG_MAGENTA,
        "✦",
        "Generate a replacement password?",
    )

    if not ask_yes_no(
        fmt(
            "  Generate one now",
            C.BOLD,
            C.BRIGHT_MAGENTA,
        ),
        default=True,
    ):
        print(fmt("  No password generated.", C.DIM, C.BRIGHT_BLACK))
        return

    length = choose_length(default_length)
    generated = choose_generation_mode(length)

    if generated is None:
        return

    print_box(
        "✦  GENERATED PASSWORD  ✦",
        (
            C.BRIGHT_GREEN,
            C.BRIGHT_CYAN,
            C.BRIGHT_MAGENTA,
            C.BRIGHT_YELLOW,
        ),
        (C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_GREEN),
        [
            (generated.password, C.BRIGHT_WHITE),
            (f"Length: {len(generated.password)} characters", C.BRIGHT_GREEN),
            (generated.mode, C.BRIGHT_CYAN),
            (generated.caution, C.BRIGHT_YELLOW),
        ],
    )

    status(
        "SAVE",
        C.BRIGHT_GREEN,
        C.BG_GREEN,
        "✓",
        "Store it safely and do not reuse it.",
    )

    if allow_handoff:
        password_manager_handoff(generated.password)


def main() -> int:
    global COLOR_ENABLED

    parser = argparse.ArgumentParser(
        description=(
            "Colorful HIBP password checker with random/salted SHA-256 "
            "generation and optional vault handoff."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--password",
        help=(
            "Password to check. Avoid this for real passwords because CLI "
            "arguments may be visible in history and process listings."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HIBP HTTP request timeout in seconds.",
    )

    parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_LENGTH,
        help="Default length for a newly generated password.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors and styles.",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the colorful launch banner.",
    )

    parser.add_argument(
        "--no-generate",
        action="store_true",
        help="Do not offer password generation after the HIBP check.",
    )

    parser.add_argument(
        "--no-handoff",
        action="store_true",
        help="Do not offer clipboard, Apple Passwords, or Bitwarden handoff.",
    )

    args = parser.parse_args()

    COLOR_ENABLED = supports_color(args.no_color)

    default_length = max(
        MIN_LENGTH,
        min(MAX_LENGTH, args.length),
    )

    if not args.no_banner:
        print_banner()

    password = args.password

    if password is None:
        try:
            prompt = (
                "  "
                + fmt("╭─", C.BRIGHT_MAGENTA)
                + fmt("[", C.BRIGHT_CYAN)
                + fmt(" PWND ", C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_MAGENTA)
                + fmt("]", C.BRIGHT_CYAN)
                + fmt("─", C.BRIGHT_MAGENTA)
                + " "
                + fmt("Enter password", C.BOLD, C.BRIGHT_YELLOW)
                + fmt(" (hidden)", C.DIM, C.BRIGHT_BLACK)
                + fmt(": ", C.BRIGHT_CYAN)
            )

            password = getpass.getpass(prompt)

        except (EOFError, KeyboardInterrupt):
            print()
            status(
                "CANCELLED",
                C.BRIGHT_YELLOW,
                C.BG_YELLOW,
                "◌",
                "No password entered.",
            )
            return 2

    if not password:
        status(
            "EMPTY",
            C.BRIGHT_YELLOW,
            C.BG_YELLOW,
            "!",
            "No password entered.",
        )
        return 2

    print()

    status(
        "LOCAL",
        C.BRIGHT_BLUE,
        C.BG_BLUE,
        "◈",
        "SHA-1 digest created locally",
    )

    status(
        "PRIVATE",
        C.BRIGHT_MAGENTA,
        C.BG_MAGENTA,
        "◉",
        "Only the first 5 SHA-1 hash characters are queried",
    )

    status(
        "QUERY",
        C.BRIGHT_CYAN,
        C.BG_CYAN,
        "↻",
        "Checking HIBP's anonymous password range…",
    )

    try:
        breach_count = check_password(password, args.timeout)

    except RuntimeError as exc:
        print_box(
            "✖  HIBP LOOKUP FAILED  ✖",
            (
                C.BRIGHT_RED,
                C.BRIGHT_MAGENTA,
                C.BRIGHT_YELLOW,
            ),
            (C.BOLD, C.BRIGHT_WHITE, C.BG_RED),
            [
                (str(exc), C.BRIGHT_RED),
                (
                    "Check the VM's Internet/proxy configuration and try again.",
                    C.BRIGHT_YELLOW,
                ),
            ],
        )
        return 1

    if breach_count:
        print_box(
            "⚠  PASSWORD FOUND IN BREACH DATA  ⚠",
            (
                C.BRIGHT_RED,
                C.BRIGHT_YELLOW,
                C.BRIGHT_MAGENTA,
            ),
            (C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_RED),
            [
                (
                    f"Known exposure count: {breach_count:,} occurrence(s)",
                    C.BRIGHT_RED,
                ),
                (
                    "Do not use this password for any account.",
                    C.BRIGHT_YELLOW,
                ),
                (
                    "Generate a unique replacement and save it in a password manager.",
                    C.BRIGHT_WHITE,
                ),
            ],
        )

        print()

        status(
            "ACTION",
            C.BRIGHT_RED,
            C.BG_RED,
            "⚑",
            "Replace this password immediately.",
        )

        if not args.no_generate:
            generate_after_check(
                default_length=default_length,
                allow_handoff=not args.no_handoff,
            )

        return 3

    print_box(
        "✓  NO KNOWN PASSWORD EXPOSURE FOUND  ✓",
        (
            C.BRIGHT_GREEN,
            C.BRIGHT_CYAN,
            C.BRIGHT_BLUE,
        ),
        (C.BOLD, C.BRIGHT_WHITE, C.BG_BRIGHT_GREEN),
        [
            (
                "No exact match was returned from the Pwned Passwords dataset.",
                C.BRIGHT_GREEN,
            ),
            (
                "This is not a guarantee of safety; use long, unique passwords.",
                C.BRIGHT_YELLOW,
            ),
            (
                "A password manager and multi-factor authentication are still recommended.",
                C.BRIGHT_CYAN,
            ),
        ],
    )

    print()

    status(
        "RESULT",
        C.BRIGHT_GREEN,
        C.BG_GREEN,
        "✓",
        "No known password exposure detected.",
    )

    if not args.no_generate:
        generate_after_check(
            default_length=default_length,
            allow_handoff=not args.no_handoff,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())