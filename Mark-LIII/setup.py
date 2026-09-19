"""
MARK LIII — one-time setup.

Installs the Python dependencies for THIS operating system only: the OS-specific
packages in requirements.txt carry `sys_platform` markers, so a macOS or Linux
user never pulls Windows-only libraries (and vice-versa). Then it fetches the
Playwright browsers needed for web automation (current-OS builds only).

The optional local wake word ("Hey Jarvis") is NOT installed here — it's a
one-click, opt-in download from ⚙ → WAKE WORD inside the app.
"""
import platform
import subprocess
import sys
from pathlib import Path

OS = platform.system()  # "Windows" | "Darwin" | "Linux"


def _pip_extra_flags() -> list[str]:
    """Extra pip flags needed where Python is marked externally managed.

    Kali, Debian and Ubuntu ship an EXTERNALLY-MANAGED marker (PEP 668), so a
    plain ``pip install`` outside a virtualenv is refused outright.  The app runs
    on the system interpreter, so ask for a user-site install explicitly;
    ``--user`` keeps every file under the owner's home directory and never
    writes into /usr.
    """
    if sys.prefix != sys.base_prefix:
        return []  # already inside a virtualenv, so nothing to override
    try:
        import sysconfig
        stdlib = Path(sysconfig.get_paths()["stdlib"])
    except Exception:
        stdlib = Path(sys.prefix) / "lib"
    return ["--user", "--break-system-packages"] if (stdlib / "EXTERNALLY-MANAGED").exists() else []


def _run(label: str, args: list[str]) -> None:
    print(f"\n▶ {label}")
    subprocess.run(args, check=True)


def main() -> None:
    print(f"⚙  MARK LIII setup — detected OS: {OS or 'unknown'}")

    # requirements.txt filters OS-specific extras by itself via pip markers.
    _run("Installing Python dependencies (OS-specific extras auto-filtered)…",
         [sys.executable, "-m", "pip", "install", "-r", "requirements.txt",
          *_pip_extra_flags()])

    # Chromium covers Chrome/Edge/Opera/Brave/Vivaldi; Firefox for Firefox.
    # (Safari automation additionally needs: python -m playwright install webkit)
    _run("Installing Playwright browsers (chromium + firefox)…",
         [sys.executable, "-m", "playwright", "install", "chromium", "firefox"])

    # ── OS-specific post-install notes ────────────────────────────────────────
    if OS == "Windows":
        try:
            import win32com.client  # noqa: F401
        except ImportError:
            postinstall = Path(sys.executable).parent / "Scripts" / "pywin32_postinstall.py"
            print(
                "\n⚠️  pywin32 did not register correctly — desktop-shortcut "
                "creation will use a slower fallback. To fix it, run:\n"
                f'    "{sys.executable}" -m pip install --force-reinstall pywin32\n'
                f'    "{sys.executable}" "{postinstall}" -install'
            )
    elif OS == "Linux":
        print(
            "\nℹ️  Linux note — Kali/Debian/GNOME Wayland already ships what the OS "
            "actions need, and the app detects it at runtime:\n"
            "    • volume      → PipeWire (wpctl), or pactl / pamixer if present\n"
            "    • brightness  → logind SetBrightness over polkit (no root, no extra pkg)\n"
            "    • screenshots → xdg-desktop-portal (GNOME Wayland); grim / scrot on X11\n"
            "    • clipboard   → wl-clipboard (wl-copy / wl-paste) or xclip\n"
            "    • reminders   → systemd (systemd-run) or 'at'\n"
            "    • open URLs   → xdg-utils          (xdg-open)\n"
            "  Nothing here needs pip: run tools/doctor.py to see what resolved."
        )
    elif OS == "Darwin":
        print(
            "\nℹ️  macOS note — volume, brightness and reminders use the built-in "
            "'osascript' / LaunchAgents, so no extra tools are required.\n"
            "    For Safari automation only: python -m playwright install webkit"
        )

    print("\n✅ Setup complete!")
    print("   1) Launch it:  python main.py")
    print("   2) Paste your free Gemini API key when the setup screen appears.")
    print("   3) (Optional) Enable 'Hey Jarvis' from ⚙ → WAKE WORD.")


if __name__ == "__main__":
    main()
