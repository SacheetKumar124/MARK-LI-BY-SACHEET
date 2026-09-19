# ⚙️ MARK LIII (53)
### The Ultimate Personal AI Assistant — Made by Sacheet

A real-time voice AI that can hear, see, understand, and control your computer. Built on the Gemini Live API for native audio streaming — zero subscriptions and total digital autonomy.

---

## ✨ Overview

MARK LIII is the version where the assistant stopped waiting to be asked.

The earlier Marks gave JARVIS a voice, a memory, and a set of tools it used when you spoke. This one adds the two things that turn a tool into an assistant: **judgement** about when it is worth speaking, and **senses** so it has something to have judgement about. It reads your screen, notices when a build breaks, knows whether you are at the desk, hears your voice, drives real keyboard and mouse input, and protects your identity and devices — while staying quiet unless something genuinely earns your attention.

It is also the version that became honest. Every boundary is enforced in code rather than requested in a prompt, every autonomous action is written to an audit trail with a reason, and when something cannot work it says so in one clear sentence instead of a stack trace.

It's not just an assistant — it's an extension of your digital life.

---

## 🚀 Capabilities

### Core Features
| Feature | Description |
|---|---|
| 🧩 Plugin System | Drop a single `.py` file into `plugins/` — JARVIS learns a new skill on next launch |
| 🎙️ Real-time Voice | Ultra-low latency conversation in any language via Gemini Live API |
| 💓 Affective Dialog | Hears the emotion in your voice and adapts its tone in response |
| 🤫 Proactive Audio | Knows when you're not talking to it — background chatter never triggers a reply |
| ♾️ Unlimited Sessions | Context compression plus resumption — one conversation lasts for hours |
| 🧠 Persistent Memory | Remembers projects, preferences and personal context across sessions |
| 🖥️ System Control | Launch apps, adjust volume/brightness, WiFi, shortcuts, power — all by voice |
| 👁️ Visual Awareness | Screen capture and webcam vision piped into your main Gemini session |
| 🌅 Morning Briefing | On first boot: greets you, reads the time, recaps yesterday, fetches live news |
| 🔔 Proactive Check-ins | Time-aware, context-aware check-ins that know your projects and the hour |
| 🗓️ Session Memory | Summarises each conversation and mentions it next morning — then forgets it |
| 📊 Hardware Monitoring | CPU, RAM, GPU and temperature telemetry with spoken alerts |
| 🌤️ Weather Report | Live weather for your city, personalised from memory |
| 🔍 Multi-Mode Web Search | `news` / `research` / `price` / `compare` / `search` — grounded first, DDG fallback |
| ⏰ Smart Reminders | OS-native scheduled notifications (systemd / LaunchAgent / Task Scheduler) |
| ✈️ Flight Finder | Live flight price and availability lookup |
| 🎮 Game Updater | Checks and triggers Steam and Epic updates on demand |
| 📂 File Processor | Read, summarise and answer questions about local files |
| 💻 Code Helper | Inline code review, debugging and generation |
| 🌐 Browser Control | Open URLs, navigate tabs, interact with the browser by voice |
| 📨 Send Message | Compose and send through WhatsApp, Telegram, Signal, Instagram and Discord |
| 🎬 YouTube Control | Search, play and control playback by voice |
| 🖱️ Desktop Control | Taskbar, window management and desktop-level operations |
| 📱 Remote Dashboard | Control the assistant from your phone via QR pairing |
| ⚡ Auto-Start on Boot | Registers with the OS startup system |
| 📋 Clipboard Intelligence | Copy any text → floating panel with Translate / Summarise / Explain / Fix |
| 🎨 Assistant Customisation | Change the assistant name, your name and the UI colour from the app |

---

## 🆕 What's New in Mark LIII

### 🧠 Judgement — JARVIS Earns the Right to Interrupt
More automatic usually means more annoying, and this is the layer that prevents it. Every observation is scored on **urgency, relevance, novelty and confidence**, then allowed to interrupt only if it clears the floor *and* the budget — a small number per hour, a larger number per day, a minimum gap between interruptions, and quiet hours overnight. Everything else queues silently into a digest you read when you choose.

Two real flaws were found and fixed by the layer's own self-test: urgent items were bypassing the repeat-check (the same alert every 45 seconds), and novelty alone was enough to earn a slot (junk mail). Silence is a valid answer, and the budget is what makes it one.

### 👁️ Senses — It Notices Instead of Waiting
A background loop watches what actually changes: listening TCP ports read straight from `/proc`, machine health, whether you are at the desk (via the desktop session's idle monitor), and how stale your last security sweep is. It emits on **change**, not on a timer — the first run stores a baseline instead of alarming about the ports that were always open.

The loop runs on your machine, in your language, and hands its findings to JARVIS itself to phrase. When something clears the attention budget you get one spoken sentence in his voice; when nothing does, you get nothing at all.

### 🖐️ Hands — It Can Read and Drive Your Screen
**Screen AI** turns the screen into a working surface:

- **Reads** whatever is open and tells you what you are actually doing
- **Understands messages** in WhatsApp, Telegram, Signal, Discord and Instagram — who wrote, what they said, and whether it is waiting on a reply
- **Drafts replies in your voice**, learned from real conversations rather than a description of your style
- **Sends them**, after checking the text is genuinely in the box
- **Finds text on screen and clicks or types into it**
- **Reads and fixes errors** — tracebacks, compiler, npm, pip, apt and service failures — by explaining the cause and running the safe inspections that narrow it down

Unattended replies are hard-gated in code, not by prompt wording: only contacts you have switched on, never the same incoming message twice across restarts, hourly caps per contact and globally, a cooldown, quiet hours, risky drafts held for your approval, and password managers and banking windows never analysed at all.

### 📱 The Phone Is a Second Node, Not a Remote
The dashboard already listens on your network, so your phone becomes a full participant rather than a viewer. Talk to JARVIS from the phone and the laptop microphone mutes; send a task from the laptop and read the result on the phone. A shared session store carries handoffs and an outbox between the two, so a job started at the desk finishes in your pocket.

### 🛡️ Personal Protection
Three bundles, all off until you configure them:

- **Identity** — watches your *own* email addresses and handles for new registrations and breach exposure. Any request about someone who is not in your configured list is refused **in code**, however it is phrased.
- **Device** — scheduled sweeps with change alerts: firewall state, free space, battery, disk encryption, and what is newly listening.
- **Personal safety** — a lock action and an SOS that sends a message with your location, both confirmation-gated.

### 🔒 Security Toolkit (HexStrike Plugin)
JARVIS gets a real offensive and defensive toolkit: a **107-entry local fast lane** for tools that are already installed, plus a large remote catalogue reached through the HexStrike MCP server on port 9999. It is built around **not lying to you**: every finding is independently verified before it is reported as real, verified and refuted results are tracked separately, and a scan target must be listed in `config/hexstrike_scope.json` or it is refused before a command is even built.

A local fast lane matters more than the raw tool count — on this machine **96 of the 107 allowlisted tools resolve locally**, so the common case never pays for a round trip.

### 🐧 Kali and Wayland Native
Written against a real Kali GNOME Wayland session, not a developer's X11 machine. A compatibility layer walks a verified backend cascade for each capability, so nothing silently does nothing:

| Feature | Backend it actually uses on Kali |
|---|---|
| Volume / mute | `wpctl` (PipeWire) → `pactl` → `pamixer` |
| Brightness | logind `SetBrightness` over polkit — no root, no extra package |
| Screenshots | xdg-desktop-portal → GNOME Shell D-Bus → `grim` → `scrot`/`import` |
| Clipboard | `wl-copy`/`wl-paste` → `xclip` → pyperclip |
| Notifications | notification daemon D-Bus (works even when `notify-send` is broken) |
| Typing / clicking | `ydotool` with `ydotoold` — real kernel-level input events |
| Window actions | GNOME keybindings for maximise and snap |

A systemd user unit ships in `config/systemd/` so the input daemon survives reboots instead of silently dying with the session.

### 🔊 Audio That Cannot Fail, and Cannot Crash
Two audio problems were eliminated at the root rather than retried around:

- **No more ALSA sample-rate errors.** PortAudio was being handed raw hardware PCMs whose clock is fixed at 44100 Hz and which cannot convert to the 16000/24000 Hz the model needs. Raw hardware devices are never auto-selected now; the app uses the sound-server devices that resample freely, and falls back to opening at a supported rate and converting in software. PortAudio's C-level complaints — which no `try`/`except` can catch — are suppressed around probe attempts, which is why listing audio devices no longer prints a wall of `pa_linux_alsa.c` internals.
- **No more segfaults on teardown.** Audio output is callback-driven, so a cancelled task can no longer interrupt a blocking device write. The old path could be cancelled mid-transaction when a session ended, leaving PortAudio operating on a stream being torn down underneath it — a crash inside C, uncatchable from Python, and fatal. Closing is now idempotent and tolerates a device that has already vanished.

### 🩺 It Can Tell You What Is Wrong With Itself
`python3 tools/doctor.py` reports the distro, session type, whether Python is externally managed, which backend each capability resolves to, live volume and brightness readings, the input-daemon socket, your security fast lane, and which optional tools are missing. `--json` for scripts, `--deep` for a real end-to-end capture test.

The same philosophy runs at startup: the microphone and speaker are opened and closed **before** the session needs them, so a device that cannot work is one clear line at launch instead of a failure mid-sentence.

### ⚙️ Reliability Details You Will Only Notice When They Are Missing
- **Session rotation is expected, not an error.** A Live session has a maximum duration; when the server rotates it, JARVIS reconnects on the resumption handle and keeps the conversation instead of printing a traceback.
- **Actions accept the names the model actually uses.** Forty-odd aliases (`key`, `enter`, `submit`, `doubleclick`, `write`, `focus`, …) because an unrecognised spelling used to cost a failed action and a retry loop.
- **Content cannot be sent twice by accident.** Identical text typed or pasted is allowed twice, then refused with an explicit message telling the model the action is complete — the fix for a real session that pasted one sentence into a chat five times. Keypresses and clicks are deliberately exempt, because pressing Enter twice is a normal thing to ask for.
- **A crashed plugin never takes JARVIS with it.** A broken plugin shows as `BROKEN` in the manager with its error, while everything else keeps working.

---

## 🧩 The Plugin System

Every new capability ships as a single `.py` file. Drop it into `plugins/`, restart, and the skill is live by voice in any language.

1. Copy `plugins/_template.py`
2. Fill in the `PLUGIN` dict and the `run()` function
3. Drop it into `plugins/` — done

Each plugin declares its own tool schema and logic in one file. The engine discovers it at startup, registers it with the Live session, and lists it in the **Plugin Manager** panel where every plugin gets its own persistent ON/OFF toggle. Discovery is crash-isolated and name collisions with core tools are rejected automatically.

Two plugins ship as worked examples: `screen_ai` (eyes and hands) and `hexstrike_mcp` (security toolkit).

---

## 🔐 Safety Model

The rules that matter are enforced in code, not requested in a prompt:

| Boundary | How it is enforced |
|---|---|
| Scanning a target | Must be listed in `config/hexstrike_scope.json`; refused before a command is built |
| Messaging as you | Only contacts with `auto_reply: true`; never the same message twice; hourly caps |
| Looking up a person | Only identifiers in your own `config/personal_watch.json`; others refused in code |
| Destructive actions | Confirmation-gated, dry-run available, every one written to the audit trail |
| Cameras and screen capture | Opt-in per sensor, with a visible indicator |
| Shell access | An argument-list allowlist with no shell interpolation — never blanket `bash -c` |

Every autonomous action is appended to `memory/activity_log.jsonl` with a `why`, so "why did it do that?" always has an answer.

---

## ⚡ Quick Start

```bash
cd Mark-LIII
pip install -r requirements.txt --break-system-packages
python main.py
```

Put your Gemini API key in `config/api_keys.json`, then run. On first launch, `setup.py` walks you through the key, your name, and the assistant name.

> ⚠️ **Kali / Debian / Ubuntu note:** system Python carries an `EXTERNALLY-MANAGED` marker (PEP 668), so `pip install` is refused outright. Use a virtualenv, or add `--user --break-system-packages` as shown above. `setup.py` and the in-app installer detect the marker and add those flags for you.

> 💡 **Check your machine first:** `python3 tools/doctor.py` tells you which backends resolve and what is missing, before you debug anything.

---

## 📋 Requirements

| Requirement | Details |
|---|---|
| **OS** | Linux (verified on Kali GNOME Wayland), macOS, Windows |
| **Python** | 3.11 or newer — developed and verified on 3.14 |
| **Microphone** | Required for voice interaction |
| **API Key** | Free Gemini API key, placed in `config/api_keys.json` |
| **Optional** | `ydotoold` for real keyboard/mouse control on Wayland (unit file included) |

Some OS-specific dependencies are deliberately not bundled in `requirements.txt` to keep the repo light. If you hit a `ModuleNotFoundError`, install the named package with `pip install <module>`.

---

## 🗂️ Project Structure

```
Mark LIII/
├── main.py                      # Core loop — Live session, audio I/O, tool dispatch
├── ui.py                        # PyQt6 HUD — waveform, log panel, plugin manager, camera
├── setup.py                     # First-run configuration wizard
│
├── core/                        # The engine
│   ├── prompt.txt               # Personality, tool routing and the [ATTENTION] protocol
│   ├── plugin_loader.py         # Plugin discovery, validation, crash isolation
│   ├── action_loader.py         # Action discovery
│   ├── attention.py             # Judgement — scoring, interruption budget, digest, quiet hours
│   ├── senses.py                # Ports, machine health, presence, staleness — emits on change
│   ├── brain.py                 # The loop: observe → score → decide → act/queue → remember
│   ├── activity_log.py          # Audit trail — every autonomous act with a reason
│   ├── personal_watch.py        # Identity, device and personal-safety watches
│   ├── phone_bridge.py          # Session handoff, outbox, phone inbox
│   ├── audio_stream.py          # Device policy, rate negotiation, crash-proof streams
│   ├── audio_devices.py         # Device picker
│   ├── desktop_input.py         # Wayland (ydotool) / X11 input bridge
│   ├── kali_compat.py           # Session-aware backend cascade for OS features
│   ├── vision_client.py         # Vision with a self-ordering model chain
│   ├── screen_watch.py          # Capture, change detection, redaction, retention
│   ├── chat_agent.py            # Read threads, draft in your voice, verified sending
│   ├── error_doctor.py          # Read on-screen errors, diagnose, run safe inspections
│   ├── local_exec.py            # Validated command executor with a tool allowlist
│   ├── confirm.py, undo.py      # Confirmation gate and undo stack
│   ├── llm_client.py            # Native tool-calling client
│   ├── installer.py             # Dependency installer (PEP 668 aware)
│   ├── tts.py, stt.py           # Optional local speech engines
│   └── wake_word.py             # Optional "Hey Jarvis" wake word
│
├── plugins/                     # Drop-in skills
│   ├── _template.py             # Copy this to write a new plugin
│   ├── screen_ai.py             # Eyes and hands — screen, messages, errors
│   └── hexstrike_mcp.py         # Security toolkit client and orchestrator
│
├── actions/                     # Voice-callable actions (22)
│   ├── assistant_control.py     # Arm/disarm the brain, attention, senses
│   ├── personal_watch.py        # Identity, device and safety actions
│   ├── computer_control.py      # Keyboard, mouse, window management
│   ├── computer_settings.py     # Volume, brightness, WiFi, power
│   ├── screen_processor.py      # Screen and webcam vision into the Live session
│   ├── dev_agent.py             # Multi-step developer tasks
│   └── …                        # search, files, messaging, media, reminders, and more
│
├── dashboard/                   # Phone control
│   ├── server.py                # FastAPI + WebSocket, bound to your LAN
│   ├── assistant_api.py         # 8 endpoints — state, digest, activity, handoff
│   └── static/jarvis_phone.html # Voice in/out phone page — no Android app needed
│
├── memory/                      # Persistent state (all local)
│   ├── memory_manager.py
│   ├── long_term.json           # Identity, preferences, projects, sessions
│   ├── live_chat_style.json     # Drafting voice
│   └── live_chat_examples.json  # Learned reply pairs
│
├── config/
│   ├── api_keys.json            # Your Gemini key and UI preferences
│   ├── assistant_policy.json    # Trust rules and sensor switches
│   ├── screen_ai.json           # Screen AI settings and contact list
│   ├── personal_watch.json      # The only identifiers Jarvis may look up
│   ├── hexstrike_scope.json     # The only targets that may be scanned
│   ├── hexstrike_tools.json     # Tool catalogue, playbooks, false-positive hints
│   └── systemd/ydotoold.service # Input daemon unit — survives reboots
│
└── tools/
    └── doctor.py                # Compatibility and capability report
```

---

## 📚 Further Reading

| Document | Covers |
|---|---|
| `SCREEN_AI.md` | Screen AI in full — what it reads, how drafting works, every safety gate |
| `ASSISTANT.md` | The judgement, senses, phone and protection layers, and how to use them |

---

## 🗺️ Roadmap

| Area | Next |
|---|---|
| **Self-healing** | Detect when its own senses or hands stop working (input daemon, portal, audio backend) and bring them back, reporting what it healed |
| **Verified actions** | Confirm typing, pasting and sending actually landed before telling you it succeeded |
| **Learned tolerance** | Derive the interruption budget from how you respond to interruptions instead of fixed thresholds |
| **Screen memory** | Continuous understanding so it can answer "what was I working on an hour ago?" |
| **Nightly watch** | Run the security sweep on schedule and report only what changed since yesterday |

---

## 🤝 Credits

**Built by Sacheet.**

An independent assistant built on top of the original Mark-LIII engine by FatihMakes, whose foundation made this possible. The audio pipeline, judgement layer, senses, screen understanding, personal protection and Kali compatibility work are additions to that base.

| Platform | Contact |
|---|---|
| Instagram | [@jamie](https://www.instagram.com/cutiefemboynya) |
| Discord | `alone_slave` |
