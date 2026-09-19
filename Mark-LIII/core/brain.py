"""core/brain.py — the loop that makes Jarvis proactive instead of reactive.

One tick is: gather what the senses noticed → let the attention engine decide
what is worth saying → hand the winners to Jarvis as a tagged message he
phrases himself → keep everything else in a digest.

Two deliberate choices
----------------------
1.  **Jarvis does the phrasing, not this module.** The tick emits a
    ``[ATTENTION]`` message into the live session, exactly like the existing
    ``[SYSTEM_ALERT]`` and ``[PROACTIVE_CHECK]`` paths. That is why an alert
    arrives in the user's own language, with personality, instead of as a
    robot string assembled in Python.
2.  **The decision is deterministic and logged.** Whether to interrupt is
    scored arithmetic with a written reason, not a model call. Model calls cost
    seconds and tokens on every tick; a rule you can read is also a rule you
    can argue with.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Optional

from core import activity_log
from core.attention import AttentionEngine, Decision, Observation, load_policy
from core.senses import SensesHub

_LOCK = threading.RLock()


class Brain:
    """Tie senses, attention and delivery into one proactive loop."""

    def __init__(
        self,
        engine: Optional[AttentionEngine] = None,
        senses: Optional[SensesHub] = None,
        deliver: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.policy = load_policy()
        self.engine = engine or AttentionEngine(self.policy)
        self.senses = senses or SensesHub(self.policy)
        self._deliver = deliver
        self._ticks = 0
        self._last_tick = 0.0
        self._last_result: dict = {}
        self._lock = threading.RLock()

    # ── wiring ──────────────────────────────────────────────────────────

    def bind_deliver(self, deliver: Callable[[str], Any]) -> None:
        """Register how a spoken line reaches the user (session or TTS)."""
        self._deliver = deliver

    @property
    def tick_seconds(self) -> int:
        return int(self.policy.get("tick_seconds", 45))

    # ── the tick ────────────────────────────────────────────────────────

    def tick(self, force: bool = False) -> dict:
        """Run one proactive cycle. Never raises; returns a summary dict."""
        started = time.monotonic()
        result: dict[str, Any] = {
            "observations": 0, "interrupts": [], "decisions": [],
            "queued": 0, "dropped": 0, "elapsed_s": 0.0, "errors": [],
        }
        try:
            observations = self.senses.gather(force=force)
        except Exception as exc:                            # noqa: BLE001
            result["errors"].append(f"senses: {exc}")
            observations = []
        result["observations"] = len(observations)

        for observation in observations:
            try:
                decision = self.engine.observe(observation)
            except Exception as exc:                        # noqa: BLE001
                result["errors"].append(f"attention: {exc}")
                continue
            result["decisions"].append(decision.as_dict())
            if decision.action == "interrupt":
                result["interrupts"].append(self.interrupt_message(decision))
            elif decision.action == "queue":
                result["queued"] += 1
            else:
                result["dropped"] += 1

        if result["interrupts"] and self._deliver is not None:
            for text in list(result["interrupts"]):
                try:
                    self._deliver(text)
                    result.setdefault("delivered", []).append(text)
                except Exception as exc:                    # noqa: BLE001
                    result["errors"].append(f"delivery: {exc}")

        result["elapsed_s"] = round(time.monotonic() - started, 3)
        with self._lock:
            self._ticks += 1
            self._last_tick = time.time()
            self._last_result = result
        if result["observations"]:
            activity_log.record(
                "attention",
                f"brain tick: {result['observations']} observation(s), "
                f"{len(result['interrupts'])} interrupt(s)",
                detail="; ".join(item.get("title", "") for item in result["decisions"][:6])[:400],
                why="proactive cycle",
                meta={"queued": result["queued"], "dropped": result["dropped"]},
            )
        return result

    # ── message shaping ─────────────────────────────────────────────────

    @staticmethod
    def interrupt_message(decision: Decision) -> str:
        """Wrap an observation so Jarvis phrases it in the user's language."""
        obs = decision.observation
        if obs is None:
            return "[ATTENTION] Something worth mentioning came up."
        parts = [
            "[ATTENTION] Something I noticed on my own — not a user request.",
            f"Fact: {obs.title}.",
        ]
        if obs.detail:
            parts.append(f"Detail: {obs.detail}")
        parts.append(f"Signal: {obs.source} sense, confidence {obs.confidence:.0%}.")
        if obs.tags:
            parts.append(f"Tags: {', '.join(obs.tags)}.")
        parts.append(
            "Say it in one short, natural sentence in the user's language. "
            "No alarmism, no lists, no reading this message aloud. "
            "If it is actionable, offer the single next step in a few words."
        )
        return " ".join(parts)

    def digest_text(self, limit: int = 12) -> str:
        return self.engine.digest_text(limit=limit)

    def digest_message(self, limit: int = 12) -> str:
        """A digest item ready to drop into the session."""
        items = self.engine.digest(limit=limit)
        if not items:
            return ""
        lines = [f"- [{item.get('time')}] {item.get('title')} ({item.get('source')})"
                 for item in items]
        return (
            "[DIGEST] These are things I noticed but chose NOT to interrupt you for. "
            "Summarise them in a few short sentences in the user's language, most "
            "important first, and say nothing if a line is trivia:\n" + "\n".join(lines)
        )

    # ── introspection ───────────────────────────────────────────────────

    def status(self) -> dict:
        with self._lock:
            ticks, last_tick, last_result = self._ticks, self._last_tick, self._last_result
        return {
            "ticks": ticks,
            "last_tick_seconds_ago": None if not last_tick else round(time.time() - last_tick, 1),
            "tick_seconds": self.tick_seconds,
            "last_result": {
                "observations": last_result.get("observations", 0),
                "interrupts": len(last_result.get("interrupts", [])),
                "queued": last_result.get("queued", 0),
                "dropped": last_result.get("dropped", 0),
            },
            "attention": self.engine.stats(),
            "senses": self.senses.snapshot(),
            "activity": activity_log.stats(),
        }

    def run_forever(self, stop_event: Optional[threading.Event] = None,
                    interval: Optional[int] = None) -> None:
        """Blocking loop, for standalone use or a dedicated thread."""
        period = int(interval or self.tick_seconds)
        while not (stop_event and stop_event.is_set()):
            self.tick()
            slept = 0.0
            while slept < period and not (stop_event and stop_event.is_set()):
                time.sleep(1)
                slept += 1


_SINGLETON: Optional[Brain] = None


def get_brain() -> Brain:
    """Process-wide brain, so actions and the loop share one attention state."""
    global _SINGLETON
    with _LOCK:
        if _SINGLETON is None:
            _SINGLETON = Brain()
        return _SINGLETON


def _self_test() -> dict:
    """Prove the loop decides sanely without ever delivering speech."""
    brain = Brain(engine=AttentionEngine(persist=False), senses=SensesHub(persist=False))
    delivered: list[str] = []
    brain.bind_deliver(delivered.append)
    result = brain.tick(force=True)
    details: dict[str, Any] = {
        "tick_ran": isinstance(result, dict),
        "no_errors": not result.get("errors"),
        "counts_add_up": (len(result["interrupts"]) + result["queued"] + result["dropped"])
        == result["observations"],
        "elapsed_under_5s": result["elapsed_s"] < 5,
    }
    hot = Observation("listeners", "New port 4444 is listening", detail="self test",
                      urgency=0.95, relevance=0.9, confidence=0.9)
    decision = brain.engine.observe(hot)
    message = Brain.interrupt_message(decision)
    details["message_tagged"] = message.startswith("[ATTENTION]")
    details["message_names_fact"] = "4444" in message
    details["status_shape"] = {"ticks", "attention", "senses"} <= set(brain.status().keys())
    details["digest_renderable"] = isinstance(brain.digest_text(limit=3), str)
    ok = all(value for key, value in details.items() if isinstance(value, bool))
    return {"ok": bool(ok), "details": details}


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, ensure_ascii=False))
