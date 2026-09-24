"""Shared, in-memory app state. Views read and write it; nothing is global elsewhere."""
import uuid
from dataclasses import dataclass, field

from services.api_client import ApiClient


@dataclass
class AppState:
    api: ApiClient
    history: list[dict] = field(default_factory=list)       # past analyses, newest first
    current: dict | None = None                            # analysis shown on the Check tab
    samples: list[dict] = field(default_factory=list)
    # Anonymous id so the server can count *independent* reporters (anti-poisoning).
    reporter_id: str = field(default_factory=lambda: "app-" + uuid.uuid4().hex[:12])

    def add_analysis(self, analysis: dict, text: str, sender: str | None = None) -> None:
        analysis = {**analysis, "_text": text, "_sender": sender}
        self.history = [h for h in self.history if h.get("analysis_id") != analysis.get("analysis_id")]
        self.history.insert(0, analysis)
        self.current = analysis

    @property
    def scams_caught(self) -> int:
        return sum(1 for h in self.history if h.get("risk_level") == "high")
