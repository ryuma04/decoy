"""Pydantic models matching 04-api-contract §C."""
from typing import Literal

from pydantic import BaseModel, Field

InputLabel = Literal["normal", "cmd_injection", "sqli", "xss", "path_traversal"]


class InputContext(BaseModel):
    service: str | None = None
    path: str | None = None
    field: Literal["query", "form", "json", "path", "username"] | None = None


class ClassifyInputRequest(BaseModel):
    param: str = ""
    value: str = Field(max_length=8192)
    context: InputContext = InputContext()


class ClassifyInputResponse(BaseModel):
    label: InputLabel
    risk: float
    scores: dict[InputLabel, float]
    top_features: list[str]
    payload: str | None
    was_encoded: bool


class FindingFact(BaseModel):
    title: str
    technique: str | None = None
    ts: str


class TimelineFact(BaseModel):
    ts: str
    line: str = Field(max_length=300)


class NarrateFacts(BaseModel):
    actor_label: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    risk_score: int | None = None
    behaviour_class: str | None = None
    services: list[str] = []
    ips: list[str] = []
    tokens: list[str] = []
    findings: list[FindingFact] = Field(default=[], max_length=15)
    timeline: list[TimelineFact] = Field(default=[], max_length=30)
    recommended_actions: list[str] = []
    dashboard_url: str = ""
    touched_production: bool = False


class NarrateRequest(BaseModel):
    kind: Literal["alert", "actor", "incident", "event"]
    ref_id: str
    audience: Literal["discord", "slack", "dashboard"] = "dashboard"
    facts: NarrateFacts
    attacker_strings: list[str] = Field(default=[], max_length=20)


class NarrateResponse(BaseModel):
    headline: str
    text: str
    bullets: list[str]
    source: Literal["llm"] = "llm"
    model: str
    prompt_hash: str
    guard: dict[str, str] = {}
