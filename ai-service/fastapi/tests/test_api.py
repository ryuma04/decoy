"""HTTP contract (04 §C)."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["models"]["input"] == "v1"
    assert body["narration"] == "off" and body["llm_model"] is None


def test_classify_input():
    r = client.post("/ml/v1/classify-input", json={"param": "host", "value": "8.8.8.8%3B%20cat%20/etc/passwd",
                                                   "context": {"service": "web", "path": "/api/diagnostics", "field": "query"}})
    assert r.status_code == 200
    b = r.json()
    assert b["label"] == "cmd_injection" and b["risk"] >= 0.8
    assert b["payload"] == "cat /etc/passwd" and b["was_encoded"] is True


def test_classify_input_validation():
    assert client.post("/ml/v1/classify-input", json={"param": "x"}).status_code == 422


def test_narrate_off_returns_503(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    r = client.post("/ml/v1/narrate", json={"kind": "actor", "ref_id": "a1", "facts": {}})
    assert r.status_code == 503 and r.json()["error"]["code"] == "llm_off"


def test_narrate_provider_failure_returns_502(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.setenv("LLM_MODEL", "m")
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9")   # nothing listens here
    r = client.post("/ml/v1/narrate", json={"kind": "actor", "ref_id": "a1", "facts": {}})
    assert r.status_code == 502 and r.json()["error"]["code"] == "llm_error"
