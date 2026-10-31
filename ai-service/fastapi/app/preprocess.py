"""Shared value normalisation for the input-risk model (10 §IR).

Training and serving import the same functions so the features match exactly.
"""
import html
import re
from urllib.parse import unquote_plus

MAX_LEN = 1024

_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_LONG_NUM = re.compile(r"\b\d{6,}\b")
_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")
_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{24,}\b")
_WS = re.compile(r"\s+")

# Shell separators that start an injected command, longest first.
SEPARATORS = ["$(", "&&", "||", "%0a", "\n", ";", "|", "`", "&"]
_SEP = re.compile(r"\$\(|&&|\|\||\n|;|\||`|&")


# Same rule as core's fast path (07 §4.1): plain values never reach the model and get risk 0.
_FAST_PATH = re.compile(r"^[A-Za-z0-9 _.,@:/+-]{0,64}$")
_NOT_PLAIN = re.compile(r"\.\.|--|file:|(^|/)(etc|proc|root|var/log|windows)/|\.ini\b", re.I)


def is_plain(value: str) -> bool:
    return bool(_FAST_PATH.match(value)) and not _NOT_PLAIN.search(value)


def decode(value: str) -> tuple[str, bool]:
    """URL-decode up to twice and HTML-entity decode once. Returns (decoded, was_encoded)."""
    out = value[:MAX_LEN * 3]
    for _ in range(2):
        nxt = unquote_plus(out) if "%" in out or "+" in out else out
        if nxt == out:
            break
        out = nxt
    nxt = html.unescape(out)
    out = nxt
    return out[:MAX_LEN], out != value[:MAX_LEN]


def normalise(value: str) -> str:
    """Text the vectorisers see: decoded, lowercased, whitespace collapsed, noisy runs replaced."""
    text, _ = decode(value)
    text = text.lower()
    text = _IP.sub(" <ip> ", text)
    text = _HEX.sub(" <hex> ", text)
    text = _B64.sub(lambda m: " <b64> " if not m.group(0).isalpha() else m.group(0), text)
    text = _LONG_NUM.sub(" <num> ", text)
    return _WS.sub(" ", text).strip()


def extract_payload(value: str) -> str | None:
    """Text after the first shell separator (decoded), for cmd_injection findings."""
    text, _ = decode(value)
    m = _SEP.search(text)
    if not m:
        return None
    payload = text[m.end():].strip()
    if payload.endswith(")") and m.group(0) == "$(":
        payload = payload[:-1].strip()
    payload = payload.strip("`").strip()
    return payload[:500] or None
