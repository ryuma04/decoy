"""Generate labelled input values for the input-risk model (10 §IR).

    python -m data.generators.inputs [--n 7000] [--seed 7]

Writes data/processed/inputs.csv with columns value,label,family. `family` is the template a row came
from; training splits by family so the test set holds value shapes the model never saw. Normal values
come in many families (hosts and IPs appear in several) so that no single held-out family is the only
place the model could have learnt that a bare IP or the word "select" is harmless.
"""
import argparse
import csv
import os
import random
import string
import uuid
from urllib.parse import quote

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "data", "processed", "inputs.csv")

def _strings(node):
    # YAML turns bare words like on / null / yes into bool / None; every slot value is text.
    if isinstance(node, dict):
        return {k: _strings(v) for k, v in node.items()}
    if isinstance(node, list):
        return ["null" if v is None else str(v).lower() if isinstance(v, bool) else str(v) for v in node]
    return node


with open(os.path.join(HERE, "slots", "inputs.yaml"), encoding="utf-8") as fh:
    S = _strings(yaml.safe_load(fh))

NORMAL_SHARE = 0.40


# ---------- encodings applied to attack values ----------

def enc_url(v: str) -> str:
    return quote(v, safe="")


def enc_url_partial(v: str) -> str:
    return "".join(quote(c, safe="") if not c.isalnum() and c not in " ./" else c for c in v)


def enc_double(v: str) -> str:
    return quote(quote(v, safe=""), safe="")


def enc_case(v: str, r: random.Random) -> str:
    return "".join(c.upper() if r.random() < 0.5 else c.lower() for c in v)


def enc_space(v: str, r: random.Random) -> str:
    return v.replace(" ", r.choice(["  ", "\t", "+", "${IFS}", " "]))


def encode(v: str, r: random.Random, allow_case=True) -> str:
    x = r.random()
    if x < 0.55:
        return v
    if x < 0.70:
        return enc_url(v)
    if x < 0.80:
        return enc_url_partial(v)
    if x < 0.87:
        return enc_double(v)
    if x < 0.94 and allow_case:
        return enc_case(v, r)
    return enc_space(v, r)


# ---------- normal values ----------

def _name(r):
    return f"{r.choice(S['first_names'])} {r.choice(S['last_names'])}"


def _ip(r):
    return ".".join(str(r.randint(1, 254)) for _ in range(4))


def _host(r):
    if r.random() < 0.4:
        return r.choice(S["hosts"])
    parts = [r.choice(S["plain_words"] + S["risky_words"]) + r.choice(["", str(r.randint(1, 20)), "-01"])
             for _ in range(r.randint(1, 3))]
    return ".".join(parts + [r.choice(S["tlds"])])


def _date(r):
    d, m, y = r.randint(1, 28), r.randint(1, 12), r.randint(2019, 2027)
    return r.choice([f"{y}-{m:02d}-{d:02d}", f"{d:02d}/{m:02d}/{y}", f"{d} Mar {y}", f"{m}/{d}/{y}"])


def _words(r, risky_share=0.35, lo=1, hi=5):
    return " ".join(r.choice(S["risky_words"]) if r.random() < risky_share else r.choice(S["plain_words"] + S["words"])
                    for _ in range(r.randint(lo, hi)))


def _password(r):
    base = r.choice(S["first_names"] + S["words"] + S["risky_words"]).replace(" ", "")
    pw = base.capitalize() + str(r.randint(0, 9999))
    for _ in range(r.randint(1, 3)):
        pw = pw + r.choice(S["password_chars"]) if r.random() < 0.6 else r.choice(S["password_chars"]) + pw
    return pw


def _cust(r, *parts):
    """Join customer-text fragments with the separators real people use (--, ;, ..., &)."""
    out = ""
    for i, p in enumerate(x for x in parts if x):
        out += (r.choice(S["cust_seps"]) if i else "") + p
    return out.strip() + r.choice(S["cust_tails"])


def _order_ref(r):
    return r.choice([f"order #{r.randint(1000, 99999)}", f"Order #{r.randint(1000, 99999)}", f"order {r.randint(100, 9999)}",
                     f"#{r.randint(1000, 99999)}", f"order no. {r.randint(1000, 99999)}", f"ref {r.randint(10000, 99999)}"])


def _customer_message(r):
    return _cust(r, r.choice(S["cust_openers"]),
                 f"need a {r.choice(S['cust_items'])} for {r.choice(S['cust_people'])}'s {r.choice(S['cust_reasons'])}",
                 r.choice(S["cust_requests"]))


def _order_note(r):
    return _cust(r, r.choice([_order_ref(r), r.choice(S["cust_requests"]).capitalize()]),
                 r.choice(S["cust_requests"]), r.choice(["", f"it's for {r.choice(S['cust_people'])}",
                                                          f"{r.choice(S['cust_items'])} or {r.choice(S['cust_items'])}?"]))


def _delivery_note(r):
    return _cust(r, r.choice([f"Flat {r.randint(1, 40)}{r.choice('ABCD')}", f"{r.randint(1, 99)}/{r.randint(1, 20)}, "
                              f"{r.choice(S['plain_words']).title()} Nagar", "Office reception", "Gate 2", "Tower B"]),
                 r.choice(S["cust_requests"]), r.choice(["", f"code {r.randint(1000, 9999)}#", "dog is friendly",
                                                          "lift not working", "near the temple", "opp. petrol pump"]))


def _review(r):
    return _cust(r, f"\"{r.choice(S['cust_feelings']).capitalize()}\"" if r.random() < 0.3 else r.choice(S["cust_feelings"]).capitalize(),
                 f"the {r.choice(S['cust_items'])} for {r.choice(S['cust_people'])}", r.choice(S["cust_feelings"]))


def _enquiry(r):
    return _cust(r, r.choice(S["cust_openers"]), r.choice([
        f"is {r.choice(S['cust_items'])} available or should I pick {r.choice(S['cust_items'])}",
        f"can I change {_order_ref(r)}", f"price > {r.randint(5, 30)}00 is fine",
        f"budget < ₹{r.randint(5, 30)}00", f"can you write '{r.choice(['Happy', 'Congrats', 'Get well soon'])} "
        f"{r.choice(S['first_names'])}' on top", f"select the {r.choice(S['cust_items'])}, drop the {r.choice(S['cust_requests'])}",
        f"{_order_ref(r)} or {_order_ref(r)}, not sure which"]), r.choice(["", r.choice(S["cust_requests"])]))


NORMAL = {
    "customer_message": _customer_message,
    "order_note": _order_note,
    "delivery_note": _delivery_note,
    "review": _review,
    "enquiry": _enquiry,
    "host": _host,
    "host_port": lambda r: f"{_host(r)}:{r.choice([22, 80, 443, 8080, 3000, 5432])}",
    "ip": _ip,
    "ip_port": lambda r: f"{_ip(r)}:{r.randint(1, 65535)}",
    "ip_list": lambda r: r.choice([", ", ",", "; ", " "]).join(_ip(r) for _ in range(r.randint(2, 3))),
    "cidr": lambda r: f"{_ip(r)}/{r.choice([8, 16, 24, 32])}",
    "email": lambda r: f"{r.choice(S['first_names']).lower()}.{r.choice(S['last_names']).lower().replace(chr(39), '')}@{r.choice(S['domains'])}",
    "name": _name,
    "name_company": lambda r: f"{_name(r)}, {r.choice(S['companies'])}",
    "username": lambda r: r.choice([f"{r.choice(S['first_names']).lower()}{r.randint(1, 99)}", "admin", "deploy",
                                    "root", "jenkins", "test_user", "priya.k", f"{r.choice(S['risky_words'])}_{r.randint(1, 9)}"]),
    "password": _password,
    "phrase": lambda r: r.choice(S["phrases"]),
    "search": lambda r: _words(r),
    "sentence": lambda r: f"{r.choice(['Hi,', 'Hello team -', 'Note:', 'FYI;', 'Q:', ''])} {_words(r, 0.3, 3, 9)}"
                          f"{r.choice(['.', '?', '!', ';', ' -- thanks', ' & regards', ' :)', ''])}",
    "title_case": lambda r: _words(r, 0.5, 1, 3).title(),
    "sku": lambda r: f"SKU-{r.randint(100, 99999)}-{r.choice(['AB', 'X', 'ZZ9', 'IN'])}",
    "date": _date,
    "time": lambda r: f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}{r.choice(['', ' IST', ':00', ' pm'])}",
    "price": lambda r: r.choice([f"{r.randint(1, 99999)}", f"{r.randint(1, 999)}.{r.randint(0, 99):02d}",
                                 f"₹{r.randint(10, 9999)}", f"${r.randint(1, 500)}", f"{r.randint(1, 99)}%"]),
    "url": lambda r: f"https://{_host(r)}{r.choice(S['paths'])}?q={_words(r, 0.3, 1, 2).replace(' ', '+')}&page={r.randint(1, 9)}",
    "url_simple": lambda r: f"{r.choice(['http', 'https'])}://{r.choice([_host(r), _ip(r)])}{r.choice(['', '/', r.choice(S['paths'])])}",
    "path": lambda r: r.choice(S["paths"]) + r.choice(["", "/", f"/{r.randint(1, 500)}"]),
    "filename": lambda r: r.choice(S["filenames"]),
    "json": lambda r: r.choice(S["json_snippets"]),
    "phone": lambda r: r.choice([f"+91 {r.randint(70000, 99999)} {r.randint(10000, 99999)}",
                                 f"({r.randint(200, 999)}) 555-{r.randint(1000, 9999)}"]),
    "number": lambda r: str(r.randint(0, 10 ** r.randint(1, 7))),
    "uuid": lambda r: str(uuid.UUID(int=r.getrandbits(128))),
    "token": lambda r: "".join(r.choice(string.ascii_letters + string.digits) for _ in range(r.randint(8, 32))),
    "math": lambda r: f"{r.randint(1, 99)}{r.choice(['+', '-', '*', '/', '=', '<', '>'])}{r.randint(1, 99)}",
    "tags": lambda r: r.choice([", ", ";", " | ", " & ", "/"]).join(r.sample(S["plain_words"] + S["risky_words"], 3)),
    "version": lambda r: f"{r.choice(['v', '', 'release-'])}{r.randint(0, 9)}.{r.randint(0, 30)}.{r.randint(0, 99)}",
    "address": lambda r: f"{r.randint(1, 999)}, {r.choice(S['plain_words']).title()} Road, {r.choice(['Mumbai', 'Pune', 'Delhi', 'Bengaluru'])} {r.randint(400001, 560100)}",
}


# ---------- attack values ----------

def _attacker_ip(r):
    return r.choice(S["attacker_ips"])


def _fill(text, r):
    if "{cust}" in text:  # SQLi hidden after normal shop text, as it arrives in a contact / order-note field
        text = text.replace("{cust}", r.choice([_order_ref(r), r.choice(S["cust_items"]), _customer_message(r)[:40],
                                                r.choice(S["first_names"]), "Mom's cake"]))
    return (text.replace("{ip}", _attacker_ip(r)).replace("{b64}", r.choice(S["b64_blobs"]))
            .replace("{user}", r.choice(["admin", "root", "deploy", r.choice(S["first_names"]).lower()]))
            .replace("{evil}", r.choice(["evil.test", "attacker.example", _attacker_ip(r)])))


CMD_GROUPS = {"recon": "recon_cmds", "cred": "cred_cmds", "dl": "dl_cmds", "rev": "revshell_cmds",
              "obf": "obf_cmds", "misc": None}


def _cmd(group, r):
    if group == "misc":
        return f"{r.choice(S['shell_verbs'])} {r.choice(S['shell_args'])}"
    return _fill(r.choice(S[CMD_GROUPS[group]]), r)


def cmd_injection(sep, group, r):
    prefix = r.choice([NORMAL[r.choice(["host", "ip", "search", "number", "username"])](r), "", "x"])
    cmd = _cmd(group, r)
    if sep == "$(":
        v = f"{prefix}$({cmd})"
    elif sep == "`":
        v = f"{prefix}`{cmd}`"
    elif sep in ("\n", "%0a"):
        v = f"{prefix}{sep}{cmd}"
    else:
        v = f"{prefix}{r.choice(['', ' '])}{sep}{r.choice(['', ' '])}{cmd}"
    return encode(v, r, allow_case=False) if sep != "%0a" else v


def wrap(payload, r):
    """Attack payloads sometimes follow a normal-looking value, like a real form field."""
    if r.random() < 0.3:
        return NORMAL[r.choice(["number", "username", "search", "name"])](r) + payload
    return payload


def generate(n: int, seed: int):
    r = random.Random(seed)
    rows = []
    n_normal = int(n * NORMAL_SHARE)
    per_attack = (n - n_normal) // 4

    keys = list(NORMAL)
    for i in range(n_normal):
        k = keys[i % len(keys)]
        rows.append((NORMAL[k](r), "normal", f"normal:{k}"))

    combos = [(s, g) for s in S["cmd_separators"] for g in CMD_GROUPS]
    for i in range(per_attack):
        s, g = combos[i % len(combos)]
        rows.append((cmd_injection(s, g, r), "cmd_injection", f"cmd:{quote(s)}:{g}"))

    for label, key, prefix in (("sqli", "sqli_payloads", "sqli"), ("xss", "xss_payloads", "xss"),
                               ("path_traversal", "traversal_payloads", "trav")):
        groups = list(S[key])
        for i in range(per_attack):
            g = groups[i % len(groups)]
            v = _fill(r.choice(S[key][g]), r)
            if label != "path_traversal":
                v = wrap(v, r)
            elif g == "dotdot" and r.random() < 0.3:
                v = v.replace("/", "\\") if r.random() < 0.5 else r.choice(["/static/", "images/", "download?file="]) + v
            rows.append((encode(v, r, allow_case=label != "path_traversal"), label, f"{prefix}:{g}"))

    r.shuffle(rows)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=9000)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rows = generate(a.n, a.seed)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["value", "label", "family"])
        w.writerows(rows)
    counts = {}
    for _, label, _ in rows:
        counts[label] = counts.get(label, 0) + 1
    print(f"wrote {len(rows)} rows to {os.path.relpath(OUT, ROOT)}: {counts}, families={len({f for *_, f in rows})}")


if __name__ == "__main__":
    main()
