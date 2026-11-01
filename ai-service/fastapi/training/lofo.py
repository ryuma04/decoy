"""Leave-one-family-out check for one attack class (default sqli).

    python -m training.lofo [--label sqli]

For every family of the class: train on everything except that family, test on it. Reports how many of the
unseen family's rows the deployed system (model + fast path) scores >= 0.5 and >= 0.8, and how many it calls
"normal". This is the fair measure of "does it catch a SQLi shape it has never seen", independent of which
families the random hold-out in train_input happens to pick.
"""
import argparse

import pandas as pd

from app.preprocess import is_plain
from training.train_input import DATA, build


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="sqli")
    a = ap.parse_args()
    df = pd.read_csv(DATA, keep_default_na=False)
    fams = sorted(df.loc[df.label == a.label, "family"].unique())
    rows = []
    for fam in fams:
        train, test = df[df.family != fam], df[df.family == fam]
        pipe = build().fit(train.value.tolist(), train.label.tolist())
        proba = pipe.predict_proba(test.value.tolist())
        classes = list(pipe.classes_)
        risk = 1.0 - proba[:, classes.index("normal")]
        for i, v in enumerate(test.value.tolist()):
            if is_plain(v):
                risk[i] = 0.0
        n = len(test)
        rows.append((fam, n, (risk >= 0.5).mean(), (risk >= 0.8).mean(), (risk < 0.5).mean()))
    print(f"{'unseen family':22} {'n':>5} {'caught@0.5':>11} {'caught@0.8':>11} {'called normal':>14}")
    for fam, n, r5, r8, miss in rows:
        print(f"{fam:22} {n:5d} {r5:11.1%} {r8:11.1%} {miss:14.1%}")
    tot = sum(r[1] for r in rows)
    w = lambda k: sum(r[1] * r[k] for r in rows) / tot
    print(f"{'ALL (weighted)':22} {tot:5d} {w(2):11.1%} {w(3):11.1%} {w(4):14.1%}")


if __name__ == "__main__":
    main()
