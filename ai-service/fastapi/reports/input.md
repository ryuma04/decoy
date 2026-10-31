# Input-risk model report (v2, 9000 training rows)

## Targets

| target | value | required | ok |
| --- | --- | --- | --- |
| family_holdout.attack_precision_at_0.8 | 1.000 | >= 0.9 | yes |
| family_holdout.normal_fpr_at_0.5 | 0.000 | <= 0.02 | yes |
| family_holdout.attack_recall_at_0.5 | 0.904 | >= 0.8 | yes |
| hard_set_holdout_model.attack_recall_at_0.5 | 0.965 | >= 0.95 | yes |
| hard_set_holdout_model.macro_f1 | 0.954 | >= 0.8 | yes |
| latency.p95_ms | 1.080 | <= 30.0 | yes |

Latency per call: p50 0.94 ms, p95 1.08 ms

## Held-out template families

cmd:%0A:dl, cmd:%24%28:cred, cmd:%24%28:dl, cmd:%24%28:rev, cmd:%26%26:cred, cmd:%3B:cred, cmd:%3B:misc, cmd:%3B:rev, cmd:%7C%7C:dl, cmd:%7C%7C:obf, cmd:%7C%7C:rev, cmd:%7C:recon, normal:address, normal:email, normal:filename, normal:math, normal:number, normal:password, normal:phone, normal:phrase, normal:title_case, normal:username, sqli:probe, sqli:union, trav:tricks, xss:misc, xss:script

### Family hold-out (n=2523, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.904 |
| attack_recall_at_0.8 | 0.820 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.000 |
| macro_f1 | 0.895 |

Per-class F1: normal 0.91, cmd_injection 0.99, sqli 0.58, xss 0.99, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  970     0     0     0     0
    1   338     0     0     0
  193     5   139     0     0
    5     1     1   533     0
    0     0     0     0   337
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=950, mean risk 0.016, attack rate 0.016
- 0.2-0.4: n=92, mean risk 0.294, attack rate 0.793
- 0.4-0.6: n=98, mean risk 0.466, attack rate 0.837
- 0.6-0.8: n=110, mean risk 0.69, attack rate 1.0
- 0.8-1.0: n=1273, mean risk 0.958, attack rate 1.0

### Family hold-out, model only (n=2523, fast path off)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.904 |
| attack_recall_at_0.8 | 0.820 |
| attack_precision_at_0.8 | 0.992 |
| normal_fpr_at_0.5 | 0.046 |
| macro_f1 | 0.883 |

Per-class F1: normal 0.89, cmd_injection 0.95, sqli 0.58, xss 0.99, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  939    26     2     3     0
    1   338     0     0     0
  193     5   139     0     0
    5     1     1   533     0
    0     0     0     0   337
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=757, mean risk 0.079, attack rate 0.02
- 0.2-0.4: n=182, mean risk 0.28, attack rate 0.401
- 0.4-0.6: n=187, mean risk 0.48, attack rate 0.439
- 0.6-0.8: n=114, mean risk 0.692, attack rate 0.965
- 0.8-1.0: n=1283, mean risk 0.958, attack rate 0.992

### Hard set, hold-out model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.965 |
| attack_recall_at_0.8 | 0.835 |
| attack_precision_at_0.8 | 0.986 |
| normal_fpr_at_0.5 | 0.025 |
| macro_f1 | 0.954 |

Per-class F1: normal 0.94, cmd_injection 0.96, sqli 0.92, xss 1.00, path_traversal 0.95

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   39     0     1     0     0
    1    24     0     0     0
    2     0    18     0     0
    0     0     0    20     0
    1     1     0     0    18
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=33, mean risk 0.034, attack rate 0.0
- 0.2-0.4: n=9, mean risk 0.274, attack rate 0.333
- 0.4-0.6: n=2, mean risk 0.525, attack rate 1.0
- 0.6-0.8: n=9, mean risk 0.705, attack rate 1.0
- 0.8-1.0: n=72, mean risk 0.957, attack rate 0.986

### Hard set, final model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.988 |
| attack_recall_at_0.8 | 0.871 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.025 |
| macro_f1 | 0.977 |

Per-class F1: normal 0.97, cmd_injection 0.96, sqli 0.98, xss 1.00, path_traversal 0.97

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   39     0     1     0     0
    1    24     0     0     0
    0     0    20     0     0
    0     0     0    20     0
    0     1     0     0    19
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=36, mean risk 0.044, attack rate 0.0
- 0.2-0.4: n=3, mean risk 0.276, attack rate 0.0
- 0.4-0.6: n=3, mean risk 0.514, attack rate 0.667
- 0.6-0.8: n=9, mean risk 0.733, attack rate 1.0
- 0.8-1.0: n=74, mean risk 0.971, attack rate 1.0
