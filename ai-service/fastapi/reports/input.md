# Input-risk model report (v1, 7000 training rows)

## Targets

| target | value | required | ok |
| --- | --- | --- | --- |
| family_holdout.attack_precision_at_0.8 | 1.000 | >= 0.9 | yes |
| family_holdout.normal_fpr_at_0.5 | 0.000 | <= 0.02 | yes |
| family_holdout.attack_recall_at_0.5 | 0.836 | >= 0.8 | yes |
| hard_set_holdout_model.attack_recall_at_0.5 | 0.965 | >= 0.95 | yes |
| hard_set_holdout_model.macro_f1 | 0.946 | >= 0.8 | yes |
| latency.p95_ms | 1.510 | <= 30.0 | yes |

Latency per call: p50 0.9 ms, p95 1.51 ms

## Held-out template families

cmd:%24%28:misc, cmd:%24%28:obf, cmd:%24%28:rev, cmd:%250a:cred, cmd:%250a:rev, cmd:%26%26:obf, cmd:%3B:cred, cmd:%60:dl, cmd:%7C%7C:cred, cmd:%7C%7C:dl, cmd:%7C:cred, cmd:%7C:obf, normal:address, normal:email, normal:host, normal:ip, normal:json, normal:price, normal:search, normal:username, sqli:error, sqli:tautology, trav:tricks, xss:tags, xss:url

### Family hold-out (n=1907, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.836 |
| attack_recall_at_0.8 | 0.745 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.000 |
| macro_f1 | 0.859 |

Per-class F1: normal 0.86, cmd_injection 0.92, sqli 0.96, xss 0.56, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  701     0     0     0     0
    1   260     0     0     0
   20     0   243     0     0
  215    43     0   162     0
    0     0     0     0   262
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=732, mean risk 0.017, attack rate 0.102
- 0.2-0.4: n=111, mean risk 0.304, attack rate 0.604
- 0.4-0.6: n=123, mean risk 0.502, attack rate 1.0
- 0.6-0.8: n=42, mean risk 0.708, attack rate 1.0
- 0.8-1.0: n=899, mean risk 0.969, attack rate 1.0

### Family hold-out, model only (n=1907, fast path off)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.836 |
| attack_recall_at_0.8 | 0.745 |
| attack_precision_at_0.8 | 0.987 |
| normal_fpr_at_0.5 | 0.036 |
| macro_f1 | 0.848 |

Per-class F1: normal 0.84, cmd_injection 0.89, sqli 0.95, xss 0.56, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  678    20     3     0     0
    1   260     0     0     0
   20     0   243     0     0
  215    43     0   162     0
    0     0     0     0   262
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=623, mean risk 0.084, attack rate 0.12
- 0.2-0.4: n=176, mean risk 0.288, attack rate 0.381
- 0.4-0.6: n=145, mean risk 0.5, attack rate 0.848
- 0.6-0.8: n=52, mean risk 0.709, attack rate 0.808
- 0.8-1.0: n=911, mean risk 0.968, attack rate 0.987

### Hard set, hold-out model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.965 |
| attack_recall_at_0.8 | 0.859 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.050 |
| macro_f1 | 0.946 |

Per-class F1: normal 0.93, cmd_injection 0.96, sqli 0.98, xss 0.95, path_traversal 0.92

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   38     1     1     0     0
    0    25     0     0     0
    0     0    20     0     0
    2     0     0    18     0
    2     1     0     0    17
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=29, mean risk 0.024, attack rate 0.0
- 0.2-0.4: n=10, mean risk 0.268, attack rate 0.1
- 0.4-0.6: n=7, mean risk 0.514, attack rate 0.714
- 0.6-0.8: n=6, mean risk 0.743, attack rate 1.0
- 0.8-1.0: n=73, mean risk 0.956, attack rate 1.0

### Hard set, final model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 1.000 |
| attack_recall_at_0.8 | 0.871 |
| attack_precision_at_0.8 | 0.987 |
| normal_fpr_at_0.5 | 0.075 |
| macro_f1 | 0.954 |

Per-class F1: normal 0.94, cmd_injection 0.96, sqli 0.93, xss 1.00, path_traversal 0.95

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   37     1     2     0     0
    0    25     0     0     0
    1     0    19     0     0
    0     0     0    20     0
    1     1     0     0    18
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=31, mean risk 0.031, attack rate 0.0
- 0.2-0.4: n=6, mean risk 0.258, attack rate 0.0
- 0.4-0.6: n=2, mean risk 0.525, attack rate 1.0
- 0.6-0.8: n=11, mean risk 0.706, attack rate 0.818
- 0.8-1.0: n=75, mean risk 0.967, attack rate 0.987
