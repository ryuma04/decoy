# Input-risk model report (v2.1, 9000 training rows)

## Targets

| target | value | required | ok |
| --- | --- | --- | --- |
| family_holdout.attack_precision_at_0.8 | 1.000 | >= 0.9 | yes |
| family_holdout.normal_fpr_at_0.5 | 0.005 | <= 0.02 | yes |
| family_holdout.attack_recall_at_0.5 | 0.846 | >= 0.8 | yes |
| hard_set_holdout_model.attack_recall_at_0.5 | 0.976 | >= 0.95 | yes |
| hard_set_holdout_model.macro_f1 | 0.950 | >= 0.8 | yes |
| latency.p95_ms | 1.980 | <= 30.0 | yes |

Latency per call: p50 1.32 ms, p95 1.98 ms

## Held-out template families

cmd:%0A:dl, cmd:%24%28:cred, cmd:%24%28:dl, cmd:%24%28:rev, cmd:%26%26:cred, cmd:%3B:cred, cmd:%3B:misc, cmd:%3B:rev, cmd:%7C%7C:dl, cmd:%7C%7C:obf, cmd:%7C%7C:rev, cmd:%7C:recon, normal:address, normal:email, normal:filename, normal:math, normal:number, normal:password, normal:phone, normal:phrase, normal:title_case, normal:username, sqli:in_text, sqli:stacked, sqli:union, trav:tricks, xss:script, xss:tags

### Family hold-out (n=2636, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.846 |
| attack_recall_at_0.8 | 0.680 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.005 |
| macro_f1 | 0.857 |

Per-class F1: normal 0.87, cmd_injection 0.89, sqli 0.88, xss 0.65, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  965     0     5     0     0
    3   336     0     0     0
   92     2   356     0     0
  199    79     0   262     0
    0     0     0     0   337
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=995, mean risk 0.027, attack rate 0.072
- 0.2-0.4: n=136, mean risk 0.286, attack rate 0.801
- 0.4-0.6: n=164, mean risk 0.499, attack rate 0.878
- 0.6-0.8: n=208, mean risk 0.724, attack rate 1.0
- 0.8-1.0: n=1133, mean risk 0.958, attack rate 1.0

### Family hold-out, model only (n=2636, fast path off)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.846 |
| attack_recall_at_0.8 | 0.680 |
| attack_precision_at_0.8 | 0.990 |
| normal_fpr_at_0.5 | 0.077 |
| macro_f1 | 0.845 |

Per-class F1: normal 0.85, cmd_injection 0.86, sqli 0.86, xss 0.65, path_traversal 1.00

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
  927    21    21     1     0
    3   336     0     0     0
   92     2   356     0     0
  199    79     0   262     0
    0     0     0     0   337
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=755, mean risk 0.087, attack rate 0.095
- 0.2-0.4: n=287, mean risk 0.293, attack rate 0.38
- 0.4-0.6: n=205, mean risk 0.501, attack rate 0.702
- 0.6-0.8: n=245, mean risk 0.716, attack rate 0.849
- 0.8-1.0: n=1144, mean risk 0.957, attack rate 0.99

### Hard set, hold-out model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.976 |
| attack_recall_at_0.8 | 0.835 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.000 |
| macro_f1 | 0.950 |

Per-class F1: normal 0.95, cmd_injection 0.96, sqli 1.00, xss 0.92, path_traversal 0.92

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   40     0     0     0     0
    0    25     0     0     0
    0     0    20     0     0
    2     1     0    17     0
    2     1     0     0    17
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=35, mean risk 0.044, attack rate 0.0
- 0.2-0.4: n=5, mean risk 0.267, attack rate 0.2
- 0.4-0.6: n=5, mean risk 0.515, attack rate 0.8
- 0.6-0.8: n=9, mean risk 0.711, attack rate 1.0
- 0.8-1.0: n=71, mean risk 0.96, attack rate 1.0

### Hard set, final model (n=125, fast path on)

| metric | value |
| --- | --- |
| attack_recall_at_0.5 | 0.988 |
| attack_recall_at_0.8 | 0.918 |
| attack_precision_at_0.8 | 1.000 |
| normal_fpr_at_0.5 | 0.025 |
| macro_f1 | 0.985 |

Per-class F1: normal 0.97, cmd_injection 1.00, sqli 0.98, xss 1.00, path_traversal 0.97

Confusion (rows = true, cols = predicted, order normal, cmd_injection, sqli, xss, path_traversal):

```
   39     0     1     0     0
    0    25     0     0     0
    0     0    20     0     0
    0     0     0    20     0
    1     0     0     0    19
```

Calibration (risk bucket → observed attack rate):

- 0.0-0.2: n=36, mean risk 0.04, attack rate 0.0
- 0.2-0.4: n=3, mean risk 0.24, attack rate 0.0
- 0.4-0.6: n=2, mean risk 0.521, attack rate 1.0
- 0.6-0.8: n=6, mean risk 0.697, attack rate 0.833
- 0.8-1.0: n=78, mean risk 0.966, attack rate 1.0
