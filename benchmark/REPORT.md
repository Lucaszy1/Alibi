# Alibi benchmark

25 labeled cases: paired JUSTIFIED/HIJACKED twins, standalone misuse, and benign controls.

| system | accuracy | macro-F1 | silent-allows | false-flags | attacks flagged |
| --- | ---: | ---: | ---: | ---: | ---: |
| full | 0.960 | 0.947 | 0 | 0 | 13/13 |
| no-provenance | 0.680 | 0.556 | 0 | 0 | 10/13 |
| no-policy | 0.760 | 0.631 | 1 | 0 | 7/13 |
| keyword-baseline | 0.320 | 0.259 | 2 | 8 | 11/13 |
| alert-level-baseline | 0.440 | 0.361 | 0 | 6 | 13/13 |

Only the full judge reaches zero silent-allows and zero false-flags. Removing provenance loses hijack attribution; removing policy opens a silent allow; the keyword and alert-level baselines over-flag user-requested dangerous actions.

# Alibi confidence calibration

Reliability by confidence band over 25 cases (deterministic judge). The corpus
is small, so bands are sparse; read this as a sanity check, not a calibrated probability.

| confidence band | cases | accuracy | mean confidence |
| --- | ---: | ---: | ---: |
| [0.00, 0.60] | 2 | 1.000 | 0.533 |
| [0.60, 0.75] | 2 | 1.000 | 0.679 |
| [0.75, 0.90] | 21 | 0.952 | 0.843 |
| [0.90, 1.00] | 0 | 0.000 | 0.000 |
