# Alibi benchmark

15 labeled cases: paired JUSTIFIED/HIJACKED twins, standalone misuse, and benign controls.

| system | accuracy | macro-F1 | silent-allows | false-flags | attacks flagged |
| --- | ---: | ---: | ---: | ---: | ---: |
| full | 0.933 | 0.915 | 0 | 0 | 8/8 |
| no-provenance | 0.667 | 0.556 | 0 | 0 | 6/8 |
| no-policy | 0.733 | 0.607 | 1 | 0 | 4/8 |
| keyword-baseline | 0.267 | 0.201 | 0 | 6 | 8/8 |
| alert-level-baseline | 0.467 | 0.385 | 0 | 3 | 8/8 |

Only the full judge reaches zero silent-allows and zero false-flags. Removing provenance loses hijack attribution; removing policy opens a silent allow; the keyword and alert-level baselines over-flag user-requested dangerous actions.
