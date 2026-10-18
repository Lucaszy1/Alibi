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
