# Sampling benchmark results

Generated: 2026-06-24 18:14:52 -03

Command:

```bash
rtk cargo bench --bench sampling
```

Environment:

- Repo: `/Users/lorenzord/Desktop/zk/dilithium-poc`
- Benchmark harness: Criterion
- Profile: `bench` / optimized

## Results

| Benchmark | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| --- | ---: | ---: | ---: |
| `expand_a` | 84.570-85.868 us | 146.23-147.85 us | 274.22-277.72 us |
| `expand_s` | 26.167-26.549 us | 68.626-69.080 us | 48.819-49.371 us |
| `expand_mask` | 16.013-16.060 us | 21.733-21.845 us | 30.442-30.584 us |
| `sample_in_ball` | 1.2636-1.2872 us | 1.5521-1.5723 us | 1.9378-1.9570 us |

These ranges are Criterion confidence intervals from a local run. Treat them as
local performance notes rather than normative conformance data.
