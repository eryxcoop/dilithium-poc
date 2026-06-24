# Signing-loop repetition results

Generated: 2026-06-24 20:15:42 -0300

Command:

```bash
rtk cargo bench --bench signing_repetitions --features instrumentation
```

Environment:

- Repo: `/Users/lorenzord/Desktop/zk/dilithium-poc`
- Benchmark harness: custom `harness = false` benchmark
- Profile: `bench` / optimized
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Host: `aarch64-apple-darwin`
- Samples per parameter set: 1024

## Results

| Parameter set | FIPS expected repetitions | Observed mean attempts | Min | Max | Histogram |
| --- | ---: | ---: | ---: | ---: | --- |
| ML-DSA-44 | 4.25 | 4.17 | 1 | 21 | `1:217, 2:206, 3:142, 4:121, 5:82, 6:66, 7:44, 8:31, 9:32, 10:19, 11:13, 12:9, 13:14, 14:7, 15:5, 16:7, 17:3, 19:2, 20:1, 21:3` |
| ML-DSA-65 | 5.10 | 5.12 | 1 | 29 | `1:192, 2:155, 3:138, 4:111, 5:71, 6:66, 7:55, 8:53, 9:26, 10:28, 11:33, 12:19, 13:20, 14:20, 15:9, 16:9, 17:4, 19:6, 20:1, 21:1, 22:2, 23:1, 24:2, 27:1, 29:1` |
| ML-DSA-87 | 3.85 | 3.83 | 1 | 28 | `1:282, 2:183, 3:128, 4:117, 5:87, 6:60, 7:45, 8:35, 9:24, 10:14, 11:14, 12:5, 13:11, 14:3, 15:3, 16:4, 17:4, 18:3, 19:1, 28:1` |

These observed means are in the same order of magnitude as the FIPS 204
expected repetition counts. They are local instrumentation notes, not normative
conformance data or KAT evidence.
