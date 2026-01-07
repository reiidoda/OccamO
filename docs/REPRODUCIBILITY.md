# Reproducibility (Dynamic Verification)

Dynamic verification runs user code, so measurements can vary with CPU
frequency scaling, VM contention, and background processes. OccamO provides
controls to reduce noise and detect unreliable results.

## Controls

- `dynamic_warmups`: warmup runs per size before timing.
- `dynamic_trials`: repeat measurements and use the median.
- `dynamic_timeout_seconds`: cap runtime per check.
- `dynamic_jitter_threshold`: mark results inconclusive when variance is high.
- `dynamic_memory_limit_mb`: soft memory cap for the subprocess.

OccamO also sets `PYTHONHASHSEED=0` and a fixed random seed for the probe
process to reduce nondeterminism.

## Recommended CI settings

- Run dynamic verification only on trusted, stable runners.
- Prefer a pinned container image for consistent environments.
- Avoid running heavy jobs concurrently on the same runner.
- Use `dynamic_jitter_threshold` to avoid flaky gating.
- Set `dynamic_jitter_threshold: 0` to disable variance gating.

## Result interpretation

If confidence is low or variance exceeds the threshold, OccamO marks the
result as `inconclusive` and does not confirm or downgrade the static finding.
