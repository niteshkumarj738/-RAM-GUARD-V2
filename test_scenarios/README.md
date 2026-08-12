# Test scenarios — validating RAM-Guard's detectors

These scripts deliberately trigger each detector under a **known, controlled
condition**, so detection can be verified against ground truth instead of
just claimed. None of them attack anything — they only allocate memory in
their own process to reproduce the pattern each detector looks for.

| Script | Triggers | What it does |
|---|---|---|
| `high_memory_hog.py` | `high_memory` | Allocates a fixed % of total system RAM |
| `leak_simulator.py` | `leak_suspect` | Grows RSS at a known, steady MB/min rate |
| `wx_page_demo.py` | `wx_pages` | Maps one page as writable+executable (Linux only) |

## Running a validation yourself

Terminal 1 — start a scenario:
```bash
python test_scenarios/leak_simulator.py --mb-per-sec 0.8 --duration 60
```

Terminal 2 — watch RAM-Guard catch it:
```bash
python main.py          # continuous mode, or:
python main.py --once   # single pass (run a few times, a few seconds apart)
```

Look for a log line / desktop popup naming the same PID the scenario script
printed at startup.

## Triggering the combined-risk escalation

Run `leak_simulator.py` at a rate that also crosses the memory percentage
threshold (e.g. `--mb-per-sec 3` on a small machine) — once both
`high_memory` and `leak_suspect` fire on the same PID in the same pass, a
`combined_risk` finding is raised on top of the two individual ones. See
`VALIDATION_RESULTS.md` for an actual captured run.
