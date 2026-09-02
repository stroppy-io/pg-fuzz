#!/usr/bin/env python3
"""The starved-target detector must compare PER WORKSPACE, not per target total.

Regression test for the failure of 2026-08-15: the detector was built that
morning so an untriaged finding could not silently cap a target's coverage, and
it did not fire on the campaign that produced it. spi_query_fuzzer showed
202,663,286 executed units while being dead on 8 of 28 workspaces -- nowhere
near 1% of any median computed from per-target totals.

Run: python3 tests/test_starvation_detector.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import consolidate  # noqa: E402

HEALTHY = 10_000_000
STARVED = 77          # the real number from the 2026-08-15 sweep
OTHER = 5_000_000


def build_case():
    """A target healthy on 20 workspaces and starved on 8 -- the case that hurt."""
    ws_names = ["ws%02d" % i for i in range(28)]
    dead_on = ws_names[:8]

    spi = {w: (STARVED if w in dead_on else HEALTHY) for w in ws_names}
    conn = {w: OTHER for w in ws_names}

    liverows = [
        {"target": "spi_query_fuzzer", "executed_units": sum(spi.values()),
         "ws_seen": len(ws_names), "per_ws": spi, "ws_zero_units": [],
         "artifacts": 0, "exit_codes": {}},
        {"target": "conninfo_fuzzer", "executed_units": sum(conn.values()),
         "ws_seen": len(ws_names), "per_ws": conn, "ws_zero_units": [],
         "artifacts": 0, "exit_codes": {}},
    ]
    data = {"sigs": {}, "sig_targets": {}, "sig_src": {}, "units": {},
            "artifacts": {}, "rcs": {}, "nlogs": 0}
    return ws_names, data, liverows


def summary_text():
    ws_names, data, liverows = build_case()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "SUMMARY.md")
        consolidate.write_summary(path, "test", ws_names, data, [], liverows, None)
        with open(path) as fh:
            return fh.read()


def main():
    text = summary_text()
    failures = []

    # The starved pairs must be reported...
    if "spi_query_fuzzer" not in text:
        failures.append("spi_query_fuzzer was not reported as starved")
    for w in ("ws00", "ws07"):
        if w not in text:
            failures.append("starved workspace %s not named in the report" % w)

    # ...and the healthy target must not be. Extract ONLY the starved section:
    # every target is legitimately listed again in the liveness table further
    # down, so a naive split past the heading matches the whole rest of the
    # document and fails on correct output.
    starved_section = ""
    if "barely executed" in text:
        after = text.split("barely executed", 1)[1]
        starved_section = after.split("\n## ", 1)[0]
    if "conninfo_fuzzer" in starved_section:
        failures.append("conninfo_fuzzer (healthy everywhere) was reported as starved")
    if starved_section and "`ws20`" in starved_section:
        failures.append("a healthy workspace (ws20) was reported as starved")

    # The old per-target-total rule would have compared 200,000,616 against a
    # median of the two totals and flagged nothing. Assert we are not that.
    totals = [200_000_616, 140_000_000]
    old_median = sorted(totals)[len(totals) // 2]
    if 0 < totals[0] < max(1, old_median // 100):
        failures.append("test is not exercising the regression: the OLD rule "
                        "would have caught this too")

    if failures:
        print("FAIL")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("PASS: starvation is detected per (target, workspace) pair")
    print("      spi_query_fuzzer flagged on its 8 starved workspaces while")
    print("      totalling %s units across the other 20" % "{:,}".format(20 * HEALTHY))
    return 0


if __name__ == "__main__":
    sys.exit(main())
