"""Fetcher independent review gates; execute from core repository root."""
import argparse
import json
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "memory/review-fix"
BASE = "e951c76d2ee9ade5cfb106edfaaafe114e0683e4"


def run(label, args, expected=0):
    result = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = "$ " + " ".join(args) + "\n" + result.stdout + f"\nexit={result.returncode}\n"
    (EVIDENCE / f"{label}.log").write_text(output, encoding="utf-8")
    print(output)
    if result.returncode != expected:
        raise SystemExit(f"{label}: expected exit {expected}, got {result.returncode}")
    return result.stdout


def baseline():
    # Go's source overlay runs the immutable original production Fetcher with
    # the same exported-API assertions. No checkout/reset or worktree rewrite.
    with tempfile.TemporaryDirectory(dir=EVIDENCE, prefix=".baseline-") as tmp:
        tmp = pathlib.Path(tmp)
        source = subprocess.check_output(["git", "show", f"{BASE}:component/resource/fetcher.go"], cwd=ROOT, text=True)
        (tmp / "fetcher.go").write_text(source, encoding="utf-8")
        tests = (ROOT / "component/resource/fetcher_review_test.go").read_text()
        selected = ["TestReviewCallbackCloseReentry", "TestReviewSlowCallbackCloseBound", "TestReviewClosedUpdateStartsNoRead"]
        # Extract complete top-level functions with brace-depth; the probe helper
        # block uses current Vehicle's staging method only for interface parity.
        def function(name):
            start = tests.index("func " + name + "(")
            brace = tests.index("{", start)
            depth = 1
            end = brace + 1
            while depth:
                depth += (tests[end] == "{") - (tests[end] == "}")
                end += 1
            return tests[start:end]
        helper = tests[tests.index("type reviewReadVehicle struct"):tests.index("func TestReviewClosedUpdateStartsNoRead")]
        header = '''package resource
import("context";"os";"path/filepath";"sync/atomic";"testing";"time";"github.com/metacubex/mihomo/common/utils";P "github.com/metacubex/mihomo/constant/provider")
'''
        (tmp / "probe_test.go").write_text(header + helper + "\n" + "\n".join(function(n) for n in selected), encoding="utf-8")
        overlay = {"Replace": {str(ROOT / "component/resource/fetcher.go"): str(tmp / "fetcher.go"), str(ROOT / "component/resource/fetcher_review_test.go"): str(tmp / "probe_test.go")}}
        (tmp / "overlay.json").write_text(json.dumps(overlay), encoding="utf-8")
        out = run("baseline-red", ["go", "test", "-overlay", str(tmp / "overlay.json"), "./component/resource", "-run", "^TestReview", "-count=1", "-v"], expected=1)
        for name in selected:
            if "--- FAIL: " + name not in out:
                raise SystemExit(f"baseline not proven RED: {name}")


def green():
    packages = ["./component/resource", "./adapter/provider", "./rules/provider", "./tunnel", "./common/utils", "./component/profile/cachefile"]
    run("normal-green", ["go", "test", *packages, "-count=1", "-v"])
    run("lowmem-green", ["go", "test", "-tags", "with_low_memory", *packages, "-count=1", "-v"])
    # HTTP ownership fixtures close the cache singleton: repeat in fresh Go
    # test processes, not -count=10 inside one process with a closed receiver.
    for iteration in range(10):
        run(f"stress-green-{iteration + 1}", ["go", "test", "./component/resource", "./adapter/provider", "./rules/provider", "-run", "TestReview|Test.*FetcherCloseRevokes|TestOwnedProvider|TestSidecarRejectsRevoked", "-count=1", "-v"])
        run(f"lowmem-stress-green-{iteration + 1}", ["go", "test", "-tags", "with_low_memory", "./component/resource", "./adapter/provider", "./rules/provider", "-run", "TestReview|Test.*FetcherCloseRevokes|TestOwnedProvider|TestSidecarRejectsRevoked", "-count=1", "-v"])
    run("vet-green", ["go", "vet", *packages])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["baseline", "green"])
    args = parser.parse_args()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    baseline() if args.mode == "baseline" else green()
