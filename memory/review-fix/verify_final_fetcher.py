"""Exact independent final-review probes against immutable RED and current GREEN."""
import io
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = "0e8081920ce5b5c23d341ee8fd72b0099a96dca3"
EVIDENCE = pathlib.Path(os.environ.get("FETCHER_EVIDENCE", ROOT / "memory/review-fix"))
PROBES = [
    ("deadline", "adapter/provider/independent_deadline_test.go", "./adapter/provider", "TestIndependentHTTPDeadline", "--- FAIL: TestIndependentHTTPDeadlineRejectsLateSubscriptionPublication"),
    ("cache", "component/profile/cachefile/independent_review_test.go", "./component/profile/cachefile", "TestIndependent", "--- FAIL: TestIndependentOwnedLegacyLastWriteWins"),
    ("callback", "common/utils/independent_callback_test.go", "./common/utils", "TestIndependentPreparedEmit", "--- FAIL: TestIndependentPreparedEmitUnregisterBeforeAdmission"),
    ("api", "independent_api/api_test.go", "./independent_api", "TestIndependent", "missing method PrepareWrite"),
]


def run(cwd, label, command):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / (label + ".log")).write_text("$ " + " ".join(command) + "\n" + result.stdout + "\nexit=" + str(result.returncode), encoding="utf-8")
    print(label, "exit=" + str(result.returncode))
    return result


def probes(cwd, red):
    overlay = {"Replace": {str(pathlib.Path(cwd) / "adapter/provider/independent_deadline_test.go"): str(ROOT / "memory/review-fix/probes/adapter/provider/independent_deadline_test.go")}}
    overlay_path = pathlib.Path(cwd) / "memory/review-fix/final-overlay.json"
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_text(json.dumps(overlay), encoding="utf-8")
    for tags in [[], ["-tags", "with_low_memory"]]:
        for label, _, package, selector, failure in PROBES:
            result = run(cwd, ("0e808192-red-" if red else "final-green-") + label + ("-lowmem" if tags else ""), ["go", "test", "-overlay", str(overlay_path), *tags, "-json", package, "-run", selector, "-count=1", "-timeout=60s"])
            if red:
                if result.returncode != 1 or failure not in result.stdout:
                    raise SystemExit("immutable RED assertion absent: " + label)
                if label == "cache" and "--- FAIL: TestIndependentCacheReceiverIsolation" not in result.stdout:
                    raise SystemExit("immutable cache isolation RED absent")
            elif result.returncode != 0:
                raise SystemExit("GREEN failure: " + label)


def red():
    with tempfile.TemporaryDirectory(prefix=".final-red-", dir=EVIDENCE) as tmp:
        root = pathlib.Path(tmp)
        core = root / "mihomo"
        core.mkdir()
        archive = subprocess.check_output(["git", "archive", BASE], cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(core, filter="data")
        # Exact fixed sibling module; never use a drifting branch or stub.
        dependency = ROOT.parent / "sing-shadowsocks2"
        expected = "0e35d2749fdc58d18dd7d612482adbfbd362c8f3"
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=dependency, text=True).strip()
        if actual != expected:
            raise SystemExit("unexpected dependency SHA: " + actual)
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(["git", "archive", expected], cwd=dependency))) as stream:
            stream.extractall(root / "sing-shadowsocks2", filter="data")
        for _, path, _, _, _ in PROBES:
            target = core / path
            target.parent.mkdir(parents=True, exist_ok=True)
            source = ROOT / path
            if not source.exists():
                source = ROOT / "memory/review-fix/probes" / path
            shutil.copyfile(source, target)
        probes(core, True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["red", "green"])
    args = parser.parse_args()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for repetition in range(3):
        red() if args.mode == "red" else probes(ROOT, False)
        for log in EVIDENCE.glob(("0e808192-red-" if args.mode == "red" else "final-green-") + "*.log"):
            if "-repeat-" not in log.stem:
                shutil.copyfile(log, log.with_name(log.stem + f"-repeat-{repetition + 1}.log"))
    (ROOT / "memory/review-fix/final-overlay.json").unlink(missing_ok=True)
