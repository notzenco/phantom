#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import build_fixtures


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build, obfuscate, run, and report on Phantom demo fixtures")
    parser.add_argument(
        "--mode",
        choices=("static", "dynamic", "all"),
        default="all",
        help="Which binary mode to exercise",
    )
    parser.add_argument("--profile", default="strings", help="Protection profile to pass to phantom-cli")
    parser.add_argument("--compiler", default="gcc", help="C compiler to invoke during fixture builds")
    parser.add_argument("--force-build", action="store_true", help="Force rebuilding fixture binaries")
    parser.add_argument(
        "--phantom-bin",
        help="Path to a phantom-cli binary. Defaults to cargo run -q -p phantom-cli --",
    )
    parser.add_argument(
        "--json-out",
        default=str(build_fixtures.REPORT_ROOT / "obfuscation_matrix.json"),
        help="Path to the JSON report to write",
    )
    return parser.parse_args(argv)


def phantom_command(args: argparse.Namespace, input_path: Path, output_path: Path) -> list[str]:
    if args.phantom_bin:
        return [
            args.phantom_bin,
            "protect",
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "--profile",
            args.profile,
        ]
    return [
        "cargo",
        "run",
        "-q",
        "-p",
        "phantom-cli",
        "--",
        "protect",
        "-i",
        str(input_path),
        "-o",
        str(output_path),
        "--profile",
        args.profile,
    ]


def run_command(command: list[str], cwd: Path) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    duration_ms = (time.perf_counter() - start) * 1000
    return proc.returncode, proc.stdout, proc.stderr, duration_ms


def stage_record(
    *,
    demo: str,
    case: str,
    mode: str,
    stage: str,
    status: str,
    started_at: str,
    duration_ms: float,
    command: list[str] | None = None,
    artifact_path: Path | None = None,
    failure_reason: str | None = None,
    details: dict | None = None,
) -> dict:
    return {
        "demo": demo,
        "case": case,
        "mode": mode,
        "stage": stage,
        "status": status,
        "started_at": started_at,
        "duration_ms": round(duration_ms, 3),
        "command": command,
        "artifact_path": str(artifact_path) if artifact_path else None,
        "failure_reason": failure_reason,
        "details": details or {},
    }


def compare_behavior(case, returncode: int, stdout: str, stderr: str) -> str | None:
    if returncode != case.expect_exit:
        return f"expected exit {case.expect_exit}, got {returncode}"
    if stdout != case.expect_stdout:
        return f"stdout mismatch: expected {case.expect_stdout!r}, got {stdout!r}"
    if stderr != case.expect_stderr:
        return f"stderr mismatch: expected {case.expect_stderr!r}, got {stderr!r}"
    return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    demos = build_fixtures.load_manifest()
    build_fixtures.ensure_directories()

    json_out = Path(args.json_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    build_cache: dict[tuple[str, str], build_fixtures.BuildResult] = {}
    protect_cache: dict[tuple[str, str], tuple[Path, list[str], int, str, str, float]] = {}
    failure_count = 0

    for demo in demos:
        for mode in build_fixtures.selected_modes(args.mode):
            build_key = (demo.name, mode)
            build_started = now_iso()
            build_failure: str | None = None

            if build_key not in build_cache:
                try:
                    build_cache[build_key] = build_fixtures.build_demo(
                        demo,
                        mode,
                        compiler=args.compiler,
                        force=args.force_build,
                        quiet=True,
                    )
                except subprocess.CalledProcessError as exc:
                    build_failure = f"build exited {exc.returncode}"
                    build_cache[build_key] = build_fixtures.BuildResult(
                        demo=demo.name,
                        mode=mode,
                        output=build_fixtures.output_path(demo, mode),
                        command=build_fixtures.build_command(demo, mode, args.compiler),
                        rebuilt=True,
                    )

            build_result = build_cache[build_key]

            if build_failure is None and not build_result.output.exists():
                build_failure = f"missing build output {build_result.output}"

            if build_failure:
                failure_count += len(demo.cases)

            for case in demo.cases:
                records.append(
                    stage_record(
                        demo=demo.name,
                        case=case.name,
                        mode=mode,
                        stage="build",
                        status="failed" if build_failure else "passed",
                        started_at=build_started,
                        duration_ms=0.0,
                        command=build_result.command,
                        artifact_path=build_result.output,
                        failure_reason=build_failure,
                        details={"rebuilt": build_result.rebuilt},
                    )
                )

                if build_failure:
                    for skipped_stage in ("baseline_run", "protect", "string_scan", "protected_run"):
                        records.append(
                            stage_record(
                                demo=demo.name,
                                case=case.name,
                                mode=mode,
                                stage=skipped_stage,
                                status="skipped",
                                started_at=now_iso(),
                                duration_ms=0.0,
                                failure_reason="build failed",
                            )
                        )
                    print(f"[FAIL] {demo.name}/{case.name}/{mode}: build failed")
                    continue

                baseline_cmd = [str(build_result.output), *case.args]
                baseline_started = now_iso()
                rc, stdout, stderr, duration_ms = run_command(baseline_cmd, build_fixtures.ROOT)
                baseline_failure = compare_behavior(case, rc, stdout, stderr)
                if baseline_failure:
                    failure_count += 1
                records.append(
                    stage_record(
                        demo=demo.name,
                        case=case.name,
                        mode=mode,
                        stage="baseline_run",
                        status="failed" if baseline_failure else "passed",
                        started_at=baseline_started,
                        duration_ms=duration_ms,
                        command=baseline_cmd,
                        artifact_path=build_result.output,
                        failure_reason=baseline_failure,
                        details={"stdout": stdout, "stderr": stderr, "returncode": rc},
                    )
                )

                protect_key = build_key
                protect_started = now_iso()
                if protect_key not in protect_cache:
                    protected_path = build_fixtures.PROTECTED_ROOT / mode / f"{demo.name}--{args.profile}"
                    protect_cmd = phantom_command(args, build_result.output, protected_path)
                    protect_rc, protect_out, protect_err, protect_ms = run_command(
                        protect_cmd, build_fixtures.ROOT.parent.parent
                    )
                    protect_cache[protect_key] = (
                        protected_path,
                        protect_cmd,
                        protect_rc,
                        protect_out,
                        protect_err,
                        protect_ms,
                    )

                protected_path, protect_cmd, protect_rc, protect_out, protect_err, protect_ms = protect_cache[protect_key]
                protect_failure = None
                if protect_rc != 0:
                    protect_failure = f"protect exited {protect_rc}"
                elif not protected_path.exists():
                    protect_failure = f"missing protected output {protected_path}"
                if protect_failure:
                    failure_count += 1
                records.append(
                    stage_record(
                        demo=demo.name,
                        case=case.name,
                        mode=mode,
                        stage="protect",
                        status="failed" if protect_failure else "passed",
                        started_at=protect_started,
                        duration_ms=protect_ms,
                        command=protect_cmd,
                        artifact_path=protected_path,
                        failure_reason=protect_failure,
                        details={"stdout": protect_out, "stderr": protect_err, "returncode": protect_rc},
                    )
                )

                string_started = now_iso()
                string_failure = None
                probe_hits: list[str] = []
                if not protect_failure:
                    data = protected_path.read_bytes()
                    for probe in demo.string_probes:
                        if probe.encode() in data:
                            probe_hits.append(probe)
                    if probe_hits:
                        string_failure = f"plaintext probes still present: {', '.join(probe_hits)}"
                        failure_count += 1
                else:
                    string_failure = "protect failed"
                records.append(
                    stage_record(
                        demo=demo.name,
                        case=case.name,
                        mode=mode,
                        stage="string_scan",
                        status="failed" if string_failure and string_failure != "protect failed" else ("skipped" if string_failure == "protect failed" else "passed"),
                        started_at=string_started,
                        duration_ms=0.0,
                        artifact_path=protected_path,
                        failure_reason=string_failure if string_failure else None,
                        details={"probe_hits": probe_hits, "string_probes": demo.string_probes},
                    )
                )

                protected_started = now_iso()
                if protect_failure:
                    records.append(
                        stage_record(
                            demo=demo.name,
                            case=case.name,
                            mode=mode,
                            stage="protected_run",
                            status="skipped",
                            started_at=protected_started,
                            duration_ms=0.0,
                            failure_reason="protect failed",
                        )
                    )
                    print(f"[FAIL] {demo.name}/{case.name}/{mode}: protect failed")
                    continue

                protected_cmd = [str(protected_path), *case.args]
                prc, pstdout, pstderr, protected_ms = run_command(protected_cmd, build_fixtures.ROOT)
                protected_failure = compare_behavior(case, prc, pstdout, pstderr)
                if protected_failure:
                    failure_count += 1
                records.append(
                    stage_record(
                        demo=demo.name,
                        case=case.name,
                        mode=mode,
                        stage="protected_run",
                        status="failed" if protected_failure else "passed",
                        started_at=protected_started,
                        duration_ms=protected_ms,
                        command=protected_cmd,
                        artifact_path=protected_path,
                        failure_reason=protected_failure,
                        details={"stdout": pstdout, "stderr": pstderr, "returncode": prc},
                    )
                )

                overall = "PASS" if not any(
                    record["status"] == "failed"
                    for record in records[-4:]
                ) else "FAIL"
                print(f"[{overall}] {demo.name}/{case.name}/{mode}")

    summary = {
        "generated_at": now_iso(),
        "profile": args.profile,
        "mode": args.mode,
        "record_count": len(records),
        "failure_count": failure_count,
        "status": "failed" if failure_count else "passed",
    }
    json_out.write_text(json.dumps({"summary": summary, "records": records}, indent=2))
    print(f"[report] {json_out}")
    return 1 if failure_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
