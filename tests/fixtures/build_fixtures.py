#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "manifest.toml"
BIN_ROOT = ROOT / "bin"
PROTECTED_ROOT = ROOT / "protected"
REPORT_ROOT = ROOT / "reports"
MODES = ("static", "dynamic")


@dataclasses.dataclass(frozen=True)
class DemoCase:
    name: str
    args: list[str]
    expect_stdout: str
    expect_stderr: str
    expect_exit: int


@dataclasses.dataclass(frozen=True)
class Demo:
    name: str
    source: Path
    string_probes: list[str]
    cases: list[DemoCase]


@dataclasses.dataclass(frozen=True)
class BuildResult:
    demo: str
    mode: str
    output: Path
    command: list[str]
    rebuilt: bool


def load_manifest(path: Path = MANIFEST_PATH) -> list[Demo]:
    data = tomllib.loads(path.read_text())
    demos_data = data.get("demo")
    if not isinstance(demos_data, list) or not demos_data:
        raise ValueError(f"{path} does not define any [[demo]] entries")

    demos: list[Demo] = []
    seen_names: set[str] = set()

    for item in demos_data:
        name = item["name"]
        if name in seen_names:
            raise ValueError(f"duplicate demo name: {name}")
        seen_names.add(name)

        source = ROOT / item["source"]
        probes = list(item.get("string_probes", []))
        if not probes:
            raise ValueError(f"demo {name} must define string_probes")

        cases_data = item.get("case", [])
        if not isinstance(cases_data, list) or not cases_data:
            raise ValueError(f"demo {name} must define at least one [[demo.case]]")

        cases: list[DemoCase] = []
        case_names: set[str] = set()
        for case in cases_data:
            case_name = case["name"]
            if case_name in case_names:
                raise ValueError(f"demo {name} has duplicate case name {case_name}")
            case_names.add(case_name)
            cases.append(
                DemoCase(
                    name=case_name,
                    args=list(case.get("args", [])),
                    expect_stdout=case["expect_stdout"],
                    expect_stderr=case["expect_stderr"],
                    expect_exit=int(case["expect_exit"]),
                )
            )

        demos.append(
            Demo(
                name=name,
                source=source,
                string_probes=probes,
                cases=cases,
            )
        )

    return demos


def ensure_directories() -> None:
    for root in (BIN_ROOT, PROTECTED_ROOT, REPORT_ROOT):
        root.mkdir(parents=True, exist_ok=True)
    for mode in MODES:
        (BIN_ROOT / mode).mkdir(parents=True, exist_ok=True)
        (PROTECTED_ROOT / mode).mkdir(parents=True, exist_ok=True)


def output_path(demo: Demo, mode: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return BIN_ROOT / mode / f"{demo.name}{suffix}"


def build_command(demo: Demo, mode: str, compiler: str) -> list[str]:
    command = [
        compiler,
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        str(demo.source),
        "-o",
        str(output_path(demo, mode)),
    ]
    if mode == "static":
        command[1:1] = ["-static", "-no-pie"]
    elif mode == "dynamic":
        command[1:1] = ["-fPIE", "-pie"]
    else:
        raise ValueError(f"unsupported mode: {mode}")
    return command


def needs_rebuild(output: Path, deps: list[Path]) -> bool:
    if not output.exists():
        return True
    output_mtime = output.stat().st_mtime
    return any(dep.stat().st_mtime > output_mtime for dep in deps if dep.exists())


def build_demo(
    demo: Demo,
    mode: str,
    *,
    compiler: str = "gcc",
    force: bool = False,
    quiet: bool = False,
) -> BuildResult:
    ensure_directories()
    output = output_path(demo, mode)
    command = build_command(demo, mode, compiler)
    deps = [MANIFEST_PATH, demo.source, Path(__file__)]

    if force or needs_rebuild(output, deps):
        if not quiet:
            print(f"[build] {mode:7s} {demo.name}")
        subprocess.run(command, check=True, cwd=ROOT)
        rebuilt = True
    else:
        if not quiet:
            print(f"[skip ] {mode:7s} {demo.name} (up to date)")
        rebuilt = False

    return BuildResult(demo=demo.name, mode=mode, output=output, command=command, rebuilt=rebuilt)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Phantom fixture binaries from manifest.toml")
    parser.add_argument(
        "--mode",
        choices=("static", "dynamic", "all"),
        default="all",
        help="Which binary mode to build",
    )
    parser.add_argument("--compiler", default="gcc", help="C compiler to invoke")
    parser.add_argument("--force", action="store_true", help="Rebuild even if outputs look fresh")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output")
    return parser.parse_args(argv)


def selected_modes(mode: str) -> tuple[str, ...]:
    if mode == "all":
        return MODES
    return (mode,)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    demos = load_manifest()
    ensure_directories()

    failures = 0
    for demo in demos:
        if not demo.source.exists():
            print(f"[fail ] source missing for {demo.name}: {demo.source}", file=sys.stderr)
            failures += 1
            continue
        for mode in selected_modes(args.mode):
            try:
                build_demo(
                    demo,
                    mode,
                    compiler=args.compiler,
                    force=args.force,
                    quiet=args.quiet,
                )
            except subprocess.CalledProcessError as exc:
                failures += 1
                print(
                    f"[fail ] build {mode} {demo.name} exited {exc.returncode}",
                    file=sys.stderr,
                )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
