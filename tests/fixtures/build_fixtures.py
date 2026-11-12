#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "manifest.toml"
BIN_ROOT = ROOT / "bin"
PROTECTED_ROOT = ROOT / "protected"
REPORT_ROOT = ROOT / "reports"


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


@dataclasses.dataclass(frozen=True)
class Target:
    mode: str
    description: str
    compilers: tuple[str, ...]
    flags: tuple[str, ...]
    magic: bytes
    suffix: str = ""


TARGETS: dict[str, Target] = {
    target.mode: target
    for target in (
        Target("static", "x86-64 Linux ELF, static", ("gcc", "cc"), ("-static", "-no-pie"), b"\x7fELF"),
        Target("dynamic", "x86-64 Linux ELF, PIE", ("gcc", "cc"), ("-fPIE", "-pie"), b"\x7fELF"),
        Target("pe", "x86-64 Windows PE (MinGW)", ("x86_64-w64-mingw32-gcc", "gcc"), (), b"MZ", ".exe"),
    )
}
MODES = tuple(TARGETS)


@dataclasses.dataclass(frozen=True)
class HostPlan:
    """How this host builds and executes binaries for one target."""

    target: Target
    compiler: str
    runner: tuple[str, ...]


def _machine() -> str:
    return platform.machine().lower()


def _first_tool(names: tuple[str, ...]) -> str | None:
    return next((name for name in names if shutil.which(name)), None)


def host_plan(mode: str, compiler_override: str | None = None) -> HostPlan | None:
    """Return a build/run plan for `mode`, or None when this host cannot execute it."""
    target = TARGETS[mode]
    x86_64 = _machine() in ("x86_64", "amd64")
    runner: tuple[str, ...] = ()

    if mode in ("static", "dynamic"):
        if not (sys.platform.startswith("linux") and x86_64):
            return None
        compiler = _first_tool(target.compilers)
    elif mode == "pe":
        if sys.platform == "win32" and x86_64:
            compiler = _first_tool(("gcc", "x86_64-w64-mingw32-gcc"))
        elif sys.platform.startswith("linux") and x86_64:
            wine = _first_tool(("wine64", "wine"))
            if wine is None:
                return None
            runner = (wine,)
            compiler = _first_tool(("x86_64-w64-mingw32-gcc",))
        else:
            return None
    else:
        raise ValueError(f"unsupported mode: {mode}")

    compiler = compiler_override or compiler
    if compiler is None:
        return None
    return HostPlan(target=target, compiler=compiler, runner=runner)


def available_modes(compiler_override: str | None = None) -> tuple[str, ...]:
    return tuple(mode for mode in MODES if host_plan(mode, compiler_override) is not None)


def ensure_directories() -> None:
    for root in (BIN_ROOT, PROTECTED_ROOT, REPORT_ROOT):
        root.mkdir(parents=True, exist_ok=True)
    for mode in MODES:
        (BIN_ROOT / mode).mkdir(parents=True, exist_ok=True)
        (PROTECTED_ROOT / mode).mkdir(parents=True, exist_ok=True)


def output_path(demo: Demo, mode: str) -> Path:
    return BIN_ROOT / mode / f"{demo.name}{TARGETS[mode].suffix}"


def build_command(demo: Demo, plan: HostPlan) -> list[str]:
    return [
        plan.compiler,
        *plan.target.flags,
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        str(demo.source),
        "-o",
        str(output_path(demo, plan.target.mode)),
    ]


def needs_rebuild(output: Path, deps: list[Path], magic: bytes) -> bool:
    if not output.exists():
        return True
    # A cached binary from a different toolchain (e.g. built on another host) would
    # otherwise look fresh and make every protect step fail.
    with output.open("rb") as handle:
        if handle.read(len(magic)) != magic:
            return True
    output_mtime = output.stat().st_mtime
    return any(dep.stat().st_mtime > output_mtime for dep in deps if dep.exists())


def build_demo(
    demo: Demo,
    plan: HostPlan,
    *,
    force: bool = False,
    quiet: bool = False,
) -> BuildResult:
    ensure_directories()
    mode = plan.target.mode
    output = output_path(demo, mode)
    command = build_command(demo, plan)
    deps = [MANIFEST_PATH, demo.source, Path(__file__)]

    if force or needs_rebuild(output, deps, plan.target.magic):
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
        choices=(*MODES, "all"),
        default="all",
        help="Which target to build; 'all' means every target this host can execute",
    )
    parser.add_argument("--compiler", help="C compiler to invoke instead of the target default")
    parser.add_argument("--force", action="store_true", help="Rebuild even if outputs look fresh")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output")
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the targets this host can build and execute as JSON, then exit",
    )
    return parser.parse_args(argv)


def selected_plans(mode: str, compiler_override: str | None = None) -> list[HostPlan]:
    """Resolve `--mode` to host plans; an explicitly requested target must be runnable."""
    if mode == "all":
        modes = available_modes(compiler_override)
    else:
        modes = (mode,)
    plans = []
    for name in modes:
        plan = host_plan(name, compiler_override)
        if plan is None:
            raise SystemExit(f"target '{name}' cannot be built and executed on this host")
        warm_up_runner(plan)
        plans.append(plan)
    return plans


def warm_up_runner(plan: HostPlan) -> None:
    """Wine creates its prefix on first use and reports that on stderr, which would
    otherwise pollute the first fixture's captured output."""
    if plan.runner:
        subprocess.run([*plan.runner, "cmd", "/c", "exit"], capture_output=True, timeout=600)


def list_targets(compiler_override: str | None) -> str:
    entries = []
    for mode in available_modes(compiler_override):
        plan = host_plan(mode, compiler_override)
        assert plan is not None
        entries.append(
            {
                "mode": mode,
                "description": plan.target.description,
                "suffix": plan.target.suffix,
                "runner": list(plan.runner),
                "bin_dir": str(BIN_ROOT / mode),
            }
        )
    return json.dumps(entries)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.list:
        print(list_targets(args.compiler))
        return 0

    demos = load_manifest()
    ensure_directories()
    plans = selected_plans(args.mode, args.compiler)

    failures = 0
    for demo in demos:
        if not demo.source.exists():
            print(f"[fail ] source missing for {demo.name}: {demo.source}", file=sys.stderr)
            failures += 1
            continue
        for plan in plans:
            try:
                build_demo(demo, plan, force=args.force, quiet=args.quiet)
            except subprocess.CalledProcessError as exc:
                failures += 1
                print(
                    f"[fail ] build {plan.target.mode} {demo.name} exited {exc.returncode}",
                    file=sys.stderr,
                )

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
