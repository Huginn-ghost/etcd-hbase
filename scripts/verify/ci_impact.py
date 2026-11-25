#!/usr/bin/env python3
"""Select PR validation groups from the changed component dependency map."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_GROUPS = (
    "j03", "j04", "j05", "j06", "j07", "j08", "j09", "j10", "j11",
    "j23", "j24", "j36-proof", "m1", "m3", "m4", "m5",
)
MAVEN_GROUPS = frozenset(WORKFLOW_GROUPS) - {"j09"}
PROTOCOL_DEPENDENT_GROUPS = frozenset({"j03", "j04", "j06", "j07", "j23", "j24", "m3", "m4", "m5"})
GO_JAVA_INTEROP_GROUPS = frozenset({"j03", "j06", "j07", "m3", "m4", "m5"})
FULL_PATH_PREFIXES = (
    ".github/workflows/", ".github/actions/", ".mvn/", "build/", "scripts/",
    "hbase/", "spi/",
)
HIGH_RISK_CORE_PACKAGES = ("bytes", "commit", "kv", "storage")


def all_checks(reason: str, include_docs: bool = False) -> dict[str, object]:
    return {
        "full": True,
        "groups": list(WORKFLOW_GROUPS),
        "maven": True,
        "docs": include_docs,
        "reason": reason,
    }


def _normalize_path(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return None
    return normalized


def _requires_full_validation(path: str) -> bool:
    if path.startswith(FULL_PATH_PREFIXES):
        return True
    if path == "pom.xml" or path.endswith("/pom.xml"):
        return True
    if path.endswith((".lock", ".lockfile", ".sum")) or path.endswith(("go.mod", "go.sum")):
        return True
    if path.startswith("grpc/src/main/proto/etcdhbase/internal/"):
        return True
    if path.startswith("core/src/") and any(
        f"/io/etcdhbase/core/{package}/" in f"/{path}"
        for package in HIGH_RISK_CORE_PACKAGES
    ):
        return True
    return False


def _groups_for_path(path: str) -> frozenset[str] | None:
    if path.startswith(("protocol/src/", "grpc/src/")):
        return PROTOCOL_DEPENDENT_GROUPS
    if path.startswith("testkit/src/"):
        return frozenset({"j08"})

    core_prefix = "/io/etcdhbase/core/"
    if path.startswith("core/src/") and core_prefix in f"/{path}":
        if any(f"{core_prefix}{package}/" in f"/{path}" for package in ("lease", "watch")):
            return frozenset({"m4"})
        if f"{core_prefix}request/" in f"/{path}":
            return frozenset({"j06", "m4", "m5"})
        if f"{core_prefix}scan/" in f"/{path}":
            return frozenset({"j10", "j11", "m1", "m3", "m4", "m5"})

    if path.startswith((
        "testkit/go/internal/client/",
        "testkit/go/internal/rpctypes/",
        "testkit/go/internal/wire/",
    )):
        return GO_JAVA_INTEROP_GROUPS
    if path.startswith((
        "testkit/go/cmd/m3",
        "testkit/go/internal/compare/m3_",
        "testkit/go/internal/scenario/m3_",
    )):
        return frozenset({"m3"})
    if path.startswith((
        "testkit/go/cmd/m4",
        "testkit/go/internal/compare/m4_",
        "testkit/go/internal/scenario/m4_",
    )):
        return frozenset({"m4"})
    if path.startswith("config/examples/m4/"):
        return frozenset({"m4"})
    return None


def classify_paths(changed_paths: Iterable[str], complete: bool = True) -> dict[str, object]:
    if not complete:
        return all_checks("changed-path-diff-incomplete", include_docs=True)

    paths = []
    for raw_path in changed_paths:
        path = _normalize_path(raw_path)
        if path is None:
            return all_checks("invalid-changed-path", include_docs=True)
        paths.append(path)
    if not paths:
        return all_checks("no-changed-paths")

    include_docs = any(path.lower().endswith(".md") for path in paths)
    selected_groups: set[str] = set()
    for path in paths:
        if path.lower().endswith(".md"):
            continue
        if _requires_full_validation(path):
            return all_checks("build-ci-or-high-risk-change", include_docs)
        groups = _groups_for_path(path)
        if groups is None:
            return all_checks("unrecognized-path", include_docs)
        selected_groups.update(groups)

    if not selected_groups and include_docs:
        return {
            "full": False,
            "groups": [],
            "maven": False,
            "docs": True,
            "reason": "documentation-only",
        }
    if not selected_groups:
        return all_checks("no-classifiable-changes", include_docs)

    ordered_groups = [group for group in WORKFLOW_GROUPS if group in selected_groups]
    return {
        "full": False,
        "groups": ordered_groups,
        "maven": any(group in MAVEN_GROUPS for group in ordered_groups),
        "docs": include_docs,
        "reason": "dependency-impact-map",
    }


def git_changed_paths(base_sha: str, head_sha: str, root: Path = ROOT) -> list[str] | None:
    sha_pattern = re.compile(r"[0-9a-f]{40,64}")
    if not sha_pattern.fullmatch(base_sha) or not sha_pattern.fullmatch(head_sha):
        return None
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", "-z", f"{base_sha}...{head_sha}"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def classify_event(
    event_name: str,
    base_sha: str = "",
    head_sha: str = "",
    root: Path = ROOT,
) -> dict[str, object]:
    if event_name == "push":
        paths = git_changed_paths(base_sha, head_sha, root)
        include_docs = any(path.lower().endswith(".md") for path in paths) if paths is not None else True
        return all_checks("main-push", include_docs=include_docs)
    if event_name == "merge_group":
        paths = git_changed_paths(base_sha, head_sha, root)
        include_docs = any(path.lower().endswith(".md") for path in paths) if paths is not None else True
        return all_checks("merge-group", include_docs=include_docs)
    if event_name != "pull_request":
        return all_checks("unsupported-event")
    paths = git_changed_paths(base_sha, head_sha, root)
    if paths is None:
        return all_checks("changed-path-diff-incomplete", include_docs=True)
    return classify_paths(paths)


def validate_results(
    plan_result: str,
    selection: dict[str, object],
    statuses: dict[str, str],
) -> list[str]:
    issues = []
    if plan_result != "success":
        return [f"selection job: expected success, received {plan_result or 'missing'}"]

    groups = selection.get("groups")
    if not isinstance(groups, list) or any(group not in WORKFLOW_GROUPS for group in groups):
        return ["selection output contains an invalid group list"]
    if len(groups) != len(set(groups)):
        return ["selection output contains duplicate groups"]

    expected_maven = any(group in MAVEN_GROUPS for group in groups)
    if selection.get("maven") is not expected_maven:
        issues.append("selection Maven flag does not match the selected groups")
    expected_docs = selection.get("docs")
    if not isinstance(expected_docs, bool):
        issues.append("selection docs flag is missing or invalid")

    required = {
        "maven-dependencies": expected_maven,
        "docs-validation": expected_docs is True,
    }
    required.update({group: group in groups for group in WORKFLOW_GROUPS})
    for check_id, selected in required.items():
        expected = "success" if selected else "skipped"
        actual = statuses.get(check_id, "missing")
        if actual != expected:
            issues.append(f"{check_id}: expected {expected}, received {actual or 'missing'}")
    return issues


def _read_bool_environment(name: str) -> bool:
    value = os.environ.get(name)
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def check_results_from_environment() -> int:
    try:
        groups = json.loads(os.environ.get("SELECTED_GROUPS", ""))
        selection = {
            "groups": groups,
            "maven": _read_bool_environment("RUN_MAVEN"),
            "docs": _read_bool_environment("RUN_DOCS"),
        }
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"invalid CI selection output: {exc}", file=sys.stderr)
        return 1

    statuses = {
        "maven-dependencies": os.environ.get("MAVEN_RESULT", ""),
        "docs-validation": os.environ.get("DOCS_RESULT", ""),
    }
    for group in WORKFLOW_GROUPS:
        env_name = "RESULT_" + re.sub(r"[^A-Za-z0-9]+", "_", group).upper()
        statuses[group] = os.environ.get(env_name, "")

    issues = validate_results(os.environ.get("PLAN_RESULT", ""), selection, statuses)
    for check_id, status in statuses.items():
        print(f"{check_id}: {status or 'missing'}")
    if issues:
        for issue in issues:
            print(f"ERROR: {issue}", file=sys.stderr)
        return 1
    print("all selected validation groups succeeded; unselected groups were skipped")
    return 0


def write_github_outputs(selection: dict[str, object], output_path: Path) -> None:
    values = {
        "groups": json.dumps(selection["groups"], separators=(",", ":")),
        "full": str(selection["full"]).lower(),
        "maven": str(selection["maven"]).lower(),
        "docs": str(selection["docs"]).lower(),
        "reason": str(selection["reason"]),
    }
    with output_path.open("a", encoding="utf-8") as output:
        for name, value in values.items():
            output.write(f"{name}={value}\n")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        groups = ", ".join(selection["groups"]) or "无代码验证组"
        summary = (
            "## CI 影响范围选择\n\n"
            f"- 选择原因：`{selection['reason']}`\n"
            f"- 完整回归：`{str(selection['full']).lower()}`\n"
            f"- 验证组：{groups}\n"
            f"- Maven 公共准备：`{str(selection['maven']).lower()}`\n"
            f"- 文档校验：`{str(selection['docs']).lower()}`\n"
        )
        with Path(summary_path).open("a", encoding="utf-8") as output:
            output.write(summary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", help="GitHub event name")
    parser.add_argument("--base", default="", help="base commit SHA for pull_request")
    parser.add_argument("--head", default="", help="head commit SHA for pull_request")
    parser.add_argument("--output", type=Path, help="GITHUB_OUTPUT path")
    parser.add_argument("--check-results", action="store_true", help="validate workflow job results")
    arguments = parser.parse_args()

    if arguments.check_results:
        return check_results_from_environment()
    if not arguments.event or not arguments.output:
        parser.error("--event and --output are required unless --check-results is used")
    selection = classify_event(arguments.event, arguments.base, arguments.head)
    write_github_outputs(selection, arguments.output)
    print(json.dumps(selection, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
