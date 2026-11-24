#!/usr/bin/env python3
"""Verify CI impact selection, fail-closed behavior, and the stable summary gate."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ci_impact", ROOT / "scripts/verify/ci_impact.py")
CI_IMPACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI_IMPACT)
JDK_SPEC = importlib.util.spec_from_file_location(
    "download_locked_jdk", ROOT / "scripts/dev/download-locked-jdk.py")
LOCKED_JDK = importlib.util.module_from_spec(JDK_SPEC)
JDK_SPEC.loader.exec_module(LOCKED_JDK)


class ImpactSelectionTest(unittest.TestCase):
    def test_markdown_only_change_runs_document_validation(self):
        selection = CI_IMPACT.classify_paths(("README.md", "docs/build/j09-public-delivery.md"))
        self.assertEqual([], selection["groups"])
        self.assertFalse(selection["maven"])
        self.assertTrue(selection["docs"])
        self.assertFalse(selection["full"])

    def test_markdown_inside_build_paths_remains_document_only(self):
        selection = CI_IMPACT.classify_paths((".github/workflows/README.md",))
        self.assertEqual([], selection["groups"])
        self.assertTrue(selection["docs"])
        self.assertFalse(selection["full"])

    def test_watch_code_selects_complete_m4_regression(self):
        selection = CI_IMPACT.classify_paths((
            "core/src/main/java/io/etcdhbase/core/lease/LeaseTimeRules.java",
        ))
        self.assertEqual(["m4"], selection["groups"])
        self.assertTrue(selection["maven"])
        self.assertFalse(selection["full"])

    def test_protocol_and_clients_select_both_ends_and_affected_watch_regression(self):
        cases = (
            ("protocol/src/main/proto/etcdserverpb/rpc.proto",
             ["j03", "j04", "j06", "j07", "j23", "j24", "m3", "m4", "m5"]),
            ("grpc/src/main/java/io/etcdhbase/grpc/service/WatchService.java",
             ["j03", "j04", "j06", "j07", "j23", "j24", "m3", "m4", "m5"]),
            ("testkit/go/internal/wire/probe.go", ["j03", "j06", "j07", "m3", "m4", "m5"]),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(expected, CI_IMPACT.classify_paths((path,))["groups"])

    def test_request_scope_changes_select_authentication_regression(self):
        selection = CI_IMPACT.classify_paths((
            "core/src/main/java/io/etcdhbase/core/request/RequestScope.java",
        ))
        self.assertEqual(["j06", "m4", "m5"], selection["groups"])

    def test_java_contract_tests_select_the_spi_contract_stage(self):
        selection = CI_IMPACT.classify_paths((
            "testkit/src/test/java/io/etcdhbase/testkit/contract/IdentityProviderContractTest.java",
        ))
        self.assertEqual(["j08"], selection["groups"])

    def test_m3_testkit_change_selects_m3(self):
        selection = CI_IMPACT.classify_paths(("testkit/go/internal/scenario/m3_txn.go",))
        self.assertEqual(["m3"], selection["groups"])
        self.assertFalse(selection["full"])

    def test_scan_dependencies_select_all_dependent_stages(self):
        selection = CI_IMPACT.classify_paths((
            "core/src/main/java/io/etcdhbase/core/scan/ScanScheduler.java",
        ))
        self.assertEqual(["j10", "j11", "m1", "m3", "m4", "m5"], selection["groups"])

    def test_document_and_code_changes_union_their_checks(self):
        selection = CI_IMPACT.classify_paths((
            "docs/testing/m4-stage-acceptance-report.md",
            "config/examples/m4/watch.yaml",
        ))
        self.assertEqual(["m4"], selection["groups"])
        self.assertTrue(selection["docs"])


class FullFallbackTest(unittest.TestCase):
    def test_public_spi_storage_format_txn_and_recovery_paths_run_full_suite(self):
        paths = (
            "spi/src/main/java/io/etcdhbase/spi/identity/BackendIdentityProvider.java",
            "hbase/src/main/java/io/etcdhbase/hbase/codec/CommitControlMessages.java",
            "core/src/main/java/io/etcdhbase/core/bytes/ByteKey.java",
            "core/src/main/java/io/etcdhbase/core/commit/CommitPublisher.java",
            "core/src/main/java/io/etcdhbase/core/kv/TxnEvaluator.java",
            "core/src/main/java/io/etcdhbase/core/storage/RecordStore.java",
            "grpc/src/main/proto/etcdhbase/internal/v1/owner.proto",
        )
        for path in paths:
            with self.subTest(path=path):
                selection = CI_IMPACT.classify_paths((path,))
                self.assertTrue(selection["full"])
                self.assertEqual(list(CI_IMPACT.WORKFLOW_GROUPS), selection["groups"])

    def test_build_lock_workflow_and_verification_script_changes_run_full_suite(self):
        paths = (
            "pom.xml",
            "build/dependency-lock.json",
            ".github/workflows/ci.yml",
            "scripts/dev/mvn21.sh",
            "scripts/verify/ci_impact.py",
            "testkit/go/go.sum",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(CI_IMPACT.classify_paths((path,))["full"])

    def test_unknown_and_incomplete_diffs_run_full_suite(self):
        self.assertTrue(CI_IMPACT.classify_paths(("LICENSE",))["full"])
        self.assertTrue(CI_IMPACT.classify_paths(("src/new-module/File.java",))["full"])
        incomplete = CI_IMPACT.classify_paths(("docs/readme.md",), complete=False)
        self.assertTrue(incomplete["full"])
        self.assertTrue(incomplete["docs"])
        invalid = CI_IMPACT.classify_paths(("../outside.md",))
        self.assertTrue(invalid["full"])
        self.assertTrue(invalid["docs"])
        self.assertTrue(CI_IMPACT.classify_paths(())["full"])

    def test_main_and_merge_group_events_run_full_suite(self):
        for event in ("push", "merge_group"):
            with self.subTest(event=event):
                selection = CI_IMPACT.classify_event(event)
                self.assertTrue(selection["full"])
                self.assertTrue(selection["docs"])
                self.assertEqual(list(CI_IMPACT.WORKFLOW_GROUPS), selection["groups"])


class StableSummaryGateTest(unittest.TestCase):
    def test_docs_only_run_passes_when_maven_and_code_groups_are_skipped(self):
        selection = {"groups": [], "maven": False, "docs": True}
        statuses = {
            "maven-dependencies": "skipped",
            "docs-validation": "success",
            **{group: "skipped" for group in CI_IMPACT.WORKFLOW_GROUPS},
        }
        self.assertEqual([], CI_IMPACT.validate_results("success", selection, statuses))

    def test_selected_group_must_succeed_and_unselected_group_must_skip(self):
        selection = {"groups": ["m4"], "maven": True, "docs": False}
        statuses = {
            "maven-dependencies": "success",
            "docs-validation": "skipped",
            **{group: ("success" if group == "m4" else "skipped")
               for group in CI_IMPACT.WORKFLOW_GROUPS},
        }
        self.assertEqual([], CI_IMPACT.validate_results("success", selection, statuses))
        statuses["m4"] = "skipped"
        self.assertTrue(CI_IMPACT.validate_results("success", selection, statuses))
        statuses["m4"] = "success"
        statuses["m3"] = "success"
        self.assertTrue(CI_IMPACT.validate_results("success", selection, statuses))

    def test_selected_m5_cannot_be_skipped_or_fail(self):
        selection = {"groups": ["m5"], "maven": True, "docs": False}
        statuses = {
            "maven-dependencies": "success",
            "docs-validation": "skipped",
            **{group: ("success" if group == "m5" else "skipped")
               for group in CI_IMPACT.WORKFLOW_GROUPS},
        }
        self.assertEqual([], CI_IMPACT.validate_results("success", selection, statuses))
        for result in ("skipped", "failure", ""):
            with self.subTest(result=result):
                statuses["m5"] = result
                self.assertTrue(CI_IMPACT.validate_results("success", selection, statuses))

    def test_failed_plan_or_maven_preparation_cannot_pass(self):
        selection = {"groups": ["j03"], "maven": True, "docs": False}
        statuses = {
            "maven-dependencies": "failure",
            "docs-validation": "skipped",
            **{group: "skipped" for group in CI_IMPACT.WORKFLOW_GROUPS},
        }
        self.assertTrue(CI_IMPACT.validate_results("failure", selection, statuses))
        self.assertTrue(CI_IMPACT.validate_results("success", selection, statuses))


class LockedJdkCacheTest(unittest.TestCase):
    def test_cached_jdk_archive_must_match_the_locked_checksum(self):
        content = b"locked jdk fixture"
        checksum = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "jdk.tar.gz"
            archive.write_bytes(content)
            self.assertEqual(checksum, LOCKED_JDK.verify_archive(archive, checksum, "fixture"))
            with self.assertRaises(ValueError):
                LOCKED_JDK.verify_archive(archive, "0" * 64, "fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
