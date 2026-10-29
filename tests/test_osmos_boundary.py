"""Synthetic contracts only: these tests never connect to Fabric."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("osmos_boundary", ROOT / "tools" / "osmos_boundary.py")
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)
TASK = "11111111-2222-4333-8444-555555555555"
WORKSPACE = "66666666-7777-4888-8999-aaaaaaaaaaaa"
LAKEHOUSE = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
SENTINEL = "SYNTHETIC_PRIVATE_SENTINEL"


class OsmosBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "task_id": TASK, "workspace_id": WORKSPACE, "lakehouse_id": LAKEHOUSE,
            "instruction": "Plan a synthetic-only consistency check inside Fabric.",
        }
        self.approval = {
            "task_id": TASK, "request_sha256": boundary.request_digest(self.request),
            "approved": True, "capacity_acknowledged": True,
        }

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(boundary.BoundaryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(code, str(caught.exception))
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_capacity_consent_is_required_and_not_truthy(self):
        for approval in (None, {}, {"approved": True}, [], SENTINEL):
            self.assert_code(
                "OSMOS_CAPACITY_CONSENT_REQUIRED", boundary.prepare_handoff,
                self.request, approval,
            )
        for key in ("approved", "capacity_acknowledged"):
            for value in (False, None, 1, "true", SENTINEL):
                approval = {**self.approval, key: value}
                self.assert_code(
                    "OSMOS_CAPACITY_CONSENT_REQUIRED", boundary.prepare_handoff,
                    self.request, approval,
                )

    def test_consent_is_bound_to_instruction_and_every_scope_field(self):
        for key, value in (
            ("instruction", "A different synthetic task"),
            ("task_id", LAKEHOUSE), ("workspace_id", TASK), ("lakehouse_id", WORKSPACE),
        ):
            request = {**self.request, key: value}
            self.assert_code(
                "OSMOS_CONSENT_SCOPE_MISMATCH", boundary.prepare_handoff,
                request, self.approval,
            )
        self.assert_code(
            "OSMOS_CONSENT_SCOPE_MISMATCH", boundary.prepare_handoff, self.request,
            {**self.approval, "task_id": LAKEHOUSE},
        )

    def test_handoff_has_read_only_boundary_but_dispatch_is_always_disabled(self):
        before = copy.deepcopy(self.request)
        handoff = boundary.prepare_handoff(self.request, self.approval)
        self.assertTrue(handoff["instruction"].startswith(self.request["instruction"]))
        self.assertIn("read-only analysis", handoff["instruction"])
        self.assertIn("Keep data, counts, analysis, messages, logs and errors in Fabric", handoff["instruction"])
        self.assertEqual(before, self.request)
        self.assert_code(
            "OSMOS_LIVE_DISABLED", boundary.dispatch, self.request, self.approval,
        )

    def test_request_rejects_endpoint_overrides_empty_scope_and_oversize_instructions(self):
        for request in (
            {**self.request, "url": "https://example.invalid/" + SENTINEL},
            {**self.request, "instruction": ""},
            {**self.request, "instruction": "x" * 8001},
            {**self.request, "instruction": "\x00" + SENTINEL},
        ):
            self.assert_code("OSMOS_INVALID_REQUEST", boundary.request_digest, request)
        for value in (SENTINEL, "00000000-0000-0000-0000-000000000000", None, True):
            self.assert_code(
                "OSMOS_INVALID_ID", boundary.request_digest,
                {**self.request, "workspace_id": value},
            )

    def test_status_projection_drops_messages_counts_errors_urls_and_nested_data(self):
        response = {
            "id": TASK, "status": "Completed", "operationId": LAKEHOUSE,
            "messages": [{"role": "Assistant", "content": SENTINEL}],
            "count": 123, "summary": SENTINEL, "url": "https://example.invalid/" + SENTINEL,
            "errorMessage": SENTINEL, "accessToken": SENTINEL,
            "runDetails": {
                "startedAt": "2026-10-29T18:00:00Z",
                "completedAt": "2026-10-29T18:01:00.123Z",
                "errorMessage": SENTINEL, "rows": [SENTINEL],
            },
        }
        result = boundary.public_status(response, expected_task_id=TASK)
        self.assertEqual({
            "task_id": TASK, "status": "Completed", "operation_id": LAKEHOUSE,
            "started_at": "2026-10-29T18:00:00Z",
            "completed_at": "2026-10-29T18:01:00.123Z",
        }, result)
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assertIn(SENTINEL, json.dumps(response))

    def test_status_rejects_free_text_malformed_selected_fields_and_other_tasks(self):
        self.assert_code(
            "OSMOS_TASK_MISMATCH", boundary.public_status,
            {"id": LAKEHOUSE, "status": "Running"}, expected_task_id=TASK,
        )
        for response in (
            None, {}, {"id": TASK, "status": SENTINEL},
            {"id": TASK, "status": True}, {"id": TASK, "status": 6},
            {"id": TASK, "status": "Running", "runDetails": SENTINEL},
            {"id": TASK, "status": "Running", "runDetails": {"startedAt": SENTINEL}},
            {"id": TASK, "status": "Running", "runDetails": {"completedAt": "2026-02-31T12:00:00Z"}},
        ):
            self.assert_code(
                "OSMOS_INVALID_STATUS", boundary.public_status, response,
                expected_task_id=TASK,
            )
        self.assert_code(
            "OSMOS_INVALID_ID", boundary.public_status,
            {"id": TASK, "status": "Running", "operationId": SENTINEL},
            expected_task_id=TASK,
        )

    def test_numeric_states_are_normalized_without_relaying_run_details(self):
        for value, expected in ((0, "Created"), ("1", "Running"), (5, "Failed")):
            self.assertEqual(
                {"task_id": TASK, "status": expected},
                boundary.public_status({
                    "id": TASK, "status": value,
                    "runDetails": {"errorMessage": SENTINEL},
                }, expected_task_id=TASK),
            )


if __name__ == "__main__":
    unittest.main()
