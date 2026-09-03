#!/usr/bin/env python3
import html
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import archery_review


class FakeArcheryHandler(BaseHTTPRequestHandler):
    actions = []
    workflow = {}

    @classmethod
    def reset(cls):
        cls.actions = []
        cls.workflow = {
            "audit_id": 9,
            "workflow_id": 42,
            "title": "Add company index",
            "submitter": "Submitter Zhang",
            "approval_flow": "研发->DBA",
            "current_approval": "DBA",
            "instance": "test-write-instance",
            "database": "app_db",
            "create_time": "2026-09-02 10:00",
            "execution_window": "无限制",
            "finish_time": "None",
            "backup": "是",
            "status": "workflow_manreviewing",
            "status_display": "待审核",
            "group": "engineering",
            "syntax_type": "DML",
            "sql": "UPDATE t_company_user SET type = 1 WHERE id = 1;",
            "can_review": True,
            "is_submitter": False,
            "next_approval": None,
            "review_rows": [
                {
                    "id": 1,
                    "sql": "UPDATE t_company_user SET type = 1 WHERE id = 1;",
                    "errlevel": 0,
                    "errormessage": "None",
                    "affected_rows": 1,
                    "stagestatus": "Audit completed",
                }
            ],
            "logs": [
                {
                    "operation_type_desc": "提交",
                    "operation_info": "等待审批",
                    "operator_display": "Submitter Zhang",
                    "operation_time": "2026-09-02 10:00:00",
                }
            ],
        }

    def log_message(self, _format, *_args):
        pass

    def _send(self, status, body=b"", content_type="text/html", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            values = value if isinstance(value, (list, tuple)) else [value]
            for item in values:
                self.send_header(name, item)
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        length = int(self.headers.get("Content-Length", "0"))
        return urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))

    def _authenticated(self):
        return "sessionid=review-session" in self.headers.get("Cookie", "")

    def _csrf_valid(self):
        expected = "login-csrf" if self.path == "/authenticate/" else "rotated-csrf"
        return self.headers.get("X-CSRFToken") == expected

    @classmethod
    def _detail_html(cls):
        item = cls.workflow
        review_button = '<button id="btnPass">Approve</button>' if item["can_review"] else ""
        submitter_button = (
            '<a id="btnSubmitOtherCluster">Submit elsewhere</a>'
            if item["is_submitter"]
            else ""
        )
        review_form = (
            '<form action="/passed/"><input name="workflow_id" value="{}"></form>'.format(
                item["workflow_id"]
            )
            if item["can_review"]
            else ""
        )
        values = [
            item["submitter"],
            item["approval_flow"],
            item["current_approval"],
            item["instance"],
            item["database"],
            item["create_time"],
            item["execution_window"],
            item["finish_time"],
            item["backup"],
            item["status_display"],
            item["group"],
            item["syntax_type"],
        ]
        cells = "".join("<td>{}</td>".format(html.escape(str(value))) for value in values)
        return (
            '<h4><a>{title}</a></h4>'
            '{submitter_button}'
            '<input id="editSqlContent" value="{sql}">'
            '<table><tbody><tr class="success">{cells}</tr></tbody></table>'
            '<span id="workflow_detail_status">{status}</span>'
            '<b id="workflow_detail_disaply">{status_display}</b>'
            '{review_form}'
            '{review_button}'
        ).format(
            title=html.escape(item["title"]),
            submitter_button=submitter_button,
            sql=html.escape(item["sql"], quote=True),
            cells=cells,
            status=item["status"],
            status_display=item["status_display"],
            review_form=review_form,
            review_button=review_button,
        ).encode("utf-8")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        item = self.workflow
        if parsed.path == "/login/":
            body = b'<input name="csrfmiddlewaretoken" value="login-csrf">'
            self._send(200, body, headers={"Set-Cookie": "csrftoken=login-csrf; Path=/"})
        elif parsed.path == "/workflow/" and self._authenticated():
            self._send(200, b'<table id="audit-list"></table>')
        elif parsed.path == "/workflow/{}/".format(item["audit_id"]) and self._authenticated():
            self._send(302, headers={"Location": "/detail/{}/".format(item["workflow_id"])})
        elif parsed.path == "/detail/{}/".format(item["workflow_id"]) and self._authenticated():
            self._send(200, self._detail_html())
        elif parsed.path == "/sqlworkflow/detail_content/" and self._authenticated():
            body = json.dumps({"rows": item["review_rows"]}, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if not self._csrf_valid():
            self._send(403, b"bad csrf")
            return
        form = self._form()
        item = self.workflow
        if self.path == "/authenticate/":
            if form.get("username") == ["reviewer"] and form.get("password") == ["review-password"]:
                body = json.dumps({"status": 0, "msg": "ok", "data": None}).encode()
                self._send(
                    200,
                    body,
                    "application/json",
                    {"Set-Cookie": ["sessionid=review-session; Path=/", "csrftoken=rotated-csrf; Path=/"]},
                )
            else:
                body = json.dumps({"status": 1, "msg": "bad credentials"}).encode()
                self._send(200, body, "application/json")
        elif not self._authenticated():
            self._send(403, b"not authenticated")
        elif self.path == "/workflow/list/":
            row = {
                "audit_id": item["audit_id"],
                "workflow_type": 2,
                "workflow_title": item["title"],
                "create_user_display": item["submitter"],
                "create_time": item["create_time"],
                "current_status": 0,
                "audit_auth_groups": "1,2",
                "current_audit": "2",
                "group_name": item["group"],
            }
            body = json.dumps({"total": 1, "rows": [row]}, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json")
        elif self.path == "/getWorkflowStatus/":
            body = json.dumps({"status": item["status"], "msg": "", "data": ""}).encode()
            self._send(200, body, "application/json")
        elif self.path == "/workflow/log/":
            body = json.dumps({"total": len(item["logs"]), "rows": item["logs"]}, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json")
        elif self.path == "/passed/":
            self.actions.append(("approve", form))
            item["logs"].insert(
                0,
                {
                    "operation_type_desc": "审批通过",
                    "operation_info": "审批备注：{}".format(form["audit_remark"][0]),
                    "operator_display": "Reviewer Li",
                    "operation_time": "2026-09-02 10:05:00",
                },
            )
            if item["next_approval"]:
                item["current_approval"] = item["next_approval"]
                item["can_review"] = False
            else:
                item["status"] = "workflow_review_pass"
                item["status_display"] = "审核通过"
                item["current_approval"] = "None"
                item["can_review"] = False
            self._send(302, headers={"Location": "/detail/{}/".format(item["workflow_id"])})
        elif self.path == "/cancel/":
            self.actions.append(("reject", form))
            item["status"] = "workflow_abort"
            item["status_display"] = "人工终止"
            item["current_approval"] = "None"
            item["can_review"] = False
            item["logs"].insert(
                0,
                {
                    "operation_type_desc": "审批不通过",
                    "operation_info": "审批备注：{}".format(form["cancel_remark"][0]),
                    "operator_display": "Reviewer Li",
                    "operation_time": "2026-09-02 10:05:00",
                },
            )
            self._send(302, headers={"Location": "/detail/{}/".format(item["workflow_id"])})
        else:
            self._send(404, b"not found")


class ArcheryReviewClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeArcheryHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = "http://127.0.0.1:{}".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        FakeArcheryHandler.reset()
        self.client = archery_review.ArcheryReviewClient(
            self.base_url, "reviewer", "review-password"
        )
        self.client.login()

    def test_lists_pending_sql_workflows_and_resolves_workflow_id(self):
        result = self.client.pending(limit=20, offset=0, search="")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["rows"][0]["audit_id"], 9)
        self.assertEqual(result["rows"][0]["workflow_id"], 42)

    def test_inspects_exact_sql_target_review_and_logs(self):
        result = self.client.inspect_workflow(42)
        self.assertEqual(result["title"], "Add company index")
        self.assertEqual(result["instance"], "test-write-instance")
        self.assertEqual(result["database"], "app_db")
        self.assertEqual(result["status"], "workflow_manreviewing")
        self.assertTrue(result["can_review"])
        self.assertFalse(result["is_submitter"])
        self.assertEqual(result["review_rows"][0]["affected_rows"], 1)
        self.assertEqual(len(result["fingerprint"]), 64)

    def test_approves_matching_pending_workflow_and_verifies_result(self):
        detail = self.client.inspect_workflow(42)
        result = self.client.approve(42, "Reviewed and accepted", detail["fingerprint"])
        self.assertEqual(len(FakeArcheryHandler.actions), 1)
        action, form = FakeArcheryHandler.actions[0]
        self.assertEqual(action, "approve")
        self.assertEqual(form["workflow_id"], ["42"])
        self.assertEqual(form["audit_remark"], ["Reviewed and accepted"])
        self.assertEqual(result["status"], "workflow_review_pass")
        self.assertEqual(result["review_progress"], "final_approved")
        self.assertEqual(result["latest_log"]["operation_type_desc"], "审批通过")

    def test_reports_multilevel_approval_without_claiming_final_approval(self):
        FakeArcheryHandler.workflow["next_approval"] = "Security"
        detail = self.client.inspect_workflow(42)
        result = self.client.approve(42, "DBA approved", detail["fingerprint"])
        self.assertEqual(result["status"], "workflow_manreviewing")
        self.assertEqual(result["current_approval"], "Security")
        self.assertEqual(result["review_progress"], "advanced_to_next_reviewer")

    def test_rejects_with_reason_and_verifies_audit_log(self):
        detail = self.client.inspect_workflow(42)
        result = self.client.reject(42, "Missing maintenance window", detail["fingerprint"])
        self.assertEqual(FakeArcheryHandler.actions[0][0], "reject")
        self.assertEqual(result["status"], "workflow_abort")
        self.assertEqual(result["review_progress"], "rejected")
        self.assertEqual(result["latest_log"]["operation_type_desc"], "审批不通过")

    def test_review_errors_block_approval_but_can_be_rejected(self):
        FakeArcheryHandler.workflow["review_rows"][0]["errlevel"] = 2
        FakeArcheryHandler.workflow["review_rows"][0]["errormessage"] = "Unsafe SQL"
        detail = self.client.inspect_workflow(42)
        with self.assertRaisesRegex(archery_review.ReviewError, "contains errors"):
            self.client.approve(42, "Approved", detail["fingerprint"])
        self.assertEqual(FakeArcheryHandler.actions, [])

        result = self.client.reject(42, "Unsafe SQL", detail["fingerprint"])
        self.assertEqual(result["review_progress"], "rejected")
        self.assertEqual(FakeArcheryHandler.actions[0][0], "reject")

    def test_blocks_stale_fingerprint_without_posting(self):
        detail = self.client.inspect_workflow(42)
        FakeArcheryHandler.workflow["sql"] = "UPDATE t_company_user SET type = 2 WHERE id = 1;"
        with self.assertRaisesRegex(archery_review.ReviewError, "fingerprint"):
            self.client.approve(42, "Approved", detail["fingerprint"])
        self.assertEqual(FakeArcheryHandler.actions, [])

    def test_blocks_self_review_permission_denial_and_nonpending_state(self):
        cases = (
            ("is_submitter", True, "own workflow"),
            ("can_review", False, "not the current reviewer"),
            ("status", "workflow_review_pass", "not pending review"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                FakeArcheryHandler.reset()
                FakeArcheryHandler.workflow[field] = value
                detail = self.client.inspect_workflow(42)
                with self.assertRaisesRegex(archery_review.ReviewError, message):
                    self.client.approve(42, "Approved", detail["fingerprint"])
                self.assertEqual(FakeArcheryHandler.actions, [])

    def test_requires_nonempty_remarks_for_both_decisions(self):
        detail = self.client.inspect_workflow(42)
        for method in (self.client.approve, self.client.reject):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(
                archery_review.ReviewError, "remark"
            ):
                method(42, "   ", detail["fingerprint"])
        self.assertEqual(FakeArcheryHandler.actions, [])

    def test_mutation_transport_failure_is_outcome_unknown_and_not_retried(self):
        detail = self.client.inspect_workflow(42)
        original = self.client._request
        calls = []

        def fail_once(path, **kwargs):
            if path == "/passed/":
                calls.append(path)
                raise archery_review.ReviewOutcomeUnknown("timed out")
            return original(path, **kwargs)

        with mock.patch.object(self.client, "_request", side_effect=fail_once):
            with self.assertRaisesRegex(archery_review.ReviewOutcomeUnknown, "timed out"):
                self.client.approve(42, "Approved", detail["fingerprint"])
        self.assertEqual(calls, ["/passed/"])

    def test_login_failure_does_not_expose_password(self):
        client = archery_review.ArcheryReviewClient(
            self.base_url, "reviewer", "secret-that-must-not-leak"
        )
        with self.assertRaises(archery_review.ReviewError) as caught:
            client.login()
        self.assertNotIn("secret-that-must-not-leak", str(caught.exception))


class DeterministicPolicyTests(unittest.TestCase):
    def test_loads_review_section_from_shared_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "base_url": "https://archery.example.com",
                        "review": {
                            "username_env": "ARCHERY_REVIEW_USERNAME",
                            "password_env": "ARCHERY_REVIEW_PASSWORD",
                            "default_limit": 20,
                            "max_limit": 100,
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = archery_review.load_config(path)
        self.assertEqual(config["base_url"], "https://archery.example.com")
        self.assertEqual(config["default_limit"], 20)

    def test_invalid_workflow_id_fails_visibly(self):
        with self.assertRaisesRegex(archery_review.ReviewError, "positive integer"):
            archery_review.normalize_workflow_id("invalid")

    def test_credentials_use_dedicated_review_environment(self):
        config = {
            "username_env": "ARCHERY_REVIEW_USERNAME",
            "password_env": "ARCHERY_REVIEW_PASSWORD",
        }
        with mock.patch.dict(
            os.environ,
            {
                "ARCHERY_REVIEW_USERNAME": "reviewer",
                "ARCHERY_REVIEW_PASSWORD": "review-password",
            },
            clear=True,
        ):
            self.assertEqual(
                archery_review.credentials(config), ("reviewer", "review-password")
            )

    def test_fingerprint_changes_with_security_relevant_fields(self):
        detail = {
            "workflow_id": 42,
            "title": "title",
            "instance": "test",
            "database": "db",
            "group": "group",
            "status": "workflow_manreviewing",
            "current_approval": "DBA",
            "sql": "UPDATE t SET a = 1 WHERE id = 1;",
            "review_rows": [{"errlevel": 0, "affected_rows": 1}],
        }
        baseline = archery_review.workflow_fingerprint(detail)
        for field, value in (
            ("instance", "prod"),
            ("database", "other"),
            ("current_approval", "Security"),
            ("sql", "UPDATE t SET a = 2 WHERE id = 1;"),
        ):
            changed = dict(detail)
            changed[field] = value
            with self.subTest(field=field):
                self.assertNotEqual(baseline, archery_review.workflow_fingerprint(changed))

    def test_full_command_flow_uses_config_and_environment(self):
        FakeArcheryHandler.reset()
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "version": "v1.8.0",
                        "base_url": "http://127.0.0.1:1",
                        "username_env": "ARCHERY_REVIEW_USERNAME",
                        "password_env": "ARCHERY_REVIEW_PASSWORD",
                        "default_limit": 20,
                        "max_limit": 100,
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "ARCHERY_REVIEW_USERNAME": "reviewer",
                    "ARCHERY_REVIEW_PASSWORD": "review-password",
                },
                clear=True,
            ), mock.patch.object(
                archery_review.ArcheryReviewClient,
                "__init__",
                return_value=None,
            ), mock.patch.object(
                archery_review.ArcheryReviewClient, "login"
            ), mock.patch.object(
                archery_review.ArcheryReviewClient,
                "pending",
                return_value={"total": 0, "rows": [], "partial": False, "errors": []},
            ):
                args = archery_review.parser().parse_args(
                    ["--config", str(config_path), "list"]
                )
                self.assertEqual(archery_review.run(args)["action"], "list")


if __name__ == "__main__":
    unittest.main()
