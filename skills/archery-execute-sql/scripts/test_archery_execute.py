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
import archery_execute


class FakeArcheryHandler(BaseHTTPRequestHandler):
    actions = []
    workflow = {}

    @classmethod
    def reset(cls):
        cls.actions = []
        cls.workflow = {
            "workflow_id": 42,
            "title": "Update company user",
            "submitter": "Submitter Zhang",
            "approval_flow": "研发->DBA",
            "current_approval": None,
            "instance": "test-write-instance",
            "database": "app_db",
            "create_time": "2026-09-02 10:00",
            "execution_window": "无限制",
            "finish_time": "None",
            "backup": "是",
            "status": "workflow_review_pass",
            "status_display": "审核通过",
            "group": "engineering",
            "syntax_type": "DML",
            "sql": "UPDATE t_company_user SET type = 1 WHERE id = 1;",
            "can_execute": True,
            "is_submitter": False,
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
                    "operation_type_desc": "审批通过",
                    "operation_info": "审批备注：测试通过",
                    "operator_display": "Reviewer Li",
                    "operation_time": "2026-09-02 10:05:00",
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
        return "sessionid=execute-session" in self.headers.get("Cookie", "")

    def _csrf_valid(self):
        expected = "login-csrf" if self.path == "/authenticate/" else "rotated-csrf"
        return self.headers.get("X-CSRFToken") == expected

    @classmethod
    def _detail_html(cls):
        item = cls.workflow
        execute_button = (
            '<input id="btnExecuteOnly" type="button" value="立即执行">'
            if item["can_execute"]
            else ""
        )
        submitter_button = (
            '<a id="btnSubmitOtherCluster">Submit elsewhere</a>'
            if item["is_submitter"]
            else ""
        )
        values = [
            item["submitter"],
            item["approval_flow"],
            item["current_approval"] or "None",
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
            '<form action="/execute/">'
            '<input name="workflow_id" value="{workflow_id}">'
            '{execute_button}</form>'
        ).format(
            title=html.escape(item["title"]),
            submitter_button=submitter_button,
            sql=html.escape(item["sql"], quote=True),
            cells=cells,
            status=item["status"],
            status_display=item["status_display"],
            workflow_id=item["workflow_id"],
            execute_button=execute_button,
        ).encode("utf-8")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        item = self.workflow
        if parsed.path == "/login/":
            self._send(
                200,
                b'<input name="csrfmiddlewaretoken" value="login-csrf">',
                headers={"Set-Cookie": "csrftoken=login-csrf; Path=/"},
            )
        elif parsed.path == "/sqlworkflow/" and self._authenticated():
            self._send(200, b'<table id="sqlaudit-list"></table>')
        elif parsed.path == "/detail/{}/".format(item["workflow_id"]) and self._authenticated():
            self._send(200, self._detail_html())
        elif parsed.path == "/sqlworkflow/detail_content/" and self._authenticated():
            body = json.dumps({"rows": item["review_rows"]}, ensure_ascii=False).encode()
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
            if form.get("username") == ["executor"] and form.get("password") == ["execute-password"]:
                body = json.dumps({"status": 0, "msg": "ok", "data": None}).encode()
                self._send(
                    200,
                    body,
                    "application/json",
                    {
                        "Set-Cookie": [
                            "sessionid=execute-session; Path=/",
                            "csrftoken=rotated-csrf; Path=/",
                        ]
                    },
                )
            else:
                self._send(
                    200,
                    json.dumps({"status": 1, "msg": "bad credentials"}).encode(),
                    "application/json",
                )
        elif not self._authenticated():
            self._send(403, b"not authenticated")
        elif self.path == "/getWorkflowStatus/":
            body = json.dumps({"status": item["status"], "msg": "", "data": ""}).encode()
            self._send(200, body, "application/json")
        elif self.path == "/workflow/log/":
            body = json.dumps(
                {"total": len(item["logs"]), "rows": item["logs"]}, ensure_ascii=False
            ).encode()
            self._send(200, body, "application/json")
        elif self.path == "/execute/":
            cls = type(self)
            cls.actions.append(("execute", form))
            item["status"] = "workflow_queuing"
            item["status_display"] = "排队中"
            item["can_execute"] = False
            item["logs"].insert(
                0,
                {
                    "operation_type_desc": "执行工单",
                    "operation_info": "工单执行排队中",
                    "operator_display": "Executor Wang",
                    "operation_time": "2026-09-02 10:10:00",
                },
            )
            self._send(302, headers={"Location": "/detail/{}/".format(item["workflow_id"])})
        else:
            self._send(404, b"not found")


class SqlPolicyTests(unittest.TestCase):
    def detail(self, sql, affected_rows=1):
        return {
            "status": "workflow_review_pass",
            "can_execute": True,
            "is_submitter": False,
            "sql": sql,
            "review_rows": [
                {"sql": sql, "affected_rows": affected_rows, "errlevel": 0}
            ],
            "affected_rows": affected_rows,
            "error_count": 0,
        }

    def assert_allowed(self, sql, affected_rows=1):
        errors = archery_execute.execution_policy_errors(
            self.detail(sql, affected_rows), 50
        )
        self.assertEqual([], errors)

    def assert_blocked(self, sql, fragment, affected_rows=1):
        errors = archery_execute.execution_policy_errors(
            self.detail(sql, affected_rows), 50
        )
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_accepts_literal_id_equality(self):
        self.assert_allowed("UPDATE t_company_user SET type=1 WHERE id=1;")

    def test_accepts_qualified_id_in_literals(self):
        self.assert_allowed(
            "UPDATE `t_company_user` u SET u.type=1 WHERE u.`id` IN (1, 2, '3') AND u.deleted=0;"
        )

    def test_accepts_insert_without_id_column(self):
        self.assert_allowed(
            "INSERT INTO t_company_user "
            "(user_id, group_id, company_name, group_name) "
            "VALUES (1, 2, '测试公司', '测试分组');",
            affected_rows=1,
        )
        self.assert_allowed(
            "INSERT INTO t_company_user (type, created_at) VALUES (1, NOW()), (2, NOW());",
            affected_rows=2,
        )

    def test_rejects_delete_and_other_statement_types(self):
        self.assert_blocked("DELETE FROM t_company_user WHERE id=1;", "only UPDATE and INSERT")
        self.assert_blocked("ALTER TABLE t_company_user ADD COLUMN x INT;", "only UPDATE and INSERT")

    def test_rejects_unsafe_insert_forms(self):
        self.assert_blocked(
            "INSERT INTO t_company_user VALUES(1, 2);", "explicit column list"
        )
        self.assert_blocked(
            "INSERT INTO t_company_user(id, type) SELECT id, type FROM old_user;",
            "INSERT ... SELECT",
        )
        self.assert_blocked(
            "INSERT INTO t_company_user SET id=1, type=1;", "explicit column list"
        )
        self.assert_blocked(
            "INSERT INTO t_company_user(type, type) VALUES(1, 2);", "duplicates"
        )
        self.assert_blocked(
            "INSERT INTO t_company_user(id, type) VALUES(1, 1) "
            "ON DUPLICATE KEY UPDATE type=2;",
            "ON DUPLICATE",
        )

    def test_rejects_missing_where(self):
        self.assert_blocked("UPDATE t_company_user SET type=1;", "WHERE")

    def test_rejects_non_literal_id_matches(self):
        self.assert_blocked("UPDATE t SET c=1 WHERE id=other_id;", "literal id")
        self.assert_blocked("UPDATE t SET c=1 WHERE id>10;", "literal id")
        self.assert_blocked("UPDATE t SET c=1 WHERE id IN (SELECT id FROM x);", "subqueries")

    def test_rejects_or_and_not(self):
        self.assert_blocked("UPDATE t SET c=1 WHERE id=1 OR active=1;", "OR")
        self.assert_blocked("UPDATE t SET c=1 WHERE NOT id=1;", "NOT")
        self.assert_blocked("UPDATE t SET c=1 WHERE id=1 AND x=1 XOR active=1;", "XOR")
        self.assert_blocked("UPDATE t SET c=1 WHERE id=1 AND x=1 || active=1;", "||")
        self.assert_blocked("UPDATE t SET c=1 WHERE !id=1;", "!")

    def test_rejects_nested_id_predicate_that_can_be_inverted(self):
        self.assert_blocked("UPDATE t SET c=1 WHERE (id=1) = 0;", "top-level literal id")

    def test_rejects_any_unsafe_statement_in_batch(self):
        self.assert_blocked(
            "UPDATE t SET c=1 WHERE id=1; UPDATE t SET c=2 WHERE active=1;",
            "literal id",
        )

    def test_requires_strictly_fewer_than_fifty_affected_rows(self):
        self.assert_allowed("UPDATE t SET c=1 WHERE id=1;", 49)
        self.assert_blocked("UPDATE t SET c=1 WHERE id=1;", "fewer than 50", 50)

    def test_insert_values_row_count_is_also_limited(self):
        values = ",".join("({}, 1)".format(index) for index in range(50))
        self.assert_blocked(
            "INSERT INTO t(id, type) VALUES {};".format(values),
            "fewer than 50 rows",
            affected_rows=1,
        )

    def test_rejects_mismatch_between_workflow_and_review_sql(self):
        detail = self.detail("UPDATE t SET c=1 WHERE id=1;")
        detail["review_rows"][0]["sql"] = "UPDATE t SET c=1 WHERE id=2;"
        errors = archery_execute.execution_policy_errors(detail, 50)
        self.assertTrue(any("does not match" in error for error in errors), errors)


class ArcheryExecuteClientTests(unittest.TestCase):
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
        cls.thread.join(timeout=2)

    def setUp(self):
        FakeArcheryHandler.reset()
        self.client = archery_execute.ArcheryExecuteClient(
            self.base_url, "executor", "execute-password"
        )
        self.client.login()

    def test_show_reports_eligible_workflow_and_fingerprint(self):
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertTrue(detail["eligible"])
        self.assertEqual(1, detail["affected_rows"])
        self.assertEqual(64, len(detail["fingerprint"]))

    def test_execute_dispatches_only_after_token_and_fingerprint_match(self):
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        result = self.client.execute(
            42,
            detail["fingerprint"],
            expected_token="correct-token",
            token_reader=lambda _prompt: "correct-token",
            max_affected_rows_exclusive=50,
        )
        self.assertTrue(result["ok"])
        self.assertEqual("workflow_queuing", result["status"])
        self.assertEqual(1, len(FakeArcheryHandler.actions))
        self.assertEqual(["auto"], FakeArcheryHandler.actions[0][1]["mode"])

    def test_wrong_token_never_dispatches(self):
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        with self.assertRaisesRegex(archery_execute.ExecuteError, "did not match"):
            self.client.execute(
                42,
                detail["fingerprint"],
                expected_token="correct-token",
                token_reader=lambda _prompt: "wrong-token",
                max_affected_rows_exclusive=50,
            )
        self.assertEqual([], FakeArcheryHandler.actions)

    def test_stale_fingerprint_never_prompts_or_dispatches(self):
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        FakeArcheryHandler.workflow["sql"] = "UPDATE t_company_user SET type=2 WHERE id=1;"
        FakeArcheryHandler.workflow["review_rows"][0]["sql"] = FakeArcheryHandler.workflow["sql"]
        prompted = []
        with self.assertRaisesRegex(archery_execute.ExecuteError, "fingerprint"):
            self.client.execute(
                42,
                detail["fingerprint"],
                expected_token="correct-token",
                token_reader=lambda prompt: prompted.append(prompt) or "correct-token",
                max_affected_rows_exclusive=50,
            )
        self.assertEqual([], prompted)
        self.assertEqual([], FakeArcheryHandler.actions)

    def test_policy_failure_never_prompts_or_dispatches(self):
        FakeArcheryHandler.workflow["review_rows"][0]["affected_rows"] = 50
        prompted = []
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertFalse(detail["eligible"])
        with self.assertRaisesRegex(archery_execute.ExecuteError, "fewer than 50"):
            self.client.execute(
                42,
                detail["fingerprint"],
                expected_token="correct-token",
                token_reader=lambda prompt: prompted.append(prompt) or "correct-token",
                max_affected_rows_exclusive=50,
            )
        self.assertEqual([], prompted)
        self.assertEqual([], FakeArcheryHandler.actions)

    def test_requires_final_approval_and_execute_permission(self):
        FakeArcheryHandler.workflow["status"] = "workflow_manreviewing"
        FakeArcheryHandler.workflow["status_display"] = "待审核"
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertTrue(any("finally approved" in item for item in detail["policy_errors"]))
        FakeArcheryHandler.workflow["status"] = "workflow_review_pass"
        FakeArcheryHandler.workflow["can_execute"] = False
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertTrue(any("permission" in item for item in detail["policy_errors"]))

    def test_review_errors_and_self_execution_are_blocked(self):
        FakeArcheryHandler.workflow["review_rows"][0]["errlevel"] = 2
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertTrue(any("review errors" in item for item in detail["policy_errors"]))
        FakeArcheryHandler.workflow["review_rows"][0]["errlevel"] = 0
        FakeArcheryHandler.workflow["is_submitter"] = True
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        self.assertTrue(any("submitted by" in item for item in detail["policy_errors"]))

    def test_mutation_transport_failure_is_outcome_unknown_and_not_retried(self):
        detail = self.client.inspect_workflow(42, max_affected_rows_exclusive=50)
        original = self.client._request
        calls = []

        def fail_execute(path, *args, **kwargs):
            if path == "/execute/":
                calls.append(path)
                raise archery_execute.ExecuteOutcomeUnknown("outcome unknown")
            return original(path, *args, **kwargs)

        with mock.patch.object(self.client, "_request", side_effect=fail_execute):
            with self.assertRaises(archery_execute.ExecuteOutcomeUnknown):
                self.client.execute(
                    42,
                    detail["fingerprint"],
                    expected_token="correct-token",
                    token_reader=lambda _prompt: "correct-token",
                    max_affected_rows_exclusive=50,
                )
        self.assertEqual(["/execute/"], calls)


class ConfigurationTests(unittest.TestCase):
    def test_loads_execute_section_from_shared_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "base_url": "https://archery.example.com",
                        "execute": {
                            "username_env": "ARCHERY_EXECUTE_USERNAME",
                            "password_env": "ARCHERY_EXECUTE_PASSWORD",
                            "confirmation_token_env": "ARCHERY_EXECUTE_CONFIRM_TOKEN",
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = archery_execute.load_config(path)
        self.assertEqual(config["base_url"], "https://archery.example.com")
        self.assertEqual(
            config["confirmation_token_env"], "ARCHERY_EXECUTE_CONFIRM_TOKEN"
        )

    def test_dedicated_environment_variables_are_required(self):
        config = {
            "username_env": "ARCHERY_EXECUTE_USERNAME",
            "password_env": "ARCHERY_EXECUTE_PASSWORD",
            "confirmation_token_env": "ARCHERY_EXECUTE_CONFIRM_TOKEN",
        }
        values = {
            "ARCHERY_EXECUTE_USERNAME": "executor",
            "ARCHERY_EXECUTE_PASSWORD": "execute-password",
            "ARCHERY_EXECUTE_CONFIRM_TOKEN": "secret-token",
        }
        with mock.patch.object(archery_execute, "environment_value", side_effect=values.get):
            self.assertEqual(("executor", "execute-password"), archery_execute.credentials(config))
            self.assertEqual("secret-token", archery_execute.expected_confirmation_token(config))

    def test_secret_values_are_not_leaked_on_failure(self):
        config = {
            "username_env": "ARCHERY_EXECUTE_USERNAME",
            "password_env": "ARCHERY_EXECUTE_PASSWORD",
            "confirmation_token_env": "ARCHERY_EXECUTE_CONFIRM_TOKEN",
        }
        with mock.patch.object(archery_execute, "environment_value", return_value=None):
            with self.assertRaises(archery_execute.ExecuteError) as caught:
                archery_execute.credentials(config)
        self.assertNotIn("execute-password", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
