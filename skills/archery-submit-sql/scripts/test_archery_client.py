#!/usr/bin/env python3
import json
import io
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
import archery_client


class FakeArcheryHandler(BaseHTTPRequestHandler):
    submissions = []

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
        return "sessionid=test-session" in self.headers.get("Cookie", "")

    def _csrf_valid(self):
        expected = "test-csrf" if self.path == "/authenticate/" else "rotated-csrf"
        return self.headers.get("X-CSRFToken") == expected

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login/":
            body = b'<input name="csrfmiddlewaretoken" value="test-csrf">'
            self._send(200, body, headers={"Set-Cookie": "csrftoken=test-csrf; Path=/"})
        elif parsed.path == "/submitsql/" and self._authenticated():
            body = (
                '<form id="form-submitsql"><select id="group_name">'
                '<option value="engineering">Engineering</option></select></form>'
            ).encode("utf-8")
            self._send(200, body)
        elif parsed.path == "/instance/instance_resource/" and self._authenticated():
            body = json.dumps({"status": 0, "msg": "ok", "data": ["app_db"]}).encode()
            self._send(200, body, "application/json")
        elif parsed.path == "/detail/42/" and self._authenticated():
            self._send(200, b"workflow detail")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if not self._csrf_valid():
            self._send(403, b"bad csrf")
            return
        form = self._form()
        if self.path == "/authenticate/":
            if form.get("username") == ["test-user"] and form.get("password") == ["test-password"]:
                body = json.dumps({"status": 0, "msg": "ok", "data": None}).encode()
                self._send(
                    200,
                    body,
                    "application/json",
                    {
                        "Set-Cookie": [
                            "sessionid=test-session; Path=/",
                            "csrftoken=rotated-csrf; Path=/",
                        ]
                    },
                )
            else:
                body = json.dumps({"status": 1, "msg": "bad credentials"}).encode()
                self._send(200, body, "application/json")
        elif not self._authenticated():
            self._send(403, b"not authenticated")
        elif self.path == "/group/instances/":
            body = json.dumps(
                {
                    "status": 0,
                    "msg": "ok",
                    "data": [
                        {
                            "id": 6,
                            "type": "master",
                            "db_type": "mysql",
                            "instance_name": "test-write-instance",
                        }
                    ],
                },
                ensure_ascii=False,
            ).encode("utf-8")
            self._send(200, body, "application/json")
        elif self.path == "/simplecheck/":
            sql = form["sql_content"][0]
            warning_count = 1 if "WARN" in sql else 0
            error_count = 1 if "BAD" in sql else 0
            body = json.dumps(
                {
                    "status": 0,
                    "msg": "ok",
                    "data": {
                        "rows": [{"sql": sql, "errlevel": error_count}],
                        "CheckWarningCount": warning_count,
                        "CheckErrorCount": error_count,
                    },
                }
            ).encode()
            self._send(200, body, "application/json")
        elif self.path == "/autoreview/":
            self.submissions.append(form)
            self._send(302, headers={"Location": "/detail/42/"})
        else:
            self._send(404, b"not found")


class ArcheryClientTests(unittest.TestCase):
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
        FakeArcheryHandler.submissions = []
        self.client = archery_client.ArcheryClient(
            self.base_url, "test-user", "test-password"
        )
        self.client.login()

    def test_login_discovers_groups_instances_and_databases(self):
        self.assertEqual(self.client.groups(), [{"name": "engineering", "label": "Engineering"}])
        self.assertEqual(self.client.instances("engineering")[0]["id"], 6)
        self.assertEqual(self.client.databases("test-write-instance"), ["app_db"])

    def test_check_and_submit_follow_v18_form_protocol(self):
        sql = "ALTER TABLE t ADD COLUMN c INT;"
        check = self.client.check(sql, "test-write-instance", "app_db")
        self.assertEqual(check["warning_count"], 0)
        self.assertEqual(check["error_count"], 0)
        workflow = self.client.submit(
            sql, "test workflow", "engineering", "test-write-instance", "app_db"
        )
        self.assertEqual(workflow["workflow_id"], 42)
        self.assertEqual(FakeArcheryHandler.submissions[0]["is_backup"], ["True"])

    def test_login_failure_does_not_expose_password(self):
        client = archery_client.ArcheryClient(self.base_url, "test-user", "wrong-secret")
        with self.assertRaises(archery_client.ArcheryError) as raised:
            client.login()
        self.assertNotIn("wrong-secret", str(raised.exception))

    def test_full_command_flow_checks_then_submits_matching_sql(self):
        sql = "ALTER TABLE t ADD COLUMN c INT;"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            sql_path = directory / "change.sql"
            sql_path.write_text(sql, encoding="utf-8")
            config_path = directory / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "base_url": self.base_url,
                        "username_env": "ARCHERY_USERNAME",
                        "password_env": "ARCHERY_PASSWORD",
                        "default_database": "app_db",
                        "instances": [
                            {
                                "id": 6,
                                "type": "master",
                                "db_type": "mysql",
                                "instance_name": "test-write-instance",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            environment = {
                "ARCHERY_USERNAME": "test-user",
                "ARCHERY_PASSWORD": "test-password",
            }
            with mock.patch.dict(os.environ, environment, clear=True):
                check_args = archery_client.parser().parse_args(
                    [
                        "--config",
                        str(config_path),
                        "check",
                        "--sql-file",
                        str(sql_path),
                        "--instance",
                        "6",
                    ]
                )
                checked = archery_client.run(check_args)
                self.assertTrue(checked["ok"])

                submit_args = archery_client.parser().parse_args(
                    [
                        "--config",
                        str(config_path),
                        "submit",
                        "--sql-file",
                        str(sql_path),
                        "--instance",
                        "6",
                        "--title",
                        "test workflow",
                        "--confirmed-sha256",
                        checked["sql_sha256"],
                    ]
                )
                submitted = archery_client.run(submit_args)
                self.assertEqual(submitted["workflow_id"], 42)


class DeterministicGateTests(unittest.TestCase):
    def test_loads_submit_section_from_shared_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "base_url": "https://archery.example.com",
                        "submit": {
                            "username_env": "ARCHERY_USERNAME",
                            "password_env": "ARCHERY_PASSWORD",
                            "instances": [],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = archery_client.load_config(path)
        self.assertEqual(config["base_url"], "https://archery.example.com")
        self.assertEqual(config["instances"], [])

    def test_submission_gate_requires_matching_hash(self):
        sql = "ALTER TABLE t ADD COLUMN c INT;"
        with self.assertRaises(archery_client.ArcheryError):
            archery_client.enforce_submission_gate(
                sql,
                "not-the-hash",
                {"warning_count": 0, "error_count": 0},
                False,
            )

    def test_submission_gate_blocks_errors_and_unaccepted_warnings(self):
        sql = "ALTER TABLE t ADD COLUMN c INT;"
        digest = archery_client.sql_sha256(sql)
        with self.assertRaises(archery_client.ArcheryError):
            archery_client.enforce_submission_gate(
                sql, digest, {"warning_count": 0, "error_count": 1}, True
            )
        with self.assertRaises(archery_client.ArcheryError):
            archery_client.enforce_submission_gate(
                sql, digest, {"warning_count": 1, "error_count": 0}, False
            )
        self.assertEqual(
            archery_client.enforce_submission_gate(
                sql, digest, {"warning_count": 1, "error_count": 0}, True
            ),
            digest,
        )

    def test_credentials_are_read_only_from_environment(self):
        config = {"username_env": "ARCHERY_USERNAME", "password_env": "ARCHERY_PASSWORD"}
        with mock.patch.dict(
            os.environ,
            {"ARCHERY_USERNAME": "env-user", "ARCHERY_PASSWORD": "env-password"},
            clear=True,
        ):
            self.assertEqual(
                archery_client.credentials(config), ("env-user", "env-password")
            )

    def test_credentials_fall_back_to_macos_login_environment(self):
        config = {"username_env": "ARCHERY_USERNAME", "password_env": "ARCHERY_PASSWORD"}
        values = {
            "ARCHERY_USERNAME": "session-user\n",
            "ARCHERY_PASSWORD": "session-password\n",
        }

        def launchctl(command, **_kwargs):
            return mock.Mock(returncode=0, stdout=values[command[-1]])

        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            archery_client.sys, "platform", "darwin"
        ), mock.patch.object(archery_client.subprocess, "run", side_effect=launchctl):
            self.assertEqual(
                archery_client.credentials(config),
                ("session-user", "session-password"),
            )

    def test_read_sql_rejects_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.sql"
            path.touch()
            with self.assertRaises(archery_client.ArcheryError):
                archery_client.read_sql(path)

    def test_main_returns_nonzero_for_completed_check_with_sql_errors(self):
        with mock.patch.object(
            archery_client, "run", return_value={"ok": False, "action": "check"}
        ), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(archery_client.main(["inspect"]), 3)


if __name__ == "__main__":
    unittest.main()
