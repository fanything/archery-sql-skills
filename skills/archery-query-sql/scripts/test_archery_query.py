#!/usr/bin/env python3
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
import archery_query


class FakeArcheryHandler(BaseHTTPRequestHandler):
    queries = []

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
        expected = "initial-csrf" if self.path == "/authenticate/" else "rotated-csrf"
        return self.headers.get("X-CSRFToken") == expected

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login/":
            body = b'<input name="csrfmiddlewaretoken" value="initial-csrf">'
            self._send(
                200, body, headers={"Set-Cookie": "csrftoken=initial-csrf; Path=/"}
            )
        elif parsed.path == "/sqlquery/" and self._authenticated():
            self._send(200, b'<form id="form-sqlquery"></form>')
        elif parsed.path == "/group/user_all_instances/" and self._authenticated():
            body = json.dumps(
                {
                    "status": 0,
                    "msg": "ok",
                    "data": [
                        {
                            "id": 6,
                            "type": "master",
                            "db_type": "mysql",
                            "instance_name": "test-query-instance",
                        }
                    ],
                },
                ensure_ascii=False,
            ).encode("utf-8")
            self._send(200, body, "application/json")
        elif parsed.path == "/instance/instance_resource/" and self._authenticated():
            body = json.dumps({"status": 0, "msg": "ok", "data": ["app_db"]}).encode()
            self._send(200, body, "application/json")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        if not self._csrf_valid():
            self._send(403, b"bad csrf")
            return
        form = self._form()
        if self.path == "/authenticate/":
            if form.get("username") == ["query-user"] and form.get("password") == ["query-password"]:
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
        elif self.path == "/query/":
            self.queries.append(form)
            if "FAIL" in form["sql_content"][0]:
                body = json.dumps({"status": 2, "msg": "no query permission"}).encode()
            else:
                body = json.dumps(
                    {
                        "status": 0,
                        "msg": "ok",
                        "data": {
                            "full_sql": form["sql_content"][0],
                            "rows": [[1]],
                            "column_list": ["value"],
                            "affected_rows": 1,
                            "query_time": "0.001",
                            "mask_time": "",
                            "is_masked": False,
                            "mask_rule_hit": False,
                            "seconds_behind_master": 0,
                        },
                    }
                ).encode()
            self._send(200, body, "application/json")
        else:
            self._send(404, b"not found")


class ArcheryQueryClientTests(unittest.TestCase):
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
        FakeArcheryHandler.queries = []
        self.client = archery_query.ArcheryQueryClient(
            self.base_url, "query-user", "query-password"
        )
        self.client.login()

    def test_discovers_query_instances_and_databases(self):
        self.assertEqual(self.client.instances()[0]["id"], 6)
        self.assertEqual(self.client.databases("test-query-instance"), ["app_db"])

    def test_query_uses_v18_form_protocol(self):
        result = self.client.query("SELECT 1", "test-query-instance", "app_db", 100)
        self.assertEqual(result["columns"], ["value"])
        self.assertEqual(result["rows"], [[1]])
        self.assertEqual(FakeArcheryHandler.queries[0]["limit_num"], ["100"])

    def test_query_permission_failure_is_visible(self):
        with self.assertRaisesRegex(archery_query.QueryError, "no query permission"):
            self.client.query("SELECT 'FAIL'", "test-query-instance", "app_db", 100)

    def test_login_failure_does_not_expose_password(self):
        client = archery_query.ArcheryQueryClient(
            self.base_url, "query-user", "wrong-secret"
        )
        with self.assertRaises(archery_query.QueryError) as raised:
            client.login()
        self.assertNotIn("wrong-secret", str(raised.exception))

    def test_full_command_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            sql_path = directory / "query.sql"
            sql_path.write_text("SELECT 1;", encoding="utf-8")
            config_path = directory / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "base_url": self.base_url,
                        "username_env": "ARCHERY_USERNAME",
                        "password_env": "ARCHERY_PASSWORD",
                        "default_database": "app_db",
                        "default_limit": 100,
                        "max_limit": 1000,
                        "aliases": {"测试": 6},
                        "instances": [
                            {
                                "id": 6,
                                "type": "master",
                                "db_type": "mysql",
                                "instance_name": "test-query-instance",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "ARCHERY_USERNAME": "query-user",
                    "ARCHERY_PASSWORD": "query-password",
                },
                clear=True,
            ):
                args = archery_query.parser().parse_args(
                    [
                        "--config",
                        str(config_path),
                        "query",
                        "--sql-file",
                        str(sql_path),
                        "--instance",
                        "测试",
                    ]
                )
                result = archery_query.run(args)
        self.assertEqual(result["query_type"], "SELECT")
        self.assertEqual(result["returned_rows"], 1)
        self.assertTrue(result["query_logged_by_archery"])


class ReadOnlyValidationTests(unittest.TestCase):
    def test_loads_query_section_from_shared_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "base_url": "https://archery.example.com",
                        "query": {
                            "username_env": "ARCHERY_USERNAME",
                            "password_env": "ARCHERY_PASSWORD",
                            "instances": [],
                            "default_limit": 100,
                            "max_limit": 1000,
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = archery_query.load_config(path)
        self.assertEqual(config["base_url"], "https://archery.example.com")
        self.assertEqual(config["max_limit"], 1000)

    def test_allows_select_and_explain_select(self):
        self.assertEqual(archery_query.validate_read_only_sql("SELECT 1;"), "SELECT")
        self.assertEqual(
            archery_query.validate_read_only_sql("EXPLAIN SELECT * FROM t"),
            "EXPLAIN SELECT",
        )

    def test_allows_keywords_inside_comments_strings_and_identifiers(self):
        sql = "/* UPDATE ignored */ SELECT 'DROP', `delete` FROM t; -- INSERT"
        self.assertEqual(archery_query.validate_read_only_sql(sql), "SELECT")

    def test_allows_semicolon_inside_string_but_only_one_statement(self):
        self.assertEqual(
            archery_query.validate_read_only_sql("SELECT ';' AS value;"), "SELECT"
        )
        with self.assertRaisesRegex(archery_query.QueryError, "one SQL statement"):
            archery_query.validate_read_only_sql("SELECT 1; SELECT 2")

    def test_rejects_every_other_statement_family(self):
        for sql in (
            "UPDATE t SET c=1",
            "DELETE FROM t",
            "INSERT INTO t VALUES (1)",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SHOW TABLES",
            "DESC t",
            "EXPLAIN UPDATE t SET c=1",
        ):
            with self.subTest(sql=sql), self.assertRaises(archery_query.QueryError):
                archery_query.validate_read_only_sql(sql)

    def test_rejects_select_side_effects_and_locking(self):
        for sql in (
            "SELECT * FROM t FOR UPDATE",
            "SELECT * INTO OUTFILE '/tmp/x' FROM t",
            "SELECT GET_LOCK('x', 1)",
            "SELECT @value := 1",
            "SELECT LAST_INSERT_ID(2)",
        ):
            with self.subTest(sql=sql), self.assertRaises(archery_query.QueryError):
                archery_query.validate_read_only_sql(sql)

    def test_rejects_executable_comments_and_unterminated_input(self):
        for sql in ("/*! SELECT 1 */", "/*+ hint */ SELECT 1", "SELECT 'value"):
            with self.subTest(sql=sql), self.assertRaises(archery_query.QueryError):
                archery_query.validate_read_only_sql(sql)

    def test_limit_is_bounded(self):
        config = {"max_limit": 1000}
        self.assertEqual(archery_query.validate_limit(config, 100), 100)
        for limit in (0, 1001):
            with self.subTest(limit=limit), self.assertRaises(archery_query.QueryError):
                archery_query.validate_limit(config, limit)

    def test_credentials_are_read_from_environment(self):
        config = {
            "username_env": "ARCHERY_USERNAME",
            "password_env": "ARCHERY_PASSWORD",
        }
        with mock.patch.dict(
            os.environ,
            {
                "ARCHERY_USERNAME": "query-user",
                "ARCHERY_PASSWORD": "query-password",
            },
            clear=True,
        ):
            self.assertEqual(
                archery_query.credentials(config), ("query-user", "query-password")
            )


if __name__ == "__main__":
    unittest.main()
