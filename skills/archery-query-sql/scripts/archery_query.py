#!/usr/bin/env python3
"""Strict read-only SELECT client for Archery v1.8.0."""

import argparse
import html
import http.cookiejar
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path


CONFIG_FILE_ENV = "ARCHERY_CONFIG_FILE"
DEFAULT_CONFIG = Path.home() / ".config" / "archery-sql-skills" / "config.json"
CONFIG_SECTIONS = ("query", "submit", "review", "execute")
MAX_SQL_BYTES = 1024 * 1024

FORBIDDEN_TOKENS = {
    "ALTER",
    "ANALYZE",
    "CALL",
    "CREATE",
    "DELETE",
    "DO",
    "DROP",
    "EXECUTE",
    "FOR",
    "GRANT",
    "HANDLER",
    "INSERT",
    "INTO",
    "LOAD",
    "LOCK",
    "OPTIMIZE",
    "PREPARE",
    "PROCEDURE",
    "PURGE",
    "RENAME",
    "REPAIR",
    "REPLACE",
    "REVOKE",
    "SET",
    "TRUNCATE",
    "UNLOCK",
    "UPDATE",
    "USE",
}

DANGEROUS_FUNCTIONS = {
    "BENCHMARK",
    "GET_LOCK",
    "LAST_INSERT_ID",
    "LOAD_FILE",
    "RELEASE_ALL_LOCKS",
    "RELEASE_LOCK",
    "SLEEP",
}


class QueryError(RuntimeError):
    pass


class _LoginPageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrfmiddlewaretoken":
            self.csrf_token = attrs.get("value")


def _compact_html(body):
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", body, flags=re.I | re.S)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return text[:800] or "empty response"


def _verified_ssl_context():
    default_paths = ssl.get_default_verify_paths()
    if default_paths.cafile:
        return ssl.create_default_context()
    for path in (os.environ.get("SSL_CERT_FILE"), "/etc/ssl/cert.pem"):
        if path and Path(path).is_file():
            return ssl.create_default_context(cafile=path)
    return ssl.create_default_context()


def environment_value(name):
    value = os.environ.get(name)
    if value or sys.platform != "darwin":
        return value
    result = subprocess.run(
        ["launchctl", "getenv", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.stdout.rstrip("\r\n") or None


def credentials(config):
    username_name = config["username_env"]
    password_name = config["password_env"]
    username = environment_value(username_name)
    password = environment_value(password_name)
    missing = [
        name
        for name, value in ((username_name, username), (password_name, password))
        if not value
    ]
    if missing:
        raise QueryError(
            "Missing required environment variable(s): {}".format(", ".join(missing))
        )
    return username, password


class ArcheryQueryClient:
    def __init__(self, base_url, username, password, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cookies = http.cookiejar.CookieJar()
        self.csrf_token = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=_verified_ssl_context()),
        )

    def _cookie(self, name):
        for cookie in self.cookies:
            if cookie.name == name:
                return cookie.value
        return None

    def _request(self, path, method="GET", fields=None):
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        data = None
        headers = {"Accept": "application/json, text/html;q=0.9"}
        if fields is not None:
            data = urllib.parse.urlencode(fields, doseq=True).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if method != "GET" and self.csrf_token:
            headers["X-CSRFToken"] = self.csrf_token
            headers["Referer"] = self.base_url + "/"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return (
                    response.status,
                    response.geturl(),
                    response.read().decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise QueryError(
                "Archery returned HTTP {} for {}: {}".format(
                    error.code, urllib.parse.urlparse(url).path, _compact_html(body)
                )
            ) from None
        except urllib.error.URLError as error:
            raise QueryError("Unable to reach Archery: {}".format(error.reason)) from None

    @staticmethod
    def _json(body, action):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise QueryError(
                "Archery returned non-JSON data during {}: {}".format(
                    action, _compact_html(body)
                )
            ) from None

    def login(self):
        _, final_url, body = self._request("/login/")
        if urllib.parse.urlparse(final_url).path not in ("/login", "/login/"):
            raise QueryError("Unexpected login page redirect: {}".format(final_url))
        parser = _LoginPageParser()
        parser.feed(body)
        self.csrf_token = self._cookie("csrftoken") or parser.csrf_token
        if not self.csrf_token:
            raise QueryError("Archery login page did not provide a CSRF token")

        _, _, body = self._request(
            "/authenticate/",
            method="POST",
            fields={"username": self.username, "password": self.password},
        )
        result = self._json(body, "login")
        if result.get("status") != 0:
            raise QueryError("Archery login failed: {}".format(result.get("msg", "unknown error")))
        if not self._cookie("sessionid"):
            raise QueryError("Archery login succeeded without a session cookie")
        self.csrf_token = self._cookie("csrftoken") or self.csrf_token

        _, final_url, body = self._request("/sqlquery/")
        if urllib.parse.urlparse(final_url).path not in ("/sqlquery", "/sqlquery/"):
            raise QueryError("SQL query page is unavailable after login")
        if 'id="form-sqlquery"' not in body:
            raise QueryError("Authenticated account does not have SQL query page access")

    def instances(self):
        query = urllib.parse.urlencode({"tag_codes[]": "can_read"})
        _, _, body = self._request("/group/user_all_instances/?" + query)
        result = self._json(body, "query instance discovery")
        if result.get("status") != 0:
            raise QueryError(
                "Query instance discovery failed: {}".format(
                    result.get("msg", "unknown error")
                )
            )
        return result.get("data", [])

    def databases(self, instance_name):
        query = urllib.parse.urlencode(
            {"instance_name": instance_name, "resource_type": "database"}
        )
        _, _, body = self._request("/instance/instance_resource/?" + query)
        result = self._json(body, "database discovery")
        if result.get("status") != 0:
            raise QueryError(
                "Database discovery failed: {}".format(
                    result.get("msg", "unknown error")
                )
            )
        return result.get("data", [])

    def query(self, sql, instance_name, database, limit):
        _, _, body = self._request(
            "/query/",
            method="POST",
            fields={
                "instance_name": instance_name,
                "db_name": database,
                "schema_name": "",
                "tb_name": "",
                "sql_content": sql,
                "limit_num": str(limit),
            },
        )
        result = self._json(body, "SQL query")
        if result.get("status") != 0:
            raise QueryError("SQL query failed: {}".format(result.get("msg", "unknown error")))
        data = result.get("data") or {}
        rows = data.get("rows") or []
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]
        return {
            "columns": data.get("column_list") or [],
            "rows": rows,
            "returned_rows": len(rows),
            "server_affected_rows": data.get("affected_rows"),
            "query_time": data.get("query_time"),
            "mask_time": data.get("mask_time"),
            "is_masked": bool(data.get("is_masked", False)),
            "mask_rule_hit": bool(data.get("mask_rule_hit", False)),
            "seconds_behind_master": data.get("seconds_behind_master"),
            "server_sql": data.get("full_sql"),
            "truncated_by_client": truncated,
        }


def load_config(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            raw_config = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise QueryError("Unable to load config {}: {}".format(path, error)) from None
    if not isinstance(raw_config, dict):
        raise QueryError("Config root must be a JSON object")
    if any(key in raw_config for key in CONFIG_SECTIONS):
        config = raw_config.get("query")
        if not isinstance(config, dict):
            raise QueryError("Shared config is missing object section: query")
        config = dict(config)
        config.setdefault("base_url", raw_config.get("base_url"))
    else:
        config = raw_config
    for key in ("base_url", "username_env", "password_env"):
        if not config.get(key):
            raise QueryError("Config is missing required field: {}".format(key))
    for key in ("instances", "default_limit", "max_limit"):
        if config.get(key) is None:
            raise QueryError("Config is missing required field: {}".format(key))
    return config


def read_sql(path):
    sql_path = Path(path)
    try:
        size = sql_path.stat().st_size
    except OSError as error:
        raise QueryError("Unable to read SQL file {}: {}".format(path, error)) from None
    if size == 0:
        raise QueryError("SQL file is empty: {}".format(path))
    if size > MAX_SQL_BYTES:
        raise QueryError("SQL file exceeds the 1 MiB client limit: {}".format(path))
    try:
        sql = sql_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise QueryError("SQL file must be readable UTF-8: {}".format(error)) from None
    if not sql.strip():
        raise QueryError("SQL file contains only whitespace")
    return sql


def _scan_tokens(sql):
    tokens = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < length else ""
        if char.isspace():
            index += 1
            continue
        if char == "#" or (char == "-" and next_char == "-"):
            newline = sql.find("\n", index + 1)
            index = length if newline == -1 else newline + 1
            continue
        if char == "/" and next_char == "*":
            if index + 2 < length and sql[index + 2] in ("!", "+"):
                raise QueryError("Executable or optimizer comments are not allowed")
            end = sql.find("*/", index + 2)
            if end == -1:
                raise QueryError("Unterminated block comment")
            index = end + 2
            continue
        if char in ("'", '"', "`"):
            quote = char
            index += 1
            while index < length:
                if sql[index] == "\\" and quote != "`":
                    index += 2
                    continue
                if sql[index] == quote:
                    if index + 1 < length and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            else:
                raise QueryError("Unterminated quoted value or identifier")
            continue
        if char == ";":
            tokens.append(";")
            index += 1
            continue
        if char == ":" and next_char == "=":
            tokens.append(":=")
            index += 2
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (sql[end].isalnum() or sql[end] in ("_", "$")):
                end += 1
            tokens.append(sql[index:end].upper())
            index = end
            continue
        index += 1
    return tokens


def validate_read_only_sql(sql):
    tokens = _scan_tokens(sql)
    if not tokens:
        raise QueryError("SQL contains no executable statement")
    semicolons = [index for index, token in enumerate(tokens) if token == ";"]
    if len(semicolons) > 1 or (semicolons and semicolons[0] != len(tokens) - 1):
        raise QueryError("Exactly one SQL statement is allowed")
    statement_tokens = [token for token in tokens if token != ";"]
    if not statement_tokens:
        raise QueryError("SQL contains no executable statement")
    if statement_tokens[0] == "SELECT":
        query_type = "SELECT"
    elif len(statement_tokens) >= 2 and statement_tokens[:2] == ["EXPLAIN", "SELECT"]:
        query_type = "EXPLAIN SELECT"
    else:
        raise QueryError("Only SELECT and EXPLAIN SELECT are allowed")
    forbidden = sorted(FORBIDDEN_TOKENS.intersection(statement_tokens))
    dangerous = sorted(DANGEROUS_FUNCTIONS.intersection(statement_tokens))
    if ":=" in statement_tokens:
        raise QueryError("SQL assignment operators are not allowed")
    if forbidden:
        raise QueryError("Forbidden SQL token(s): {}".format(", ".join(forbidden)))
    if dangerous:
        raise QueryError("Dangerous SQL function(s): {}".format(", ".join(dangerous)))
    return query_type


def resolve_instance(config, selector):
    alias_value = (config.get("aliases") or {}).get(str(selector))
    selector = str(alias_value if alias_value is not None else selector)
    matches = [
        item
        for item in config["instances"]
        if str(item.get("id")) == selector or item.get("instance_name") == selector
    ]
    if len(matches) != 1:
        raise QueryError("Configured instance is missing or ambiguous: {}".format(selector))
    return matches[0]


def validate_limit(config, limit):
    if limit < 1:
        raise QueryError("Query limit must be at least 1")
    if limit > int(config["max_limit"]):
        raise QueryError(
            "Query limit exceeds the configured maximum of {}".format(
                config["max_limit"]
            )
        )
    return limit


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--config", default=environment_value(CONFIG_FILE_ENV) or str(DEFAULT_CONFIG)
    )
    result.add_argument("--timeout", type=int, default=30)
    commands = result.add_subparsers(dest="command", required=True)

    commands.add_parser("inspect", help="List instances available for SQL query")

    databases = commands.add_parser("databases", help="List databases for an instance")
    databases.add_argument("--instance", required=True)

    query = commands.add_parser("query", help="Execute one SELECT or EXPLAIN SELECT")
    query.add_argument("--sql-file", required=True)
    query.add_argument("--instance", required=True)
    query.add_argument("--database")
    query.add_argument("--limit", type=int)
    return result


def run(args):
    config = load_config(args.config)
    username, password = credentials(config)
    client = ArcheryQueryClient(
        config["base_url"], username, password, timeout=args.timeout
    )
    client.login()
    remote_instances = client.instances()

    if args.command == "inspect":
        return {"ok": True, "action": "inspect", "instances": remote_instances}

    instance = resolve_instance(config, args.instance)
    if not any(
        str(item.get("id")) == str(instance["id"])
        and item.get("instance_name") == instance["instance_name"]
        for item in remote_instances
    ):
        raise QueryError("Selected instance is not available for SQL query")
    databases = client.databases(instance["instance_name"])

    if args.command == "databases":
        return {
            "ok": True,
            "action": "databases",
            "instance": instance,
            "databases": databases,
        }

    database = args.database or config.get("default_database")
    if not database:
        raise QueryError("Database is required")
    if database not in databases:
        raise QueryError("Database is not available on the selected instance: {}".format(database))
    limit = validate_limit(
        config,
        args.limit if args.limit is not None else int(config["default_limit"]),
    )
    sql = read_sql(args.sql_file)
    query_type = validate_read_only_sql(sql)
    query_result = client.query(sql, instance["instance_name"], database, limit)
    return {
        "ok": True,
        "action": "query",
        "query_type": query_type,
        "instance": instance,
        "database": database,
        "requested_limit": limit,
        "query_logged_by_archery": True,
        **query_result,
    }


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except QueryError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
