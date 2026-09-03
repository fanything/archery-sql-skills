#!/usr/bin/env python3
"""Deterministic Archery v1.8.0 SQL check and workflow submission client."""

import argparse
import hashlib
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
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path


CONFIG_FILE_ENV = "ARCHERY_CONFIG_FILE"
DEFAULT_CONFIG = Path.home() / ".config" / "archery-sql-skills" / "config.json"
CONFIG_SECTIONS = ("query", "submit", "review", "execute")
MAX_SQL_BYTES = 10 * 1024 * 1024


class ArcheryError(RuntimeError):
    pass


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None
        self.groups = []
        self._in_group_select = False
        self._option_value = None
        self._option_text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrfmiddlewaretoken":
            self.csrf_token = attrs.get("value")
        elif tag == "select" and attrs.get("id") == "group_name":
            self._in_group_select = True
        elif tag == "option" and self._in_group_select:
            self._option_value = attrs.get("value")
            self._option_text = []

    def handle_data(self, data):
        if self._option_value is not None:
            self._option_text.append(data)

    def handle_endtag(self, tag):
        if tag == "option" and self._option_value is not None:
            value = self._option_value.strip()
            label = "".join(self._option_text).strip()
            if value:
                self.groups.append({"name": value, "label": label or value})
            self._option_value = None
            self._option_text = []
        elif tag == "select" and self._in_group_select:
            self._in_group_select = False


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


class ArcheryClient:
    def __init__(self, base_url, username, password, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=_verified_ssl_context()),
        )
        self.csrf_token = None
        self.submit_page = None

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
                body = response.read().decode("utf-8", errors="replace")
                return response.status, response.geturl(), body
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise ArcheryError(
                "Archery returned HTTP {} for {}: {}".format(
                    error.code, urllib.parse.urlparse(url).path, _compact_html(body)
                )
            ) from None
        except urllib.error.URLError as error:
            raise ArcheryError("Unable to reach Archery: {}".format(error.reason)) from None

    @staticmethod
    def _json(body, action):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise ArcheryError(
                "Archery returned non-JSON data during {}: {}".format(
                    action, _compact_html(body)
                )
            ) from None

    def login(self):
        _, final_url, body = self._request("/login/")
        if urllib.parse.urlparse(final_url).path not in ("/login", "/login/"):
            raise ArcheryError("Unexpected login page redirect: {}".format(final_url))
        parser = _PageParser()
        parser.feed(body)
        self.csrf_token = self._cookie("csrftoken") or parser.csrf_token
        if not self.csrf_token:
            raise ArcheryError("Archery login page did not provide a CSRF token")

        _, _, body = self._request(
            "/authenticate/",
            method="POST",
            fields={"username": self.username, "password": self.password},
        )
        result = self._json(body, "login")
        if result.get("status") != 0:
            raise ArcheryError("Archery login failed: {}".format(result.get("msg", "unknown error")))
        if not self._cookie("sessionid"):
            raise ArcheryError("Archery login succeeded without a session cookie")
        self.csrf_token = self._cookie("csrftoken") or self.csrf_token

        _, final_url, self.submit_page = self._request("/submitsql/")
        if urllib.parse.urlparse(final_url).path not in ("/submitsql", "/submitsql/"):
            raise ArcheryError("SQL submission page is unavailable after login")
        if 'id="form-submitsql"' not in self.submit_page:
            raise ArcheryError("Authenticated page does not contain the SQL submission form")

    def groups(self):
        if self.submit_page is None:
            raise ArcheryError("Login is required before group discovery")
        parser = _PageParser()
        parser.feed(self.submit_page)
        if not parser.groups:
            raise ArcheryError("No writable Archery resource groups were found")
        return parser.groups

    def instances(self, group_name):
        _, _, body = self._request(
            "/group/instances/",
            method="POST",
            fields={"group_name": group_name, "tag_code": "can_write"},
        )
        result = self._json(body, "instance discovery")
        if result.get("status") != 0:
            raise ArcheryError("Instance discovery failed: {}".format(result.get("msg", "unknown error")))
        return result.get("data", [])

    def databases(self, instance_name):
        query = urllib.parse.urlencode(
            {"instance_name": instance_name, "resource_type": "database"}
        )
        _, _, body = self._request("/instance/instance_resource/?" + query)
        result = self._json(body, "database discovery")
        if result.get("status") != 0:
            raise ArcheryError("Database discovery failed: {}".format(result.get("msg", "unknown error")))
        return result.get("data", [])

    def check(self, sql, instance_name, database):
        _, _, body = self._request(
            "/simplecheck/",
            method="POST",
            fields={
                "sql_content": sql,
                "instance_name": instance_name,
                "db_name": database,
            },
        )
        result = self._json(body, "SQL check")
        if result.get("status") != 0:
            raise ArcheryError("SQL check failed: {}".format(result.get("msg", "unknown error")))
        data = result.get("data") or {}
        return {
            "warning_count": int(data.get("CheckWarningCount", 0)),
            "error_count": int(data.get("CheckErrorCount", 0)),
            "rows": data.get("rows", []),
        }

    def submit(
        self,
        sql,
        title,
        group_name,
        instance_name,
        database,
        demand_url="",
        backup=True,
        run_date_start="",
        run_date_end="",
    ):
        _, final_url, body = self._request(
            "/autoreview/",
            method="POST",
            fields={
                "sql_content": sql,
                "workflow_name": title,
                "demand_url": demand_url,
                "group_name": group_name,
                "instance_name": instance_name,
                "db_name": database,
                "is_backup": "True" if backup else "False",
                "run_date_start": run_date_start,
                "run_date_end": run_date_end,
            },
        )
        match = re.search(r"/detail/(\d+)/?$", urllib.parse.urlparse(final_url).path)
        if not match:
            raise ArcheryError(
                "Workflow submission did not reach a detail page: {}".format(
                    _compact_html(body)
                )
            )
        return {"workflow_id": int(match.group(1)), "url": final_url}


def load_config(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            raw_config = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ArcheryError("Unable to load config {}: {}".format(path, error)) from None
    if not isinstance(raw_config, dict):
        raise ArcheryError("Config root must be a JSON object")
    if any(key in raw_config for key in CONFIG_SECTIONS):
        config = raw_config.get("submit")
        if not isinstance(config, dict):
            raise ArcheryError("Shared config is missing object section: submit")
        config = dict(config)
        config.setdefault("base_url", raw_config.get("base_url"))
    else:
        config = raw_config
    for key in ("base_url", "username_env", "password_env"):
        if not config.get(key):
            raise ArcheryError("Config is missing required field: {}".format(key))
    if config.get("instances") is None:
        raise ArcheryError("Config is missing required field: instances")
    return config


def credentials(config):
    username_name = config["username_env"]
    password_name = config["password_env"]
    username = environment_value(username_name)
    password = environment_value(password_name)
    missing = [name for name, value in ((username_name, username), (password_name, password)) if not value]
    if missing:
        raise ArcheryError("Missing required environment variable(s): {}".format(", ".join(missing)))
    return username, password


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


def read_sql(path):
    sql_path = Path(path)
    try:
        size = sql_path.stat().st_size
    except OSError as error:
        raise ArcheryError("Unable to read SQL file {}: {}".format(path, error)) from None
    if size == 0:
        raise ArcheryError("SQL file is empty: {}".format(path))
    if size > MAX_SQL_BYTES:
        raise ArcheryError("SQL file exceeds the Archery 10 MiB limit: {}".format(path))
    try:
        sql = sql_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ArcheryError("SQL file must be readable UTF-8: {}".format(error)) from None
    if not sql.strip():
        raise ArcheryError("SQL file contains only whitespace")
    return sql


def sql_sha256(sql):
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def resolve_instance(config, selector):
    selector = str(selector)
    matches = [
        item
        for item in config["instances"]
        if str(item.get("id")) == selector or item.get("instance_name") == selector
    ]
    if len(matches) != 1:
        raise ArcheryError("Configured instance is missing or ambiguous: {}".format(selector))
    return matches[0]


def validate_window(start, end):
    if bool(start) != bool(end):
        raise ArcheryError("Both execution window start and end are required together")
    if not start:
        return
    try:
        start_value = datetime.strptime(start, "%Y-%m-%d %H:%M")
        end_value = datetime.strptime(end, "%Y-%m-%d %H:%M")
    except ValueError:
        raise ArcheryError("Execution window must use YYYY-MM-DD HH:MM") from None
    if end_value <= start_value:
        raise ArcheryError("Execution window end must be later than start")


def enforce_submission_gate(sql, confirmed_sha256, check_result, allow_warnings):
    digest = sql_sha256(sql)
    if confirmed_sha256 != digest:
        raise ArcheryError("Confirmed SQL SHA-256 does not match the current SQL file")
    if check_result["error_count"] > 0:
        raise ArcheryError("Submission blocked because the SQL check returned errors")
    if check_result["warning_count"] > 0 and not allow_warnings:
        raise ArcheryError("Submission blocked because warnings were not explicitly accepted")
    return digest


def target_context(client, config, instance, database, requested_group=None):
    groups = client.groups()
    available = []
    for group in groups:
        remote_instances = client.instances(group["name"])
        if any(
            str(item.get("id")) == str(instance["id"])
            and item.get("instance_name") == instance["instance_name"]
            for item in remote_instances
        ):
            available.append(group["name"])
    if requested_group:
        if requested_group not in available:
            raise ArcheryError("Instance is not writable in resource group: {}".format(requested_group))
        group_name = requested_group
    elif len(available) == 1:
        group_name = available[0]
    elif not available:
        raise ArcheryError("Configured instance is not writable in any available resource group")
    else:
        raise ArcheryError("Resource group is ambiguous; choose one of: {}".format(", ".join(available)))

    databases = client.databases(instance["instance_name"])
    if database not in databases:
        raise ArcheryError("Database is not available on the selected instance: {}".format(database))
    return group_name, available


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--config", default=environment_value(CONFIG_FILE_ENV) or str(DEFAULT_CONFIG)
    )
    result.add_argument("--timeout", type=int, default=30)
    commands = result.add_subparsers(dest="command", required=True)

    commands.add_parser("inspect", help="List writable resource groups and instances")

    databases = commands.add_parser("databases", help="List databases for a configured instance")
    databases.add_argument("--instance", required=True)

    check = commands.add_parser("check", help="Run Archery server-side SQL checking")
    check.add_argument("--sql-file", required=True)
    check.add_argument("--instance", required=True)
    check.add_argument("--database")
    check.add_argument("--group")

    submit = commands.add_parser("submit", help="Recheck and submit an SQL approval workflow")
    submit.add_argument("--sql-file", required=True)
    submit.add_argument("--instance", required=True)
    submit.add_argument("--database")
    submit.add_argument("--group")
    submit.add_argument("--title", required=True)
    submit.add_argument("--demand-url", default="")
    submit.add_argument("--no-backup", action="store_true")
    submit.add_argument("--run-date-start", default="")
    submit.add_argument("--run-date-end", default="")
    submit.add_argument("--confirmed-sha256", required=True)
    submit.add_argument("--allow-warnings", action="store_true")
    return result


def run(args):
    config = load_config(args.config)
    username, password = credentials(config)
    client = ArcheryClient(config["base_url"], username, password, timeout=args.timeout)
    client.login()

    if args.command == "inspect":
        groups = []
        for group in client.groups():
            groups.append({**group, "instances": client.instances(group["name"])})
        return {"ok": True, "action": "inspect", "groups": groups}

    instance = resolve_instance(config, args.instance)
    if args.command == "databases":
        return {
            "ok": True,
            "action": "databases",
            "instance": instance,
            "databases": client.databases(instance["instance_name"]),
        }

    sql = read_sql(args.sql_file)
    database = args.database or config.get("default_database")
    if not database:
        raise ArcheryError("Database is required")
    group_name, available_groups = target_context(
        client, config, instance, database, args.group
    )
    check_result = client.check(sql, instance["instance_name"], database)
    digest = sql_sha256(sql)
    common = {
        "sql_sha256": digest,
        "instance": instance,
        "database": database,
        "resource_group": group_name,
        "available_resource_groups": available_groups,
        "check": check_result,
    }

    if args.command == "check":
        return {"ok": check_result["error_count"] == 0, "action": "check", **common}

    if not args.title.strip():
        raise ArcheryError("Workflow title is required")
    if len(args.title) > 50:
        raise ArcheryError("Workflow title exceeds the Archery 50-character limit")
    if len(args.demand_url) > 500:
        raise ArcheryError("Demand URL exceeds the Archery 500-character limit")
    validate_window(args.run_date_start, args.run_date_end)
    enforce_submission_gate(sql, args.confirmed_sha256, check_result, args.allow_warnings)
    workflow = client.submit(
        sql=sql,
        title=args.title,
        group_name=group_name,
        instance_name=instance["instance_name"],
        database=database,
        demand_url=args.demand_url,
        backup=not args.no_backup,
        run_date_start=args.run_date_start,
        run_date_end=args.run_date_end,
    )
    return {"ok": True, "action": "submit", **common, **workflow}


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except ArcheryError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
