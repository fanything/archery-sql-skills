#!/usr/bin/env python3
"""Safely dispatch one approved UPDATE or INSERT workflow through Archery v1.8.0."""

import argparse
import getpass
import hashlib
import hmac
import html
import http.client
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
WORKFLOW_TYPE_SQL_REVIEW = 2
APPROVED_STATUS = "workflow_review_pass"
DISPATCHED_STATUSES = {
    "workflow_queuing": "queued",
    "workflow_executing": "running",
    "workflow_finish": "finished",
    "workflow_exception": "failed",
}
MAX_AFFECTED_ROWS_EXCLUSIVE = 50


class ExecuteError(RuntimeError):
    pass


class ExecuteOutcomeUnknown(ExecuteError):
    pass


class SqlPolicyError(ExecuteError):
    pass


class _LoginPageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.csrf_token = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "csrfmiddlewaretoken":
            self.csrf_token = attrs.get("value")


class _WorkflowDetailParser(HTMLParser):
    SUMMARY_FIELDS = (
        "submitter",
        "approval_flow",
        "current_approval",
        "instance",
        "database",
        "create_time",
        "execution_window",
        "finish_time",
        "backup",
        "status_display",
        "group",
        "syntax_type",
    )

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.workflow_id = None
        self.sql = None
        self.title_parts = []
        self.status_parts = []
        self.display_parts = []
        self.cells = []
        self.can_execute = False
        self.is_submitter = False
        self._in_title = False
        self._in_summary_row = False
        self._in_cell = False
        self._cell_parts = []
        self._in_status = False
        self._in_display = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        element_id = attrs.get("id")
        if tag == "h4":
            self._in_title = True
        if tag == "input":
            if element_id == "editSqlContent":
                self.sql = attrs.get("value", "")
            if attrs.get("name") == "workflow_id" and attrs.get("value"):
                self.workflow_id = attrs["value"]
        if element_id == "btnExecuteOnly":
            self.can_execute = True
        if element_id == "btnSubmitOtherCluster":
            self.is_submitter = True
        if tag == "tr" and "success" in attrs.get("class", "").split():
            self._in_summary_row = True
        elif tag == "td" and self._in_summary_row:
            self._in_cell = True
            self._cell_parts = []
        if element_id == "workflow_detail_status":
            self._in_status = True
        if element_id == "workflow_detail_disaply":
            self._in_display = True

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        if self._in_cell:
            self._cell_parts.append(data)
        if self._in_status:
            self.status_parts.append(data)
        if self._in_display:
            self.display_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "h4":
            self._in_title = False
        elif tag == "td" and self._in_cell:
            self.cells.append(_clean_text("".join(self._cell_parts)))
            self._in_cell = False
            self._cell_parts = []
        elif tag == "tr" and self._in_summary_row:
            self._in_summary_row = False
        elif tag == "span" and self._in_status:
            self._in_status = False
        elif tag == "b" and self._in_display:
            self._in_display = False

    def result(self, expected_workflow_id):
        if self.workflow_id is not None and normalize_workflow_id(
            self.workflow_id
        ) != normalize_workflow_id(expected_workflow_id):
            raise ExecuteError("Workflow detail page contained a different workflow ID")
        if self.sql is None:
            raise ExecuteError("Workflow detail page did not expose the approved SQL")
        if len(self.cells) < len(self.SUMMARY_FIELDS):
            raise ExecuteError("Workflow detail page did not contain expected summary fields")
        result = dict(zip(self.SUMMARY_FIELDS, self.cells[: len(self.SUMMARY_FIELDS)]))
        result.update(
            {
                "workflow_id": int(expected_workflow_id),
                "title": _clean_text("".join(self.title_parts)),
                "sql": self.sql,
                "status": _clean_text("".join(self.status_parts)),
                "status_display": _clean_text("".join(self.display_parts))
                or result["status_display"],
                "can_execute": self.can_execute,
                "is_submitter": self.is_submitter,
            }
        )
        if result["current_approval"] in ("", "None"):
            result["current_approval"] = None
        return result


def _clean_text(value):
    return re.sub(r"\s+", " ", value).strip()


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
    names = (config["username_env"], config["password_env"])
    values = tuple(environment_value(name) for name in names)
    missing = [name for name, value in zip(names, values) if not value]
    if missing:
        raise ExecuteError(
            "Missing required environment variable(s): {}".format(", ".join(missing))
        )
    return values


def expected_confirmation_token(config):
    name = config["confirmation_token_env"]
    value = environment_value(name)
    if not value:
        raise ExecuteError("Missing required environment variable: {}".format(name))
    return value


def load_config(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            raw_config = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ExecuteError("Unable to load config {}: {}".format(path, error)) from None
    if not isinstance(raw_config, dict):
        raise ExecuteError("Config root must be a JSON object")
    if any(key in raw_config for key in CONFIG_SECTIONS):
        config = raw_config.get("execute")
        if not isinstance(config, dict):
            raise ExecuteError("Shared config is missing object section: execute")
        config = dict(config)
        config.setdefault("base_url", raw_config.get("base_url"))
    else:
        config = raw_config
    for key in ("base_url", "username_env", "password_env", "confirmation_token_env"):
        if not config.get(key):
            raise ExecuteError("Config is missing required field: {}".format(key))
    return config


def normalize_workflow_id(value):
    try:
        workflow_id = int(value)
    except (TypeError, ValueError):
        raise ExecuteError("Workflow ID must be a positive integer") from None
    if workflow_id < 1:
        raise ExecuteError("Workflow ID must be a positive integer")
    return workflow_id


def _tokenize(sql):
    tokens = []
    index = 0
    while index < len(sql):
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith("--", index) or char == "#":
            newline = sql.find("\n", index)
            index = len(sql) if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            if sql.startswith("/*!", index):
                raise SqlPolicyError("MySQL executable comments are not allowed")
            end = sql.find("*/", index + 2)
            if end < 0:
                raise SqlPolicyError("SQL contains an unterminated comment")
            index = end + 2
            continue
        if char in ("'", '"'):
            quote = char
            start = index
            index += 1
            while index < len(sql):
                if sql[index] == "\\":
                    index += 2
                    continue
                if sql[index] == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            else:
                raise SqlPolicyError("SQL contains an unterminated string literal")
            tokens.append(("STRING", sql[start:index]))
            continue
        if char == "`":
            index += 1
            parts = []
            while index < len(sql):
                if sql[index] == "`":
                    if index + 1 < len(sql) and sql[index + 1] == "`":
                        parts.append("`")
                        index += 2
                        continue
                    index += 1
                    break
                parts.append(sql[index])
                index += 1
            else:
                raise SqlPolicyError("SQL contains an unterminated quoted identifier")
            tokens.append(("WORD", "".join(parts).upper()))
            continue
        if char.isdigit():
            start = index
            while index < len(sql) and sql[index].isdigit():
                index += 1
            tokens.append(("NUMBER", sql[start:index]))
            continue
        if char.isalpha() or char == "_" or ord(char) >= 128:
            start = index
            while index < len(sql):
                current = sql[index]
                if not (current.isalnum() or current in ("_", "$") or ord(current) >= 128):
                    break
                index += 1
            tokens.append(("WORD", sql[start:index].upper()))
            continue
        operator = next(
            (item for item in ("<=>", "<=", ">=", "<>", "!=", ":=") if sql.startswith(item, index)),
            None,
        )
        if operator:
            tokens.append(("SYMBOL", operator))
            index += len(operator)
        else:
            tokens.append(("SYMBOL", char))
            index += 1
    return tokens


def _split_statements(sql):
    statements = []
    current = []
    depth = 0
    for token in _tokenize(sql):
        if token == ("SYMBOL", "("):
            depth += 1
        elif token == ("SYMBOL", ")"):
            depth -= 1
            if depth < 0:
                raise SqlPolicyError("SQL contains unbalanced parentheses")
        if token == ("SYMBOL", ";") and depth == 0:
            if current:
                statements.append(current)
                current = []
            continue
        current.append(token)
    if depth != 0:
        raise SqlPolicyError("SQL contains unbalanced parentheses")
    if current:
        statements.append(current)
    if not statements:
        raise SqlPolicyError("SQL is empty")
    return statements


def _is_word(token, value):
    return token[0] == "WORD" and token[1] == value


def _literal_boundary(tokens, index):
    if index >= len(tokens):
        return True
    token = tokens[index]
    if token == ("SYMBOL", ")"):
        return True
    return token[0] == "WORD" and token[1] in ("AND", "OR", "ORDER", "LIMIT")


def _has_literal_id_predicate(where_tokens):
    depth = 0
    for index, token in enumerate(where_tokens):
        if token == ("SYMBOL", "("):
            depth += 1
            continue
        if token == ("SYMBOL", ")"):
            depth -= 1
            continue
        if depth != 0:
            continue
        if not _is_word(token, "ID") or index + 1 >= len(where_tokens):
            continue
        operator = where_tokens[index + 1]
        if operator == ("SYMBOL", "=") and index + 2 < len(where_tokens):
            value = where_tokens[index + 2]
            if value[0] in ("NUMBER", "STRING") and _literal_boundary(
                where_tokens, index + 3
            ):
                return True
        if _is_word(operator, "IN") and index + 2 < len(where_tokens):
            if where_tokens[index + 2] != ("SYMBOL", "("):
                continue
            cursor = index + 3
            expect_literal = True
            literal_count = 0
            while cursor < len(where_tokens):
                current = where_tokens[cursor]
                if current == ("SYMBOL", ")"):
                    if not expect_literal and literal_count > 0 and _literal_boundary(
                        where_tokens, cursor + 1
                    ):
                        return True
                    break
                if expect_literal:
                    if current[0] not in ("NUMBER", "STRING"):
                        break
                    literal_count += 1
                    expect_literal = False
                else:
                    if current != ("SYMBOL", ","):
                        break
                    expect_literal = True
                cursor += 1
    return False


def _find_matching_paren(tokens, start):
    if start >= len(tokens) or tokens[start] != ("SYMBOL", "("):
        raise SqlPolicyError("expected opening parenthesis")
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == ("SYMBOL", "("):
            depth += 1
        elif tokens[index] == ("SYMBOL", ")"):
            depth -= 1
            if depth == 0:
                return index
    raise SqlPolicyError("SQL contains unbalanced parentheses")


def _split_top_level(tokens):
    values = []
    current = []
    depth = 0
    for token in tokens:
        if token == ("SYMBOL", "("):
            depth += 1
        elif token == ("SYMBOL", ")"):
            depth -= 1
        if token == ("SYMBOL", ",") and depth == 0:
            values.append(current)
            current = []
        else:
            current.append(token)
    values.append(current)
    return values


def _validate_update_statement(tokens, number):
    if any(_is_word(token, "SELECT") for token in tokens):
        raise SqlPolicyError("statement {}: subqueries are not allowed".format(number))
    depth = 0
    where_index = None
    for index, token in enumerate(tokens):
        if token == ("SYMBOL", "("):
            depth += 1
        elif token == ("SYMBOL", ")"):
            depth -= 1
        elif depth == 0 and _is_word(token, "WHERE"):
            where_index = index
            break
    if where_index is None or where_index == len(tokens) - 1:
        raise SqlPolicyError("statement {}: UPDATE requires a nonempty WHERE clause".format(number))
    where_tokens = tokens[where_index + 1 :]
    if any(_is_word(token, "OR") for token in where_tokens):
        raise SqlPolicyError("statement {}: OR is not allowed in the WHERE clause".format(number))
    if any(_is_word(token, "NOT") for token in where_tokens):
        raise SqlPolicyError("statement {}: NOT is not allowed in the WHERE clause".format(number))
    if any(_is_word(token, "XOR") for token in where_tokens):
        raise SqlPolicyError("statement {}: XOR is not allowed in the WHERE clause".format(number))
    if any(token == ("SYMBOL", "!") for token in where_tokens):
        raise SqlPolicyError("statement {}: ! is not allowed in the WHERE clause".format(number))
    if any(
        where_tokens[index] == ("SYMBOL", "|")
        and where_tokens[index + 1] == ("SYMBOL", "|")
        for index in range(len(where_tokens) - 1)
    ):
        raise SqlPolicyError("statement {}: || is not allowed in the WHERE clause".format(number))
    if not _has_literal_id_predicate(where_tokens):
        raise SqlPolicyError(
            "statement {}: WHERE must contain a top-level literal id = value or "
            "id IN (values)".format(number)
        )


def _validate_insert_statement(tokens, number):
    if any(_is_word(token, "SELECT") for token in tokens):
        raise SqlPolicyError("statement {}: INSERT ... SELECT is not allowed".format(number))
    if any(
        _is_word(tokens[index], "ON") and _is_word(tokens[index + 1], "DUPLICATE")
        for index in range(len(tokens) - 1)
    ):
        raise SqlPolicyError("statement {}: ON DUPLICATE KEY UPDATE is not allowed".format(number))
    cursor = 1
    if cursor < len(tokens) and _is_word(tokens[cursor], "INTO"):
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor][0] != "WORD":
        raise SqlPolicyError("statement {}: INSERT target table is missing".format(number))
    cursor += 1
    if cursor + 1 < len(tokens) and tokens[cursor] == ("SYMBOL", "."):
        if tokens[cursor + 1][0] != "WORD":
            raise SqlPolicyError("statement {}: invalid qualified table name".format(number))
        cursor += 2
    if cursor >= len(tokens) or tokens[cursor] != ("SYMBOL", "("):
        raise SqlPolicyError("statement {}: INSERT requires an explicit column list".format(number))
    columns_end = _find_matching_paren(tokens, cursor)
    column_parts = _split_top_level(tokens[cursor + 1 : columns_end])
    if not column_parts or any(len(part) != 1 or part[0][0] != "WORD" for part in column_parts):
        raise SqlPolicyError("statement {}: INSERT column list is invalid".format(number))
    columns = [part[0][1] for part in column_parts]
    if len(columns) != len(set(columns)):
        raise SqlPolicyError("statement {}: INSERT column list contains duplicates".format(number))
    cursor = columns_end + 1
    if cursor >= len(tokens) or not _is_word(tokens[cursor], "VALUES"):
        raise SqlPolicyError("statement {}: INSERT must use explicit VALUES rows".format(number))
    cursor += 1
    row_count = 0
    while cursor < len(tokens):
        if tokens[cursor] != ("SYMBOL", "("):
            raise SqlPolicyError("statement {}: INSERT VALUES syntax is invalid".format(number))
        row_end = _find_matching_paren(tokens, cursor)
        values = _split_top_level(tokens[cursor + 1 : row_end])
        if len(values) != len(columns):
            raise SqlPolicyError("statement {}: INSERT value count does not match columns".format(number))
        row_count += 1
        if row_count >= MAX_AFFECTED_ROWS_EXCLUSIVE:
            raise SqlPolicyError("statement {}: INSERT must contain fewer than 50 rows".format(number))
        cursor = row_end + 1
        if cursor == len(tokens):
            break
        if tokens[cursor] != ("SYMBOL", ","):
            raise SqlPolicyError("statement {}: trailing INSERT clauses are not allowed".format(number))
        cursor += 1
    if row_count == 0:
        raise SqlPolicyError("statement {}: INSERT VALUES must not be empty".format(number))


def _validated_statements(sql):
    statements = _split_statements(sql)
    for number, tokens in enumerate(statements, 1):
        if not tokens or tokens[0][0] != "WORD":
            raise SqlPolicyError("statement {}: only UPDATE and INSERT are allowed".format(number))
        if _is_word(tokens[0], "UPDATE"):
            _validate_update_statement(tokens, number)
        elif _is_word(tokens[0], "INSERT"):
            _validate_insert_statement(tokens, number)
        else:
            raise SqlPolicyError("statement {}: only UPDATE and INSERT are allowed".format(number))
    return statements


def execution_policy_errors(detail, max_affected_rows_exclusive=MAX_AFFECTED_ROWS_EXCLUSIVE):
    if not 1 <= int(max_affected_rows_exclusive) <= MAX_AFFECTED_ROWS_EXCLUSIVE:
        raise ExecuteError("Affected-row policy limit cannot exceed 50")
    errors = []
    if detail.get("status") != APPROVED_STATUS:
        errors.append("workflow is not finally approved")
    if not detail.get("can_execute"):
        errors.append("authenticated account lacks current execute permission")
    if detail.get("is_submitter"):
        errors.append("workflow was submitted by the execution account")
    if detail.get("error_count"):
        errors.append("workflow review errors must be zero")
    affected_rows = detail.get("affected_rows")
    if not isinstance(affected_rows, int) or affected_rows < 0:
        errors.append("workflow affected-row count is unavailable or invalid")
    elif affected_rows >= int(max_affected_rows_exclusive):
        errors.append("total affected rows must be fewer than 50")

    workflow_statements = None
    try:
        workflow_statements = _validated_statements(detail.get("sql") or "")
    except SqlPolicyError as error:
        errors.append(str(error))

    review_statements = []
    review_rows = detail.get("review_rows")
    if not isinstance(review_rows, list) or not review_rows:
        errors.append("workflow review rows are unavailable")
    else:
        for row_number, row in enumerate(review_rows, 1):
            if not isinstance(row, dict) or not isinstance(row.get("sql"), str):
                errors.append("review row {} has no SQL".format(row_number))
                continue
            try:
                review_statements.extend(_validated_statements(row["sql"]))
            except SqlPolicyError as error:
                errors.append("review row {}: {}".format(row_number, error))
    if workflow_statements is not None and review_statements:
        if workflow_statements != review_statements:
            errors.append("workflow SQL does not match server review SQL")
    return errors


def workflow_fingerprint(detail):
    protected = {
        key: detail.get(key)
        for key in (
            "workflow_id",
            "title",
            "instance",
            "database",
            "group",
            "status",
            "execution_window",
            "backup",
            "sql",
            "review_rows",
            "affected_rows",
            "warning_count",
            "error_count",
            "can_execute",
            "is_submitter",
        )
    }
    canonical = json.dumps(protected, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def read_confirmation_token(prompt):
    if not sys.stdin.isatty():
        raise ExecuteError("Execution confirmation token requires an interactive TTY")
    return getpass.getpass(prompt)


class ArcheryExecuteClient:
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

    def _request(self, path, method="GET", fields=None, mutation=False):
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
                return response.status, response.geturl(), response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            message = "Archery returned HTTP {} for {}: {}".format(
                error.code, urllib.parse.urlparse(url).path, _compact_html(body)
            )
            if mutation and error.code >= 500:
                raise ExecuteOutcomeUnknown(
                    message + "; execution outcome is unknown, do not retry automatically"
                ) from None
            raise ExecuteError(message) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.RemoteDisconnected) as error:
            reason = getattr(error, "reason", error)
            if mutation:
                raise ExecuteOutcomeUnknown(
                    "Archery execution request failed after dispatch: {}; outcome is unknown, "
                    "do not retry automatically; inspect workflow status and logs".format(reason)
                ) from None
            raise ExecuteError("Unable to reach Archery: {}".format(reason)) from None

    @staticmethod
    def _json(body, action):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise ExecuteError(
                "Archery returned non-JSON data during {}: {}".format(action, _compact_html(body))
            ) from None

    def login(self):
        _, final_url, body = self._request("/login/")
        if urllib.parse.urlparse(final_url).path not in ("/login", "/login/"):
            raise ExecuteError("Unexpected login page redirect: {}".format(final_url))
        parser = _LoginPageParser()
        parser.feed(body)
        self.csrf_token = self._cookie("csrftoken") or parser.csrf_token
        if not self.csrf_token:
            raise ExecuteError("Archery login page did not provide a CSRF token")
        _, _, body = self._request(
            "/authenticate/", method="POST", fields={"username": self.username, "password": self.password}
        )
        result = self._json(body, "login")
        if result.get("status") != 0:
            raise ExecuteError("Archery login failed: {}".format(result.get("msg", "unknown error")))
        if not self._cookie("sessionid"):
            raise ExecuteError("Archery login succeeded without a session cookie")
        self.csrf_token = self._cookie("csrftoken") or self.csrf_token
        _, final_url, body = self._request("/sqlworkflow/")
        if urllib.parse.urlparse(final_url).path not in ("/sqlworkflow", "/sqlworkflow/"):
            raise ExecuteError("Archery SQL workflow page is unavailable after login")
        if 'id="sqlaudit-list"' not in body:
            raise ExecuteError("Authenticated account cannot access SQL workflow records")

    def _review_rows(self, workflow_id):
        query = urllib.parse.urlencode({"workflow_id": str(workflow_id)})
        _, _, body = self._request("/sqlworkflow/detail_content/?" + query)
        rows = self._json(body, "workflow review detail").get("rows")
        if not isinstance(rows, list):
            raise ExecuteError("Archery returned invalid workflow review rows")
        return rows

    def _status(self, workflow_id):
        _, _, body = self._request(
            "/getWorkflowStatus/", method="POST", fields={"workflow_id": str(workflow_id)}
        )
        status = self._json(body, "workflow status").get("status")
        if not isinstance(status, str) or not status:
            raise ExecuteError("Archery returned an invalid workflow status")
        return status

    def _logs(self, workflow_id):
        _, _, body = self._request(
            "/workflow/log/",
            method="POST",
            fields={"workflow_id": str(workflow_id), "workflow_type": str(WORKFLOW_TYPE_SQL_REVIEW)},
        )
        rows = self._json(body, "workflow log").get("rows")
        if not isinstance(rows, list):
            raise ExecuteError("Archery returned invalid workflow logs")
        return rows

    def inspect_workflow(self, workflow_id, max_affected_rows_exclusive=MAX_AFFECTED_ROWS_EXCLUSIVE):
        workflow_id = normalize_workflow_id(workflow_id)
        _, final_url, body = self._request("/detail/{}/".format(workflow_id))
        if urllib.parse.urlparse(final_url).path.rstrip("/") != "/detail/{}".format(workflow_id):
            raise ExecuteError("Workflow detail is unavailable or not visible to this account")
        parser = _WorkflowDetailParser()
        parser.feed(body)
        detail = parser.result(workflow_id)
        detail["review_rows"] = self._review_rows(workflow_id)
        detail["logs"] = self._logs(workflow_id)
        server_status = self._status(workflow_id)
        if detail["status"] != server_status:
            raise ExecuteError("Workflow status is inconsistent across Archery responses")
        levels = []
        affected_rows = 0
        for row in detail["review_rows"]:
            if not isinstance(row, dict):
                raise ExecuteError("Workflow review contains an invalid row")
            try:
                level = int(row.get("errlevel") or 0)
                affected = int(row["affected_rows"])
            except (KeyError, TypeError, ValueError):
                raise ExecuteError("Workflow review contains invalid affected-row data") from None
            if affected < 0:
                raise ExecuteError("Workflow review contains a negative affected-row count")
            levels.append(level)
            affected_rows += affected
        detail["warning_count"] = sum(level == 1 for level in levels)
        detail["error_count"] = sum(level >= 2 for level in levels)
        detail["affected_rows"] = affected_rows
        detail["fingerprint"] = workflow_fingerprint(detail)
        detail["policy_errors"] = execution_policy_errors(detail, max_affected_rows_exclusive)
        detail["eligible"] = not detail["policy_errors"]
        return detail

    def execute(
        self,
        workflow_id,
        confirmed_fingerprint,
        expected_token,
        token_reader=read_confirmation_token,
        max_affected_rows_exclusive=MAX_AFFECTED_ROWS_EXCLUSIVE,
    ):
        before = self.inspect_workflow(workflow_id, max_affected_rows_exclusive)
        if before["policy_errors"]:
            raise ExecuteError("; ".join(before["policy_errors"]))
        if not confirmed_fingerprint or not hmac.compare_digest(
            confirmed_fingerprint, before["fingerprint"]
        ):
            raise ExecuteError("Confirmed workflow fingerprint does not match current details")
        if not expected_token:
            raise ExecuteError("Execution confirmation token is not configured")
        supplied_token = token_reader("Execution confirmation token: ")
        if not isinstance(supplied_token, str) or not hmac.compare_digest(expected_token, supplied_token):
            raise ExecuteError("Execution confirmation token did not match")
        _, final_url, body = self._request(
            "/execute/",
            method="POST",
            fields={"workflow_id": str(before["workflow_id"]), "mode": "auto"},
            mutation=True,
        )
        expected_path = "/detail/{}".format(before["workflow_id"])
        if urllib.parse.urlparse(final_url).path.rstrip("/") != expected_path:
            raise ExecuteOutcomeUnknown(
                "Archery execution response could not be verified: {}; inspect status and logs, "
                "do not retry automatically".format(_compact_html(body))
            )
        try:
            status = self._status(before["workflow_id"])
            logs = self._logs(before["workflow_id"])
        except ExecuteError as error:
            raise ExecuteOutcomeUnknown(
                "Execution was dispatched but verification failed: {}; do not retry automatically".format(error)
            ) from None
        dispatch_log = next((row for row in logs if row.get("operation_type_desc") == "执行工单"), None)
        if status not in DISPATCHED_STATUSES or dispatch_log is None:
            raise ExecuteOutcomeUnknown(
                "Execution response lacked a verified dispatched status or execution log; "
                "inspect the workflow before any further action"
            )
        return {
            "ok": True,
            "action": "execute",
            "workflow_id": before["workflow_id"],
            "previous_fingerprint": before["fingerprint"],
            "status": status,
            "execution_progress": DISPATCHED_STATUSES[status],
            "dispatch_log": dispatch_log,
            "latest_log": logs[0] if logs else None,
            "url": urllib.parse.urljoin(self.base_url + "/", expected_path.lstrip("/")) + "/",
        }


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--config", default=environment_value(CONFIG_FILE_ENV) or str(DEFAULT_CONFIG)
    )
    result.add_argument("--timeout", type=int, default=30)
    commands = result.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="Inspect execution eligibility for one workflow")
    show.add_argument("--workflow-id", type=int, required=True)
    execute = commands.add_parser("execute", help="Execute one eligible approved workflow")
    execute.add_argument("--workflow-id", type=int, required=True)
    execute.add_argument("--confirmed-fingerprint", required=True)
    return result


def run(args):
    config = load_config(args.config)
    username, password = credentials(config)
    client = ArcheryExecuteClient(config["base_url"], username, password, timeout=args.timeout)
    client.login()
    if args.command == "show":
        return {"ok": True, "action": "show", **client.inspect_workflow(args.workflow_id)}
    return client.execute(
        args.workflow_id, args.confirmed_fingerprint, expected_confirmation_token(config)
    )


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except ExecuteOutcomeUnknown as error:
        print(
            json.dumps({"ok": False, "outcome_unknown": True, "error": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 3
    except ExecuteError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
