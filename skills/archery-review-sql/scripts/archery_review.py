#!/usr/bin/env python3
"""Review pending Archery v1.8.0 SQL workflows without executing them."""

import argparse
import hashlib
import hmac
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
WORKFLOW_TYPE_SQL_REVIEW = 2
PENDING_STATUS = "workflow_manreviewing"
APPROVED_STATUS = "workflow_review_pass"
REJECTED_STATUS = "workflow_abort"
MAX_REMARK_CHARS = 1000


class ReviewError(RuntimeError):
    pass


class ReviewOutcomeUnknown(ReviewError):
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
        self.can_review = False
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
        if element_id == "btnPass":
            self.can_review = True
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
            raise ReviewError("Workflow detail page did not contain the expected workflow ID")
        if self.sql is None:
            raise ReviewError("Workflow detail page did not expose the reviewed SQL")
        if len(self.cells) < len(self.SUMMARY_FIELDS):
            raise ReviewError("Workflow detail page did not contain the expected summary fields")
        result = dict(zip(self.SUMMARY_FIELDS, self.cells[: len(self.SUMMARY_FIELDS)]))
        result.update(
            {
                "workflow_id": int(expected_workflow_id),
                "title": _clean_text("".join(self.title_parts)),
                "sql": self.sql,
                "status": _clean_text("".join(self.status_parts)),
                "status_display": _clean_text("".join(self.display_parts))
                or result["status_display"],
                "can_review": self.can_review,
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
        raise ReviewError(
            "Missing required environment variable(s): {}".format(", ".join(missing))
        )
    return username, password


def load_config(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            raw_config = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ReviewError("Unable to load config {}: {}".format(path, error)) from None
    if not isinstance(raw_config, dict):
        raise ReviewError("Config root must be a JSON object")
    if any(key in raw_config for key in CONFIG_SECTIONS):
        config = raw_config.get("review")
        if not isinstance(config, dict):
            raise ReviewError("Shared config is missing object section: review")
        config = dict(config)
        config.setdefault("base_url", raw_config.get("base_url"))
    else:
        config = raw_config
    for key in ("base_url", "username_env", "password_env"):
        if not config.get(key):
            raise ReviewError("Config is missing required field: {}".format(key))
    for key in ("default_limit", "max_limit"):
        if config.get(key) is None:
            raise ReviewError("Config is missing required field: {}".format(key))
    return config


def validate_pagination(config, limit, offset):
    if limit < 1 or limit > int(config["max_limit"]):
        raise ReviewError(
            "List limit must be between 1 and {}".format(config["max_limit"])
        )
    if offset < 0:
        raise ReviewError("List offset must not be negative")
    return limit, offset


def validate_remark(remark):
    value = (remark or "").strip()
    if not value:
        raise ReviewError("A nonempty review remark is required")
    if len(value) > MAX_REMARK_CHARS:
        raise ReviewError(
            "Review remark exceeds the {} character limit".format(MAX_REMARK_CHARS)
        )
    return value


def normalize_workflow_id(value):
    try:
        workflow_id = int(value)
    except (TypeError, ValueError):
        raise ReviewError("Workflow ID must be a positive integer") from None
    if workflow_id < 1:
        raise ReviewError("Workflow ID must be a positive integer")
    return workflow_id


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
            "current_approval",
            "sql",
            "review_rows",
        )
    }
    canonical = json.dumps(
        protected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ArcheryReviewClient:
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
                return (
                    response.status,
                    response.geturl(),
                    response.read().decode("utf-8", errors="replace"),
                )
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            message = "Archery returned HTTP {} for {}: {}".format(
                error.code, urllib.parse.urlparse(url).path, _compact_html(body)
            )
            if mutation and error.code >= 500:
                raise ReviewOutcomeUnknown(
                    message + "; review outcome is unknown, do not retry automatically"
                ) from None
            raise ReviewError(message) from None
        except (urllib.error.URLError, TimeoutError) as error:
            reason = getattr(error, "reason", error)
            if mutation:
                raise ReviewOutcomeUnknown(
                    "Archery review request failed after dispatch: {}; outcome is unknown, "
                    "do not retry automatically; inspect the workflow state and log".format(reason)
                ) from None
            raise ReviewError("Unable to reach Archery: {}".format(reason)) from None

    @staticmethod
    def _json(body, action):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise ReviewError(
                "Archery returned non-JSON data during {}: {}".format(
                    action, _compact_html(body)
                )
            ) from None

    def login(self):
        _, final_url, body = self._request("/login/")
        if urllib.parse.urlparse(final_url).path not in ("/login", "/login/"):
            raise ReviewError("Unexpected login page redirect: {}".format(final_url))
        parser = _LoginPageParser()
        parser.feed(body)
        self.csrf_token = self._cookie("csrftoken") or parser.csrf_token
        if not self.csrf_token:
            raise ReviewError("Archery login page did not provide a CSRF token")
        _, _, body = self._request(
            "/authenticate/",
            method="POST",
            fields={"username": self.username, "password": self.password},
        )
        result = self._json(body, "login")
        if result.get("status") != 0:
            raise ReviewError(
                "Archery login failed: {}".format(result.get("msg", "unknown error"))
            )
        if not self._cookie("sessionid"):
            raise ReviewError("Archery login succeeded without a session cookie")
        self.csrf_token = self._cookie("csrftoken") or self.csrf_token
        _, final_url, body = self._request("/workflow/")
        if urllib.parse.urlparse(final_url).path not in ("/workflow", "/workflow/"):
            raise ReviewError("Archery review page is unavailable after login")
        if 'id="audit-list"' not in body:
            raise ReviewError("Authenticated account does not have the review page available")

    def pending(self, limit, offset, search=""):
        _, _, body = self._request(
            "/workflow/list/",
            method="POST",
            fields={
                "limit": str(limit),
                "offset": str(offset),
                "workflow_type": str(WORKFLOW_TYPE_SQL_REVIEW),
                "search": search,
            },
        )
        result = self._json(body, "pending review discovery")
        rows = result.get("rows")
        if not isinstance(rows, list) or not isinstance(result.get("total"), int):
            raise ReviewError("Archery returned an invalid pending review list")
        resolved = []
        errors = []
        for row in rows:
            item = dict(row)
            audit_id = item.get("audit_id")
            try:
                if audit_id is None:
                    raise ReviewError("pending item has no audit_id")
                _, final_url, _ = self._request("/workflow/{}/".format(audit_id))
                match = re.fullmatch(
                    r"/detail/(\d+)/?", urllib.parse.urlparse(final_url).path
                )
                if not match:
                    raise ReviewError("pending item did not resolve to an SQL workflow")
                item["workflow_id"] = int(match.group(1))
                resolved.append(item)
            except ReviewError as error:
                errors.append({"audit_id": audit_id, "error": str(error)})
        return {
            "total": result["total"],
            "rows": resolved,
            "partial": bool(errors),
            "errors": errors,
        }

    def _review_rows(self, workflow_id):
        query = urllib.parse.urlencode({"workflow_id": str(workflow_id)})
        _, _, body = self._request("/sqlworkflow/detail_content/?" + query)
        result = self._json(body, "workflow review detail")
        rows = result.get("rows")
        if not isinstance(rows, list):
            raise ReviewError("Archery returned invalid workflow review rows")
        return rows

    def _status(self, workflow_id):
        _, _, body = self._request(
            "/getWorkflowStatus/",
            method="POST",
            fields={"workflow_id": str(workflow_id)},
        )
        result = self._json(body, "workflow status")
        status = result.get("status")
        if not isinstance(status, str) or not status:
            raise ReviewError("Archery returned an invalid workflow status")
        return status

    def _logs(self, workflow_id):
        _, _, body = self._request(
            "/workflow/log/",
            method="POST",
            fields={
                "workflow_id": str(workflow_id),
                "workflow_type": str(WORKFLOW_TYPE_SQL_REVIEW),
            },
        )
        result = self._json(body, "workflow log")
        rows = result.get("rows")
        if not isinstance(rows, list):
            raise ReviewError("Archery returned invalid workflow logs")
        return rows

    def inspect_workflow(self, workflow_id):
        workflow_id = normalize_workflow_id(workflow_id)
        _, final_url, body = self._request("/detail/{}/".format(workflow_id))
        if urllib.parse.urlparse(final_url).path.rstrip("/") != "/detail/{}".format(
            workflow_id
        ):
            raise ReviewError("Workflow detail is unavailable or not visible to this account")
        parser = _WorkflowDetailParser()
        parser.feed(body)
        detail = parser.result(workflow_id)
        detail["review_rows"] = self._review_rows(workflow_id)
        detail["logs"] = self._logs(workflow_id)
        server_status = self._status(workflow_id)
        if detail["status"] != server_status:
            raise ReviewError("Workflow status is inconsistent across Archery responses")
        levels = []
        affected_rows = 0
        for row in detail["review_rows"]:
            try:
                levels.append(int(row.get("errlevel") or 0))
            except (TypeError, ValueError):
                raise ReviewError("Workflow review contains an invalid error level") from None
            try:
                affected_rows += int(row.get("affected_rows") or 0)
            except (TypeError, ValueError):
                raise ReviewError("Workflow review contains an invalid affected row count") from None
        detail["warning_count"] = sum(level == 1 for level in levels)
        detail["error_count"] = sum(level >= 2 for level in levels)
        detail["affected_rows"] = affected_rows
        detail["fingerprint"] = workflow_fingerprint(detail)
        return detail

    def _preflight(
        self, workflow_id, remark, confirmed_fingerprint, allow_review_errors=False
    ):
        remark = validate_remark(remark)
        detail = self.inspect_workflow(workflow_id)
        if detail["status"] != PENDING_STATUS:
            raise ReviewError("Workflow is not pending review")
        if detail["is_submitter"]:
            raise ReviewError("Reviewing your own workflow is not allowed")
        if not detail["can_review"]:
            raise ReviewError("Authenticated account is not the current reviewer")
        if detail["error_count"] and not allow_review_errors:
            raise ReviewError("Workflow review contains errors and cannot be reviewed here")
        if not confirmed_fingerprint or not hmac.compare_digest(
            confirmed_fingerprint, detail["fingerprint"]
        ):
            raise ReviewError("Confirmed workflow fingerprint does not match current details")
        return detail, remark

    @staticmethod
    def _latest_log(detail):
        return detail["logs"][0] if detail["logs"] else None

    @staticmethod
    def _verify_log(detail, operation, remark):
        latest = ArcheryReviewClient._latest_log(detail)
        if not latest or latest.get("operation_type_desc") != operation:
            raise ReviewError("Archery did not record the expected review operation")
        if remark not in str(latest.get("operation_info", "")):
            raise ReviewError("Archery review log does not contain the confirmed remark")
        return latest

    def approve(self, workflow_id, remark, confirmed_fingerprint):
        before, remark = self._preflight(workflow_id, remark, confirmed_fingerprint)
        _, final_url, body = self._request(
            "/passed/",
            method="POST",
            fields={"workflow_id": str(workflow_id), "audit_remark": remark},
            mutation=True,
        )
        expected_path = "/detail/{}".format(int(workflow_id))
        if urllib.parse.urlparse(final_url).path.rstrip("/") != expected_path:
            raise ReviewError("Archery approval failed: {}".format(_compact_html(body)))
        after = self.inspect_workflow(workflow_id)
        latest = self._verify_log(after, "审批通过", remark)
        if after["status"] == APPROVED_STATUS:
            progress = "final_approved"
        elif after["status"] == PENDING_STATUS:
            progress = "advanced_to_next_reviewer"
        else:
            raise ReviewError(
                "Archery recorded approval but returned unexpected status: {}".format(
                    after["status"]
                )
            )
        return {
            "ok": True,
            "action": "approve",
            "workflow_id": int(workflow_id),
            "previous_fingerprint": before["fingerprint"],
            "status": after["status"],
            "current_approval": after["current_approval"],
            "review_progress": progress,
            "latest_log": latest,
            "url": urllib.parse.urljoin(self.base_url + "/", expected_path.lstrip("/")) + "/",
        }

    def reject(self, workflow_id, remark, confirmed_fingerprint):
        before, remark = self._preflight(
            workflow_id, remark, confirmed_fingerprint, allow_review_errors=True
        )
        _, final_url, body = self._request(
            "/cancel/",
            method="POST",
            fields={"workflow_id": str(workflow_id), "cancel_remark": remark},
            mutation=True,
        )
        expected_path = "/detail/{}".format(int(workflow_id))
        if urllib.parse.urlparse(final_url).path.rstrip("/") != expected_path:
            raise ReviewError("Archery rejection failed: {}".format(_compact_html(body)))
        after = self.inspect_workflow(workflow_id)
        latest = self._verify_log(after, "审批不通过", remark)
        if after["status"] != REJECTED_STATUS:
            raise ReviewError(
                "Archery recorded rejection but returned unexpected status: {}".format(
                    after["status"]
                )
            )
        return {
            "ok": True,
            "action": "reject",
            "workflow_id": int(workflow_id),
            "previous_fingerprint": before["fingerprint"],
            "status": after["status"],
            "current_approval": after["current_approval"],
            "review_progress": "rejected",
            "latest_log": latest,
            "url": urllib.parse.urljoin(self.base_url + "/", expected_path.lstrip("/")) + "/",
        }


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--config", default=environment_value(CONFIG_FILE_ENV) or str(DEFAULT_CONFIG)
    )
    result.add_argument("--timeout", type=int, default=30)
    commands = result.add_subparsers(dest="command", required=True)
    pending = commands.add_parser("list", help="List SQL workflows pending this reviewer")
    pending.add_argument("--limit", type=int)
    pending.add_argument("--offset", type=int, default=0)
    pending.add_argument("--search", default="")
    show = commands.add_parser("show", help="Inspect one SQL workflow before review")
    show.add_argument("--workflow-id", type=int, required=True)
    for name in ("approve", "reject"):
        decision = commands.add_parser(name, help="{} one pending SQL workflow".format(name.title()))
        decision.add_argument("--workflow-id", type=int, required=True)
        decision.add_argument("--remark", required=True)
        decision.add_argument("--confirmed-fingerprint", required=True)
    return result


def run(args):
    config = load_config(args.config)
    username, password = credentials(config)
    client = ArcheryReviewClient(
        config["base_url"], username, password, timeout=args.timeout
    )
    client.login()
    if args.command == "list":
        limit, offset = validate_pagination(
            config,
            args.limit if args.limit is not None else int(config["default_limit"]),
            args.offset,
        )
        return {
            "ok": True,
            "action": "list",
            "limit": limit,
            "offset": offset,
            **client.pending(limit=limit, offset=offset, search=args.search),
        }
    if args.command == "show":
        return {"ok": True, "action": "show", **client.inspect_workflow(args.workflow_id)}
    if args.command == "approve":
        return client.approve(args.workflow_id, args.remark, args.confirmed_fingerprint)
    return client.reject(args.workflow_id, args.remark, args.confirmed_fingerprint)


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
    except ReviewOutcomeUnknown as error:
        print(
            json.dumps(
                {"ok": False, "outcome_unknown": True, "error": str(error)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 3
    except ReviewError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
