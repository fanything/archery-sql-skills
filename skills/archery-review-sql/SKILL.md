---
name: archery-review-sql
description: Inspect, approve, or reject pending SQL approval workflows through a configured Archery v1.8.0 service. Use when the user asks to list SQL review tasks, review a workflow/order, approve/pass a pending SQL workflow, or reject/deny one through Archery. Require a fresh detail preview and explicit confirmation of its fingerprint; never submit or execute SQL.
---

# Archery SQL Review

Run commands from the directory containing this `SKILL.md`. Use `scripts/archery_review.py` for every Archery review read and decision. Do not reproduce login, CSRF, workflow parsing, approval, or rejection with ad hoc requests.

## Configuration

Require `ARCHERY_CONFIG_FILE` to identify the external shared configuration file. If it is absent, the client uses `~/.config/archery-sql-skills/config.json`. Read only the `review` section.

## Credentials

Require dedicated reviewer credentials:

- `ARCHERY_REVIEW_USERNAME`
- `ARCHERY_REVIEW_PASSWORD`

Read them from the process environment; on macOS the client also accepts login-session environment values. Never print, persist, place in command arguments, or include credentials in an answer. Do not fall back to submitter or query credentials.

## Inspect

List only SQL workflows currently assigned to this reviewer:

```bash
python3 scripts/archery_review.py list
```

Inspect one workflow before any decision:

```bash
python3 scripts/archery_review.py show --workflow-id 16408
```

Report the workflow ID, title, submitter, approval chain, current approval group, instance, database, resource group, SQL type, backup choice, execution window, exact SQL, review rows, warnings, errors, affected rows, logs, status, and fingerprint. Fail visibly if any portion is unavailable or inconsistent.

## Decision Gate

1. Always run `show` immediately before a decision.
2. Refuse either decision unless status is `workflow_manreviewing`, the account is the current reviewer, and the workflow was not submitted by this account. Additionally refuse approval when review errors are nonzero; rejection remains available for erroneous SQL.
3. Explain warnings, errors, and risks. Obtain an explicit approve or reject instruction after showing the fresh details and fingerprint. Earlier confirmation does not count.
4. Require a nonempty review remark for both decisions.
5. Pass the exact displayed fingerprint. Never invent or reuse an older fingerprint.

Approve:

```bash
python3 scripts/archery_review.py approve \
  --workflow-id 16408 \
  --remark '<review-remark>' \
  --confirmed-fingerprint '<fingerprint-from-show>'
```

Reject:

```bash
python3 scripts/archery_review.py reject \
  --workflow-id 16408 \
  --remark '<rejection-reason>' \
  --confirmed-fingerprint '<fingerprint-from-show>'
```

After approval, distinguish final approval from advancement to another approval group. After rejection, require `workflow_abort` plus a latest `审批不通过` log. Return the verified status, progress, latest log, and workflow URL.

## Safety Boundary

- Review one workflow per command. Never batch approve or reject.
- Never review a workflow submitted by the authenticated reviewer.
- Never call SQL submission, execution, timing-task, rollback, manual-execution, permission-management, or arbitrary cancellation endpoints.
- Use `/cancel/` only through the guarded `reject` command while the workflow is pending and assigned to the reviewer.
- Never retry an approval or rejection after timeout, connection loss, or HTTP 5xx. The outcome may be unknown; inspect the workflow state and log before any further user decision.
- Do not persist SQL, review details, or logs unless the user explicitly requests it.
