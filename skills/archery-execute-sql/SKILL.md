---
name: archery-execute-sql
description: Inspect and immediately execute one finally approved UPDATE or INSERT workflow through a configured Archery v1.8.0 service. Use when the user asks to run, execute, release, or上线 an approved SQL workflow through Archery. Require a fresh fingerprint, explicit confirmation, a matching environment-backed token, fewer than 50 affected rows, and deterministic UPDATE ID guards; always reject DELETE.
---

# Archery SQL Execution

Run commands from the directory containing this `SKILL.md`. Use
`scripts/archery_execute.py` for every inspection and execution request. Never reproduce login,
CSRF handling, policy checks, or `/execute/` calls with ad hoc requests.

## Configuration

Require `ARCHERY_CONFIG_FILE` to identify the external shared configuration file. If it is absent, the client uses `~/.config/archery-sql-skills/config.json`. Read only the `execute` section.

## Credentials and Token

Require dedicated execution credentials and a confirmation token:

- `ARCHERY_EXECUTE_USERNAME`
- `ARCHERY_EXECUTE_PASSWORD`
- `ARCHERY_EXECUTE_CONFIRM_TOKEN`

Read them only through the bundled client. On macOS it also accepts login-session environment
values. Never inspect, print, persist, place in command arguments, or include their values in an
answer. Do not fall back to query, submission, or review credentials. Treat the token as an
accidental-execution guard, not as protection against a process that can read the environment.

## Inspect

Always inspect exactly one workflow immediately before execution:

```bash
python3 scripts/archery_execute.py show --workflow-id 16408
```

Report the workflow ID, title, submitter, instance, database, resource group, backup choice,
execution window, exact SQL, every review row, warnings, errors, total affected rows, policy
errors, logs, status, eligibility, and fingerprint. Refuse to continue if any detail is partial or
inconsistent.

## Decision Gate

Require all of the following:

1. Status is exactly `workflow_review_pass`; all other states are ineligible.
2. The authenticated dedicated executor currently has Archery execution permission and did not
   submit the workflow.
3. Every statement is `UPDATE` or `INSERT`. Always reject `DELETE`, DDL, SELECT, CTE, and other
   SQL types.
4. Every `UPDATE` has a nonempty `WHERE` containing `id = <literal>` or
   `id IN (<literal-list>)`. Reject `OR`, `NOT`, `XOR`, `||`, `!`, subqueries, ranges,
   computed ID expressions, variables, and executable comments. Require the ID predicate at the
   top level of `WHERE` so surrounding expressions cannot invert it.
5. Every `INSERT` explicitly lists its columns and uses `VALUES`; do not require an `id` column
   because the database may generate it. Reject omitted or duplicate columns,
   `INSERT ... SELECT`, `INSERT ... SET`, `ON DUPLICATE KEY UPDATE`, trailing clauses, and 50 or
   more VALUES rows.
6. Server review errors are zero and the sum of server-reported affected rows is strictly less
   than 50. The fixed maximum is 49 and cannot be raised through configuration.
7. Workflow SQL exactly matches server review SQL after deterministic tokenization.
8. Show warnings and risks, then obtain explicit execution confirmation after the fresh preview.
   Earlier confirmation does not count.
9. Pass the exact displayed fingerprint. Never invent or reuse an older fingerprint.
10. Ask the user for the confirmation token only after steps 1-9 pass. Run the command in an
    interactive TTY so the token is entered without echo; never put it in the command line.

Execute:

```bash
python3 scripts/archery_execute.py execute \
  --workflow-id 16408 \
  --confirmed-fingerprint '<fingerprint-from-show>'
```

The client refreshes all details before prompting for the token. It dispatches only `mode=auto`
to `/execute/`, then verifies a queued, running, finished, or failed state plus an `执行工单` log.
Report the verified state, progress, log, and workflow URL. A queued or running state means the
asynchronous database execution has not yet completed.

## Safety Boundary

- Execute one workflow per command. Never batch workflows.
- Never approve, reject, submit, schedule, manually mark complete, cancel, roll back, or change
  permissions from this skill.
- Never execute SQL supplied directly by the user; execute only the exact SQL stored in the
  approved workflow.
- Never weaken or bypass the SQL type, UPDATE ID, affected-row, fingerprint, or token checks.
- Never retry after timeout, connection loss, HTTP 5xx, an unverifiable redirect, or failed
  post-dispatch verification. The outcome may be unknown; inspect Archery state and logs before
  asking the user for a new decision.
- Do not persist SQL, execution details, logs, or secrets unless explicitly requested.
