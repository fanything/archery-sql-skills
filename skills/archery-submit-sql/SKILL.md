---
name: archery-submit-sql
description: Check MySQL SQL and submit an approval workflow to a configured Archery v1.8.0 service. Use when the user asks to validate SQL, inspect available Archery resource groups or databases, or submit an SQL approval order through Archery. Require explicit confirmation after server-side SQL checking; never approve or execute a workflow.
---

# Archery SQL Submission

Run commands from the directory containing this `SKILL.md`, and use `scripts/archery_client.py` for all Archery decisions and HTTP calls. Do not reproduce the login, CSRF, validation, or submission flow with ad hoc shell commands.

## Configuration

Require `ARCHERY_CONFIG_FILE` to identify the external shared configuration file. If it is absent, the client uses `~/.config/archery-sql-skills/config.json`. Read only the `submit` section and its configured writable-instance allowlist. Never infer an instance or database not present in that configuration.

## Credentials

Require both environment variables before contacting Archery:

- `ARCHERY_USERNAME`
- `ARCHERY_PASSWORD`

Read credentials from the process environment. On macOS, the client also accepts values from the login-session environment. Never print, persist, interpolate into command arguments, or include either value in an answer. If either variable is absent, stop and report its name only.

## Workflow

1. Obtain the SQL file, workflow title, target instance, database, optional demand URL, backup choice, and optional execution window. Do not infer an ambiguous target.
2. Inspect available groups or databases when needed:

   ```bash
   python3 scripts/archery_client.py inspect
   python3 scripts/archery_client.py databases --instance '<configured-instance>'
   ```

3. Run server-side checking before discussing submission:

   ```bash
   python3 scripts/archery_client.py check \
     --sql-file /absolute/path/change.sql \
     --instance '<configured-instance>' \
     --database '<database>'
   ```

4. Report the exact target, SQL SHA-256, warning count, error count, affected rows when present, and every returned review error. Fail visibly if checking is partial or unavailable.
5. Never submit when `error_count` is greater than zero. When warnings exist, explain them and require the user to explicitly accept them.
6. Ask for explicit submission confirmation after showing the check result. Confirmation given before checking does not count.
7. Submit the same SQL by passing the confirmed SHA-256. Add `--allow-warnings` only when the user explicitly accepted the reported warnings:

   ```bash
   python3 scripts/archery_client.py submit \
     --sql-file /absolute/path/change.sql \
     --instance '<configured-instance>' \
     --database '<database>' \
     --group '<resource-group-name>' \
     --title '<workflow-title>' \
     --confirmed-sha256 '<sha256-from-check>'
   ```

8. Return the created workflow ID and URL. If the response does not contain a workflow detail redirect, treat submission as failed.

## Safety Boundary

- Create SQL approval workflows only. Never call approval, pass, execute, timing-task, cancel, or rollback endpoints.
- Use only instances allowed by the external `submit` configuration.
- Verify the selected instance is writable in the chosen resource group and that the database exists before checking or submitting.
- Recheck SQL immediately before submission. The Archery server also performs its own check.
- Treat `auditors` values as approval-role configuration, not as the resource group name required by v1.8.0 submission.
- Keep backup enabled unless the user explicitly requests otherwise.
- Preserve all server errors in the result, but never expose cookies, CSRF tokens, usernames, or passwords.
