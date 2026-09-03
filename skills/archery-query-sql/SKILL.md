---
name: archery-query-sql
description: Execute read-only MySQL queries through a configured Archery v1.8.0 service. Use when the user asks to query, select, inspect, count, list, or explain data through Archery. Accept exactly one SELECT or EXPLAIN SELECT statement, enforce result limits, and reject all other SQL types.
---

# Archery SQL Query

Run commands from the directory containing this `SKILL.md`, and use `scripts/archery_query.py` for every query and target lookup. Do not reproduce authentication, CSRF handling, SQL classification, or query execution with ad hoc commands.

## Configuration

Require `ARCHERY_CONFIG_FILE` to identify the external shared configuration file. If it is absent, the client uses `~/.config/archery-sql-skills/config.json`. Read only the `query` section and its configured instance allowlist. Never infer an instance or database not present in that configuration.

## Credentials

Require `ARCHERY_USERNAME` and `ARCHERY_PASSWORD` from the process environment. On macOS, the client also accepts values from the login-session environment. Never print, persist, place in command arguments, or include either value in an answer.

## Workflow

1. Obtain the exact instance, database, SQL, and requested row limit. Resolve aliases only through the external configuration; do not infer ambiguous environments.
2. Inspect available query targets when needed:

   ```bash
   python3 scripts/archery_query.py inspect
   python3 scripts/archery_query.py databases --instance '<configured-instance>'
   ```

3. Put inline SQL in a temporary UTF-8 `.sql` file. Keep the SQL exact and remove the temporary file after the command finishes.
4. Pass the SQL file by absolute path. Omit `--limit` to use 100 rows; never exceed 1000:

   ```bash
   python3 scripts/archery_query.py query \
     --sql-file /absolute/path/query.sql \
     --instance '<configured-instance>' \
     --database '<database>' \
     --limit 100
   ```

5. Report the exact target, returned row count, columns, rows, query time, masking state, master lag, and whether the client truncated results. State that Archery records successful queries in its query log.
6. Fail visibly on permission denial, timeout, masking failure, unavailable targets, or server errors. Do not retry against another instance or database.

## Safety Boundary

- Permit exactly one statement beginning with `SELECT`, or `EXPLAIN SELECT`.
- Reject `WITH`, `SHOW`, `DESC`, `DESCRIBE`, all DML/DDL, multiple statements, executable comments, `SELECT ... INTO`, locking reads, assignment operators, and dangerous functions.
- Treat local validation as an additional fail-closed guard. Rely on Archery for authoritative query permission, SQL filtering, timeout, masking, and server-side row limits.
- Never apply for query permission, change permissions, submit an approval workflow, or execute a write operation.
- Do not persist query results or add them to the knowledge base unless the user explicitly requests it.
- Do not expose cookies, CSRF tokens, credentials, or unrelated databases and rows in the final answer.
