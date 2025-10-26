# Balansoved Migrations

A small toolkit to generate, apply, and rollback YDB (Yandex Database) migrations with goose, featuring a per‑database folder layout and safe logging.

## Quick setup
- Install Yandex Cloud CLI and authenticate: `yc init`. Install YDB CLI and goose: `go install github.com/pressly/goose/v3/cmd/goose@latest`.
- Install Python deps: `python -m pip install -r requirements.txt`. The first run of `create_migration.py` will fetch and save an IAM token to `iam.token`.

## Folder layout
- Migrations are written to: `<db_uid> (<db_name>)/<ydb_parent_path>/<table_name>/<timestamp>_migration.sql`.
- Absolute table paths are embedded in SQL (backticks), so each migration targets the exact database/table regardless of DSN.

## Scripts

### create_migration.py
- Opens a Tk UI to choose a YDB database and a table, groups tables by schema signature, and generates a migration that adds/drops `remote_interface_access_key`.
- Writes the file under `<db_uid> (<db_name>)/…/<table_name>/` using absolute table paths and goose Up/Down sections.

### apply_migration.py
- Lets you pick a `.sql` file, parses absolute database paths, builds a temporary one‑file subset per DB, and runs `goose up-to <version>`.
- Prints status before/after and safely ignores YDB close‑time `DeadlineExceeded` noise.

### rollback_migration.py
- Lets you pick a `.sql` file, extracts the version from its name, derives the database path from SQL, and runs `goose down-to <version-1>` (skips if the chosen version wasn’t applied).
- Prints status before/after and safely ignores YDB close‑time `DeadlineExceeded` noise.

## Notes
- Secrets (like `iam.token`) are excluded by `.gitignore`. Do not commit tokens or private keys.
- Goose applies/rolls back strictly by version numbers taken from file names; a migration remains Pending if its Up fails (e.g., trying to add an already existing column).
