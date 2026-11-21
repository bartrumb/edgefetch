# Hub Database Migrations (`hub/migrations`)

## Overview
Groups the SQLite / Cloudflare D1 database migration schemas for EdgeFetch Hub, separating core operational metadata tracking (`meta`) from document chunk full-text search indexing (`search`).

## Subdirectories & Boundaries
- `meta`: [`./meta/EGM.md`](./meta/EGM.md) - `STRICT` SQLite / D1 tracking schema (`0001_tracking.sql`) defining `artifacts`, `crawls`, `pages`, `fetches`, and `documents` tables and lookup indexes.
- `search`: [`./search/EGM.md`](./search/EGM.md) - `STRICT` SQLite / D1 full-text search schema (`0001_fts.sql`) defining the `chunks` table, external-content `chunks_fts` FTS5 virtual table, and synchronization triggers (`chunks_ai`, `chunks_ad`, `chunks_au`).
