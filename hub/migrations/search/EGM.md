# Search Schema Migrations (`hub/migrations/search`)

## Overview
Defines the SQLite / Cloudflare D1 full-text search schema (`0001_fts.sql`) for EdgeFetch Hub document chunk storage and synchronized FTS5 lexical indexing.

## Interface
- `CREATE TABLE chunks (...) STRICT` (`id INTEGER PRIMARY KEY`, `collection_id`, `document_id`, `page_id`, `ordinal`, `url`, `title`, `heading`, `text`, `fetched_at`) `[0001_fts.sql:chunks]`
- `CREATE INDEX chunks_collection_time_idx ON chunks(collection_id, fetched_at DESC)` `[0001_fts.sql:chunks_collection_time_idx]`
- `CREATE VIRTUAL TABLE chunks_fts USING fts5(title, heading, text, content = 'chunks', content_rowid = 'id', tokenize = 'porter unicode61 remove_diacritics 2')` `[0001_fts.sql:chunks_fts]`
- `CREATE TRIGGER chunks_ai AFTER INSERT ON chunks` `[0001_fts.sql:chunks_ai]`
- `CREATE TRIGGER chunks_ad AFTER DELETE ON chunks` `[0001_fts.sql:chunks_ad]`
- `CREATE TRIGGER chunks_au AFTER UPDATE ON chunks` `[0001_fts.sql:chunks_au]`

## Invariants
- `chunks` enforces SQLite `STRICT` typing, integer primary key `id INTEGER PRIMARY KEY`, `NOT NULL` on all columns (`title` and `heading` defaulting to `''`), and composite uniqueness `UNIQUE (collection_id, page_id, ordinal)` `[0001_fts.sql:chunks]`.
- `chunks_fts` is an external-content FTS5 virtual table (`content = 'chunks'`, `content_rowid = 'id'`) tokenized with `'porter unicode61 remove_diacritics 2'` and kept synchronized with `chunks` exclusively through `chunks_ai`, `chunks_ad`, and `chunks_au` triggers `[0001_fts.sql:chunks_fts]`.

## Side Effects
- Creates `STRICT` table `chunks`, index `chunks_collection_time_idx`, FTS5 virtual table `chunks_fts`, and triggers `chunks_ai`, `chunks_ad`, and `chunks_au` in the target SQLite / D1 database `[0001_fts.sql:chunks]` `[0001_fts.sql:chunks_collection_time_idx]` `[0001_fts.sql:chunks_fts]`.
- `AFTER INSERT ON chunks` fires `chunks_ai` to insert `(new.id, new.title, new.heading, new.text)` into `chunks_fts` `[0001_fts.sql:chunks_ai]`.
- `AFTER DELETE ON chunks` fires `chunks_ad` to issue the FTS5 `'delete'` command for `(old.id, old.title, old.heading, old.text)` against `chunks_fts` `[0001_fts.sql:chunks_ad]`.
- `AFTER UPDATE ON chunks` fires `chunks_au` to issue the FTS5 `'delete'` command for old values followed by inserting updated `(new.id, new.title, new.heading, new.text)` into `chunks_fts` `[0001_fts.sql:chunks_au]`.

## Verification
- Run: `npm --prefix hub test`
